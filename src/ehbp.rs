//! Encrypted HTTP Body Protocol (EHBP) client support.
//!
//! EHBP encrypts HTTP message bodies end-to-end between this client and
//! the attested enclave while leaving headers in the clear, so an
//! untrusted proxy can route, authenticate, and meter requests without
//! ever seeing plaintext. Request bodies are sealed with HPKE (RFC 9180)
//! to the enclave's attested public key; response keys are derived from
//! the request's HPKE context following the EHBP specification (which
//! mirrors OHTTP, RFC 9458).
//!
//! Wire format (both directions): a sequence of chunks, each
//! `LEN (4-byte big-endian u32) || CIPHERTEXT (LEN bytes)`, where every
//! chunk is sealed with AES-256-GCM and empty AAD.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use bytes::{Buf, Bytes, BytesMut};
use futures_util::Stream;
use hkdf::Hkdf;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem, X25519HkdfSha256};
use hpke::{setup_sender, Deserializable as _, OpModeS, Serializable as _};
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Request header carrying the hex-encoded HPKE encapsulated key.
pub(crate) const ENCAPSULATED_KEY_HEADER: &str = "ehbp-encapsulated-key";
/// Response header carrying the hex-encoded 32-byte response nonce.
pub(crate) const RESPONSE_NONCE_HEADER: &str = "ehbp-response-nonce";
/// Header telling the proxy which enclave to forward the request to.
pub(crate) const ENCLAVE_URL_HEADER: &str = "x-tinfoil-enclave-url";

const HPKE_REQUEST_INFO: &[u8] = b"ehbp request";
const EXPORT_LABEL: &[u8] = b"ehbp response";
const EXPORT_LENGTH: usize = 32;
const REQUEST_ENC_LENGTH: usize = 32;
const RESPONSE_NONCE_LENGTH: usize = 32;
const AES256_KEY_LENGTH: usize = 32;
const AES_GCM_NONCE_LENGTH: usize = 12;
const RESPONSE_KEY_LABEL: &[u8] = b"key";
const RESPONSE_NONCE_LABEL: &[u8] = b"nonce";
/// Upper bound on a single response chunk's declared ciphertext length,
/// enforced before buffering so a hostile length prefix cannot trigger a
/// multi-gigabyte allocation.
const MAX_CHUNK_BYTES: usize = 64 * 1024 * 1024;

type Aead256 = AesGcm256;
type Kdf = HkdfSha256;
type KemSuite = X25519HkdfSha256;

/// The enclave's attested HPKE public key, used to seal request bodies.
pub(crate) struct EhbpIdentity {
    public_key: <KemSuite as Kem>::PublicKey,
}

impl EhbpIdentity {
    /// Build an identity from the attested HPKE public key (lowercase hex,
    /// as carried in the attestation report's `report_data`).
    pub(crate) fn from_public_key_hex(public_key_hex: &str) -> Result<Self> {
        let bytes = hex::decode(public_key_hex)
            .map_err(|err| Error::Ehbp(format!("invalid HPKE public key hex: {err}")))?;
        if bytes.len() != REQUEST_ENC_LENGTH {
            return Err(Error::Ehbp(format!(
                "HPKE public key must be {REQUEST_ENC_LENGTH} bytes, got {}",
                bytes.len()
            )));
        }
        let public_key = <KemSuite as Kem>::PublicKey::from_bytes(&bytes)
            .map_err(|err| Error::Ehbp(format!("invalid X25519 public key: {err:?}")))?;
        Ok(Self { public_key })
    }

    /// Seal a request body to the enclave key.
    ///
    /// Returns `None` for empty bodies: per SPEC §7.4 bodyless requests
    /// pass through unencrypted because the encrypted body is what
    /// authenticates the encapsulated key.
    pub(crate) fn encrypt_request_body(
        &self,
        plaintext: &[u8],
    ) -> Result<Option<EncryptedRequestBody>> {
        if plaintext.is_empty() {
            return Ok(None);
        }

        let mut csprng = StdRng::from_os_rng();
        let (enc, mut sender) = setup_sender::<Aead256, Kdf, KemSuite, _>(
            &OpModeS::Base,
            &self.public_key,
            HPKE_REQUEST_INFO,
            &mut csprng,
        )
        .map_err(|err| Error::Ehbp(format!("failed to set up HPKE sender: {err:?}")))?;

        let ciphertext = sender
            .seal(plaintext, &[])
            .map_err(|err| Error::Ehbp(format!("failed to seal request body: {err:?}")))?;
        let body = frame_chunk(&ciphertext)?;

        let mut exported_secret = Zeroizing::new(vec![0u8; EXPORT_LENGTH]);
        sender
            .export(EXPORT_LABEL, &mut exported_secret)
            .map_err(|err| Error::Ehbp(format!("failed to export response secret: {err:?}")))?;

        let request_enc = enc.to_bytes().to_vec();
        Ok(Some(EncryptedRequestBody {
            encapsulated_key_hex: hex::encode(&request_enc),
            body,
            context: ResponseContext {
                exported_secret,
                request_enc,
            },
        }))
    }
}

/// A sealed request body plus the material needed to decrypt its response.
pub(crate) struct EncryptedRequestBody {
    pub(crate) encapsulated_key_hex: String,
    pub(crate) body: Vec<u8>,
    pub(crate) context: ResponseContext,
}

/// Per-exchange secrets binding the response to its request (SPEC §4.4).
pub(crate) struct ResponseContext {
    exported_secret: Zeroizing<Vec<u8>>,
    request_enc: Vec<u8>,
}

/// Derived AES-256-GCM key material for one response.
pub(crate) struct ResponseKeyMaterial {
    key: [u8; AES256_KEY_LENGTH],
    nonce_base: [u8; AES_GCM_NONCE_LENGTH],
}

impl Drop for ResponseKeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce_base.zeroize();
    }
}

/// Derive response keys per SPEC §4.4.1:
/// `prk = Extract(salt = enc || response_nonce, secret)` then
/// `key = Expand(prk, "key")`, `nonce_base = Expand(prk, "nonce")`.
pub(crate) fn derive_response_keys(
    exported_secret: &[u8],
    request_enc: &[u8],
    response_nonce: &[u8],
) -> Result<ResponseKeyMaterial> {
    if exported_secret.len() != EXPORT_LENGTH {
        return Err(Error::Ehbp(format!(
            "exported secret must be {EXPORT_LENGTH} bytes, got {}",
            exported_secret.len()
        )));
    }
    if request_enc.len() != REQUEST_ENC_LENGTH {
        return Err(Error::Ehbp(format!(
            "request enc must be {REQUEST_ENC_LENGTH} bytes, got {}",
            request_enc.len()
        )));
    }
    if response_nonce.len() != RESPONSE_NONCE_LENGTH {
        return Err(Error::Ehbp(format!(
            "response nonce must be {RESPONSE_NONCE_LENGTH} bytes, got {}",
            response_nonce.len()
        )));
    }

    let mut salt = Vec::with_capacity(request_enc.len() + response_nonce.len());
    salt.extend_from_slice(request_enc);
    salt.extend_from_slice(response_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), exported_secret);
    let mut key = [0u8; AES256_KEY_LENGTH];
    let mut nonce_base = [0u8; AES_GCM_NONCE_LENGTH];
    hk.expand(RESPONSE_KEY_LABEL, &mut key)
        .map_err(|err| Error::Ehbp(format!("failed to derive response key: {err}")))?;
    hk.expand(RESPONSE_NONCE_LABEL, &mut nonce_base)
        .map_err(|err| Error::Ehbp(format!("failed to derive response nonce: {err}")))?;

    Ok(ResponseKeyMaterial { key, nonce_base })
}

/// Nonce for chunk `seq` is `nonce_base XOR seq` with the sequence number
/// big-endian aligned to the end of the nonce.
fn compute_nonce(nonce_base: &[u8; AES_GCM_NONCE_LENGTH], seq: u64) -> [u8; AES_GCM_NONCE_LENGTH] {
    let mut nonce = *nonce_base;
    for i in 0..8 {
        nonce[AES_GCM_NONCE_LENGTH - 1 - i] ^= (seq >> (i * 8)) as u8;
    }
    nonce
}

fn decrypt_chunk(
    key_material: &ResponseKeyMaterial,
    seq: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&key_material.key)
        .map_err(|err| Error::Ehbp(format!("failed to create AES-GCM cipher: {err}")))?;
    let nonce = Nonce::from(compute_nonce(&key_material.nonce_base, seq));
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|err| Error::Ehbp(format!("failed to decrypt response chunk: {err}")))
}

fn frame_chunk(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(ciphertext.len())
        .map_err(|_| Error::Ehbp("ciphertext chunk is too large".into()))?;
    let mut framed = Vec::with_capacity(4 + ciphertext.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(ciphertext);
    Ok(framed)
}

/// Extract and validate the response nonce header.
fn response_nonce(headers: &reqwest::header::HeaderMap) -> Result<Vec<u8>> {
    let mut values = headers.get_all(RESPONSE_NONCE_HEADER).iter();
    let nonce = values
        .next()
        .ok_or_else(|| Error::Ehbp(format!("missing {RESPONSE_NONCE_HEADER} header")))?;
    // Duplicate nonce headers are ambiguous framing — fail closed rather
    // than pick one.
    if values.next().is_some() {
        return Err(Error::Ehbp(format!(
            "multiple {RESPONSE_NONCE_HEADER} headers"
        )));
    }
    let nonce = nonce
        .to_str()
        .map_err(|err| Error::Ehbp(format!("invalid response nonce header: {err}")))?;
    let nonce = hex::decode(nonce)
        .map_err(|err| Error::Ehbp(format!("invalid response nonce hex: {err}")))?;
    if nonce.len() != RESPONSE_NONCE_LENGTH {
        return Err(Error::Ehbp(format!(
            "invalid response nonce length: expected {RESPONSE_NONCE_LENGTH}, got {}",
            nonce.len()
        )));
    }
    Ok(nonce)
}

/// Decrypt an encrypted response in place, returning a rebuilt
/// `reqwest::Response` whose body is the decrypted byte stream.
///
/// The framing headers describing the ciphertext (`Content-Length`,
/// `Transfer-Encoding`) are stripped because the plaintext has a
/// different length.
pub(crate) fn decrypt_response(
    mut response: reqwest::Response,
    context: &ResponseContext,
) -> Result<reqwest::Response> {
    use reqwest::ResponseBuilderExt;

    let nonce = response_nonce(response.headers())?;
    let key_material =
        derive_response_keys(&context.exported_secret, &context.request_enc, &nonce)?;

    let status = response.status();
    let version = response.version();
    let url = response.url().clone();
    let extensions = std::mem::take(response.extensions_mut());
    let mut headers = response.headers().clone();
    headers.remove(reqwest::header::CONTENT_LENGTH);
    headers.remove(reqwest::header::TRANSFER_ENCODING);

    let decrypted = decrypt_body_stream(response.bytes_stream(), key_material);
    let mut builder = http::Response::builder().status(status).version(version);
    if let Some(target) = builder.headers_mut() {
        *target = headers;
    }
    // Carry over the original extensions before setting the URL, since
    // `url()` installs the extension reqwest reads the real URL from.
    if let Some(target) = builder.extensions_mut() {
        *target = extensions;
    }
    let rebuilt = builder
        .url(url)
        .body(reqwest::Body::wrap_stream(decrypted))
        .map_err(|err| Error::Ehbp(format!("failed to rebuild decrypted response: {err}")))?;
    Ok(reqwest::Response::from(rebuilt))
}

/// Whether a response carries an encrypted body.
pub(crate) fn is_encrypted_response(response: &reqwest::Response) -> bool {
    response.headers().contains_key(RESPONSE_NONCE_HEADER)
}

/// Incrementally decrypt the length-prefixed chunk stream of a response
/// body. Frames may arrive fragmented across transport reads; a truncated
/// trailing frame is an error (fail closed, SPEC §5.4.1).
fn decrypt_body_stream<S, E>(
    mut body: S,
    key_material: ResponseKeyMaterial,
) -> impl Stream<Item = Result<Bytes>> + Send
where
    S: Stream<Item = std::result::Result<Bytes, E>> + Send + Unpin + 'static,
    E: std::fmt::Display + Send,
{
    async_stream::try_stream! {
        let mut buffer = BytesMut::new();
        let mut seq = 0u64;

        while let Some(chunk) = poll_next(&mut body).await {
            let chunk = chunk.map_err(|err| Error::Ehbp(format!("response body error: {err}")))?;
            buffer.extend_from_slice(&chunk);

            loop {
                if buffer.len() < 4 {
                    break;
                }

                let chunk_len =
                    u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

                // Zero-length chunks are legal (empty writes) and skipped.
                if chunk_len == 0 {
                    buffer.advance(4);
                    continue;
                }

                if chunk_len > MAX_CHUNK_BYTES {
                    Err(Error::Ehbp(
                        "response chunk exceeds maximum allowed size".into(),
                    ))?;
                }

                if buffer.len() < 4 + chunk_len {
                    break;
                }

                buffer.advance(4);
                let ciphertext = buffer.split_to(chunk_len).freeze();
                let plaintext = decrypt_chunk(&key_material, seq, &ciphertext)?;
                seq = seq
                    .checked_add(1)
                    .ok_or_else(|| Error::Ehbp("response chunk sequence overflow".into()))?;
                yield Bytes::from(plaintext);
            }
        }

        if !buffer.is_empty() {
            Err(Error::Ehbp("truncated encrypted response chunk".into()))?;
        }
    }
}

async fn poll_next<S>(stream: &mut S) -> Option<S::Item>
where
    S: Stream + Unpin,
{
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_next(cx)).await
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Server-side EHBP helpers for tests: play the enclave role with the
    //! raw `hpke` crate so client-side code is verified against an
    //! independent implementation of the spec text.

    use super::*;
    use hpke::{setup_receiver, OpModeR};

    pub(crate) struct TestEnclave {
        private_key: <KemSuite as Kem>::PrivateKey,
        public_key: <KemSuite as Kem>::PublicKey,
    }

    impl TestEnclave {
        pub(crate) fn generate() -> Self {
            let mut csprng = StdRng::from_os_rng();
            let (private_key, public_key) = KemSuite::gen_keypair(&mut csprng);
            Self {
                private_key,
                public_key,
            }
        }

        pub(crate) fn public_key_hex(&self) -> String {
            hex::encode(self.public_key.to_bytes())
        }

        /// Decrypt a framed request body and export the response secret,
        /// mirroring the server middleware.
        pub(crate) fn open_request(
            &self,
            encapsulated_key_hex: &str,
            framed_body: &[u8],
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let request_enc = hex::decode(encapsulated_key_hex).unwrap();
            let encapped = <KemSuite as Kem>::EncappedKey::from_bytes(&request_enc).unwrap();
            let mut receiver = setup_receiver::<Aead256, Kdf, KemSuite>(
                &OpModeR::Base,
                &self.private_key,
                &encapped,
                HPKE_REQUEST_INFO,
            )
            .unwrap();

            let mut plaintext = Vec::new();
            let mut offset = 0usize;
            while offset < framed_body.len() {
                let len = u32::from_be_bytes(framed_body[offset..offset + 4].try_into().unwrap())
                    as usize;
                offset += 4;
                if len == 0 {
                    continue;
                }
                plaintext.extend_from_slice(
                    &receiver
                        .open(&framed_body[offset..offset + len], &[])
                        .unwrap(),
                );
                offset += len;
            }

            let mut exported_secret = vec![0u8; EXPORT_LENGTH];
            receiver.export(EXPORT_LABEL, &mut exported_secret).unwrap();
            (plaintext, exported_secret, request_enc)
        }

        /// Derive the export secret for an exchange without reading the
        /// request body (a proxy-style responder only needs `enc`).
        pub(crate) fn export_secret(&self, encapsulated_key_hex: &str) -> (Vec<u8>, Vec<u8>) {
            let request_enc = hex::decode(encapsulated_key_hex).unwrap();
            let encapped = <KemSuite as Kem>::EncappedKey::from_bytes(&request_enc).unwrap();
            let receiver = setup_receiver::<Aead256, Kdf, KemSuite>(
                &OpModeR::Base,
                &self.private_key,
                &encapped,
                HPKE_REQUEST_INFO,
            )
            .unwrap();
            let mut exported_secret = vec![0u8; EXPORT_LENGTH];
            receiver.export(EXPORT_LABEL, &mut exported_secret).unwrap();
            (exported_secret, request_enc)
        }
    }

    /// Encrypt one response body as `chunks` sequential AEAD frames, the
    /// way the server middleware streams a reply.
    pub(crate) fn encrypt_response_chunks(
        exported_secret: &[u8],
        request_enc: &[u8],
        response_nonce: &[u8; RESPONSE_NONCE_LENGTH],
        chunks: &[&[u8]],
    ) -> Vec<u8> {
        let key_material =
            derive_response_keys(exported_secret, request_enc, response_nonce).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key_material.key).unwrap();

        let mut body = Vec::new();
        for (seq, chunk) in chunks.iter().enumerate() {
            let nonce = Nonce::from(compute_nonce(&key_material.nonce_base, seq as u64));
            let ciphertext = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: chunk,
                        aad: &[],
                    },
                )
                .unwrap();
            body.extend_from_slice(&frame_chunk(&ciphertext).unwrap());
        }
        body
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{encrypt_response_chunks, TestEnclave};
    use super::*;
    use futures_util::StreamExt;

    #[test]
    fn nonce_uses_big_endian_sequence_xor() {
        let base = [0u8; AES_GCM_NONCE_LENGTH];
        let nonce = compute_nonce(&base, 0x0102_0304_0506_0708);
        assert_eq!(nonce, [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn rejects_malformed_public_keys() {
        assert!(EhbpIdentity::from_public_key_hex("not-hex").is_err());
        assert!(EhbpIdentity::from_public_key_hex("0011").is_err());
        let ok = hex::encode([7u8; REQUEST_ENC_LENGTH]);
        assert!(EhbpIdentity::from_public_key_hex(&ok).is_ok());
    }

    #[test]
    fn empty_request_bodies_pass_through_plaintext() {
        let enclave = TestEnclave::generate();
        let identity = EhbpIdentity::from_public_key_hex(&enclave.public_key_hex()).unwrap();
        assert!(identity.encrypt_request_body(b"").unwrap().is_none());
    }

    /// Round-trip against an independent HPKE receiver: what our sender
    /// seals must open server-side, and the exported response secrets on
    /// both ends must agree.
    #[test]
    fn request_encryption_round_trips_through_hpke_receiver() {
        let enclave = TestEnclave::generate();
        let identity = EhbpIdentity::from_public_key_hex(&enclave.public_key_hex()).unwrap();

        let encrypted = identity
            .encrypt_request_body(b"{\"model\":\"gpt-oss-120b\"}")
            .unwrap()
            .expect("non-empty bodies are encrypted");

        let (plaintext, server_secret, server_enc) =
            enclave.open_request(&encrypted.encapsulated_key_hex, &encrypted.body);

        assert_eq!(plaintext, b"{\"model\":\"gpt-oss-120b\"}");
        assert_eq!(
            server_secret.as_slice(),
            &*encrypted.context.exported_secret
        );
        assert_eq!(server_enc, encrypted.context.request_enc);
    }

    /// Full response leg: server derives keys from its receiver context and
    /// encrypts; the client-side stream decryptor recovers the plaintext,
    /// including frames fragmented across transport reads.
    #[tokio::test]
    async fn response_decryption_handles_fragmented_frames() {
        let enclave = TestEnclave::generate();
        let identity = EhbpIdentity::from_public_key_hex(&enclave.public_key_hex()).unwrap();
        let encrypted = identity.encrypt_request_body(b"request").unwrap().unwrap();
        let (secret, enc) = enclave.export_secret(&encrypted.encapsulated_key_hex);

        let response_nonce = [9u8; RESPONSE_NONCE_LENGTH];
        let body = encrypt_response_chunks(
            &secret,
            &enc,
            &response_nonce,
            &[b"hello ", b"from the ", b"enclave"],
        );

        let key_material = derive_response_keys(
            &encrypted.context.exported_secret,
            &encrypted.context.request_enc,
            &response_nonce,
        )
        .unwrap();

        // Feed the framed ciphertext 3 bytes at a time to exercise buffering.
        let fragments: Vec<_> = body
            .chunks(3)
            .map(|c| Ok::<Bytes, std::convert::Infallible>(Bytes::copy_from_slice(c)))
            .collect();
        let mut stream = Box::pin(decrypt_body_stream(
            futures_util::stream::iter(fragments),
            key_material,
        ));

        let mut plaintext = Vec::new();
        while let Some(chunk) = stream.next().await {
            plaintext.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(plaintext, b"hello from the enclave");
    }

    #[tokio::test]
    async fn tampered_response_chunks_fail_closed() {
        let enclave = TestEnclave::generate();
        let identity = EhbpIdentity::from_public_key_hex(&enclave.public_key_hex()).unwrap();
        let encrypted = identity.encrypt_request_body(b"request").unwrap().unwrap();
        let (secret, enc) = enclave.export_secret(&encrypted.encapsulated_key_hex);

        let response_nonce = [9u8; RESPONSE_NONCE_LENGTH];
        let mut body = encrypt_response_chunks(&secret, &enc, &response_nonce, &[b"payload"]);
        *body.last_mut().unwrap() ^= 0xff;

        let key_material = derive_response_keys(
            &encrypted.context.exported_secret,
            &encrypted.context.request_enc,
            &response_nonce,
        )
        .unwrap();
        let mut stream = Box::pin(decrypt_body_stream(
            futures_util::stream::iter([Ok::<Bytes, std::convert::Infallible>(Bytes::from(body))]),
            key_material,
        ));

        let err = stream.next().await.unwrap().unwrap_err();
        assert!(matches!(err, Error::Ehbp(msg) if msg.contains("decrypt")));
    }

    #[tokio::test]
    async fn oversized_chunk_length_is_rejected_before_buffering() {
        let key_material = ResponseKeyMaterial {
            key: [0u8; AES256_KEY_LENGTH],
            nonce_base: [0u8; AES_GCM_NONCE_LENGTH],
        };
        // A length prefix declaring a ~4 GiB chunk must fail immediately.
        let framed = Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        let mut stream = Box::pin(decrypt_body_stream(
            futures_util::stream::iter([Ok::<Bytes, std::convert::Infallible>(framed)]),
            key_material,
        ));

        let err = stream.next().await.unwrap().unwrap_err();
        assert!(matches!(err, Error::Ehbp(msg) if msg.contains("maximum allowed size")));
    }

    #[tokio::test]
    async fn truncated_trailing_frame_is_an_error() {
        let key_material = ResponseKeyMaterial {
            key: [0u8; AES256_KEY_LENGTH],
            nonce_base: [0u8; AES_GCM_NONCE_LENGTH],
        };
        // Declares 16 ciphertext bytes but delivers only 2.
        let framed = Bytes::from_static(&[0x00, 0x00, 0x00, 0x10, 0xAA, 0xBB]);
        let mut stream = Box::pin(decrypt_body_stream(
            futures_util::stream::iter([Ok::<Bytes, std::convert::Infallible>(framed)]),
            key_material,
        ));

        let err = stream.next().await.unwrap().unwrap_err();
        assert!(matches!(err, Error::Ehbp(msg) if msg.contains("truncated")));
    }

    /// The rebuilt response must keep the original URL and extensions
    /// instead of reqwest's placeholder, stripping only framing headers.
    #[tokio::test]
    async fn decrypted_response_preserves_url_extensions_and_headers() {
        use reqwest::ResponseBuilderExt;

        #[derive(Clone, Debug, PartialEq)]
        struct Marker(u8);

        let enclave = TestEnclave::generate();
        let identity = EhbpIdentity::from_public_key_hex(&enclave.public_key_hex()).unwrap();
        let encrypted = identity.encrypt_request_body(b"request").unwrap().unwrap();
        let (secret, enc) = enclave.export_secret(&encrypted.encapsulated_key_hex);

        let response_nonce = [9u8; RESPONSE_NONCE_LENGTH];
        let body = encrypt_response_chunks(&secret, &enc, &response_nonce, &[b"plaintext"]);

        let url = reqwest::Url::parse("https://proxy.example.com/v1/chat/completions").unwrap();
        let http_response = http::Response::builder()
            .status(200)
            .url(url.clone())
            .header("content-type", "application/json")
            .header(reqwest::header::CONTENT_LENGTH, body.len())
            .header(RESPONSE_NONCE_HEADER, hex::encode(response_nonce))
            .body(reqwest::Body::from(body))
            .unwrap();
        let mut response = reqwest::Response::from(http_response);
        response.extensions_mut().insert(Marker(7));

        let decrypted = decrypt_response(response, &encrypted.context).unwrap();
        assert_eq!(decrypted.url().as_str(), url.as_str());
        assert_eq!(decrypted.extensions().get::<Marker>(), Some(&Marker(7)));
        assert_eq!(
            decrypted.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert!(decrypted
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .is_none());
        assert_eq!(decrypted.bytes().await.unwrap().as_ref(), b"plaintext");
    }

    #[test]
    fn duplicate_response_nonce_headers_fail_closed() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(RESPONSE_NONCE_HEADER, "00".parse().unwrap());
        headers.append(RESPONSE_NONCE_HEADER, "00".parse().unwrap());
        assert!(response_nonce(&headers).is_err());
    }
}
