//! Unit-test helpers shared across in-crate test modules (compiled only
//! under `cfg(test)`, see `lib.rs`).

use std::sync::{Arc, Mutex};

use serde_json::Value;

pub(crate) mod ehbp {
    //! Server-side EHBP helpers for tests: play the enclave role with the
    //! raw `hpke` crate so the SDK's use of the released `tinfoil-ehbp`
    //! client is verified against an independent implementation of the
    //! spec text.

    use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hpke::aead::AesGcm256;
    use hpke::kdf::HkdfSha256;
    use hpke::kem::{Kem, X25519HkdfSha256};
    use hpke::{setup_receiver, Deserializable as _, OpModeR, Serializable as _};
    use rand::rngs::StdRng;
    use rand::SeedableRng as _;
    use tinfoil_ehbp::{
        compute_nonce, derive_response_keys, EXPORT_LABEL, EXPORT_LENGTH, HPKE_REQUEST_INFO,
        RESPONSE_NONCE_LENGTH,
    };

    type Aead256 = AesGcm256;
    type Kdf = HkdfSha256;
    type KemSuite = X25519HkdfSha256;
    type Receiver = hpke::aead::AeadCtxR<Aead256, Kdf, KemSuite>;

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
            let (mut receiver, exported_secret, request_enc) =
                self.setup_receiver_and_export(encapsulated_key_hex);

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

            (plaintext, exported_secret, request_enc)
        }

        /// Derive the export secret for an exchange without reading the
        /// request body (a proxy-style responder only needs `enc`).
        pub(crate) fn export_secret(&self, encapsulated_key_hex: &str) -> (Vec<u8>, Vec<u8>) {
            let (_, exported_secret, request_enc) =
                self.setup_receiver_and_export(encapsulated_key_hex);
            (exported_secret, request_enc)
        }

        fn setup_receiver_and_export(
            &self,
            encapsulated_key_hex: &str,
        ) -> (Receiver, Vec<u8>, Vec<u8>) {
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
            (receiver, exported_secret, request_enc)
        }
    }

    fn frame_chunk(ciphertext: &[u8]) -> Vec<u8> {
        let len = u32::try_from(ciphertext.len()).unwrap();
        let mut framed = Vec::with_capacity(4 + ciphertext.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(ciphertext);
        framed
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
            body.extend_from_slice(&frame_chunk(&ciphertext));
        }
        body
    }
}

/// Minimal one-request-per-connection HTTP/1.1 server; the crate carries
/// no mock-server dev-dependency. Every request body received is parsed as
/// JSON and pushed onto `received`, then answered with a fixed
/// chat-completion response.
pub(crate) async fn serve_chat_completions(
    listener: tokio::net::TcpListener,
    received: Arc<Mutex<Vec<Value>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let received = Arc::clone(&received);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (headers_end, content_length) = loop {
                let Ok(n) = stream.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let content_length = headers
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::to_string)
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (pos + 4, content_length);
                }
            };
            while buf.len() < headers_end + content_length {
                let Ok(n) = stream.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            if buf.len() < headers_end + content_length {
                // Connection closed before the full body arrived.
                return;
            }
            let body = &buf[headers_end..headers_end + content_length];
            received
                .lock()
                .unwrap()
                .push(serde_json::from_slice(body).unwrap_or(Value::Null));

            let response_body = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop","logprobs":null}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
