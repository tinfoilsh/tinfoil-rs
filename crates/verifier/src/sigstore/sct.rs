// Adapted from sigstore-rs (Apache 2.0 License)
// https://github.com/sigstore/sigstore-rs/blob/main/src/crypto/transparency.rs
// https://github.com/sigstore/sigstore-rs/blob/main/src/crypto/keyring.rs
//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modifications: the TLS structures are read and written by hand, log keys
// come from the trusted root, and a log's validity period is checked at the
// timestamp.

//! Signed certificate timestamps embedded in a signing certificate
//! (RFC 6962): proof that a certificate transparency log has seen the
//! certificate.

use ::der::asn1::{ObjectIdentifier, OctetStringRef};
use ::der::{Decode, Encode};
use sha2::{Digest, Sha256};

use super::SigstoreError;
use super::trusted_root::{TransparencyLog, TrustedRoot};
use crate::instant::Instant;
use crate::stub::pending;
use crate::x509::{Certificate, EcdsaHash, SignatureScheme};

/// The certificate extension that carries the timestamp list.
pub const OID_SCT_LIST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

/// The most timestamps that one certificate may embed.
pub const MAX_SCTS: usize = 16;

const SCT_VERSION_1: u8 = 0;
const SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP: u8 = 0;
const ENTRY_TYPE_PRECERTIFICATE: u16 = 1;
const HASH_ALGORITHM_SHA256: u8 = 4;
const SIGNATURE_ALGORITHM_ECDSA: u8 = 3;

/// One signed certificate timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sct {
    /// The identifier of the log that issued the timestamp.
    pub log_id: [u8; 32],
    /// When the log saw the certificate, in milliseconds since the Unix
    /// epoch.
    pub timestamp_ms: u64,
    /// The timestamp's extensions, as encoded.
    pub extensions: Vec<u8>,
    /// The TLS hash algorithm of the signature.
    pub hash_algorithm: u8,
    /// The TLS signature algorithm of the signature.
    pub signature_algorithm: u8,
    /// The signature.
    pub signature: Vec<u8>,
}

impl Sct {
    /// The instant of the timestamp. An error when it is beyond the
    /// representable range.
    pub fn time(&self) -> Result<Instant, SigstoreError> {
        let seconds = i64::try_from(self.timestamp_ms / 1000).ok();
        let nanos = u32::try_from(self.timestamp_ms % 1000)
            .ok()
            .and_then(|millis| millis.checked_mul(1_000_000));
        seconds
            .zip(nanos)
            .and_then(|(seconds, nanos)| Instant::from_unix(seconds, nanos))
            .ok_or_else(|| error("certificate timestamp is out of range"))
    }
}

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

/// Reads fields of a TLS structure from the front of a byte string.
struct TlsReader<'a> {
    bytes: &'a [u8],
}

impl<'a> TlsReader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(count)?;
        self.bytes = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.bytes.split_first_chunk::<N>()?;
        self.bytes = rest;
        Some(*head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// A byte string with a two-byte length in front.
    fn opaque16(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The signed certificate timestamps that a certificate embeds, in order.
///
/// A certificate without the extension has none. A present extension must
/// be an OCTET STRING that holds one well-formed list: every length exact,
/// 1 to [`MAX_SCTS`] timestamps, each of version 1.
pub fn embedded_scts(certificate: &Certificate) -> Result<Vec<Sct>, SigstoreError> {
    let Some(extension) = certificate.extension(OID_SCT_LIST) else {
        return Ok(Vec::new());
    };
    let malformed = || error("certificate timestamp list is malformed");
    let list = OctetStringRef::from_der(extension.value).map_err(|_| malformed())?;
    let mut outer = TlsReader {
        bytes: list.as_bytes(),
    };
    let mut entries = TlsReader {
        bytes: outer.opaque16().ok_or_else(malformed)?,
    };
    if !outer.is_empty() {
        return Err(malformed());
    }
    let mut scts = Vec::new();
    while !entries.is_empty() {
        if scts.len() >= MAX_SCTS {
            return Err(error("certificate embeds too many timestamps"));
        }
        let mut entry = TlsReader {
            bytes: entries.opaque16().ok_or_else(malformed)?,
        };
        if entry.u8().ok_or_else(malformed)? != SCT_VERSION_1 {
            return Err(error("certificate timestamp has an unsupported version"));
        }
        let sct = Sct {
            log_id: entry.array().ok_or_else(malformed)?,
            timestamp_ms: entry.u64().ok_or_else(malformed)?,
            extensions: entry.opaque16().ok_or_else(malformed)?.to_vec(),
            hash_algorithm: entry.u8().ok_or_else(malformed)?,
            signature_algorithm: entry.u8().ok_or_else(malformed)?,
            signature: entry.opaque16().ok_or_else(malformed)?.to_vec(),
        };
        if !entry.is_empty() {
            return Err(malformed());
        }
        scts.push(sct);
    }
    if scts.is_empty() {
        return Err(malformed());
    }
    Ok(scts)
}

/// Rejects a list in which two timestamps come from the same log, so that
/// one log cannot count twice.
pub fn reject_duplicate_logs(scts: &[Sct]) -> Result<(), SigstoreError> {
    let mut seen: Vec<&[u8; 32]> = Vec::with_capacity(scts.len());
    for sct in scts {
        if seen.contains(&&sct.log_id) {
            return Err(error(
                "certificate carries more than one timestamp from the same log",
            ));
        }
        seen.push(&sct.log_id);
    }
    Ok(())
}

/// The bytes that a log signed when it issued `sct` for `certificate`: the
/// RFC 6962 `digitally-signed` structure of a precertificate entry.
///
/// The precertificate is the certificate's `tbsCertificate` without the
/// timestamp list extension, and it is bound to the issuer by the SHA-256 of
/// the issuer's SubjectPublicKeyInfo.
pub fn signed_payload(
    certificate: &Certificate,
    issuer_spki_der: &[u8],
    sct: &Sct,
) -> Result<Vec<u8>, SigstoreError> {
    let mut precertificate = certificate.parsed().tbs_certificate.clone();
    precertificate.extensions = precertificate.extensions.map(|extensions| {
        extensions
            .into_iter()
            .filter(|extension| extension.extn_id != OID_SCT_LIST)
            .collect()
    });
    let precertificate = precertificate
        .to_der()
        .map_err(|cause| error(format!("encoding the precertificate: {cause}")))?;
    let too_long = || error("certificate timestamp input is too long");
    let precertificate_len = u32::try_from(precertificate.len())
        .ok()
        .filter(|length| *length < 1 << 24)
        .ok_or_else(too_long)?;
    let [_, length_bytes @ ..] = precertificate_len.to_be_bytes();
    let extensions_len = u16::try_from(sct.extensions.len()).map_err(|_| too_long())?;

    let mut payload = Vec::with_capacity(precertificate.len().saturating_add(64));
    payload.push(SCT_VERSION_1);
    payload.push(SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP);
    payload.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    payload.extend_from_slice(&ENTRY_TYPE_PRECERTIFICATE.to_be_bytes());
    payload.extend_from_slice(&Sha256::digest(issuer_spki_der));
    payload.extend_from_slice(&length_bytes);
    payload.extend_from_slice(&precertificate);
    payload.extend_from_slice(&extensions_len.to_be_bytes());
    payload.extend_from_slice(&sct.extensions);
    Ok(payload)
}

/// Verifies one timestamp of `certificate` under a log's key, and returns
/// the instant of the timestamp.
///
/// The log is the one that the timestamp names; the timestamp's instant is
/// within the period for which the log's key is trusted; the signature is
/// ECDSA with SHA-256 over [`signed_payload`] for the given issuer.
pub fn verify_sct(
    certificate: &Certificate,
    issuer: &Certificate,
    sct: &Sct,
    log: &TransparencyLog,
) -> Result<Instant, SigstoreError> {
    if log.log_id != sct.log_id {
        return Err(error("certificate timestamp is from another log"));
    }
    let time = sct.time()?;
    if !log.valid_for.contains(time) {
        return Err(error(
            "certificate timestamp is outside the period of its log's key",
        ));
    }
    if sct.hash_algorithm != HASH_ALGORITHM_SHA256
        || sct.signature_algorithm != SIGNATURE_ALGORITHM_ECDSA
    {
        return Err(error(
            "certificate timestamp is not signed with ECDSA and SHA-256",
        ));
    }
    let payload = signed_payload(certificate, &issuer.spki_der()?, sct)?;
    log.key
        .verify(
            SignatureScheme::EcdsaDer(EcdsaHash::Sha256),
            &payload,
            &sct.signature,
        )
        .map_err(|cause| error(format!("certificate timestamp: {cause}")))?;
    Ok(time)
}

/// Verifies the embedded timestamps of a signing certificate against the
/// certificate transparency logs of a trusted root, and returns how many
/// verified.
///
/// In order:
///
/// 1. the certificate's timestamp list decodes ([`embedded_scts`]), and no
///    two timestamps name the same log ([`reject_duplicate_logs`]);
/// 2. a timestamp from a log that the trusted root does not list, or whose
///    instant is outside the period of that log's key, is skipped;
/// 3. each remaining timestamp is verified with [`verify_sct`] against each
///    of `issuers` in turn (the certificates that may have issued the leaf:
///    the intermediates and roots of the paths that verified), and counts
///    when it verifies under one of them;
/// 4. at least one timestamp counts; otherwise the certificate is
///    rejected.
pub fn verify_scts(
    root: &TrustedRoot,
    certificate: &Certificate,
    issuers: &[Certificate],
) -> Result<usize, SigstoreError> {
    pending("sigstore::sct::verify_scts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::trusted_root::ValidFor;
    use crate::x509::PublicKey;
    use crate::x509::certificate::testdata::{
        FULCIO_INTERMEDIATE_PEM, FULCIO_LEAF_PEM, certificate,
    };

    /// The key of the certificate transparency log that was in use in
    /// December 2023.
    const CT_LOG_KEY_PEM: &str = include_str!("../../tests/data/sigstore/ctfe_2022.pub.pem");

    fn at(text: &str) -> Instant {
        Instant::parse_rfc3339(text).unwrap()
    }

    fn ct_log() -> TransparencyLog {
        let key = PublicKey::from_pem(CT_LOG_KEY_PEM).unwrap();
        TransparencyLog {
            base_url: "https://ctfe.sigstore.dev/2022".to_string(),
            log_id: key.spki_sha256().to_vec(),
            key,
            valid_for: ValidFor {
                start: Some(at("2022-10-20T00:00:00Z")),
                end: None,
            },
        }
    }

    fn leaf_sct() -> (Certificate, Certificate, Sct) {
        let leaf = certificate(FULCIO_LEAF_PEM);
        let issuer = certificate(FULCIO_INTERMEDIATE_PEM);
        let mut scts = embedded_scts(&leaf).unwrap();
        assert_eq!(scts.len(), 1);
        (leaf, issuer, scts.remove(0))
    }

    #[test]
    fn an_embedded_timestamp_decodes() {
        let (_, _, sct) = leaf_sct();
        assert_eq!(sct.log_id.as_slice(), ct_log().log_id);
        assert_eq!(sct.time().unwrap(), at("2023-12-13T05:50:55.02Z"));
        assert!(sct.extensions.is_empty());
        assert_eq!(
            (sct.hash_algorithm, sct.signature_algorithm),
            (HASH_ALGORITHM_SHA256, SIGNATURE_ALGORITHM_ECDSA)
        );
    }

    #[test]
    fn an_embedded_timestamp_verifies_under_its_log_key() {
        let (leaf, issuer, sct) = leaf_sct();
        assert_eq!(
            verify_sct(&leaf, &issuer, &sct, &ct_log()).unwrap(),
            at("2023-12-13T05:50:55.02Z")
        );
    }

    #[test]
    fn a_timestamp_does_not_verify_for_another_issuer() {
        let (leaf, _, sct) = leaf_sct();
        assert!(verify_sct(&leaf, &leaf, &sct, &ct_log()).is_err());
    }

    #[test]
    fn a_changed_timestamp_does_not_verify() {
        let (leaf, issuer, sct) = leaf_sct();
        let later = Sct {
            timestamp_ms: sct.timestamp_ms + 1,
            ..sct.clone()
        };
        assert!(verify_sct(&leaf, &issuer, &later, &ct_log()).is_err());
        let extended = Sct {
            extensions: vec![0],
            ..sct.clone()
        };
        assert!(verify_sct(&leaf, &issuer, &extended, &ct_log()).is_err());
        let mut resigned = sct.clone();
        let last = resigned.signature.len() - 1;
        resigned.signature[last] ^= 1;
        assert!(verify_sct(&leaf, &issuer, &resigned, &ct_log()).is_err());
    }

    #[test]
    fn a_timestamp_outside_the_period_of_the_log_key_is_rejected() {
        let (leaf, issuer, sct) = leaf_sct();
        let mut log = ct_log();
        log.valid_for.start = Some(at("2023-12-13T05:50:55.021Z"));
        let error = verify_sct(&leaf, &issuer, &sct, &log).unwrap_err();
        assert!(error.to_string().contains("outside the period"), "{error}");

        log.valid_for = ValidFor {
            start: Some(at("2022-10-20T00:00:00Z")),
            end: Some(at("2023-12-13T05:50:55.019Z")),
        };
        assert!(verify_sct(&leaf, &issuer, &sct, &log).is_err());

        log.valid_for.end = Some(at("2023-12-13T05:50:55.02Z"));
        assert!(verify_sct(&leaf, &issuer, &sct, &log).is_ok());
    }

    #[test]
    fn a_timestamp_is_checked_against_the_log_that_it_names() {
        let (leaf, issuer, sct) = leaf_sct();
        let mut log = ct_log();
        log.log_id[0] ^= 1;
        let error = verify_sct(&leaf, &issuer, &sct, &log).unwrap_err();
        assert!(error.to_string().contains("another log"), "{error}");
    }

    #[test]
    fn a_timestamp_with_another_algorithm_is_rejected() {
        let (leaf, issuer, sct) = leaf_sct();
        let sha384 = Sct {
            hash_algorithm: 5,
            ..sct.clone()
        };
        assert!(verify_sct(&leaf, &issuer, &sha384, &ct_log()).is_err());
        let rsa = Sct {
            signature_algorithm: 1,
            ..sct
        };
        assert!(verify_sct(&leaf, &issuer, &rsa, &ct_log()).is_err());
    }

    #[test]
    fn a_certificate_without_the_extension_has_no_timestamps() {
        let intermediate = certificate(FULCIO_INTERMEDIATE_PEM);
        assert!(embedded_scts(&intermediate).unwrap().is_empty());
    }

    #[test]
    fn two_timestamps_from_one_log_are_rejected() {
        let (_, _, sct) = leaf_sct();
        let mut other = sct.clone();
        other.log_id[0] ^= 1;
        reject_duplicate_logs(&[sct.clone(), other]).unwrap();
        reject_duplicate_logs(&[]).unwrap();
        let later = Sct {
            timestamp_ms: sct.timestamp_ms + 1,
            ..sct.clone()
        };
        assert!(reject_duplicate_logs(&[sct, later]).is_err());
    }

    #[test]
    fn the_signed_payload_leaves_out_the_timestamp_list() {
        let (leaf, issuer, sct) = leaf_sct();
        let payload = signed_payload(&leaf, &issuer.spki_der().unwrap(), &sct).unwrap();
        assert_eq!(&payload[..2], [0, 0]);
        assert_eq!(payload[2..10], sct.timestamp_ms.to_be_bytes());
        assert_eq!(&payload[10..12], [0, 1]);
        assert_eq!(payload[12..44], issuer.public_key().unwrap().spki_sha256());
        let precertificate_len = u32::from_be_bytes([0, payload[44], payload[45], payload[46]]);
        assert_eq!(payload.len(), 47 + precertificate_len as usize + 2);
        assert!((precertificate_len as usize) < leaf.tbs_der().len());
        let list_oid = OID_SCT_LIST.as_bytes();
        assert!(
            leaf.tbs_der()
                .windows(list_oid.len())
                .any(|w| w == list_oid)
        );
        assert!(!payload.windows(list_oid.len()).any(|w| w == list_oid));
    }
}
