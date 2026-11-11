//! The Sigstore trusted root: the transparency logs, certificate
//! authorities and timestamp authorities that bundle verification trusts,
//! each with the period for which it is trusted.

use super::SigstoreError;
use crate::instant::Instant;
use crate::stub::pending;
use crate::x509::{Certificate, PublicKey};

/// The media type of the trusted root documents that are read.
pub const TRUSTED_ROOT_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1";

/// The most certificates in one authority's chain.
pub const MAX_AUTHORITY_CHAIN: usize = 8;

/// The period for which a key or an authority is trusted. Both ends belong
/// to the period; a missing end leaves that side open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValidFor {
    /// The first instant of the period.
    pub start: Option<Instant>,
    /// The last instant of the period.
    pub end: Option<Instant>,
}

impl ValidFor {
    /// Whether `at` is within the period: not before `start` and not after
    /// `end`.
    pub fn contains(&self, at: Instant) -> bool {
        self.start.is_none_or(|start| start <= at) && self.end.is_none_or(|end| at <= end)
    }
}

/// A transparency log: a Rekor log or a certificate transparency log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparencyLog {
    /// The log's base URL.
    pub base_url: String,
    /// The identifier that entries of this log carry, as stated in the
    /// trusted root. For some logs it is not the hash of the key, so it is
    /// never recomputed.
    pub log_id: Vec<u8>,
    /// The log's public key.
    pub key: PublicKey,
    /// When the key is trusted. A log always states a start.
    pub valid_for: ValidFor,
}

impl TransparencyLog {
    /// The host of the log's base URL: the name under which the log signs
    /// its checkpoints. An error when the base URL has no host.
    pub fn checkpoint_name(&self) -> Result<&str, SigstoreError> {
        pending("sigstore::trusted_root::TransparencyLog::checkpoint_name")
    }
}

/// A certificate authority that issues signing certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthority {
    /// The authority's URI.
    pub uri: String,
    /// The authority's intermediate certificates, nearest to the leaf
    /// first. Empty when the root issues leaves directly.
    pub intermediates: Vec<Certificate>,
    /// The authority's root certificate.
    pub root: Certificate,
    /// When the authority is trusted. Open on both sides when the trusted
    /// root states no period.
    pub valid_for: ValidFor,
}

/// An RFC 3161 timestamp authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampAuthority {
    /// The authority's URI.
    pub uri: String,
    /// The certificate that signs timestamps, when the chain states one:
    /// the first certificate of the chain if it is not a CA.
    pub leaf: Option<Certificate>,
    /// The intermediate certificates, nearest to the leaf first.
    pub intermediates: Vec<Certificate>,
    /// The root certificate.
    pub root: Certificate,
    /// When the authority is trusted.
    pub valid_for: ValidFor,
}

/// A parsed trusted root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRoot {
    rekor_logs: Vec<TransparencyLog>,
    ct_logs: Vec<TransparencyLog>,
    certificate_authorities: Vec<CertificateAuthority>,
    timestamp_authorities: Vec<TimestampAuthority>,
}

impl TrustedRoot {
    /// Parses a trusted root document.
    ///
    /// The document is strict JSON (no repeated member names, valid UTF-8,
    /// nothing after it), and every object is read with a closed set of
    /// member names: an unknown member is an error at any depth. Rules, each
    /// an error when broken:
    ///
    /// - `mediaType` is [`TRUSTED_ROOT_MEDIA_TYPE`];
    /// - `tlogs`, `ctlogs`, `certificateAuthorities` and
    ///   `timestampAuthorities` are arrays; each may be empty or absent;
    /// - a log has `hashAlgorithm` `SHA2_256`, a `logId.keyId` (canonical
    ///   base64, not empty), a `publicKey` with `rawBytes` (canonical
    ///   base64 of a SubjectPublicKeyInfo that
    ///   [`PublicKey::from_spki_der`] accepts), a `keyDetails` that names
    ///   the key's type (`PKIX_ECDSA_P256_SHA_256` or `PKIX_ED25519`; any
    ///   other value is an error), and a `validFor` with a `start`;
    /// - two logs of one list do not share an identifier;
    /// - an authority has a `certChain.certificates` array of 1 to
    ///   [`MAX_AUTHORITY_CHAIN`] entries, each `rawBytes` the canonical
    ///   base64 of a certificate that [`Certificate::from_der`] accepts.
    ///   The last certificate is the root; for a timestamp authority the
    ///   first is the signing certificate when it is not a CA. `validFor`
    ///   is optional, and so are its `start` and `end`;
    /// - times are RFC 3339 as [`Instant::parse_rfc3339`] reads them.
    ///
    /// Nothing is filtered at parse time. Whether a log or an authority is
    /// trusted for a given signature is decided at verification, by the
    /// time that the signature's own evidence proves.
    pub fn from_json(data: &[u8]) -> Result<Self, SigstoreError> {
        pending("sigstore::trusted_root::TrustedRoot::from_json")
    }

    /// The Rekor logs, in document order.
    pub fn rekor_logs(&self) -> &[TransparencyLog] {
        &self.rekor_logs
    }

    /// The certificate transparency logs, in document order.
    pub fn ct_logs(&self) -> &[TransparencyLog] {
        &self.ct_logs
    }

    /// The certificate authorities, in document order.
    pub fn certificate_authorities(&self) -> &[CertificateAuthority] {
        &self.certificate_authorities
    }

    /// The timestamp authorities, in document order.
    pub fn timestamp_authorities(&self) -> &[TimestampAuthority] {
        &self.timestamp_authorities
    }

    /// The Rekor log with the given identifier.
    pub fn rekor_log(&self, log_id: &[u8]) -> Option<&TransparencyLog> {
        self.rekor_logs.iter().find(|log| log.log_id == log_id)
    }

    /// The certificate transparency log with the given identifier.
    pub fn ct_log(&self, log_id: &[u8]) -> Option<&TransparencyLog> {
        self.ct_logs.iter().find(|log| log.log_id == log_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Instant {
        Instant::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn a_period_includes_both_of_its_ends() {
        let period = ValidFor {
            start: Some(at("2021-03-07T03:20:29Z")),
            end: Some(at("2022-12-31T23:59:59.999Z")),
        };
        assert!(period.contains(at("2021-03-07T03:20:29Z")));
        assert!(period.contains(at("2022-12-31T23:59:59.999Z")));
        assert!(period.contains(at("2022-01-01T00:00:00Z")));
        assert!(!period.contains(at("2021-03-07T03:20:28.999999999Z")));
        assert!(!period.contains(at("2022-12-31T23:59:59.999000001Z")));
    }

    #[test]
    fn a_missing_end_leaves_the_period_open() {
        let from = ValidFor {
            start: Some(at("2021-01-12T11:53:27Z")),
            end: None,
        };
        assert!(from.contains(at("9999-12-31T23:59:59Z")));
        assert!(!from.contains(at("2021-01-12T11:53:26Z")));
        assert!(ValidFor::default().contains(Instant::UNIX_EPOCH));
    }
}
