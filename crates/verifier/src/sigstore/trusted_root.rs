//! The Sigstore trusted root: the transparency logs, certificate
//! authorities and timestamp authorities that bundle verification trusts,
//! each with the period for which it is trusted.

use super::SigstoreError;
use super::wire::Members;
use crate::instant::Instant;
use crate::json::{self, Value};
use crate::x509::{Certificate, KeyAlgorithm, PublicKey};

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
    /// its checkpoints.
    ///
    /// The base URL has the form `scheme://host`, optionally followed by a
    /// numeric port and by a path, query or fragment. The host consists of
    /// letters, digits, `-` and `.`. Any other base URL is an error.
    pub fn checkpoint_name(&self) -> Result<&str, SigstoreError> {
        let invalid = || {
            SigstoreError::new(format!(
                "transparency log base URL {:?} has no usable host",
                self.base_url
            ))
        };
        let (scheme, rest) = self.base_url.split_once("://").ok_or_else(invalid)?;
        let scheme_ok = scheme.starts_with(|first: char| first.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, port),
            None => (authority, ""),
        };
        let host_ok = !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'));
        if !scheme_ok || !host_ok || !port.chars().all(|c| c.is_ascii_digit()) {
            return Err(invalid());
        }
        Ok(host)
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
    /// The root certificate: the last certificate of the chain, unless the
    /// chain is a single signing certificate, which leaves the authority
    /// without a root and unable to authenticate anything.
    pub root: Option<Certificate>,
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
    /// member names: an unknown member is an error at any depth, and `null`
    /// reads as absent. The members, with those that are read but not
    /// interpreted marked "kept" or "ignored":
    ///
    /// - the document: `mediaType`, `tlogs`, `certificateAuthorities`,
    ///   `ctlogs`, `timestampAuthorities`;
    /// - a log (`tlogs`, `ctlogs`): `baseUrl` (kept), `hashAlgorithm`,
    ///   `publicKey`, `logId`, `checkpointKeyId` (an object with `keyId`;
    ///   ignored);
    /// - `publicKey`: `rawBytes`, `keyDetails`, `validFor`;
    /// - `logId`: `keyId`;
    /// - an authority (`certificateAuthorities`, `timestampAuthorities`):
    ///   `subject` (an object with the strings `organization` and
    ///   `commonName`; ignored), `uri` (kept), `certChain`, `validFor`;
    /// - `certChain`: `certificates`, each an object with `rawBytes`;
    /// - `validFor`: `start`, `end`.
    ///
    /// Rules, each an error when broken:
    ///
    /// - `mediaType` is [`TRUSTED_ROOT_MEDIA_TYPE`];
    /// - `tlogs`, `ctlogs`, `certificateAuthorities` and
    ///   `timestampAuthorities` are arrays; each may be empty or absent;
    /// - a log has `hashAlgorithm` `SHA2_256`, a `logId.keyId` (canonical
    ///   base64, not empty), a `publicKey` with `rawBytes` (canonical
    ///   base64 of a SubjectPublicKeyInfo that
    ///   [`PublicKey::from_spki_der`] accepts), a `keyDetails` that names
    ///   the kind of the key (one of the `PKIX_ECDSA_*` values for an ECDSA
    ///   key, whatever its curve; one of the `PKIX_RSA_PKCS1V15_*_SHA256`
    ///   values for an RSA key; `PKCS1_RSA_PKCS1V5` for an RSA key whose
    ///   `rawBytes` are a bare `RSAPublicKey`; `PKIX_ED25519` for an
    ///   Ed25519 key; any other value is an error), and a `validFor` with a
    ///   `start`. A log with an RSA key is listed, but nothing verifies
    ///   under it;
    /// - two logs of one list do not share an identifier;
    /// - an authority has a `certChain.certificates` array of 1 to
    ///   [`MAX_AUTHORITY_CHAIN`] entries, each `rawBytes` the canonical
    ///   base64 of a certificate that [`Certificate::from_der`] accepts.
    ///   The last certificate is the root. For a timestamp authority the
    ///   first is the signing certificate when it is not a CA; a chain
    ///   that is one such certificate has no root. `validFor` is optional,
    ///   and so are its `start` and `end`;
    /// - times are RFC 3339 as [`Instant::parse_rfc3339`] reads them.
    ///
    /// Nothing is filtered at parse time. Whether a log or an authority is
    /// trusted for a given signature is decided at verification, by the
    /// time that the signature's own evidence proves.
    pub fn from_json(data: &[u8]) -> Result<Self, SigstoreError> {
        let document = json::parse(data)
            .map_err(|cause| SigstoreError::new(format!("trusted root: {cause}")))?;
        let root = Members::required(
            Some(&document),
            "trusted root",
            &[
                "mediaType",
                "tlogs",
                "certificateAuthorities",
                "ctlogs",
                "timestampAuthorities",
            ],
        )?;
        if root.string("mediaType")? != Some(TRUSTED_ROOT_MEDIA_TYPE) {
            return Err(SigstoreError::new("unsupported trusted root media type"));
        }
        let mut certificate_authorities = Vec::new();
        for value in root.array("certificateAuthorities")? {
            let (uri, mut chain, valid_for) = authority(value, "certificateAuthorities")?;
            let root = chain
                .pop()
                .ok_or_else(|| SigstoreError::new("certificate authority chain is empty"))?;
            certificate_authorities.push(CertificateAuthority {
                uri,
                intermediates: chain,
                root,
                valid_for,
            });
        }
        let mut timestamp_authorities = Vec::new();
        for value in root.array("timestampAuthorities")? {
            let (uri, chain, valid_for) = authority(value, "timestampAuthorities")?;
            let mut chain = std::collections::VecDeque::from(chain);
            let first_is_ca = match chain.front() {
                Some(first) => first
                    .basic_constraints()?
                    .is_some_and(|constraints| constraints.ca),
                None => true,
            };
            let leaf = if first_is_ca { None } else { chain.pop_front() };
            let root = chain.pop_back();
            timestamp_authorities.push(TimestampAuthority {
                uri,
                leaf,
                intermediates: chain.into(),
                root,
                valid_for,
            });
        }
        Ok(Self {
            rekor_logs: logs(root.array("tlogs")?, "tlogs")?,
            ct_logs: logs(root.array("ctlogs")?, "ctlogs")?,
            certificate_authorities,
            timestamp_authorities,
        })
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

fn valid_for(value: Option<&Value>, path: &str) -> Result<Option<ValidFor>, SigstoreError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(period) = Members::of(value, path, &["start", "end"])? else {
        return Ok(None);
    };
    Ok(Some(ValidFor {
        start: period.time("start")?,
        end: period.time("end")?,
    }))
}

fn logs(values: &[Value], list: &str) -> Result<Vec<TransparencyLog>, SigstoreError> {
    const ECDSA: [&str; 3] = [
        "PKIX_ECDSA_P256_SHA_256",
        "PKIX_ECDSA_P384_SHA_384",
        "PKIX_ECDSA_P521_SHA_512",
    ];
    const RSA: [&str; 3] = [
        "PKIX_RSA_PKCS1V15_2048_SHA256",
        "PKIX_RSA_PKCS1V15_3072_SHA256",
        "PKIX_RSA_PKCS1V15_4096_SHA256",
    ];
    /// The key details of an RSA key given as a bare `RSAPublicKey`.
    const BARE_RSA: &str = "PKCS1_RSA_PKCS1V5";
    let mut logs: Vec<TransparencyLog> = Vec::with_capacity(values.len());
    for value in values {
        let log = Members::required(
            Some(value),
            list,
            &[
                "baseUrl",
                "hashAlgorithm",
                "publicKey",
                "logId",
                "checkpointKeyId",
            ],
        )?;
        if log.string("hashAlgorithm")? != Some("SHA2_256") {
            return Err(SigstoreError::new(format!(
                "{list}: unsupported log hash algorithm"
            )));
        }
        if let Some(ignored) = log.get("checkpointKeyId")
            && let Some(identifier) = Members::of(ignored, "checkpointKeyId", &["keyId"])?
        {
            identifier.bytes("keyId")?;
        }
        let log_id =
            Members::required(log.get("logId"), "logId", &["keyId"])?.required_bytes("keyId")?;
        let public_key = Members::required(
            log.get("publicKey"),
            "publicKey",
            &["rawBytes", "keyDetails", "validFor"],
        )?;
        let details = public_key.string("keyDetails")?.unwrap_or_default();
        let raw = public_key.required_bytes("rawBytes")?;
        let key = if details == BARE_RSA {
            PublicKey::from_spki_der(&rsa_spki(&raw))?
        } else {
            PublicKey::from_spki_der(&raw)?
        };
        let fits = match key.algorithm() {
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => ECDSA.contains(&details),
            KeyAlgorithm::Rsa => RSA.contains(&details) || details == BARE_RSA,
            KeyAlgorithm::Ed25519 => details == "PKIX_ED25519",
        };
        if !fits {
            return Err(SigstoreError::new(format!(
                "{list}: key details {details:?} do not fit the log's key"
            )));
        }
        let valid_for = valid_for(public_key.get("validFor"), "validFor")?
            .filter(|period| period.start.is_some())
            .ok_or_else(|| {
                SigstoreError::new(format!("{list}: log key states no start of validity"))
            })?;
        if logs.iter().any(|earlier| earlier.log_id == log_id) {
            return Err(SigstoreError::new(format!(
                "{list}: two logs share an identifier"
            )));
        }
        logs.push(TransparencyLog {
            base_url: log.string("baseUrl")?.unwrap_or_default().to_string(),
            log_id,
            key,
            valid_for,
        });
    }
    Ok(logs)
}

/// The SubjectPublicKeyInfo around a bare `RSAPublicKey`.
fn rsa_spki(rsa_public_key: &[u8]) -> Vec<u8> {
    use crate::x509::der::{TAG_BIT_STRING, TAG_SEQUENCE, push_element};
    // AlgorithmIdentifier { rsaEncryption, NULL }
    const RSA_ENCRYPTION: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut bits = Vec::with_capacity(rsa_public_key.len().saturating_add(1));
    bits.push(0);
    bits.extend_from_slice(rsa_public_key);
    let mut content = RSA_ENCRYPTION.to_vec();
    push_element(&mut content, TAG_BIT_STRING, &bits);
    let mut spki = Vec::with_capacity(content.len().saturating_add(4));
    push_element(&mut spki, TAG_SEQUENCE, &content);
    spki
}

/// The URI, certificate chain and period of one authority.
fn authority(
    value: &Value,
    list: &str,
) -> Result<(String, Vec<Certificate>, ValidFor), SigstoreError> {
    let authority = Members::required(
        Some(value),
        list,
        &["subject", "uri", "certChain", "validFor"],
    )?;
    if let Some(subject) = authority.get("subject")
        && let Some(subject) = Members::of(subject, "subject", &["organization", "commonName"])?
    {
        subject.string("organization")?;
        subject.string("commonName")?;
    }
    let chain = Members::required(authority.get("certChain"), "certChain", &["certificates"])?;
    let encoded = chain.array("certificates")?;
    if encoded.is_empty() || encoded.len() > MAX_AUTHORITY_CHAIN {
        return Err(SigstoreError::new(format!(
            "{list}: an authority has {} certificates, want 1 to {MAX_AUTHORITY_CHAIN}",
            encoded.len()
        )));
    }
    let mut certificates = Vec::with_capacity(encoded.len());
    for value in encoded {
        let der = Members::required(Some(value), "certificates", &["rawBytes"])?
            .required_bytes("rawBytes")?;
        certificates.push(Certificate::from_der(&der)?);
    }
    Ok((
        authority.string("uri")?.unwrap_or_default().to_string(),
        certificates,
        valid_for(authority.get("validFor"), "validFor")?.unwrap_or_default(),
    ))
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
