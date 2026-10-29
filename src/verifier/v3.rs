//! Explicit-node V3 attestation using Tinfoil's CLI/Go wire protocol.
//!
//! This mode supports AMD SEV-SNP and code/platform collateral v2. Unsupported
//! evidence is rejected, without an automatic downgrade to legacy verification.

use std::time::{Duration, SystemTime};

use super::attestation::{self, GroundTruth, Measurement, PredicateType};
use super::{v3_document, v3_endorsements};
use crate::error::{Error, Result};

pub use v3_endorsements::PinnedRelease;

/// One caller-approved release and launch measurement. Pins are inputs from
/// the application, never learned from the unverified server document.
#[derive(Debug, Clone)]
pub struct ApprovedRelease {
    pub release: PinnedRelease,
    pub measurement: Measurement,
}

/// Immutable current/staged release allowlist for one explicit node client.
#[derive(Debug, Clone)]
pub struct DirectPolicy {
    approved: Vec<ApprovedRelease>,
}

impl DirectPolicy {
    pub fn new(approved: Vec<ApprovedRelease>) -> Result<Self> {
        if approved.is_empty() || approved.len() > 16 {
            return Err(Error::Configuration(
                "direct policy requires 1..=16 approved releases".into(),
            ));
        }
        let repo = regex::Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").unwrap();
        let tag = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.+/-]*$").unwrap();
        for (i, entry) in approved.iter().enumerate() {
            if !repo.is_match(&entry.release.repo)
                || !tag.is_match(&entry.release.tag)
                || !lower_hex(&entry.release.digest, 32)
            {
                return Err(Error::Configuration(
                    "direct policy requires explicit repo, tag and lowercase SHA-256 digest".into(),
                ));
            }
            let count = match entry.measurement.type_ {
                PredicateType::SevGuestV2 => 1,
                PredicateType::SnpTdxMultiPlatformV1 => 3,
                _ => {
                    return Err(Error::Configuration(
                        "direct SNP policy requires SNP or multiplatform measurement pins".into(),
                    ))
                }
            };
            if entry.measurement.registers.len() != count
                || entry
                    .measurement
                    .registers
                    .iter()
                    .any(|r| !lower_hex(r, 48))
            {
                return Err(Error::Configuration(
                    "direct measurement pins must be complete lowercase SHA-384 registers".into(),
                ));
            }
            if approved[..i]
                .iter()
                .any(|previous| previous.release == entry.release)
            {
                return Err(Error::Configuration(
                    "duplicate release in direct policy".into(),
                ));
            }
        }
        Ok(Self { approved })
    }

    fn select(&self, reference: &v3_document::SigstoreReference) -> Result<&ApprovedRelease> {
        self.approved
            .iter()
            .find(|e| {
                e.release.repo == reference.repo
                    && e.release.tag == reference.tag
                    && e.release.digest == reference.digest
            })
            .ok_or_else(|| {
                Error::AttestationVerification(
                    "node release is not in the caller's approved direct policy".into(),
                )
            })
    }
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Authenticated state used to build the standard origin-bound TLS transport.
pub struct VerifiedDirect {
    pub ground_truth: GroundTruth,
    pub freshness_expires_at: SystemTime,
}

fn origin(host: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(&format!("https://{host}"))
        .map_err(|_| Error::Configuration("invalid explicit node hostname".into()))?;
    if url.scheme() != "https"
        || url.host_str() != Some(host)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Configuration(
            "direct node must be a bare HTTPS hostname without a port or URL components".into(),
        ));
    }
    Ok(url)
}

/// Fetch a fresh nonce-bound document only from the explicit node, then verify
/// it. The bootstrap request has no API key or application/user content.
pub async fn verify(host: &str, policy: &DirectPolicy) -> Result<VerifiedDirect> {
    crate::ensure_crypto_provider();
    let mut url = origin(host)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|_| Error::AttestationFetch("could not generate attestation challenge".into()))?;
    url.set_path("/.well-known/tinfoil-attestation");
    url.query_pairs_mut()
        .append_pair("nonce", &hex::encode(nonce));
    let bootstrap = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(Error::Http)?;
    let mut response = bootstrap
        .get(url)
        .headers(attestation::attestation_headers())
        .send()
        .await
        .map_err(Error::Http)?;
    if !response.status().is_success() {
        return Err(Error::AttestationFetch(format!(
            "explicit node returned HTTP {}",
            response.status()
        )));
    }
    const LIMIT: usize = 32 * 1024 * 1024;
    if response.content_length().is_some_and(|n| n > LIMIT as u64) {
        return Err(Error::AttestationFetch(
            "attestation document exceeds 32 MiB".into(),
        ));
    }
    let mut raw = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(Error::Http)? {
        if chunk.len() > LIMIT - raw.len() {
            return Err(Error::AttestationFetch(
                "attestation document exceeds 32 MiB".into(),
            ));
        }
        raw.extend_from_slice(&chunk);
    }
    verify_document(&raw, &nonce, policy)
}

/// Verify previously captured bytes against the original caller nonce and an
/// current appraisal time. This performs no network calls. Production callers
/// should use `verify` to generate a fresh challenge for each verification.
pub fn verify_document(raw: &[u8], nonce: &[u8], policy: &DirectPolicy) -> Result<VerifiedDirect> {
    verify_document_at(raw, nonce, policy, SystemTime::now())
}

fn verify_document_at(
    raw: &[u8],
    nonce: &[u8],
    policy: &DirectPolicy,
    now: SystemTime,
) -> Result<VerifiedDirect> {
    let document = v3_document::parse_document(raw, nonce)?;
    let code = document.collateral.sigstore_code.as_ref().ok_or_else(|| {
        Error::AttestationVerification("V3 document has no code collateral".into())
    })?;
    let approved = policy.select(code)?;
    let refs =
        v3_endorsements::authenticate_legacy_refs(&document.collateral, &approved.release, now)?;
    approved
        .measurement
        .equals(&refs.measurement)
        .map_err(|_| {
            Error::AttestationVerification(
                "signed code measurement does not match caller-approved measurement".into(),
            )
        })?;
    if refs.freshness_expires_at <= now {
        return Err(Error::AttestationVerification(
            "V3 endorsement freshness has expired".into(),
        ));
    }

    // Selecting a candidate policy from CHIP_ID is safe only because the same
    // raw report bytes are subsequently signature-verified with that policy.
    let chip_id = document
        .raw_cpu_report
        .get(0x1a0..0x1e0)
        .ok_or_else(|| Error::AttestationVerification("truncated SNP CHIP_ID".into()))?;
    let artifact = &refs.platform_artifact;
    let chip_id_hex = hex::encode(chip_id);
    let policy_name = artifact
        .get("machines")
        .and_then(|m| m.get(chip_id_hex.as_str()))
        .and_then(|n| n.as_str())
        .ok_or_else(|| {
            Error::AttestationVerification(
                "CPU is not in the authenticated platform machine map".into(),
            )
        })?;
    let selected = artifact
        .get("policies")
        .and_then(|p| p.get(policy_name))
        .ok_or_else(|| {
            Error::AttestationVerification("authenticated machine policy is missing".into())
        })?;
    if selected.get("platform").and_then(|v| v.as_str()) != Some("sev-snp") {
        return Err(Error::UnsupportedFormat(
            "direct V3 mode supports AMD SEV-SNP policy only".into(),
        ));
    }
    let cpu_policy = selected.get("sev_snp").ok_or_else(|| {
        Error::AttestationVerification("authenticated SNP policy is missing".into())
    })?;
    let vcek = document.collateral.amd_vcek.as_ref().ok_or_else(|| {
        Error::AttestationVerification("V3 document is missing AMD VCEK collateral".into())
    })?;
    let crl = document.collateral.amd_crl.as_ref().ok_or_else(|| {
        Error::AttestationVerification("V3 document is missing AMD CRL collateral".into())
    })?;
    let enclave = attestation::sev::verify_evidence(
        attestation::sev::Evidence {
            report: &document.raw_cpu_report,
            vcek_der: &vcek.vcek_der,
            cert_chain_pem: vcek.cert_chain_pem.as_bytes(),
            crl_der: crl,
        },
        &document.expected_report_data,
        cpu_policy,
    )?;
    enclave.equals(&refs.measurement).map_err(|_| {
        Error::AttestationVerification(
            "signed hardware measurement does not match approved code".into(),
        )
    })?;
    approved.measurement.equals(&enclave).map_err(|_| {
        Error::AttestationVerification("hardware measurement is not approved for this node".into())
    })?;

    let tls = document
        .crypto_material
        .iter()
        .find(|k| k.id == "tls" && k.format == "https://tinfoil.sh/key/spki-fp-sha256/v1")
        .ok_or_else(|| {
            Error::AttestationVerification("V3 document has no supported TLS key".into())
        })?;
    if tls.data.len() != 32 || tls.data.iter().all(|b| *b == 0) {
        return Err(Error::AttestationVerification(
            "invalid attested TLS fingerprint".into(),
        ));
    }
    let hpke = document
        .crypto_material
        .iter()
        .find(|k| k.id == "hpke" && k.format == "https://tinfoil.sh/key/x25519-hpke/v1")
        .map(|k| hex::encode(&k.data));
    let code_fingerprint = refs.measurement.fingerprint_for_target(&enclave.type_);
    let enclave_fingerprint = enclave.fingerprint();
    Ok(VerifiedDirect {
        freshness_expires_at: refs.freshness_expires_at,
        ground_truth: GroundTruth {
            config_repo: approved.release.repo.clone(),
            release_tag: Some(approved.release.tag.clone()),
            digest: approved.release.digest.clone(),
            tls_public_key: Some(hex::encode(&tls.data)),
            hpke_public_key: hpke,
            code_measurement: refs.measurement,
            enclave_measurement: enclave,
            code_fingerprint,
            enclave_fingerprint,
            verifier: attestation::types::verifier_identity(),
            verified_at: attestation::types::verification_timestamp(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> ApprovedRelease {
        ApprovedRelease {
            release: PinnedRelease {
                repo: "example/config".into(),
                tag: "v1.0.0".into(),
                digest: "a".repeat(64),
            },
            measurement: Measurement {
                type_: PredicateType::SevGuestV2,
                registers: vec!["b".repeat(96)],
            },
        }
    }

    #[test]
    fn policy_rejects_empty_duplicate_and_incomplete_pins() {
        assert!(DirectPolicy::new(vec![]).is_err());
        assert!(DirectPolicy::new(vec![entry(), entry()]).is_err());
        let mut e = entry();
        e.release.digest.clear();
        assert!(DirectPolicy::new(vec![e]).is_err());
        let mut e = entry();
        e.measurement.registers[0] = "B".repeat(96);
        assert!(DirectPolicy::new(vec![e]).is_err());
    }

    #[test]
    fn explicit_origin_rejects_urls_ports_and_credential_components() {
        assert!(origin("i01.example.com").is_ok());
        for bad in [
            "http://example.com",
            "user@example.com",
            "example.com:443",
            "example.com/path",
            "example.com?x",
            "example.com#x",
        ] {
            assert!(origin(bad).is_err(), "accepted non-host input");
        }
    }
}
