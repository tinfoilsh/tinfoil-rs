//! Strict parsing for Tinfoil's v3 attestation envelope, ported from
//! `tinfoil-go` document/ at 4e83c0ce632fe33253b36e9f553ad3eeb373acf3.
//!
//! Parsing authenticates nothing. The CPU verifier must authenticate the SNP
//! quote and compare its REPORT_DATA to `expected_report_data` before callers
//! trust the endorsed keys or device evidence. Collateral is unendorsed and
//! must independently pass its certificate/signature/freshness verification.
//! This implementation deliberately supports the deployed legacy-collateral
//! policy only: an unsupported policy is rejected, never downgraded.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub(crate) const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const ATTESTATION_V3_FORMAT: &str = "https://tinfoil.sh/predicate/attestation/v3";
pub(crate) const REPORT_DATA_V1_ALGORITHM: &str = "https://tinfoil.sh/report-data/v1";
pub(crate) const COLLATERAL_V2_FORMAT: &str =
    "https://tinfoil.sh/predicate/attestation-collaterals/v2";
pub(crate) const SEV_SNP_REPORT_V1_FORMAT: &str = "https://tinfoil.sh/format/sev-snp-report/v1";
pub(crate) const TLS_KEY_FORMAT: &str = "https://tinfoil.sh/key/spki-fp-sha256/v1";
pub(crate) const HPKE_KEY_FORMAT: &str = "https://tinfoil.sh/key/x25519-hpke/v1";

const CRYPTO_MATERIAL_V1_FORMAT: &str = "https://tinfoil.sh/crypto-material/v1";
const DEVICE_EVIDENCE_V1_FORMAT: &str = "https://tinfoil.sh/device-evidence/v1";
const AMD_VCEK_FORMAT: &str = "https://tinfoil.sh/collateral/amd-vcek/v1";
const AMD_CRL_FORMAT: &str = "https://tinfoil.sh/collateral/amd-crl/v1";
const INTEL_PCS_FORMAT: &str = "https://tinfoil.sh/collateral/intel-pcs/v1";
const SIGSTORE_CODE_FORMAT: &str = "https://tinfoil.sh/collateral/sigstore-code/v1";
const SIGSTORE_PLATFORM_FORMAT: &str = "https://tinfoil.sh/collateral/sigstore-platform/v1";
const SIGSTORE_FRESHNESS_FORMAT: &str = "https://tinfoil.sh/collateral/sigstore-freshness/v1";

/// Parsed, nonce-bound, but **not authenticated** evidence.
#[derive(Debug, Clone)]
pub(crate) struct ParsedDocument {
    pub(crate) nonce: [u8; 32],
    pub(crate) expected_report_data: [u8; 64],
    pub(crate) raw_cpu_report: Vec<u8>,
    pub(crate) crypto_material: Vec<CryptoMaterialItem>,
    /// Hash-bound only; this module does not appraise NVIDIA evidence.
    pub(crate) device_evidence: Vec<DeviceEvidenceItem>,
    pub(crate) crypto_material_bytes: Vec<u8>,
    pub(crate) device_evidence_bytes: Vec<u8>,
    pub(crate) collateral: DecodedCollateral,
}

impl ParsedDocument {
    /// Read the conventional TLS key only if its exact protocol format matches.
    pub(crate) fn tls_fingerprint(&self) -> Result<[u8; 32]> {
        self.protocol_key("tls", TLS_KEY_FORMAT)
    }

    /// Read the conventional HPKE key only if its exact protocol format matches.
    pub(crate) fn hpke_public_key(&self) -> Result<[u8; 32]> {
        self.protocol_key("hpke", HPKE_KEY_FORMAT)
    }

    fn protocol_key(&self, id: &str, format: &str) -> Result<[u8; 32]> {
        let item = self
            .crypto_material
            .iter()
            .find(|item| item.id == id)
            .ok_or_else(|| invalid(format!("missing crypto_material item {id:?}")))?;
        if item.format != format {
            return Err(invalid(format!(
                "crypto_material item {id:?} has unsupported format {:?}",
                item.format
            )));
        }
        item.data
            .as_slice()
            .try_into()
            .map_err(|_| invalid(format!("crypto_material item {id:?} must be 32 bytes")))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CryptoMaterialItem {
    pub(crate) id: String,
    pub(crate) format: String,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceEvidenceItem {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) vendor: String,
    #[serde(default)]
    pub(crate) format: String,
    #[serde(default)]
    pub(crate) evidence: Value,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DecodedCollateral {
    pub(crate) amd_vcek: Option<AmdVcek>,
    pub(crate) amd_crl: Option<Vec<u8>>,
    pub(crate) intel_pcs: Option<Vec<IntelPcsResponse>>,
    pub(crate) sigstore_code: Option<SigstoreReference>,
    pub(crate) sigstore_platform: Option<SigstoreReference>,
    pub(crate) freshness: BTreeMap<String, Freshness>,
}

#[derive(Debug, Clone)]
pub(crate) struct AmdVcek {
    pub(crate) vcek_der: Vec<u8>,
    /// ASK then ARK certificates, as supplied by the document, still untrusted.
    pub(crate) cert_chain_pem: String,
}

#[derive(Debug, Clone)]
pub(crate) struct IntelPcsResponse {
    pub(crate) url: String,
    pub(crate) headers: BTreeMap<String, Vec<String>>,
    pub(crate) body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct SigstoreReference {
    pub(crate) repo: String,
    pub(crate) tag: String,
    pub(crate) digest: String,
    /// Untrusted bundle; its internal schema and signatures are verified later.
    pub(crate) bundle: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct Freshness {
    pub(crate) format: String,
    pub(crate) bundle: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDocument {
    format: String,
    challenge: Challenge,
    cpu_evidence: RawCpuEvidence,
    crypto_material: String,
    device_evidence: String,
    #[serde(default)]
    collateral_format: String,
    #[serde(default)]
    collateral: Option<Vec<RawCollateral>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: String,
    report_data: String,
    report_data_algorithm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCpuEvidence {
    format: String,
    report_base64: String,
    endorsed: EndorsedHashes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndorsedHashes {
    crypto_material_hash: String,
    device_evidence_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoMaterialSection {
    format: String,
    items: Vec<RawCryptoMaterialItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCryptoMaterialItem {
    id: String,
    format: String,
    data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceEvidenceSection {
    format: String,
    items: Vec<DeviceEvidenceItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCollateral {
    id: String,
    role: String,
    format: String,
    #[serde(default)]
    subjects: Option<Vec<String>>,
    data: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AmdVcekData {
    #[serde(default)]
    vcek_der_base64: String,
    #[serde(default)]
    cert_chain_pem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AmdCrlData {
    #[serde(default)]
    crl_der_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntelPcsData {
    #[serde(default)]
    responses: Option<Vec<RawIntelPcsResponse>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIntelPcsResponse {
    #[serde(default)]
    url: String,
    #[serde(default)]
    headers: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    body_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigstoreData {
    #[serde(default)]
    repo: String,
    #[serde(default)]
    tag: String,
    digest: String,
    sigstore_bundle: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessData {
    sigstore_bundle: Value,
}

/// Parse the exact endorsed bytes, enforce canonical encodings, and recompute
/// Tinfoil's report-data binding. The caller must supply its own fresh nonce.
pub(crate) fn parse_document(bytes: &[u8], expected_nonce: &[u8]) -> Result<ParsedDocument> {
    let expected_nonce: [u8; 32] = expected_nonce.try_into().map_err(|_| {
        Error::Configuration(format!(
            "expected nonce must be 32 bytes, got {}",
            expected_nonce.len()
        ))
    })?;
    let raw: RawDocument = strict_json(bytes, "attestation document")?;
    if raw.format != ATTESTATION_V3_FORMAT {
        return Err(Error::UnsupportedFormat(format!(
            "unsupported document format {:?}",
            raw.format
        )));
    }
    if raw.collateral_format != "" && raw.collateral_format != COLLATERAL_V2_FORMAT {
        return Err(Error::UnsupportedFormat(format!(
            "unsupported collateral format {:?}; only legacy collateral v2 is supported",
            raw.collateral_format
        )));
    }
    if raw.challenge.report_data_algorithm != REPORT_DATA_V1_ALGORITHM {
        return Err(Error::UnsupportedFormat(format!(
            "unsupported challenge.report_data_algorithm {:?}",
            raw.challenge.report_data_algorithm
        )));
    }
    let nonce = fixed_hex::<32>("challenge.nonce", &raw.challenge.nonce)?;
    if nonce != expected_nonce {
        return Err(invalid("challenge nonce does not match the expected nonce"));
    }
    let declared_report_data =
        fixed_hex::<64>("challenge.report_data", &raw.challenge.report_data)?;
    let declared_crypto_hash = fixed_hex::<32>(
        "cpu_evidence.endorsed.crypto_material_hash",
        &raw.cpu_evidence.endorsed.crypto_material_hash,
    )?;
    let declared_device_hash = fixed_hex::<32>(
        "cpu_evidence.endorsed.device_evidence_hash",
        &raw.cpu_evidence.endorsed.device_evidence_hash,
    )?;
    if raw.cpu_evidence.format != SEV_SNP_REPORT_V1_FORMAT {
        return Err(Error::UnsupportedFormat(format!(
            "unsupported cpu_evidence format {:?}; only raw SEV-SNP v1 is supported",
            raw.cpu_evidence.format
        )));
    }
    let raw_cpu_report = canonical_base64(
        "cpu_evidence.report_base64",
        &raw.cpu_evidence.report_base64,
    )?;
    if raw_cpu_report.len() != 1184 {
        return Err(invalid(format!(
            "cpu_evidence.report_base64 must decode to a 1184-byte SEV-SNP report, got {}",
            raw_cpu_report.len()
        )));
    }
    let crypto_material_bytes = canonical_base64("crypto_material", &raw.crypto_material)?;
    let device_evidence_bytes = canonical_base64("device_evidence", &raw.device_evidence)?;
    let cm: CryptoMaterialSection = strict_json(&crypto_material_bytes, "crypto_material")?;
    if cm.format != CRYPTO_MATERIAL_V1_FORMAT {
        return Err(Error::UnsupportedFormat(format!(
            "unsupported crypto_material section format {:?}",
            cm.format
        )));
    }
    let mut crypto_material = Vec::with_capacity(cm.items.len());
    let mut crypto_ids = HashSet::new();
    for item in cm.items {
        if item.id.is_empty() || item.format.is_empty() {
            return Err(invalid("crypto_material item is incomplete"));
        }
        if !crypto_ids.insert(item.id.clone()) {
            return Err(invalid(format!(
                "duplicate crypto_material item id {:?}",
                item.id
            )));
        }
        let label = format!("crypto_material item {:?} data", item.id);
        let data = if item.format == TLS_KEY_FORMAT || item.format == HPKE_KEY_FORMAT {
            fixed_hex::<32>(&label, &item.data)?.to_vec()
        } else {
            let bytes = lower_hex(&label, &item.data)?;
            if bytes.is_empty() {
                return Err(invalid(format!("{label} is empty")));
            }
            bytes
        };
        crypto_material.push(CryptoMaterialItem {
            id: item.id,
            format: item.format,
            data,
        });
    }
    let de: DeviceEvidenceSection = strict_json(&device_evidence_bytes, "device_evidence")?;
    if de.format != DEVICE_EVIDENCE_V1_FORMAT {
        return Err(Error::UnsupportedFormat(format!(
            "unsupported device_evidence section format {:?}",
            de.format
        )));
    }
    let mut device_ids = HashSet::new();
    for item in &de.items {
        if item.id.is_empty() {
            return Err(invalid("device_evidence item has no id"));
        }
        if !device_ids.insert(item.id.clone()) {
            return Err(invalid(format!(
                "duplicate device_evidence item id {:?}",
                item.id
            )));
        }
    }
    let crypto_hash: [u8; 32] = Sha256::digest(&crypto_material_bytes).into();
    let device_hash: [u8; 32] = Sha256::digest(&device_evidence_bytes).into();
    if crypto_hash != declared_crypto_hash {
        return Err(invalid(
            "crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash",
        ));
    }
    if device_hash != declared_device_hash {
        return Err(invalid(
            "device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash",
        ));
    }
    let expected_report_data = compute_report_data(&nonce, &crypto_hash, &device_hash);
    if declared_report_data != expected_report_data {
        return Err(invalid(
            "challenge report_data does not match the recomputed value",
        ));
    }
    let collateral = decode_collateral(raw.collateral.unwrap_or_default())?;
    Ok(ParsedDocument {
        nonce,
        expected_report_data,
        raw_cpu_report,
        crypto_material,
        device_evidence: de.items,
        crypto_material_bytes,
        device_evidence_bytes,
        collateral,
    })
}

pub(crate) fn compute_report_data(
    nonce: &[u8; 32],
    crypto_hash: &[u8; 32],
    device_hash: &[u8; 32],
) -> [u8; 64] {
    let mut hash = Sha256::new();
    hash.update(REPORT_DATA_V1_ALGORITHM.as_bytes());
    hash.update(nonce);
    hash.update(crypto_hash);
    hash.update(device_hash);
    let mut result = [0; 64];
    result[..32].copy_from_slice(&hash.finalize());
    result
}

fn decode_collateral(entries: Vec<RawCollateral>) -> Result<DecodedCollateral> {
    let mut result = DecodedCollateral::default();
    let mut ids = HashSet::new();
    for entry in entries {
        if entry.id.is_empty() || entry.format.is_empty() {
            return Err(invalid("collateral entry is incomplete"));
        }
        if !ids.insert(entry.id.clone()) {
            return Err(invalid(format!(
                "duplicate collateral entry id {:?}",
                entry.id
            )));
        }
        if entry.role != "endorsement" && entry.role != "reference-values" {
            return Err(invalid(format!(
                "collateral entry {:?} has unknown role {:?}",
                entry.id, entry.role
            )));
        }
        if !entry.data.is_object() {
            return Err(invalid(format!(
                "collateral entry {:?} data is not a valid JSON object",
                entry.id
            )));
        }
        // These entries belong to the new collateral-v3 policy. Never treat
        // them as opaque extras under the older policy that this module knows.
        if entry.id == "tinfoil-config"
            || entry.id == "runtime"
            || entry.id == "runtime-freshness"
            || matches!(
                entry.format.as_str(),
                "https://tinfoil.sh/collateral/config-endorsement/v1"
                    | "https://tinfoil.sh/collateral/config/v1"
                    | "https://tinfoil.sh/collateral/igvm-runtime/v1"
                    | "https://tinfoil.sh/collateral/artifact-freshness/v1"
            )
        {
            return Err(Error::UnsupportedFormat(format!(
                "collateral entry {:?} requires unsupported collateral format v3",
                entry.id
            )));
        }
        let cpu = entry
            .subjects
            .as_ref()
            .is_some_and(|subjects| subjects.iter().any(|s| s == "cpu"));
        let label = format!("{} collateral entry {:?}", entry.format, entry.id);
        match (entry.role.as_str(), entry.format.as_str()) {
            ("endorsement", AMD_VCEK_FORMAT) => {
                let data: AmdVcekData = typed_value(entry.data, &label)?;
                let value = AmdVcek {
                    vcek_der: canonical_base64("vcek_der_base64", &data.vcek_der_base64)?,
                    cert_chain_pem: data.cert_chain_pem,
                };
                if cpu && result.amd_vcek.is_none() {
                    result.amd_vcek = Some(value);
                }
            }
            ("endorsement", AMD_CRL_FORMAT) => {
                let data: AmdCrlData = typed_value(entry.data, &label)?;
                let value = canonical_base64("crl_der_base64", &data.crl_der_base64)?;
                if cpu && result.amd_crl.is_none() {
                    result.amd_crl = Some(value);
                }
            }
            ("endorsement", INTEL_PCS_FORMAT) => {
                let data: IntelPcsData = typed_value(entry.data, &label)?;
                let mut responses = Vec::new();
                for response in data.responses.unwrap_or_default() {
                    responses.push(IntelPcsResponse {
                        url: response.url,
                        headers: response.headers.unwrap_or_default(),
                        body: canonical_base64("body_base64", &response.body_base64)?,
                    });
                }
                if cpu && result.intel_pcs.is_none() {
                    result.intel_pcs = Some(responses);
                }
            }
            ("reference-values", SIGSTORE_CODE_FORMAT | SIGSTORE_PLATFORM_FORMAT) => {
                let data: SigstoreData = typed_value(entry.data, &label)?;
                if data.digest.is_empty() {
                    return Err(invalid(format!("{label} is missing digest")));
                }
                require_bundle(&data.sigstore_bundle, &label)?;
                let value = SigstoreReference {
                    repo: data.repo,
                    tag: data.tag,
                    digest: data.digest,
                    bundle: data.sigstore_bundle,
                };
                let target = if entry.format == SIGSTORE_CODE_FORMAT {
                    &mut result.sigstore_code
                } else {
                    &mut result.sigstore_platform
                };
                if target.is_none() {
                    *target = Some(value);
                }
            }
            ("reference-values", SIGSTORE_FRESHNESS_FORMAT) => {
                let data: FreshnessData = typed_value(entry.data, &label)?;
                require_bundle(&data.sigstore_bundle, &label)?;
                result.freshness.insert(
                    entry.id,
                    Freshness {
                        format: entry.format,
                        bundle: data.sigstore_bundle,
                    },
                );
            }
            // Match the Go format registry: unknown formats and known formats
            // under another role are shape-checked but never consumed/trusted.
            _ => {}
        }
    }
    Ok(result)
}

fn require_bundle(value: &Value, label: &str) -> Result<()> {
    if value.is_null() {
        return Err(invalid(format!("{label} is missing sigstore_bundle")));
    }
    Ok(())
}

fn typed_value<T: DeserializeOwned>(value: Value, label: &str) -> Result<T> {
    serde_json::from_value(value).map_err(|error| invalid(format!("parsing {label}: {error}")))
}

fn lower_hex(label: &str, encoded: &str) -> Result<Vec<u8>> {
    if !encoded
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{label} is not lowercase hex")));
    }
    hex::decode(encoded).map_err(|error| invalid(format!("{label} is not hex: {error}")))
}

fn fixed_hex<const N: usize>(label: &str, encoded: &str) -> Result<[u8; N]> {
    let decoded = lower_hex(label, encoded)?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        invalid(format!("{label} must be {N} bytes, got {}", bytes.len()))
    })
}

fn canonical_base64(label: &str, encoded: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|error| invalid(format!("decoding {label}: {error}")))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(invalid(format!("{label} is not canonical base64")));
    }
    Ok(bytes)
}

fn invalid(message: impl Into<String>) -> Error {
    Error::AttestationVerification(message.into())
}

fn strict_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(invalid(format!("{label} exceeds the 32 MiB limit")));
    }
    // serde_json::Value normally silently keeps the last duplicate member.
    // Visit recursively before typed decoding so even opaque nested evidence,
    // maps, and Sigstore bundles reject duplicate or escaped-equivalent keys.
    let value: UniqueValue = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("parsing {label}: {error}")))?;
    typed_value(value.0, label)
}

/// Shared strict JSON entry point for independently signed collateral payloads.
/// Duplicate detection precedes any consumer's typed decoding.
pub(crate) fn parse_strict_json(bytes: &[u8]) -> Result<Value> {
    strict_json(bytes, "signed collateral payload")
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate member names")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON member {key:?}")));
                    }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nonce() -> [u8; 32] {
        std::array::from_fn(|index| index as u8)
    }

    fn document_with_sections(crypto: &[u8], device: &[u8]) -> Value {
        let crypto_hash = Sha256::digest(crypto).into();
        let device_hash = Sha256::digest(device).into();
        json!({
            "format": ATTESTATION_V3_FORMAT,
            "challenge": {
                "nonce": hex::encode(nonce()),
                "report_data": hex::encode(compute_report_data(&nonce(), &crypto_hash, &device_hash)),
                "report_data_algorithm": REPORT_DATA_V1_ALGORITHM,
            },
            "cpu_evidence": {
                "format": SEV_SNP_REPORT_V1_FORMAT,
                "report_base64": STANDARD.encode([1; 1184]),
                "endorsed": {
                    "crypto_material_hash": hex::encode(crypto_hash),
                    "device_evidence_hash": hex::encode(device_hash),
                },
            },
            "crypto_material": STANDARD.encode(crypto),
            "device_evidence": STANDARD.encode(device),
            "collateral": [
                {"id":"cpu-endorsement","role":"endorsement","format":AMD_VCEK_FORMAT,"subjects":["cpu"],"data":{"vcek_der_base64":"AQI=","cert_chain_pem":"synthetic"}},
                {"id":"cpu-crl","role":"endorsement","format":AMD_CRL_FORMAT,"subjects":["cpu"],"data":{"crl_der_base64":"AwQ="}},
                {"id":"code","role":"reference-values","format":SIGSTORE_CODE_FORMAT,"data":{"repo":"org/code","tag":"v1","digest":"abcd","sigstore_bundle":{}}},
                {"id":"platform","role":"reference-values","format":SIGSTORE_PLATFORM_FORMAT,"data":{"repo":"org/platform","tag":"v1","digest":"ef01","sigstore_bundle":{}}},
                {"id":"code-freshness","role":"reference-values","format":SIGSTORE_FRESHNESS_FORMAT,"data":{"sigstore_bundle":{}}},
                {"id":"platform-freshness","role":"reference-values","format":SIGSTORE_FRESHNESS_FORMAT,"data":{"sigstore_bundle":{}}},
            ],
        })
    }

    fn fixture() -> Value {
        let crypto = serde_json::to_vec(&json!({
            "format": CRYPTO_MATERIAL_V1_FORMAT,
            "items": [
                {"id":"tls","format":TLS_KEY_FORMAT,"data":hex::encode([0xaa;32])},
                {"id":"hpke","format":HPKE_KEY_FORMAT,"data":hex::encode([0xbb;32])},
            ],
        }))
        .unwrap();
        let device =
            serde_json::to_vec(&json!({"format":DEVICE_EVIDENCE_V1_FORMAT,"items":[]})).unwrap();
        document_with_sections(&crypto, &device)
    }

    fn parse(value: &Value) -> Result<ParsedDocument> {
        parse_document(&serde_json::to_vec(value).unwrap(), &nonce())
    }

    fn failure(value: &Value) -> String {
        parse(value).unwrap_err().to_string()
    }

    fn section(value: &Value, name: &str) -> Value {
        serde_json::from_slice(&STANDARD.decode(value[name].as_str().unwrap()).unwrap()).unwrap()
    }

    fn update_section(value: &mut Value, name: &str, section: &Value) {
        value[name] = Value::String(STANDARD.encode(serde_json::to_vec(section).unwrap()));
        rebind(value);
    }

    fn rebind(value: &mut Value) {
        let crypto = STANDARD
            .decode(value["crypto_material"].as_str().unwrap())
            .unwrap();
        let device = STANDARD
            .decode(value["device_evidence"].as_str().unwrap())
            .unwrap();
        let crypto_hash = Sha256::digest(crypto).into();
        let device_hash = Sha256::digest(device).into();
        value["cpu_evidence"]["endorsed"]["crypto_material_hash"] = json!(hex::encode(crypto_hash));
        value["cpu_evidence"]["endorsed"]["device_evidence_hash"] = json!(hex::encode(device_hash));
        value["challenge"]["report_data"] = json!(hex::encode(compute_report_data(
            &nonce(),
            &crypto_hash,
            &device_hash
        )));
    }

    // Exact official public vectors from document/testdata/attested-keys-vectors.json
    // at the Go reference commit named in this module. These independent fixed
    // expected hashes detect changing the URI, field order, or hashing JSON
    // after reserialization instead of the original decoded section bytes.
    #[test]
    fn official_go_attested_key_report_data_vectors() {
        const VECTORS: &str = r###"[
  {
    "algorithm": "ecdsa-p256",
    "item": {
      "id": "workload-key",
      "format": "https://tinfoil.sh/key/spki/v1",
      "data": "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    },
    "nonce": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "crypto_material": "eyJmb3JtYXQiOiJodHRwczovL3RpbmZvaWwuc2gvY3J5cHRvLW1hdGVyaWFsL3YxIiwiaXRlbXMiOlt7ImlkIjoid29ya2xvYWQta2V5IiwiZm9ybWF0IjoiaHR0cHM6Ly90aW5mb2lsLnNoL2tleS9zcGtpL3YxIiwiZGF0YSI6IjMwNTkzMDEzMDYwNzJhODY0OGNlM2QwMjAxMDYwODJhODY0OGNlM2QwMzAxMDcwMzQyMDAwNDZiMTdkMWYyZTEyYzQyNDdmOGJjZTZlNTYzYTQ0MGYyNzcwMzdkODEyZGViMzNhMGY0YTEzOTQ1ZDg5OGMyOTY0ZmUzNDJlMmZlMWE3ZjliOGVlN2ViNGE3YzBmOWUxNjJiY2UzMzU3NmIzMTVlY2VjYmI2NDA2ODM3YmY1MWY1In1dfQ==",
    "device_evidence": "eyJmb3JtYXQiOiJodHRwczovL3RpbmZvaWwuc2gvZGV2aWNlLWV2aWRlbmNlL3YxIiwiaXRlbXMiOltdfQ==",
    "crypto_material_hash": "004580594693e8f98ab0537d7e408f55f691bad5e55b0bd83f0bc32f2a05abc6",
    "device_evidence_hash": "5e84f632e01293bff4596cf72c45de0f9e1037e5cda3232b850c478d1a6b592b",
    "report_data": "e134a51739248a669e7d75a94c242d2b2b973684061d1885205cea0e1b40ec580000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    "algorithm": "ed25519",
    "item": {
      "id": "workload-key",
      "format": "https://tinfoil.sh/key/spki/v1",
      "data": "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    },
    "nonce": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "crypto_material": "eyJmb3JtYXQiOiJodHRwczovL3RpbmZvaWwuc2gvY3J5cHRvLW1hdGVyaWFsL3YxIiwiaXRlbXMiOlt7ImlkIjoid29ya2xvYWQta2V5IiwiZm9ybWF0IjoiaHR0cHM6Ly90aW5mb2lsLnNoL2tleS9zcGtpL3YxIiwiZGF0YSI6IjMwMmEzMDA1MDYwMzJiNjU3MDAzMjEwMGQ3NWE5ODAxODJiMTBhYjdkNTRiZmVkM2M5NjQwNzNhMGVlMTcyZjNkYWE2MjMyNWFmMDIxYTY4ZjcwNzUxMWEifV19",
    "device_evidence": "eyJmb3JtYXQiOiJodHRwczovL3RpbmZvaWwuc2gvZGV2aWNlLWV2aWRlbmNlL3YxIiwiaXRlbXMiOltdfQ==",
    "crypto_material_hash": "d8f98fff52635b917d390080f09f2b68eed1b410810f4965e3411b99b204f727",
    "device_evidence_hash": "5e84f632e01293bff4596cf72c45de0f9e1037e5cda3232b850c478d1a6b592b",
    "report_data": "471c373ed1a81ba6b4f9469e15b61277759d825f28a7415c3de5effb1c80a5e70000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    "algorithm": "x25519",
    "item": {
      "id": "workload-key",
      "format": "https://tinfoil.sh/key/spki/v1",
      "data": "302a300506032b656e0321008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    },
    "nonce": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "crypto_material": "eyJmb3JtYXQiOiJodHRwczovL3RpbmZvaWwuc2gvY3J5cHRvLW1hdGVyaWFsL3YxIiwiaXRlbXMiOlt7ImlkIjoid29ya2xvYWQta2V5IiwiZm9ybWF0IjoiaHR0cHM6Ly90aW5mb2lsLnNoL2tleS9zcGtpL3YxIiwiZGF0YSI6IjMwMmEzMDA1MDYwMzJiNjU2ZTAzMjEwMDg1MjBmMDA5ODkzMGE3NTQ3NDhiN2RkY2I0M2VmNzVhMGRiZjNhMGQyNjM4MWFmNGViYTRhOThlYWE5YjRlNmEifV19",
    "device_evidence": "eyJmb3JtYXQiOiJodHRwczovL3RpbmZvaWwuc2gvZGV2aWNlLWV2aWRlbmNlL3YxIiwiaXRlbXMiOltdfQ==",
    "crypto_material_hash": "ed4444b3b58d22e8e2b8181ac2a16ffd396f5273acd783b6c36afbb34ee120c3",
    "device_evidence_hash": "5e84f632e01293bff4596cf72c45de0f9e1037e5cda3232b850c478d1a6b592b",
    "report_data": "4f4049335c395580da60f8d34aacb770dc4aa3acba2d71a370c92da0d09debe20000000000000000000000000000000000000000000000000000000000000000"
  }
]
"###;
        let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            let mut doc = fixture();
            doc["crypto_material"] = vector["crypto_material"].clone();
            doc["device_evidence"] = vector["device_evidence"].clone();
            doc["cpu_evidence"]["endorsed"]["crypto_material_hash"] =
                vector["crypto_material_hash"].clone();
            doc["cpu_evidence"]["endorsed"]["device_evidence_hash"] =
                vector["device_evidence_hash"].clone();
            doc["challenge"]["report_data"] = vector["report_data"].clone();
            let parsed = parse(&doc).unwrap();
            assert_eq!(
                hex::encode(parsed.expected_report_data),
                vector["report_data"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(Sha256::digest(&parsed.crypto_material_bytes)),
                vector["crypto_material_hash"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(Sha256::digest(&parsed.device_evidence_bytes)),
                vector["device_evidence_hash"].as_str().unwrap()
            );
            assert_eq!(
                parsed.crypto_material[0].data,
                hex::decode(vector["item"]["data"].as_str().unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn synthetic_document_parses_but_does_not_authenticate_dummy_cpu_report() {
        let parsed = parse(&fixture()).unwrap();
        assert_eq!(parsed.nonce, nonce());
        assert_eq!(parsed.raw_cpu_report, [1; 1184]);
        assert_eq!(parsed.tls_fingerprint().unwrap(), [0xaa; 32]);
        assert_eq!(parsed.hpke_public_key().unwrap(), [0xbb; 32]);
        assert_eq!(&parsed.expected_report_data[32..], [0; 32]);
        assert!(parsed.device_evidence.is_empty());
        assert_eq!(parsed.collateral.amd_vcek.unwrap().vcek_der, [1, 2]);
        assert_eq!(parsed.collateral.amd_crl.unwrap(), [3, 4]);
        assert_eq!(parsed.collateral.sigstore_code.unwrap().repo, "org/code");
        assert_eq!(parsed.collateral.sigstore_platform.unwrap().digest, "ef01");
        assert_eq!(parsed.collateral.freshness.len(), 2);
    }

    #[test]
    fn explicit_legacy_collateral_policy_matches_omitted_policy() {
        let mut doc = fixture();
        let omitted = parse(&doc).unwrap();
        doc["collateral_format"] = json!(COLLATERAL_V2_FORMAT);
        assert_eq!(
            parse(&doc).unwrap().expected_report_data,
            omitted.expected_report_data
        );
    }

    #[test]
    fn expected_nonce_must_be_exactly_32_bytes_and_match() {
        let bytes = serde_json::to_vec(&fixture()).unwrap();
        for size in [0, 31, 33] {
            let err = parse_document(&bytes, &vec![0; size]).unwrap_err();
            assert!(err.is_configuration());
        }
        assert!(parse_document(&bytes, &[0; 32])
            .unwrap_err()
            .to_string()
            .contains("nonce does not match"));
    }

    #[test]
    fn rejects_unknown_fields_in_every_known_outer_and_collateral_struct() {
        for pointer in [
            "",
            "/challenge",
            "/cpu_evidence",
            "/cpu_evidence/endorsed",
            "/collateral/0",
            "/collateral/0/data",
            "/collateral/1/data",
            "/collateral/2/data",
            "/collateral/3/data",
            "/collateral/4/data",
            "/collateral/5/data",
        ] {
            let mut doc = fixture();
            doc.pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".to_owned(), json!(true));
            assert!(failure(&doc).contains("unknown field"), "pointer {pointer}");
        }
    }

    #[test]
    fn rejects_unknown_fields_in_both_endorsed_sections_and_items() {
        for (name, pointer) in [
            ("crypto_material", ""),
            ("crypto_material", "/items/0"),
            ("device_evidence", ""),
            ("device_evidence", "/items/0"),
        ] {
            let mut doc = fixture();
            let mut value = section(&doc, name);
            if name == "device_evidence" {
                value["items"] = json!([{"id":"gpu"}]);
            }
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".to_owned(), json!(1));
            update_section(&mut doc, name, &value);
            assert!(failure(&doc).contains("unknown field"), "{name}{pointer}");
        }
    }

    #[test]
    fn rejects_duplicates_recursively_even_in_opaque_or_escaped_json_members() {
        for json in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":{"b":1,"b":2}}"#,
            r#"[{"x":1,"x":2}]"#,
            r#"{"a":1,"\u0061":2}"#,
        ] {
            assert!(parse_strict_json(json.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("duplicate JSON member"));
        }
        let doc = fixture();
        let encoded = serde_json::to_string(&doc).unwrap();
        let duplicated = encoded.replacen(
            "\"challenge\":{",
            "\"challenge\":{\"nonce\":\"ignored\",",
            1,
        );
        assert!(parse_document(duplicated.as_bytes(), &nonce())
            .unwrap_err()
            .to_string()
            .contains("duplicate JSON member"));
    }

    #[test]
    fn rejects_duplicate_keys_inside_base64_sections_and_collateral_bundles() {
        for name in ["crypto_material", "device_evidence"] {
            let mut doc = fixture();
            let bytes = STANDARD.decode(doc[name].as_str().unwrap()).unwrap();
            let duplicate =
                String::from_utf8(bytes)
                    .unwrap()
                    .replacen('{', "{\"format\":\"ignored\",", 1);
            doc[name] = json!(STANDARD.encode(duplicate));
            rebind(&mut doc);
            assert!(failure(&doc).contains("duplicate JSON member"));
        }
        let source = serde_json::to_string(&fixture()).unwrap().replacen(
            "\"sigstore_bundle\":{}",
            "\"sigstore_bundle\":{\"x\":1,\"x\":2}",
            1,
        );
        assert!(parse_document(source.as_bytes(), &nonce())
            .unwrap_err()
            .to_string()
            .contains("duplicate JSON member"));
    }

    #[test]
    fn changing_raw_section_whitespace_without_rebinding_fails() {
        let mut doc = fixture();
        let old = STANDARD
            .decode(doc["crypto_material"].as_str().unwrap())
            .unwrap();
        let mut changed = b" ".to_vec();
        changed.extend_from_slice(&old);
        doc["crypto_material"] = json!(STANDARD.encode(&changed));
        assert!(failure(&doc).contains("crypto_material hash does not match"));
        rebind(&mut doc);
        let parsed = parse(&doc).unwrap();
        assert_eq!(parsed.crypto_material_bytes, changed);
        assert_eq!(
            parsed.device_evidence_bytes,
            STANDARD
                .decode(doc["device_evidence"].as_str().unwrap())
                .unwrap()
        );
    }

    #[test]
    fn declared_section_hash_or_report_data_change_fails() {
        for pointer in [
            "/cpu_evidence/endorsed/crypto_material_hash",
            "/cpu_evidence/endorsed/device_evidence_hash",
            "/challenge/report_data",
        ] {
            let mut doc = fixture();
            let old = doc.pointer(pointer).unwrap().as_str().unwrap();
            let mut changed = old.to_owned();
            changed.replace_range(..1, if old.starts_with('0') { "1" } else { "0" });
            *doc.pointer_mut(pointer).unwrap() = json!(changed);
            assert!(failure(&doc).contains("does not match"));
        }
    }

    #[test]
    fn report_data_zero_tail_is_checked() {
        let mut doc = fixture();
        let mut changed = doc["challenge"]["report_data"].as_str().unwrap().to_owned();
        changed.replace_range(126..128, "01");
        doc["challenge"]["report_data"] = json!(changed);
        assert!(failure(&doc).contains("report_data does not match"));
    }

    #[test]
    fn rejects_non_lowercase_and_wrong_length_hex() {
        for pointer in [
            "/challenge/nonce",
            "/challenge/report_data",
            "/cpu_evidence/endorsed/crypto_material_hash",
            "/cpu_evidence/endorsed/device_evidence_hash",
        ] {
            for bad in ["AA", "a", "00", "00 00"] {
                let mut doc = fixture();
                *doc.pointer_mut(pointer).unwrap() = json!(bad);
                assert!(parse(&doc).is_err(), "{pointer} {bad}");
            }
        }
    }

    #[test]
    fn rejects_noncanonical_base64_at_all_binary_fields() {
        for pointer in [
            "/crypto_material",
            "/device_evidence",
            "/cpu_evidence/report_base64",
            "/collateral/0/data/vcek_der_base64",
            "/collateral/1/data/crl_der_base64",
        ] {
            for bad in ["AQ", "AR==", "AQ==\n", "AQ==\r\n", "AQ-_", " AQ=="] {
                let mut doc = fixture();
                *doc.pointer_mut(pointer).unwrap() = json!(bad);
                assert!(parse(&doc).is_err(), "{pointer} {bad:?}");
            }
        }
    }

    #[test]
    fn fixed_protocol_keys_must_not_be_truncated_or_odd_or_uppercase() {
        for id in 0..2 {
            for bad in ["", "a", "AA", "00"] {
                let mut doc = fixture();
                let mut cm = section(&doc, "crypto_material");
                cm["items"][id]["data"] = json!(bad);
                update_section(&mut doc, "crypto_material", &cm);
                assert!(parse(&doc).is_err());
            }
        }
    }

    #[test]
    fn unknown_key_formats_require_nonempty_decodable_lower_hex() {
        for (data, valid) in [("", false), ("abc", false), ("AB", false), ("abcd", true)] {
            let mut doc = fixture();
            let mut cm = section(&doc, "crypto_material");
            cm["items"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"future","format":"https://example.com/key/v9","data":data}));
            update_section(&mut doc, "crypto_material", &cm);
            assert_eq!(parse(&doc).is_ok(), valid);
        }
    }

    #[test]
    fn conventional_key_ids_do_not_override_protocol_format() {
        let mut doc = fixture();
        let mut cm = section(&doc, "crypto_material");
        cm["items"][0]["format"] = json!(HPKE_KEY_FORMAT);
        update_section(&mut doc, "crypto_material", &cm);
        assert!(parse(&doc).unwrap().tls_fingerprint().is_err());
        cm["items"] = json!([]);
        update_section(&mut doc, "crypto_material", &cm);
        assert!(parse(&doc).unwrap().hpke_public_key().is_err());
    }

    #[test]
    fn ids_are_nonempty_and_unique_in_all_three_item_collections() {
        for name in ["crypto_material", "device_evidence"] {
            for empty in [false, true] {
                let mut doc = fixture();
                let mut value = section(&doc, name);
                if name == "device_evidence" {
                    value["items"] = json!([{"id":"gpu"}]);
                }
                let mut item = value["items"][0].clone();
                if empty {
                    item["id"] = json!("");
                }
                value["items"].as_array_mut().unwrap().push(item);
                update_section(&mut doc, name, &value);
                assert!(parse(&doc).is_err());
            }
        }
        let mut doc = fixture();
        let duplicate = doc["collateral"][0].clone();
        doc["collateral"].as_array_mut().unwrap().push(duplicate);
        assert!(failure(&doc).contains("duplicate collateral entry id"));
    }

    #[test]
    fn unsupported_document_cpu_binding_and_collateral_formats_fail_closed() {
        for (pointer, value) in [
            ("/format", "legacy"),
            (
                "/cpu_evidence/format",
                "https://tinfoil.sh/format/tdx-quote/v1",
            ),
            (
                "/challenge/report_data_algorithm",
                "https://tinfoil.sh/report-data/v2",
            ),
            (
                "/collateral_format",
                "https://tinfoil.sh/predicate/attestation-collaterals/v3",
            ),
            ("/collateral_format", "future"),
        ] {
            let mut doc = fixture();
            if pointer == "/collateral_format" {
                doc["collateral_format"] = json!(value);
            } else {
                *doc.pointer_mut(pointer).unwrap() = json!(value);
            }
            assert!(matches!(
                parse(&doc).unwrap_err(),
                Error::UnsupportedFormat(_)
            ));
        }
    }

    #[test]
    fn v3_collateral_entries_do_not_silently_pass_under_v2_policy() {
        for (id, format) in [
            ("tinfoil-config", "https://example.com/unknown"),
            ("runtime", "https://example.com/unknown"),
            ("runtime-freshness", SIGSTORE_FRESHNESS_FORMAT),
            ("future", "https://tinfoil.sh/collateral/config/v1"),
            ("future", "https://tinfoil.sh/collateral/igvm-runtime/v1"),
            (
                "platform-freshness",
                "https://tinfoil.sh/collateral/artifact-freshness/v1",
            ),
        ] {
            let mut doc = fixture();
            doc["collateral"] =
                json!([{"id":id,"role":"reference-values","format":format,"data":{}}]);
            assert!(matches!(
                parse(&doc).unwrap_err(),
                Error::UnsupportedFormat(_)
            ));
        }
    }

    #[test]
    fn malformed_known_collateral_rejects_even_if_not_selected_or_not_cpu_subject() {
        for index in 0..6 {
            let mut doc = fixture();
            let mut ignored = doc["collateral"][index].clone();
            ignored["id"] = json!("additional");
            ignored["subjects"] = json!(["other-device"]);
            ignored["data"]["unknown"] = json!(true);
            doc["collateral"].as_array_mut().unwrap().push(ignored);
            assert!(failure(&doc).contains("unknown field"));
        }
    }

    #[test]
    fn collateral_role_data_and_bundle_shape_are_checked() {
        for data in [Value::Null, json!([]), json!("wrong")] {
            let mut doc = fixture();
            doc["collateral"][0]["data"] = data;
            assert!(failure(&doc).contains("data is not a valid JSON object"));
        }
        for index in 2..6 {
            let mut doc = fixture();
            doc["collateral"][index]["data"]["sigstore_bundle"] = Value::Null;
            assert!(failure(&doc).contains("missing sigstore_bundle"));
        }
        let mut doc = fixture();
        doc["collateral"][0]["role"] = json!("other");
        assert!(failure(&doc).contains("unknown role"));
    }

    #[test]
    fn unknown_collateral_is_shape_checked_and_never_retained_as_trusted_data() {
        let mut doc = fixture();
        doc["collateral"] = json!([{"id":"other","role":"endorsement","format":"https://example.com/future","data":{"future":true}}]);
        let parsed = parse(&doc).unwrap();
        assert!(parsed.collateral.amd_vcek.is_none());
        assert!(parsed.collateral.sigstore_code.is_none());
    }

    #[test]
    fn cpu_collateral_requires_explicit_cpu_subject() {
        let mut doc = fixture();
        doc["collateral"][0]["subjects"] = json!(["different-device"]);
        doc["collateral"][1]["subjects"] = json!([]);
        let parsed = parse(&doc).unwrap();
        assert!(parsed.collateral.amd_vcek.is_none());
        assert!(parsed.collateral.amd_crl.is_none());
    }

    #[test]
    fn intel_pcs_known_data_is_also_strictly_decoded_even_for_snp() {
        let mut doc = fixture();
        doc["collateral"] = json!([{"id":"intel","role":"endorsement","format":INTEL_PCS_FORMAT,"subjects":["cpu"],"data":{"responses":[{"url":"https://example.invalid","headers":{"content-type":["application/json"]},"body_base64":"AQI="}]}}]);
        let parsed = parse(&doc).unwrap();
        assert_eq!(parsed.collateral.intel_pcs.unwrap()[0].body, [1, 2]);
        doc["collateral"][0]["data"]["responses"][0]["unknown"] = json!(1);
        assert!(failure(&doc).contains("unknown field"));
    }

    #[test]
    fn device_evidence_is_retained_as_hash_bound_not_independently_appraised() {
        let mut doc = fixture();
        let device = json!({"format":DEVICE_EVIDENCE_V1_FORMAT,"items":[{"id":"gpu0","kind":"gpu","vendor":"nvidia","format":"https://tinfoil.sh/format/nvidia-gpu-evidence/v1","evidence":{"synthetic":"not a cryptographically valid NVIDIA quote"}}]});
        update_section(&mut doc, "device_evidence", &device);
        let parsed = parse(&doc).unwrap();
        assert_eq!(parsed.device_evidence[0].vendor, "nvidia");
        assert!(parsed.device_evidence[0].evidence["synthetic"]
            .as_str()
            .unwrap()
            .contains("not a cryptographically valid"));
    }

    #[test]
    fn snp_raw_report_requires_exact_1184_bytes() {
        for size in [0, 1, 1183, 1185] {
            let mut doc = fixture();
            doc["cpu_evidence"]["report_base64"] = json!(STANDARD.encode(vec![0; size]));
            assert!(failure(&doc).contains("1184-byte"));
        }
    }

    #[test]
    fn missing_or_null_endorsed_items_and_trailing_json_reject() {
        for name in ["crypto_material", "device_evidence"] {
            for absent in [false, true] {
                let mut doc = fixture();
                let mut value = section(&doc, name);
                if absent {
                    value.as_object_mut().unwrap().remove("items");
                } else {
                    value["items"] = Value::Null;
                }
                update_section(&mut doc, name, &value);
                assert!(parse(&doc).is_err());
            }
        }
        let mut bytes = serde_json::to_vec(&fixture()).unwrap();
        bytes.extend_from_slice(b" {}");
        assert!(parse_document(&bytes, &nonce()).is_err());
    }

    #[test]
    fn enforces_document_size_before_json_processing() {
        let bytes = vec![b' '; MAX_DOCUMENT_BYTES + 1];
        assert!(parse_document(&bytes, &nonce())
            .unwrap_err()
            .to_string()
            .contains("32 MiB"));
    }
}
