//! The v3 attestation document: its wire format and its strict parsing,
//! which checks the challenge against the caller's nonce.
//!
//! The document is flat: a challenge, CPU evidence, two endorsed sections
//! (`crypto_material` and `device_evidence`) and an array of collateral
//! entries. The endorsed sections are bound into the CPU quote's report data
//! by hash:
//!
//! ```text
//! crypto_material_hash = SHA-256(base64-decoded crypto_material bytes)
//! device_evidence_hash = SHA-256(base64-decoded device_evidence bytes)
//! report_data[0..32]   = SHA-256(algorithm URI || nonce || crypto_material_hash || device_evidence_hash)
//! report_data[32..64]  = zeros
//! ```
//!
//! The hashes cover the exact decoded section bytes, which are never
//! re-serialized.
//!
//! Parsing authenticates nothing by itself: the CPU quote must prove that the
//! hardware bound the recomputed report data before any part of the document
//! is trusted.

pub mod collateral;

use std::collections::HashSet;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::canonical::{self, CanonicalError};
use crate::json::decode::{self, DecodeError};
use crate::json::{self, Value};
use collateral::{
    CollateralError, ConfigEndorsement, CpuEndorsements, Freshness, Runtime, SigstoreRef,
};

/// Format of the v3 attestation document.
pub const ATTESTATION_V3_FORMAT: &str = "https://tinfoil.sh/predicate/attestation/v3";

/// The report-data derivation described in the module documentation.
pub const REPORT_DATA_V1_ALGORITHM: &str = "https://tinfoil.sh/report-data/v1";

/// Format of the `crypto_material` section.
pub const CRYPTO_MATERIAL_V1_FORMAT: &str = "https://tinfoil.sh/crypto-material/v1";
/// Format of the `device_evidence` section.
pub const DEVICE_EVIDENCE_V1_FORMAT: &str = "https://tinfoil.sh/device-evidence/v1";

/// CPU evidence format: a raw 1184-byte SEV-SNP report.
pub const SEV_SNP_REPORT_V1_FORMAT: &str = "https://tinfoil.sh/format/sev-snp-report/v1";
/// CPU evidence format: a raw TDX quote, version 4.
pub const TDX_QUOTE_V1_FORMAT: &str = "https://tinfoil.sh/format/tdx-quote/v1";
/// Device evidence format: an NVIDIA GPU evidence payload.
pub const NVIDIA_GPU_EVIDENCE_V1_FORMAT: &str = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1";

/// Key format: the 32-byte SHA-256 of a DER-encoded SubjectPublicKeyInfo.
pub const KEY_SPKI_FP_SHA256_V1_FORMAT: &str = "https://tinfoil.sh/key/spki-fp-sha256/v1";
/// Key format: a complete DER-encoded SubjectPublicKeyInfo. Consumers
/// validate the key algorithm for their protocol.
pub const KEY_SPKI_V1_FORMAT: &str = "https://tinfoil.sh/key/spki/v1";
/// Key format: a raw 32-byte X25519 public key used for HPKE.
pub const KEY_X25519_HPKE_V1_FORMAT: &str = "https://tinfoil.sh/key/x25519-hpke/v1";

/// The conventional id of the TLS key fingerprint.
pub const CRYPTO_MATERIAL_ID_TLS: &str = "tls";
/// The conventional id of the HPKE public key.
pub const CRYPTO_MATERIAL_ID_HPKE: &str = "hpke";

/// The size in bytes of a challenge nonce.
pub const NONCE_SIZE: usize = 32;

/// The size in bytes of the report data that a CPU quote binds.
pub const REPORT_DATA_SIZE: usize = 64;

/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;

/// Why a document was not parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentError {
    /// The caller's own input is wrong: a nonce of the wrong length. The
    /// document was not looked at.
    InvalidInput(String),
    /// The document is malformed, is not bound to the nonce, or contradicts
    /// itself.
    Rejected(String),
}

impl DocumentError {
    /// Whether the error is the caller's mistake and not a verdict on the
    /// document.
    pub fn is_invalid_input(&self) -> bool {
        matches!(self, DocumentError::InvalidInput(_))
    }

    fn rejected(message: impl Into<String>) -> Self {
        DocumentError::Rejected(message.into())
    }
}

impl fmt::Display for DocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DocumentError::InvalidInput(message) => write!(f, "invalid input: {message}"),
            DocumentError::Rejected(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DocumentError {}

impl From<CanonicalError> for DocumentError {
    fn from(error: CanonicalError) -> Self {
        Self::rejected(error.to_string())
    }
}

impl From<CollateralError> for DocumentError {
    fn from(error: CollateralError) -> Self {
        Self::rejected(error.to_string())
    }
}

/// A document's decoded hardware evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuEvidence {
    /// The format that selects the platform, such as
    /// [`SEV_SNP_REPORT_V1_FORMAT`].
    pub format: String,
    /// The raw report (SEV-SNP) or quote (TDX).
    pub report: Vec<u8>,
}

/// One endorsed key. The item format fully determines how `data`, lowercase
/// hex, is interpreted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CryptoMaterialItem {
    /// The item's id, unique within the section.
    pub id: String,
    /// The key format, such as [`KEY_X25519_HPKE_V1_FORMAT`].
    pub format: String,
    /// The key material, lowercase hex.
    pub data: String,
}

/// One device's evidence. The item format versions the `evidence` payload.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DeviceEvidenceItem {
    /// The item's id, unique within the section.
    pub id: String,
    /// The kind of device.
    pub kind: String,
    /// The device vendor.
    pub vendor: String,
    /// The format of `evidence`.
    pub format: String,
    /// The evidence payload; `None` when the item leaves it out.
    pub evidence: Option<Value>,
}

/// The challenge that binds a document to a verifier-chosen nonce.
#[derive(Debug, Default)]
struct Challenge {
    nonce: String,
    report_data: String,
    report_data_algorithm: String,
}

/// The SHA-256 hashes of the two endorsed sections, lowercase hex.
#[derive(Debug, Default)]
struct EndorsedHashes {
    crypto_material_hash: String,
    device_evidence_hash: String,
}

/// The hardware quote and the endorsed-section hashes that it binds.
#[derive(Debug, Default)]
struct RawCpuEvidence {
    format: String,
    report_base64: String,
    endorsed: EndorsedHashes,
}

/// The serialized shape of a document. The endorsed sections travel
/// base64-encoded, so that the encoded string carries the exact bytes that
/// were hashed.
#[derive(Debug, Default)]
struct RawDocument {
    format: String,
    challenge: Challenge,
    cpu_evidence: RawCpuEvidence,
    crypto_material: String,
    device_evidence: String,
    collateral_format: String,
    collateral: Vec<collateral::Entry>,
}

/// A parsed v3 attestation document.
///
/// [`parse`] decodes every field and checks the challenge against the
/// caller's nonce. A parsed document is not authenticated: nothing in it is
/// trusted until the CPU quote proves that the hardware bound
/// [`Document::expected_report_data`].
#[derive(Debug)]
pub struct Document {
    challenge: Challenge,
    endorsed: EndorsedHashes,
    evidence: CpuEvidence,
    /// The endorsement collateral of the evidence's own platform.
    cpu_endorsements: CpuEndorsements,
    collateral: collateral::Set,
    collateral_format: String,
    crypto_material_bytes: Vec<u8>,
    device_evidence_bytes: Vec<u8>,
    crypto_material: Vec<CryptoMaterialItem>,
    device_evidence: Vec<DeviceEvidenceItem>,
    /// The recomputed report data, once the challenge has been checked
    /// against the caller's nonce.
    report_data: Option<[u8; REPORT_DATA_SIZE]>,
}

/// Derives the report data: SHA-256 over the algorithm URI, as a
/// domain-separation label, followed by the three 32-byte inputs in order;
/// the upper half is zero.
pub fn compute_report_data(
    nonce: &[u8],
    crypto_material_hash: &[u8],
    device_evidence_hash: &[u8],
) -> Result<[u8; REPORT_DATA_SIZE], DocumentError> {
    if nonce.len() != NONCE_SIZE
        || crypto_material_hash.len() != SHA256_SIZE
        || device_evidence_hash.len() != SHA256_SIZE
    {
        return Err(DocumentError::rejected(format!(
            "report data inputs must be 32 bytes each (got {}, {}, {})",
            nonce.len(),
            crypto_material_hash.len(),
            device_evidence_hash.len()
        )));
    }
    let digest = Sha256::new()
        .chain_update(REPORT_DATA_V1_ALGORITHM)
        .chain_update(nonce)
        .chain_update(crypto_material_hash)
        .chain_update(device_evidence_hash)
        .finalize();
    let mut out = [0; REPORT_DATA_SIZE];
    for (target, byte) in out.iter_mut().zip(digest) {
        *target = byte;
    }
    Ok(out)
}

/// Generates a challenge nonce from the operating system's random source.
///
/// # Errors
///
/// Fails when the operating system cannot supply random bytes.
pub fn random_nonce() -> std::io::Result<[u8; NONCE_SIZE]> {
    let mut nonce = [0; NONCE_SIZE];
    getrandom::fill(&mut nonce)?;
    Ok(nonce)
}

/// Strictly parses a v3 document and checks its challenge against
/// `expected_nonce`, the nonce that the caller sent: nonce equality, the
/// hashes of the endorsed sections, and the report data.
///
/// Parsing is strict: unknown members are rejected, member names are
/// case-sensitive and unique, hex is lowercase, base64 is canonical and item
/// ids are unique.
pub fn parse(doc: &[u8], expected_nonce: &[u8]) -> Result<Document, DocumentError> {
    if expected_nonce.len() != NONCE_SIZE {
        return Err(DocumentError::InvalidInput(format!(
            "expected nonce must be {NONCE_SIZE} bytes, got {}",
            expected_nonce.len()
        )));
    }
    let mut document = decode(doc)?;
    document.bind(expected_nonce)?;
    Ok(document)
}

/// Applies the structural rules alone, without checking the challenge
/// against a nonce.
///
/// The result has no expected report data, and nothing may treat it as bound
/// to a challenge: a replayed document passes this function.
pub fn decode(doc: &[u8]) -> Result<Document, DocumentError> {
    let parsing = |error: &dyn fmt::Display| {
        DocumentError::rejected(format!("parsing attestation document: {error}"))
    };
    let value = json::parse(doc).map_err(|error| parsing(&error))?;
    let raw = decode_raw_document(value).map_err(|error| parsing(&error))?;

    if raw.format != ATTESTATION_V3_FORMAT {
        return Err(DocumentError::rejected(format!(
            "unsupported document format {:?}",
            raw.format
        )));
    }
    check_challenge(&raw.challenge)?;
    let report = decode_report(&raw.cpu_evidence)?;
    let (crypto_material, crypto_material_bytes) = parse_crypto_material(&raw.crypto_material)?;
    let (device_evidence, device_evidence_bytes) = parse_device_evidence(&raw.device_evidence)?;
    let mut set = decode_collateral(&raw.collateral_format, raw.collateral)?;

    // Only the collateral of the evidence's own platform endorses it.
    let all = std::mem::take(&mut set.cpu);
    let cpu_endorsements = match raw.cpu_evidence.format.as_str() {
        SEV_SNP_REPORT_V1_FORMAT => CpuEndorsements {
            amd_vcek: all.amd_vcek,
            amd_crl: all.amd_crl,
            intel_pcs: None,
        },
        TDX_QUOTE_V1_FORMAT => CpuEndorsements {
            amd_vcek: None,
            amd_crl: None,
            intel_pcs: all.intel_pcs,
        },
        _ => CpuEndorsements::default(),
    };

    Ok(Document {
        challenge: raw.challenge,
        endorsed: raw.cpu_evidence.endorsed,
        evidence: CpuEvidence {
            format: raw.cpu_evidence.format,
            report,
        },
        cpu_endorsements,
        collateral: set,
        collateral_format: raw.collateral_format,
        crypto_material_bytes,
        device_evidence_bytes,
        crypto_material,
        device_evidence,
        report_data: None,
    })
}

impl Document {
    /// The collateral format, which selects a verification policy and not a
    /// trust anchor. A document that names none uses
    /// [`collateral::FORMAT_V2`].
    pub fn collateral_format(&self) -> &str {
        if self.collateral_format.is_empty() {
            collateral::FORMAT_V2
        } else {
            &self.collateral_format
        }
    }

    /// The decoded CPU evidence.
    pub fn cpu_evidence(&self) -> &CpuEvidence {
        &self.evidence
    }

    /// The endorsement collateral that the document's CPU evidence format
    /// uses, for the reserved CPU subject. Collateral that the document does
    /// not carry is `None`.
    pub fn cpu_endorsements(&self) -> &CpuEndorsements {
        &self.cpu_endorsements
    }

    /// The `crypto_material` items, in document order.
    pub fn crypto_material_items(&self) -> &[CryptoMaterialItem] {
        &self.crypto_material
    }

    /// The `crypto_material` item with the given id.
    pub fn crypto_material_item(&self, id: &str) -> Option<&CryptoMaterialItem> {
        self.crypto_material.iter().find(|item| item.id == id)
    }

    /// The `device_evidence` items, in document order.
    pub fn device_evidence_items(&self) -> &[DeviceEvidenceItem] {
        &self.device_evidence
    }

    /// The code-provenance reference-values entry.
    pub fn sigstore_code(&self) -> Result<&SigstoreRef, CollateralError> {
        self.collateral.sigstore_code.as_ref().ok_or_else(|| {
            not_found(format!(
                "document carries no {} reference-values entry",
                collateral::SIGSTORE_CODE_V1_FORMAT
            ))
        })
    }

    /// The platform-endorsements reference-values entry.
    pub fn sigstore_platform(&self) -> Result<&SigstoreRef, CollateralError> {
        self.collateral.sigstore_platform.as_ref().ok_or_else(|| {
            not_found(format!(
                "document carries no {} reference-values entry",
                collateral::SIGSTORE_PLATFORM_V1_FORMAT
            ))
        })
    }

    /// The freshness witness with the given entry id, such as
    /// [`collateral::FRESHNESS_ID_CODE`].
    pub fn freshness(&self, id: &str) -> Result<&Freshness, CollateralError> {
        self.collateral.freshness.get(id).ok_or_else(|| {
            not_found(format!(
                "document carries no {} reference-values entry {id:?}",
                collateral::SIGSTORE_FRESHNESS_V1_FORMAT
            ))
        })
    }

    /// The decoded, unauthenticated config entry.
    pub fn config_endorsement(&self) -> Result<&ConfigEndorsement, CollateralError> {
        self.collateral.config.as_ref().ok_or_else(|| {
            not_found(format!(
                "document carries no {:?} reference-values entry",
                collateral::CONFIG_ID
            ))
        })
    }

    /// The decoded, unauthenticated runtime entry.
    pub fn runtime(&self) -> Result<&Runtime, CollateralError> {
        self.collateral.runtime.as_ref().ok_or_else(|| {
            not_found(format!(
                "document carries no {:?} reference-values entry",
                collateral::RUNTIME_ID
            ))
        })
    }

    /// The platform reference for config verification, which must be
    /// unambiguous.
    pub fn config_platform(&self) -> Result<&SigstoreRef, CollateralError> {
        self.collateral.config_platform()
    }

    /// The report data that the document's CPU quote must bind, recomputed
    /// from the caller's nonce and the endorsed sections. `None` for a
    /// document whose challenge was never checked against a nonce.
    pub fn expected_report_data(&self) -> Option<[u8; REPORT_DATA_SIZE]> {
        self.report_data
    }

    /// Checks the challenge against the caller's nonce and records the
    /// recomputed report data.
    fn bind(&mut self, expected_nonce: &[u8]) -> Result<(), DocumentError> {
        if self.challenge.nonce != canonical::encode_lower_hex(expected_nonce) {
            return Err(DocumentError::rejected(
                "challenge nonce does not match the expected nonce",
            ));
        }
        let crypto_hash = Sha256::digest(&self.crypto_material_bytes);
        let device_hash = Sha256::digest(&self.device_evidence_bytes);
        if canonical::encode_lower_hex(&crypto_hash) != self.endorsed.crypto_material_hash {
            return Err(DocumentError::rejected(
                "crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash",
            ));
        }
        if canonical::encode_lower_hex(&device_hash) != self.endorsed.device_evidence_hash {
            return Err(DocumentError::rejected(
                "device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash",
            ));
        }
        let report_data = compute_report_data(expected_nonce, &crypto_hash, &device_hash)?;
        if canonical::encode_lower_hex(&report_data) != self.challenge.report_data {
            return Err(DocumentError::rejected(
                "challenge report_data does not match the recomputed value",
            ));
        }
        self.report_data = Some(report_data);
        Ok(())
    }
}

fn not_found(what: String) -> CollateralError {
    CollateralError::NotFound(what)
}

fn decode_raw_document(value: Value) -> Result<RawDocument, DecodeError> {
    const PATH: &str = "attestation document";
    let mut raw = RawDocument::default();
    let Some(object) = decode::object(value, PATH)? else {
        return Ok(raw);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "format" => raw.format = decode::string(value, &name)?,
            "challenge" => raw.challenge = decode_challenge(value)?,
            "cpu_evidence" => raw.cpu_evidence = decode_cpu_evidence(value)?,
            "crypto_material" => raw.crypto_material = decode::string(value, &name)?,
            "device_evidence" => raw.device_evidence = decode::string(value, &name)?,
            "collateral_format" => raw.collateral_format = decode::string(value, &name)?,
            "collateral" => {
                raw.collateral = decode::array(value, &name)?
                    .unwrap_or_default()
                    .into_iter()
                    .map(|entry| collateral::Entry::from_value(entry, "collateral"))
                    .collect::<Result<_, _>>()?;
            }
            _ => return Err(decode::unknown_member(PATH, &name)),
        }
    }
    Ok(raw)
}

fn decode_challenge(value: Value) -> Result<Challenge, DecodeError> {
    const PATH: &str = "challenge";
    let mut challenge = Challenge::default();
    let Some(object) = decode::object(value, PATH)? else {
        return Ok(challenge);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "nonce" => challenge.nonce = decode::string(value, "challenge.nonce")?,
            "report_data" => {
                challenge.report_data = decode::string(value, "challenge.report_data")?;
            }
            "report_data_algorithm" => {
                challenge.report_data_algorithm =
                    decode::string(value, "challenge.report_data_algorithm")?;
            }
            _ => return Err(decode::unknown_member(PATH, &name)),
        }
    }
    Ok(challenge)
}

fn decode_cpu_evidence(value: Value) -> Result<RawCpuEvidence, DecodeError> {
    const PATH: &str = "cpu_evidence";
    let mut evidence = RawCpuEvidence::default();
    let Some(object) = decode::object(value, PATH)? else {
        return Ok(evidence);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "format" => evidence.format = decode::string(value, "cpu_evidence.format")?,
            "report_base64" => {
                evidence.report_base64 = decode::string(value, "cpu_evidence.report_base64")?;
            }
            "endorsed" => evidence.endorsed = decode_endorsed(value)?,
            _ => return Err(decode::unknown_member(PATH, &name)),
        }
    }
    Ok(evidence)
}

fn decode_endorsed(value: Value) -> Result<EndorsedHashes, DecodeError> {
    const PATH: &str = "cpu_evidence.endorsed";
    let mut endorsed = EndorsedHashes::default();
    let Some(object) = decode::object(value, PATH)? else {
        return Ok(endorsed);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "crypto_material_hash" => {
                endorsed.crypto_material_hash =
                    decode::string(value, "cpu_evidence.endorsed.crypto_material_hash")?;
            }
            "device_evidence_hash" => {
                endorsed.device_evidence_hash =
                    decode::string(value, "cpu_evidence.endorsed.device_evidence_hash")?;
            }
            _ => return Err(decode::unknown_member(PATH, &name)),
        }
    }
    Ok(endorsed)
}

fn check_challenge(challenge: &Challenge) -> Result<(), DocumentError> {
    if challenge.report_data_algorithm != REPORT_DATA_V1_ALGORITHM {
        return Err(DocumentError::rejected(format!(
            "unsupported challenge.report_data_algorithm {:?}",
            challenge.report_data_algorithm
        )));
    }
    canonical::decode_lower_hex("challenge.nonce", &challenge.nonce, NONCE_SIZE)?;
    canonical::decode_lower_hex(
        "challenge.report_data",
        &challenge.report_data,
        REPORT_DATA_SIZE,
    )?;
    Ok(())
}

/// Checks the CPU evidence and returns its decoded report.
fn decode_report(evidence: &RawCpuEvidence) -> Result<Vec<u8>, DocumentError> {
    canonical::decode_lower_hex(
        "cpu_evidence.endorsed.crypto_material_hash",
        &evidence.endorsed.crypto_material_hash,
        SHA256_SIZE,
    )?;
    canonical::decode_lower_hex(
        "cpu_evidence.endorsed.device_evidence_hash",
        &evidence.endorsed.device_evidence_hash,
        SHA256_SIZE,
    )?;
    if evidence.format.is_empty() || evidence.report_base64.is_empty() {
        return Err(DocumentError::rejected("cpu_evidence is incomplete"));
    }
    Ok(canonical::decode_base64(
        "cpu_evidence.report_base64",
        &evidence.report_base64,
    )?)
}

/// A section envelope: its format and its items, `None` when the section has
/// no `items` member or a `null` one.
struct RawSection {
    format: String,
    items: Option<Vec<Value>>,
}

/// Decodes the base64 of an endorsed section and the envelope inside it.
fn decode_section(name: &str, encoded: &str) -> Result<(RawSection, Vec<u8>), DocumentError> {
    if encoded.is_empty() {
        return Err(DocumentError::rejected(format!(
            "{name} section is missing"
        )));
    }
    let bytes = canonical::decode_base64(name, encoded)?;
    let parsing =
        |error: &dyn fmt::Display| DocumentError::rejected(format!("parsing {name}: {error}"));
    let value = json::parse(&bytes).map_err(|error| parsing(&error))?;
    let mut section = RawSection {
        format: String::new(),
        items: None,
    };
    let object = decode::object(value, name).map_err(|error| parsing(&error))?;
    for (member, value) in object.unwrap_or_default().into_members() {
        let decoded = match member.as_str() {
            "format" => decode::string(value, "format").map(|format| section.format = format),
            "items" => decode::array(value, "items").map(|items| section.items = items),
            _ => Err(decode::unknown_member(name, &member)),
        };
        decoded.map_err(|error| parsing(&error))?;
    }
    Ok((section, bytes))
}

fn parse_crypto_material(
    encoded: &str,
) -> Result<(Vec<CryptoMaterialItem>, Vec<u8>), DocumentError> {
    let (section, bytes) = decode_section("crypto_material", encoded)?;
    // Every item is decoded before any is checked.
    let present = section.items.is_some();
    let mut items = Vec::new();
    for value in section.items.unwrap_or_default() {
        let item = decode_crypto_material_item(value).map_err(|error| {
            DocumentError::rejected(format!("parsing crypto_material: {error}"))
        })?;
        items.push(item);
    }
    if section.format != CRYPTO_MATERIAL_V1_FORMAT {
        return Err(DocumentError::rejected(format!(
            "unsupported crypto_material section format {:?}",
            section.format
        )));
    }
    if !present {
        return Err(DocumentError::rejected("crypto_material.items is missing"));
    }
    let mut seen = HashSet::with_capacity(items.len());
    for item in &items {
        if item.id.is_empty() || item.format.is_empty() {
            return Err(DocumentError::rejected(
                "crypto_material item is incomplete",
            ));
        }
        if !seen.insert(item.id.as_str()) {
            return Err(DocumentError::rejected(format!(
                "duplicate crypto_material item id {:?}",
                item.id
            )));
        }
        match item.format.as_str() {
            // The known key formats are exactly 32 bytes.
            KEY_SPKI_FP_SHA256_V1_FORMAT | KEY_X25519_HPKE_V1_FORMAT => {
                let name = format!("crypto_material item {:?} data", item.id);
                canonical::decode_lower_hex(&name, &item.data, 32)?;
            }
            // Other formats still carry non-empty lowercase hex of whole
            // bytes.
            _ => {
                if item.data.is_empty() {
                    return Err(DocumentError::rejected(format!(
                        "crypto_material item {:?} data is empty",
                        item.id
                    )));
                }
                if !canonical::is_lower_hex(&item.data) || item.data.len() % 2 != 0 {
                    return Err(DocumentError::rejected(format!(
                        "crypto_material item {:?} data is not lowercase hex",
                        item.id
                    )));
                }
            }
        }
    }
    Ok((items, bytes))
}

fn decode_crypto_material_item(value: Value) -> Result<CryptoMaterialItem, DecodeError> {
    const PATH: &str = "items";
    let mut item = CryptoMaterialItem::default();
    let Some(object) = decode::object(value, PATH)? else {
        return Ok(item);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "id" => item.id = decode::string(value, &name)?,
            "format" => item.format = decode::string(value, &name)?,
            "data" => item.data = decode::string(value, &name)?,
            _ => return Err(decode::unknown_member(PATH, &name)),
        }
    }
    Ok(item)
}

fn parse_device_evidence(
    encoded: &str,
) -> Result<(Vec<DeviceEvidenceItem>, Vec<u8>), DocumentError> {
    let (section, bytes) = decode_section("device_evidence", encoded)?;
    let present = section.items.is_some();
    let mut items = Vec::new();
    for value in section.items.unwrap_or_default() {
        let item = decode_device_evidence_item(value).map_err(|error| {
            DocumentError::rejected(format!("parsing device_evidence: {error}"))
        })?;
        items.push(item);
    }
    if section.format != DEVICE_EVIDENCE_V1_FORMAT {
        return Err(DocumentError::rejected(format!(
            "unsupported device_evidence section format {:?}",
            section.format
        )));
    }
    if !present {
        return Err(DocumentError::rejected("device_evidence.items is missing"));
    }
    let mut seen = HashSet::with_capacity(items.len());
    for item in &items {
        if item.id.is_empty() {
            return Err(DocumentError::rejected("device_evidence item has no id"));
        }
        if !seen.insert(item.id.as_str()) {
            return Err(DocumentError::rejected(format!(
                "duplicate device_evidence item id {:?}",
                item.id
            )));
        }
    }
    Ok((items, bytes))
}

fn decode_device_evidence_item(value: Value) -> Result<DeviceEvidenceItem, DecodeError> {
    const PATH: &str = "items";
    let mut item = DeviceEvidenceItem::default();
    let Some(object) = decode::object(value, PATH)? else {
        return Ok(item);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "id" => item.id = decode::string(value, &name)?,
            "kind" => item.kind = decode::string(value, &name)?,
            "vendor" => item.vendor = decode::string(value, &name)?,
            "format" => item.format = decode::string(value, &name)?,
            "evidence" => item.evidence = Some(value),
            _ => return Err(decode::unknown_member(PATH, &name)),
        }
    }
    Ok(item)
}

/// Decodes the collateral entries and checks them against the collateral
/// format that the document names.
fn decode_collateral(
    format: &str,
    entries: Vec<collateral::Entry>,
) -> Result<collateral::Set, DocumentError> {
    let is_v3 = match format {
        "" | collateral::FORMAT_V2 => false,
        collateral::FORMAT_V3 => true,
        _ => {
            return Err(DocumentError::rejected(format!(
                "unsupported collateral format {format:?}"
            )));
        }
    };
    let set = collateral::decode(entries)?;
    if is_v3 {
        if set.sigstore_code.is_some() {
            return Err(DocumentError::rejected(format!(
                "legacy code collateral is incompatible with {format:?}"
            )));
        }
    } else if set.config.is_some() || set.runtime.is_some() {
        return Err(DocumentError::rejected(format!(
            "config and runtime collateral require {:?}",
            collateral::FORMAT_V3
        )));
    }
    for witness in set.freshness.values() {
        if is_v3 != (witness.format == collateral::ARTIFACT_FRESHNESS_V1_FORMAT) {
            return Err(DocumentError::rejected(format!(
                "freshness collateral is incompatible with {format:?}"
            )));
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests;
