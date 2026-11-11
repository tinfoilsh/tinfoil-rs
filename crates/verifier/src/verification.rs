//! The facts that a verification proves.

use std::fmt;
use std::time::SystemTime;

use crate::document::{
    CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, CryptoMaterialItem,
    KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT,
};
use crate::instant::Instant;
use crate::measurement::{Expected, Measurement, Register};
use crate::policy::{PLATFORM_SEV_SNP, PLATFORM_TDX};

/// Why reference values were accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReferenceSource {
    /// A verified endorsement vouches for them.
    Endorsement,
    /// The caller supplied them as embedded references.
    Embedded,
    /// The caller's config authorizer accepted them.
    Policy,
}

impl ReferenceSource {
    /// The source's name: `endorsement`, `embedded` or `policy`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReferenceSource::Endorsement => "endorsement",
            ReferenceSource::Embedded => "embedded",
            ReferenceSource::Policy => "policy",
        }
    }
}

impl fmt::Display for ReferenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The config that a verification bound to the hardware.
///
/// What is known depends on the source: an embedded config has no
/// endorsement reference, key hint or times, and a config that the caller's
/// authorizer accepted has a digest only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfigVerification {
    /// Why the config was accepted.
    pub source: ReferenceSource,
    /// The versioned config name, `/org/project/revision`.
    pub name: Option<String>,
    /// The SHA-256 of the config, lowercase hex.
    pub digest: String,
    /// The reference of the verified endorsement statement.
    pub reference: Option<String>,
    /// The hint of the key that signed the endorsement.
    pub signing_key_hint: Option<String>,
    /// The authenticated time of the endorsement's approval.
    pub approval_time: Option<SystemTime>,
    /// The registry that the endorsement belongs to: the one that its
    /// certificate names, or the public registry for a key-signed registry
    /// endorsement.
    pub registry_id: Option<String>,
    /// The authenticated time of the signature of a certificate-signed
    /// endorsement.
    pub signature_time: Option<SystemTime>,
}

/// Reference values that a verification accepted, and their authority: the
/// runtime or the platform policy artifact.
///
/// An embedded artifact has no authenticated commit or approval time, and
/// an embedded platform artifact is known by its digest alone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactVerification {
    /// Why the artifact was accepted.
    pub source: ReferenceSource,
    /// The repository that released the artifact.
    pub repo: Option<String>,
    /// The release tag.
    pub tag: Option<String>,
    /// The SHA-256 of the artifact, lowercase hex.
    pub digest: String,
    /// The artifact's file name in its release.
    pub name: Option<String>,
    /// The commit that the release was built from.
    pub commit: Option<String>,
    /// The authenticated time of the artifact's freshness approval.
    pub approval_time: Option<SystemTime>,
}

/// Software that took part in a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SoftwareIdentity {
    /// The software's name.
    pub name: String,
    /// Its version.
    pub version: String,
}

/// How a verification was performed. The verifier fills this in from its
/// own state; none of it is attested by the document or checked against
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerificationMetadata {
    /// The SDK that performed the verification.
    pub verifier: SoftwareIdentity,
    /// The instant that the document was appraised at: the one clock
    /// sample of [`Verifier::verify_v3`](crate::Verifier::verify_v3), or
    /// the caller's time for
    /// [`Verifier::verify_v3_at`](crate::Verifier::verify_v3_at). It is not
    /// a freshness guarantee.
    pub verified_at: SystemTime,
}

/// The facts proven by the verification of an attestation document, and
/// what the verifier adds about the verification itself.
///
/// Only a [`Verifier`](crate::Verifier) creates one, and it cannot be
/// changed afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub(crate) config_repo: String,
    pub(crate) code_digest: String,
    pub(crate) code_tag: String,
    pub(crate) code_measurement: Expected,
    pub(crate) config: Option<ConfigVerification>,
    pub(crate) runtime: Option<ArtifactVerification>,
    pub(crate) platform: Option<ArtifactVerification>,
    pub(crate) enclave_measurement: Measurement,
    pub(crate) crypto_material: Vec<CryptoMaterialItem>,
    pub(crate) freshness_expires_at: Option<SystemTime>,
    pub(crate) metadata: VerificationMetadata,
}

impl Verification {
    /// The repository of the verified code or runtime, without version
    /// pins.
    pub fn config_repo(&self) -> &str {
        &self.config_repo
    }

    /// The digest of the verified code or runtime artifact.
    pub fn code_digest(&self) -> &str {
        &self.code_digest
    }

    /// The release tag of the verified code or runtime artifact.
    pub fn code_tag(&self) -> &str {
        &self.code_tag
    }

    /// The registers that the release fixes on the enclave's platform,
    /// with `None` for a register that the release leaves to the platform.
    pub fn code_measurement(&self) -> &Expected {
        &self.code_measurement
    }

    /// The quote's authenticated registers, proven to match the
    /// expectations.
    pub fn enclave_measurement(&self) -> &Measurement {
        &self.enclave_measurement
    }

    /// The endorsed TLS key fingerprint: the `tls` crypto-material item in
    /// the SPKI SHA-256 format. `None` when the document endorses no such
    /// item, which includes a `tls` item in another format.
    pub fn tls_public_key_fp(&self) -> Option<&str> {
        self.crypto_material_data(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT)
    }

    /// The endorsed HPKE public key: the `hpke` crypto-material item in the
    /// X25519 HPKE format. `None` when the document endorses no such item,
    /// which includes an `hpke` item in another format.
    pub fn hpke_public_key(&self) -> Option<&str> {
        self.crypto_material_data(CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)
    }

    /// The endorsed key items, which are hash-bound into the quote.
    pub fn crypto_material(&self) -> &[CryptoMaterialItem] {
        &self.crypto_material
    }

    /// The endorsed lowercase-hex data for exactly `id` and `format`, or
    /// `None` when the document endorses no such item. The lookup neither
    /// refreshes evidence nor enforces
    /// [`freshness_expires_at`](Self::freshness_expires_at).
    pub fn crypto_material_data(&self, id: &str, format: &str) -> Option<&str> {
        crypto_material_data(&self.crypto_material, id, format)
    }

    /// When the freshness proofs stop vouching for the document.
    ///
    /// A cached verification must not authorize new requests at or after
    /// this time, and verifying the same proofs again does not extend it.
    /// For a code release it is the earlier deadline of the code and
    /// platform witnesses; for a config it is the earliest deadline among
    /// the config, platform and runtime approvals. Embedded components and
    /// a config accepted by the caller's authorizer add no deadline, so
    /// the result is `None` when no endorsement was consulted: renewal is
    /// then the caller's own policy, and `None` is not a promise that the
    /// evidence stays valid.
    pub fn freshness_expires_at(&self) -> Option<SystemTime> {
        self.freshness_expires_at
    }

    /// The config bound to the hardware. `None` for verification against a
    /// code release, which has no config.
    pub fn config(&self) -> Option<&ConfigVerification> {
        self.config.as_ref()
    }

    /// The runtime that a config-based verification accepted. `None` for
    /// verification against a code release.
    pub fn runtime(&self) -> Option<&ArtifactVerification> {
        self.runtime.as_ref()
    }

    /// The platform policy artifact that a config-based verification
    /// accepted. `None` for verification against a code release.
    pub fn platform(&self) -> Option<&ArtifactVerification> {
        self.platform.as_ref()
    }

    /// What the verifier records about the verification itself.
    pub fn metadata(&self) -> &VerificationMetadata {
        &self.metadata
    }

    /// The facts as compact JSON, for logging or persisting.
    ///
    /// Registers are lowercase hex and times are RFC 3339 in UTC. A fact
    /// that was not established is left out: an open register, an absent
    /// name or time, and the `config`, `runtime` and `platform` records of
    /// a code-release verification. The members, in order:
    ///
    /// - `code_digest`, `code_tag`, `config_repo`: strings;
    /// - `code_measurement`, `enclave_measurement`: `platform` (`sev-snp`
    ///   or `tdx`) and the registers `launch`, or `mrtd` and `rtmr0` to
    ///   `rtmr3`;
    /// - `crypto_material`: an array of `id`, `format`, `data`;
    /// - `config`: `source`, `name`, `digest`, `reference`,
    ///   `signing_key_hint`, `approval_time`, `registry_id`,
    ///   `signature_time`;
    /// - `runtime`, `platform`: `source`, `repo`, `tag`, `digest`, `name`,
    ///   `commit`, `approval_time`;
    /// - `freshness_expires_at`;
    /// - `metadata`: `verifier` with `name` and `version`, and
    ///   `verified_at`.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.record().write(&mut out);
        out
    }

    /// The serialised form of the verification.
    fn record(&self) -> Json {
        let mut members = vec![
            ("code_digest", Json::text(&self.code_digest)),
            ("code_tag", Json::text(&self.code_tag)),
            ("config_repo", Json::text(&self.config_repo)),
            ("code_measurement", expected_record(&self.code_measurement)),
            (
                "enclave_measurement",
                measurement_record(&self.enclave_measurement),
            ),
            (
                "crypto_material",
                Json::Array(
                    self.crypto_material
                        .iter()
                        .map(|item| {
                            Json::Object(vec![
                                ("id", Json::text(&item.id)),
                                ("format", Json::text(&item.format)),
                                ("data", Json::text(&item.data)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ];
        if let Some(config) = &self.config {
            members.push(("config", config_record(config)));
        }
        if let Some(runtime) = &self.runtime {
            members.push(("runtime", artifact_record(runtime)));
        }
        if let Some(platform) = &self.platform {
            members.push(("platform", artifact_record(platform)));
        }
        if let Some(expires_at) = self.freshness_expires_at {
            members.push(("freshness_expires_at", time_record(expires_at)));
        }
        members.push((
            "metadata",
            Json::Object(vec![
                (
                    "verifier",
                    Json::Object(vec![
                        ("name", Json::text(&self.metadata.verifier.name)),
                        ("version", Json::text(&self.metadata.verifier.version)),
                    ]),
                ),
                ("verified_at", time_record(self.metadata.verified_at)),
            ]),
        ));
        Json::Object(members)
    }
}

/// Looks up exactly `id` and `format` among endorsed key items, and returns
/// the item's lowercase-hex data; `None` when no item matches.
///
/// It is a free function so that a caller that holds its own record of a
/// verification uses the same lookup.
pub fn crypto_material_data<'a>(
    items: &'a [CryptoMaterialItem],
    id: &str,
    format: &str,
) -> Option<&'a str> {
    items
        .iter()
        .find(|item| item.id == id && item.format == format)
        .map(|item| item.data.as_str())
}

/// A JSON value of the serialised record: strings, arrays and objects with
/// their members in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Json {
    Null,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    fn text(value: &str) -> Self {
        Json::String(value.to_owned())
    }

    /// Appends the compact JSON text of the value.
    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::String(value) => write_string(value, out),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(members) => {
                out.push('{');
                for (index, (name, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(name, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Appends `value` as a JSON string: the quotation mark, the reverse
/// solidus and the control characters are escaped, everything else is
/// written as it is.
pub(crate) fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < ' ' => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Appends `name` with the register as hex when the register is set.
fn push_register(
    members: &mut Vec<(&'static str, Json)>,
    name: &'static str,
    register: Option<&Register>,
) {
    if let Some(register) = register {
        members.push((name, Json::String(register.to_string())));
    }
}

/// Appends `name` with the text when there is one.
fn push_text(members: &mut Vec<(&'static str, Json)>, name: &'static str, value: Option<&str>) {
    if let Some(value) = value {
        members.push((name, Json::text(value)));
    }
}

/// Appends `name` with the time when there is one.
fn push_time(
    members: &mut Vec<(&'static str, Json)>,
    name: &'static str,
    value: Option<SystemTime>,
) {
    if let Some(value) = value {
        members.push((name, time_record(value)));
    }
}

/// A time as RFC 3339 in UTC. A time outside the years 0000 to 9999 has no
/// such form and is written as `null`; a verification holds none.
fn time_record(time: SystemTime) -> Json {
    Instant::from_system_time(time).map_or(Json::Null, |instant| Json::String(instant.to_rfc3339()))
}

/// The registers of an expectation, with the open ones left out.
pub(crate) fn expected_members(expected: &Expected) -> Vec<(&'static str, Option<&Register>)> {
    match expected {
        Expected::SevSnp { launch } => vec![("launch", launch.as_ref())],
        Expected::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => vec![
            ("mrtd", mrtd.as_ref()),
            ("rtmr0", rtmr0.as_ref()),
            ("rtmr1", rtmr1.as_ref()),
            ("rtmr2", rtmr2.as_ref()),
            ("rtmr3", rtmr3.as_ref()),
        ],
    }
}

fn expected_record(expected: &Expected) -> Json {
    let platform = match expected {
        Expected::SevSnp { .. } => PLATFORM_SEV_SNP,
        Expected::Tdx { .. } => PLATFORM_TDX,
    };
    let mut members = vec![("platform", Json::text(platform))];
    for (name, register) in expected_members(expected) {
        push_register(&mut members, name, register);
    }
    Json::Object(members)
}

fn measurement_record(measurement: &Measurement) -> Json {
    expected_record(&measurement.expected())
}

fn config_record(config: &ConfigVerification) -> Json {
    let mut members = vec![("source", Json::text(config.source.as_str()))];
    push_text(&mut members, "name", config.name.as_deref());
    members.push(("digest", Json::text(&config.digest)));
    push_text(&mut members, "reference", config.reference.as_deref());
    push_text(
        &mut members,
        "signing_key_hint",
        config.signing_key_hint.as_deref(),
    );
    push_time(&mut members, "approval_time", config.approval_time);
    push_text(&mut members, "registry_id", config.registry_id.as_deref());
    push_time(&mut members, "signature_time", config.signature_time);
    Json::Object(members)
}

fn artifact_record(artifact: &ArtifactVerification) -> Json {
    let mut members = vec![("source", Json::text(artifact.source.as_str()))];
    push_text(&mut members, "repo", artifact.repo.as_deref());
    push_text(&mut members, "tag", artifact.tag.as_deref());
    members.push(("digest", Json::text(&artifact.digest)));
    push_text(&mut members, "name", artifact.name.as_deref());
    push_text(&mut members, "commit", artifact.commit.as_deref());
    push_time(&mut members, "approval_time", artifact.approval_time);
    Json::Object(members)
}

/// `serde::Serialize` for the public record types, in the shape of
/// [`Verification::to_json`].
#[cfg(feature = "serde")]
mod serialize {
    use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

    use super::{Json, Verification, expected_record, measurement_record};
    use crate::measurement::{Expected, Measurement, Register};

    impl Serialize for Json {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                Json::Null => serializer.serialize_none(),
                Json::String(value) => serializer.serialize_str(value),
                Json::Array(items) => {
                    let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                    for item in items {
                        sequence.serialize_element(item)?;
                    }
                    sequence.end()
                }
                Json::Object(members) => {
                    let mut map = serializer.serialize_map(Some(members.len()))?;
                    for (name, value) in members {
                        map.serialize_entry(name, value)?;
                    }
                    map.end()
                }
            }
        }
    }

    /// The fields of [`Verification::to_json`], in the same order.
    impl Serialize for Verification {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.record().serialize(serializer)
        }
    }

    /// Lowercase hex.
    impl Serialize for Register {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self)
        }
    }

    /// `platform` and every register as lowercase hex.
    impl Serialize for Measurement {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            measurement_record(self).serialize(serializer)
        }
    }

    /// `platform` and the registers that are set, as lowercase hex.
    impl Serialize for Expected {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            expected_record(self).serialize(serializer)
        }
    }
}
