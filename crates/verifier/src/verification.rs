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
///
/// A record is a plain value. It is evidence of a verification only while
/// it is read from the [`VerifiedFacts`] that hold it: a copy can be
/// changed, and carries no proof of where it came from.
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

/// How a verification was performed. The verifier and the client that
/// called it fill this in from their own state; none of it is attested by
/// the document or checked against it.
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
    /// The enclave that the client contacted for the document, a host with
    /// an optional port: for a router client the router that it chose. It
    /// is what the client connected to, not an attested fact, so it proves
    /// nothing about the enclave. The verifier does not know the host and
    /// leaves it `None`; the clients of the `tinfoil` crate set it on every
    /// report that they hand out, and a caller that calls the verifier
    /// itself can set it with
    /// [`VerificationReport::with_host`](crate::VerificationReport::with_host).
    pub host: Option<String>,
}

/// The facts proven by the verification of an attestation document,
/// including the channel keys that a caller binds its traffic to.
///
/// Only a [`Verifier`](crate::Verifier) creates them, as the
/// [`verified_facts`](crate::VerificationReport::verified_facts) of a
/// report on a document that it accepted, and they cannot be changed
/// afterwards. They are the only part of a report that carries channel
/// keys. What the verifier records about the verification itself is the
/// report's [`metadata`](crate::VerificationReport::metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFacts {
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
}

impl VerifiedFacts {
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

    /// The earliest approval or current CPU collateral deadline.
    ///
    /// Cached verification must not authorize requests at or after this
    /// time. Hardware bounds the result even when every reference is
    /// embedded. Verifying the same evidence again does not extend it.
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

    /// The facts as compact JSON: the `verified_facts` member of the JSON
    /// form that every Tinfoil SDK writes, which
    /// [`VerificationReport::to_json`](crate::VerificationReport::to_json)
    /// describes.
    ///
    /// Registers and digests are lowercase hex and times are RFC 3339 in
    /// UTC. A fact that was not established is left out, and no member is
    /// `null` or `""`. The members:
    ///
    /// - `config_repo`, `code_digest` and `code_tag`: strings, with
    ///   `code_tag` only when the artifact has a tag;
    /// - `code_measurement`: `platform` (`sev-snp` or `tdx`) and the
    ///   registers that the release fixes, `launch`, or some of `mrtd` and
    ///   `rtmr0` to `rtmr3`; left out when the release fixes none;
    /// - `enclave_measurement`: `platform` and every register;
    /// - `config`: `source`, `name`, `digest`, `reference`,
    ///   `signing_key_hint`, `approval_time`, `registry_id` and
    ///   `signature_time`, for a config-based verification only;
    /// - `runtime` and `platform`: `source`, `repo`, `tag`, `digest`,
    ///   `name`, `commit` and `approval_time`, for a config-based
    ///   verification only;
    /// - `crypto_material`: an array of `id`, `format` and `data`, in the
    ///   document's order. It is the only member that holds the TLS and
    ///   HPKE keys;
    /// - `freshness_expires_at`.
    ///
    /// The JSON is for display and transport, and authorizes nothing: no
    /// API of this crate reads it back into verified facts, so a channel is
    /// bound only to the keys of facts that a verification returned.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.record().write(&mut out);
        out
    }

    /// The serialised form of the facts.
    pub(crate) fn record(&self) -> Json {
        let mut members = Vec::new();
        push_text(&mut members, "config_repo", Some(&self.config_repo));
        push_text(&mut members, "code_digest", Some(&self.code_digest));
        push_text(&mut members, "code_tag", Some(&self.code_tag));
        if let Some(code) = code_measurement_record(&self.code_measurement) {
            members.push(("code_measurement", code));
        }
        members.push((
            "enclave_measurement",
            measurement_record(&self.enclave_measurement),
        ));
        if let Some(config) = &self.config {
            members.push(("config", config_record(config)));
        }
        if let Some(runtime) = &self.runtime {
            members.push(("runtime", artifact_record(runtime)));
        }
        if let Some(platform) = &self.platform {
            members.push(("platform", artifact_record(platform)));
        }
        members.push((
            "crypto_material",
            Json::Array(
                self.crypto_material
                    .iter()
                    .map(|item| {
                        let mut members = Vec::new();
                        push_text(&mut members, "id", Some(&item.id));
                        push_text(&mut members, "format", Some(&item.format));
                        push_text(&mut members, "data", Some(&item.data));
                        Json::Object(members)
                    })
                    .collect(),
            ),
        ));
        push_time(
            &mut members,
            "freshness_expires_at",
            self.freshness_expires_at,
        );
        Json::Object(members)
    }
}

impl VerificationMetadata {
    /// The serialised form of the metadata: `verified_at`, when its name
    /// and version are known, `verifier`, and, when it is set, `host`.
    pub(crate) fn record(&self) -> Json {
        let mut members = Vec::new();
        push_time(&mut members, "verified_at", Some(self.verified_at));
        if !self.verifier.name.is_empty() && !self.verifier.version.is_empty() {
            members.push((
                "verifier",
                Json::Object(vec![
                    ("name", Json::text(&self.verifier.name)),
                    ("version", Json::text(&self.verifier.version)),
                ]),
            ));
        }
        push_text(&mut members, "host", self.host.as_deref());
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

/// A JSON value of the serialised record: integers, strings, arrays and
/// objects with their members in order. It has no `null`, because the JSON
/// form leaves out a fact that was not established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Json {
    Integer(u32),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    pub(crate) fn text(value: &str) -> Self {
        Json::String(value.to_owned())
    }

    /// Appends the compact JSON text of the value.
    pub(crate) fn write(&self, out: &mut String) {
        match self {
            Json::Integer(value) => out.push_str(&value.to_string()),
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
/// solidus and the control characters are escaped, with the short escape
/// where JSON has one, and everything else is written as it is.
pub(crate) fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
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

/// Appends `name` with the text when there is one that is not empty: the
/// JSON form never writes a string that is absent as `""`.
pub(crate) fn push_text(
    members: &mut Vec<(&'static str, Json)>,
    name: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        members.push((name, Json::text(value)));
    }
}

/// Appends `name` with the time as RFC 3339 in UTC when there is one. A
/// time outside the years 0000 to 9999 has no such form and is left out; a
/// verification holds none.
fn push_time(
    members: &mut Vec<(&'static str, Json)>,
    name: &'static str,
    value: Option<SystemTime>,
) {
    if let Some(instant) = value.and_then(Instant::from_system_time) {
        members.push((name, Json::String(instant.to_rfc3339())));
    }
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

/// A measurement in the JSON form: its `platform` and the registers that
/// are set, named, in lowercase hex.
pub(crate) fn expected_record(expected: &Expected) -> Json {
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

/// The registers that a release fixes, or `None` when it fixes none, so
/// that a code measurement without a register is left out.
pub(crate) fn code_measurement_record(expected: &Expected) -> Option<Json> {
    expected_members(expected)
        .iter()
        .any(|(_, register)| register.is_some())
        .then(|| expected_record(expected))
}

pub(crate) fn measurement_record(measurement: &Measurement) -> Json {
    expected_record(&measurement.expected())
}

pub(crate) fn config_record(config: &ConfigVerification) -> Json {
    let mut members = vec![("source", Json::text(config.source.as_str()))];
    push_text(&mut members, "name", config.name.as_deref());
    push_text(&mut members, "digest", Some(&config.digest));
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

pub(crate) fn artifact_record(artifact: &ArtifactVerification) -> Json {
    let mut members = vec![("source", Json::text(artifact.source.as_str()))];
    push_text(&mut members, "repo", artifact.repo.as_deref());
    push_text(&mut members, "tag", artifact.tag.as_deref());
    push_text(&mut members, "digest", Some(&artifact.digest));
    push_text(&mut members, "name", artifact.name.as_deref());
    push_text(&mut members, "commit", artifact.commit.as_deref());
    push_time(&mut members, "approval_time", artifact.approval_time);
    Json::Object(members)
}

/// `serde::Serialize` for the report and the types that it holds, in the
/// JSON form that
/// [`VerificationReport::to_json`](crate::VerificationReport::to_json) writes. There is no
/// `Deserialize`: verified facts read from JSON would be forgeable.
#[cfg(feature = "serde")]
mod serialize {
    use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

    use super::{Json, VerificationMetadata, VerifiedFacts, expected_record, measurement_record};
    use crate::measurement::{Expected, Measurement, Register};
    use crate::report::{ExpectedFacts, MeasuredFacts, PartialFacts, Step, VerificationReport};

    impl Serialize for Json {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                Json::Integer(value) => serializer.serialize_u32(*value),
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

    /// Implements `Serialize` as the type's serialised record.
    macro_rules! serialize_record {
        ($($(#[$doc:meta])* $type:ty;)*) => {$(
            $(#[$doc])*
            impl Serialize for $type {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    self.record().serialize(serializer)
                }
            }
        )*};
    }

    serialize_record! {
        /// The JSON form of [`VerificationReport::to_json`].
        VerificationReport;
        /// The `verified_facts` member of the JSON form.
        VerifiedFacts;
        /// The `partial_facts` member of the JSON form.
        PartialFacts;
        /// The `partial_facts.expected` member of the JSON form.
        ExpectedFacts;
        /// The `partial_facts.measured` member of the JSON form.
        MeasuredFacts;
        /// A member of the `steps` of the JSON form.
        Step;
        /// The `metadata` member of the JSON form.
        VerificationMetadata;
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
