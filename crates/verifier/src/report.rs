//! The report of a verification: the steps that the verifier ran, and the
//! facts that they established.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::canonical;
use crate::document::{
    CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, CryptoMaterialItem,
    KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT,
};
use crate::error::Layer;
use crate::measurement::{Expected, Measurement};
use crate::verification::{
    ArtifactVerification, ConfigVerification, Json, VerificationMetadata, VerifiedFacts,
    artifact_record, config_record, crypto_material_data, expected_record, measurement_record,
    push_text,
};

/// The layers in the order that a report lists their steps.
const LAYERS: [Layer; 4] = [
    Layer::Envelope,
    Layer::Provenance,
    Layer::Quote,
    Layer::Policy,
];

/// What one verification of an attestation document did, step by step, and
/// what each step established.
///
/// [`Verifier::verify_v3`](crate::Verifier::verify_v3) returns a report for
/// a document that it accepts, and the
/// [`VerificationError`](crate::VerificationError) of a document that it
/// rejects carries one, so that a caller can show what happened either way.
/// Exactly one of [`verified_facts`](Self::verified_facts) and
/// [`partial_facts`](Self::partial_facts) is set.
///
/// A report authorizes nothing by itself: only the endorsed keys in its
/// verified facts may be bound to a channel. Only the verifier creates a
/// report, and it cannot be changed afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    steps: Vec<Step>,
    verified_facts: Option<VerifiedFacts>,
    partial_facts: Option<PartialFacts>,
    metadata: VerificationMetadata,
}

impl VerificationReport {
    /// One step for each layer, in layer order: `envelope`, `provenance`,
    /// `quote` and `policy`. Every step is always present. A new layer
    /// adds a step, so a caller must tolerate steps of layers that it does
    /// not recognize.
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// The facts that the verification proved, set if and only if no step
    /// failed. They are the only part of a report that carries the keys
    /// that a channel binds to.
    pub fn verified_facts(&self) -> Option<&VerifiedFacts> {
        self.verified_facts.as_ref()
    }

    /// What the steps before the failed one established, set if and only
    /// if a step failed.
    pub fn partial_facts(&self) -> Option<&PartialFacts> {
        self.partial_facts.as_ref()
    }

    /// What the verifier records about the verification itself.
    pub fn metadata(&self) -> &VerificationMetadata {
        &self.metadata
    }

    /// The step that failed, or `None` when none did. At most one step
    /// fails: the step of the layer that rejected the document.
    pub fn failed_step(&self) -> Option<&Step> {
        self.steps
            .iter()
            .find(|step| step.status == StepStatus::Failed)
    }

    /// The report as compact JSON, for logging or persisting.
    ///
    /// Registers and fingerprints are lowercase hex and times are RFC 3339
    /// in UTC. A fact that was not established is left out. The members, in
    /// order:
    ///
    /// - `steps`: an array of `layer`, `status` (`passed`, `failed`,
    ///   `skipped` or `not_run`) and, when it is not empty, `message`;
    /// - `verified_facts`: the facts as
    ///   [`VerifiedFacts::to_json`] writes them, when no step failed;
    /// - `partial_facts`, when a step failed: `expected` with
    ///   `config_repo`, `artifact`, `config`, `platform`,
    ///   `code_measurement` and `measurement`; and `measured` with `cpu`
    ///   (its `measurement`), `tls_public_key_fp` and
    ///   `hpke_public_key_fp`;
    /// - `metadata`: `verifier` with `name` and `version`, and
    ///   `verified_at`.
    ///
    /// The step messages are diagnostic: their text is not stable.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.record().write(&mut out);
        out
    }

    /// The serialised form of the report.
    pub(crate) fn record(&self) -> Json {
        let steps = self
            .steps
            .iter()
            .map(|step| {
                let mut members = vec![
                    ("layer", Json::text(step.layer.as_str())),
                    ("status", Json::text(step.status.as_str())),
                ];
                if !step.message.is_empty() {
                    members.push(("message", Json::text(&step.message)));
                }
                Json::Object(members)
            })
            .collect();
        let mut members = vec![("steps", Json::Array(steps))];
        if let Some(facts) = &self.verified_facts {
            members.push(("verified_facts", facts.record()));
        }
        if let Some(facts) = &self.partial_facts {
            members.push(("partial_facts", facts.record()));
        }
        members.push(("metadata", self.metadata.record()));
        Json::Object(members)
    }

    /// A report of a rejection at `layer`, with no facts, for the tests of
    /// the errors that carry one.
    #[cfg(test)]
    pub(crate) fn rejected_for_test(layer: Layer, message: &str) -> Self {
        ReportBuilder::new().failed(
            layer,
            message.to_owned(),
            VerificationMetadata {
                verifier: crate::verification::SoftwareIdentity {
                    name: "test".to_owned(),
                    version: "0".to_owned(),
                },
                verified_at: std::time::SystemTime::UNIX_EPOCH,
            },
        )
    }
}

/// The outcome of one verification layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Step {
    /// The layer that the step covers.
    pub layer: Layer,
    /// Whether the layer accepted the document.
    pub status: StepStatus,
    /// For a failed step, the message of the error that the layer
    /// rejected the document with; for a skipped step, the reason that it
    /// was skipped; otherwise empty. Messages are diagnostic.
    pub message: String,
}

/// The outcome of a [`Step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepStatus {
    /// Every check of the layer ran and passed.
    Passed,
    /// The layer rejected the document.
    Failed,
    /// The layer does not apply: for provenance, a verifier that embeds
    /// every reference value, so that there is no endorsement to
    /// authenticate. It is not a failure.
    Skipped,
    /// The checks of the layer did not all run, because another layer
    /// rejected the document first.
    NotRun,
}

impl StepStatus {
    /// The status's name: `passed`, `failed`, `skipped` or `not_run`.
    pub fn as_str(&self) -> &'static str {
        match self {
            StepStatus::Passed => "passed",
            StepStatus::Failed => "failed",
            StepStatus::Skipped => "skipped",
            StepStatus::NotRun => "not_run",
        }
    }
}

impl fmt::Display for StepStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a rejected verification established before the step that failed.
///
/// Every fact in them is authenticated, except the key fingerprints, which
/// [`MeasuredFacts`] describes. None of them authorizes anything: a channel
/// is never bound to a value in partial facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PartialFacts {
    /// The reference values that the provenance step accepted; `None`
    /// unless that step passed or was skipped.
    pub expected: Option<ExpectedFacts>,
    /// What the document and its hardware evidence claim; `None` unless the
    /// envelope step passed.
    pub measured: Option<MeasuredFacts>,
}

impl PartialFacts {
    fn record(&self) -> Json {
        let mut members = Vec::new();
        if let Some(expected) = &self.expected {
            members.push(("expected", expected.record()));
        }
        if let Some(measured) = &self.measured {
            members.push(("measured", measured.record()));
        }
        Json::Object(members)
    }
}

/// The reference values that the provenance step accepted: what the
/// enclave should be running.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExpectedFacts {
    /// The repository of the selected code or runtime, without version
    /// pins.
    pub config_repo: String,
    /// The code release, or the runtime for a config-based verification.
    pub artifact: ArtifactVerification,
    /// The config that a config-based verification accepted; `None` for a
    /// code release.
    pub config: Option<ConfigVerification>,
    /// The platform policy artifact that a config-based verification
    /// accepted; `None` for a code release.
    pub platform: Option<ArtifactVerification>,
    /// The registers that the release fixes, in the layout of the platform
    /// that the document's CPU evidence names, with `None` for a register
    /// that the release leaves to the platform. The values are
    /// authenticated; the platform that selects their layout is
    /// authenticated only once the quote step passed. `None` when the
    /// evidence names no platform that the verifier knows.
    pub code_measurement: Option<Expected>,
    /// Every register that the quote must attest: the code measurement,
    /// the verifier's register pins and, for a code release on TDX, the
    /// platform registers (MRTD and RTMR0) that the platform policy
    /// artifact supplies for the quote's machine. It is set once the policy
    /// step resolved every register, even if a later check of that step
    /// failed, and `None` otherwise.
    pub measurement: Option<Measurement>,
}

impl ExpectedFacts {
    fn record(&self) -> Json {
        let mut members = vec![
            ("config_repo", Json::text(&self.config_repo)),
            ("artifact", artifact_record(&self.artifact)),
        ];
        if let Some(config) = &self.config {
            members.push(("config", config_record(config)));
        }
        if let Some(platform) = &self.platform {
            members.push(("platform", artifact_record(platform)));
        }
        if let Some(code) = &self.code_measurement {
            members.push(("code_measurement", expected_record(code)));
        }
        if let Some(measurement) = &self.measurement {
            members.push(("measurement", measurement_record(measurement)));
        }
        Json::Object(members)
    }
}

/// What the document and its hardware evidence claim.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MeasuredFacts {
    /// What the authenticated CPU evidence proves; set only once the quote
    /// step passed, so that what it holds came from the hardware.
    pub cpu: Option<CpuEvidence>,
    /// The SPKI SHA-256 fingerprint of the TLS key that the document
    /// endorses, as [`VerifiedFacts::tls_public_key_fp`] returns it, or
    /// `None` when it endorses none.
    ///
    /// Only the policy step binds the keys to the enclave, so in a rejected
    /// report this fingerprint is always unverified: the document's claim,
    /// which a user interface must present as such.
    pub tls_public_key_fp: Option<String>,
    /// The fingerprint of the HPKE public key that the document endorses
    /// ([`hpke_public_key_fp`]), never the key itself, or `None` when it
    /// endorses none. It is unverified for the same reason as
    /// [`tls_public_key_fp`](Self::tls_public_key_fp).
    pub hpke_public_key_fp: Option<String>,
}

impl MeasuredFacts {
    /// The key fingerprints that `items` endorse, with no CPU evidence yet.
    fn of_keys(items: &[CryptoMaterialItem]) -> Self {
        Self {
            cpu: None,
            tls_public_key_fp: crypto_material_data(
                items,
                CRYPTO_MATERIAL_ID_TLS,
                KEY_SPKI_FP_SHA256_V1_FORMAT,
            )
            .map(str::to_owned),
            hpke_public_key_fp: crypto_material_data(
                items,
                CRYPTO_MATERIAL_ID_HPKE,
                KEY_X25519_HPKE_V1_FORMAT,
            )
            .and_then(hpke_public_key_fp),
        }
    }

    fn record(&self) -> Json {
        let mut members = Vec::new();
        if let Some(cpu) = &self.cpu {
            members.push((
                "cpu",
                Json::Object(vec![("measurement", measurement_record(&cpu.measurement))]),
            ));
        }
        push_text(
            &mut members,
            "tls_public_key_fp",
            self.tls_public_key_fp.as_deref(),
        );
        push_text(
            &mut members,
            "hpke_public_key_fp",
            self.hpke_public_key_fp.as_deref(),
        );
        Json::Object(members)
    }
}

/// What the CPU's authenticated evidence proves.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CpuEvidence {
    /// Every register that the hardware measured, in its platform's native
    /// layout.
    pub measurement: Measurement,
}

/// The fingerprint that [`MeasuredFacts::hpke_public_key_fp`] reports for
/// `key`, an HPKE public key in lowercase hex as a document endorses it:
/// the lowercase-hex SHA-256 of the key's bytes. `None` when `key` is
/// empty or not lowercase hex.
pub fn hpke_public_key_fp(key: &str) -> Option<String> {
    let bytes = canonical::decode_lower_hex("HPKE public key", key, key.len() / 2).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(canonical::encode_lower_hex(&Sha256::digest(&bytes)))
}

/// Records each step of a verification as the verifier runs it, and the
/// facts that each step establishes.
#[derive(Debug)]
pub(crate) struct ReportBuilder {
    steps: Vec<Step>,
    expected: Option<ExpectedFacts>,
    measured: Option<MeasuredFacts>,
}

impl ReportBuilder {
    /// A report in which no step has run yet.
    pub(crate) fn new() -> Self {
        Self {
            steps: LAYERS
                .iter()
                .map(|layer| Step {
                    layer: *layer,
                    status: StepStatus::NotRun,
                    message: String::new(),
                })
                .collect(),
            expected: None,
            measured: None,
        }
    }

    fn set(&mut self, layer: Layer, status: StepStatus, message: String) {
        if let Some(step) = self.steps.iter_mut().find(|step| step.layer == layer) {
            step.status = status;
            step.message = message;
        }
    }

    /// Marks the step of `layer` as passed.
    pub(crate) fn passed(&mut self, layer: Layer) {
        self.set(layer, StepStatus::Passed, String::new());
    }

    /// Marks the step of `layer` as skipped, for `reason`.
    pub(crate) fn skipped(&mut self, layer: Layer, reason: &str) {
        self.set(layer, StepStatus::Skipped, reason.to_owned());
    }

    /// Records the measured facts once the envelope step passed: the key
    /// fingerprints that the parsed document's items endorse.
    pub(crate) fn measured_keys(&mut self, items: &[CryptoMaterialItem]) {
        self.measured = Some(MeasuredFacts::of_keys(items));
    }

    /// Records the expected facts once the provenance step passed.
    pub(crate) fn expected(&mut self, expected: ExpectedFacts) {
        self.expected = Some(expected);
    }

    /// Records the authenticated measurement once the quote step passed.
    pub(crate) fn cpu(&mut self, measurement: Measurement) {
        if let Some(measured) = &mut self.measured {
            measured.cpu = Some(CpuEvidence { measurement });
        }
    }

    /// Records the full expected measurement once the policy step resolved
    /// it.
    pub(crate) fn expected_measurement(&mut self, measurement: Measurement) {
        if let Some(expected) = &mut self.expected {
            expected.measurement = Some(measurement);
        }
    }

    /// The report of a verification that every step accepted.
    pub(crate) fn passed_all(
        self,
        facts: VerifiedFacts,
        metadata: VerificationMetadata,
    ) -> VerificationReport {
        VerificationReport {
            steps: self.steps,
            verified_facts: Some(facts),
            partial_facts: None,
            metadata,
        }
    }

    /// The report of a verification that `layer` rejected with `message`.
    pub(crate) fn failed(
        mut self,
        layer: Layer,
        message: String,
        metadata: VerificationMetadata,
    ) -> VerificationReport {
        self.set(layer, StepStatus::Failed, message);
        VerificationReport {
            steps: self.steps,
            verified_facts: None,
            partial_facts: Some(PartialFacts {
                expected: self.expected,
                measured: self.measured,
            }),
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurement::Register;

    fn metadata() -> VerificationMetadata {
        VerificationMetadata {
            verifier: crate::verification::SoftwareIdentity {
                name: "tinfoil-rs".to_owned(),
                version: "1.0.0".to_owned(),
            },
            verified_at: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    fn statuses(report: &VerificationReport) -> Vec<StepStatus> {
        report.steps().iter().map(|step| step.status).collect()
    }

    #[test]
    fn a_new_report_lists_every_layer_in_order_and_none_has_run() {
        let report = ReportBuilder::new().failed(Layer::Envelope, "bad".to_owned(), metadata());
        let layers: Vec<Layer> = report.steps().iter().map(|step| step.layer).collect();
        assert_eq!(layers, LAYERS);
        assert_eq!(
            statuses(&report),
            [
                StepStatus::Failed,
                StepStatus::NotRun,
                StepStatus::NotRun,
                StepStatus::NotRun
            ]
        );
        assert_eq!(report.failed_step().unwrap().message, "bad");
        assert!(report.verified_facts().is_none());
        let partial = report.partial_facts().unwrap();
        assert_eq!(partial.expected, None);
        assert_eq!(partial.measured, None);
    }

    #[test]
    fn facts_are_kept_only_for_the_steps_that_established_them() {
        let mut steps = ReportBuilder::new();
        // The CPU measurement needs measured facts to go in.
        steps.cpu(Measurement::SevSnp {
            launch: Register::new([1; 48]),
        });
        steps.passed(Layer::Envelope);
        let hpke = "ab".repeat(32);
        steps.measured_keys(&[
            CryptoMaterialItem {
                id: CRYPTO_MATERIAL_ID_TLS.to_owned(),
                format: KEY_SPKI_FP_SHA256_V1_FORMAT.to_owned(),
                data: "cd".repeat(32),
            },
            CryptoMaterialItem {
                id: CRYPTO_MATERIAL_ID_HPKE.to_owned(),
                format: KEY_X25519_HPKE_V1_FORMAT.to_owned(),
                data: hpke.clone(),
            },
        ]);
        let report = steps.failed(Layer::Provenance, "stale".to_owned(), metadata());
        assert_eq!(
            statuses(&report),
            [
                StepStatus::Passed,
                StepStatus::Failed,
                StepStatus::NotRun,
                StepStatus::NotRun
            ]
        );
        let measured = report.partial_facts().unwrap().measured.as_ref().unwrap();
        assert_eq!(measured.cpu, None);
        assert_eq!(measured.tls_public_key_fp, Some("cd".repeat(32)));
        assert_eq!(
            measured.hpke_public_key_fp,
            hpke_public_key_fp(&hpke),
            "a fingerprint, never the key"
        );
        assert_ne!(measured.hpke_public_key_fp.as_deref(), Some(hpke.as_str()));
    }

    #[test]
    fn the_hpke_fingerprint_is_the_sha256_of_the_key_bytes() {
        // SHA-256 of the 32 zero bytes.
        assert_eq!(
            hpke_public_key_fp(&"00".repeat(32)).as_deref(),
            Some("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")
        );
        assert_eq!(hpke_public_key_fp(""), None);
        assert_eq!(hpke_public_key_fp("abc"), None);
        assert_eq!(hpke_public_key_fp("AB"), None);
        assert_eq!(hpke_public_key_fp("zz"), None);
    }

    #[test]
    fn the_json_lists_steps_and_the_established_facts() {
        let mut steps = ReportBuilder::new();
        steps.passed(Layer::Envelope);
        steps.measured_keys(&[]);
        steps.skipped(Layer::Provenance, "embedded");
        let report = steps.failed(Layer::Quote, "bad \"quote\"".to_owned(), metadata());
        assert_eq!(
            report.to_json(),
            concat!(
                r#"{"steps":[{"layer":"envelope","status":"passed"},"#,
                r#"{"layer":"provenance","status":"skipped","message":"embedded"},"#,
                r#"{"layer":"quote","status":"failed","message":"bad \"quote\""},"#,
                r#"{"layer":"policy","status":"not_run"}],"#,
                r#""partial_facts":{"measured":{}},"#,
                r#""metadata":{"verifier":{"name":"tinfoil-rs","version":"1.0.0"},"#,
                r#""verified_at":"1970-01-01T00:00:00Z"}}"#
            )
        );
    }

    #[test]
    fn statuses_have_stable_names() {
        let names: Vec<String> = [
            StepStatus::Passed,
            StepStatus::Failed,
            StepStatus::Skipped,
            StepStatus::NotRun,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(names, ["passed", "failed", "skipped", "not_run"]);
    }
}
