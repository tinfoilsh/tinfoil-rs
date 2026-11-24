//! The conformance adapter for the shared v3 vector suite.
//!
//! The suite invokes the `tinfoil-conformance` binary once per fixture as
//! `tinfoil-conformance <stage>`, with the fixture's input as JSON on stdin.
//! The adapter answers with JSON on stdout and an exit code; the exit code is
//! the verdict and the JSON carries the verified facts or the rejection code.
//!
//! Full verification runs through the verifier's public entry point. The
//! fixtures' synthetic trust anchors, and the internal modules that the
//! single-layer stages isolate, are reachable only in a verifier built with
//! `--cfg tinfoil_conformance`. Built without that flag, the adapter
//! implements no stage, says so in its capabilities, and reports
//! [`EXIT_UNSUPPORTED`] for every stage once its input has parsed, so that
//! the suite skips its fixtures instead of failing them.
//!
//! The `live-verify` command ([`live`]) verifies a running enclave through
//! the client instead. It uses no seam and is part of every build.

// Clippy has no test exemption for this lint; see the workspace lints.
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

use serde::{Deserialize, Serialize};
use tinfoil_verifier::Pin;

/// The document was accepted; [`Output::outputs`] carries the verified facts.
pub const EXIT_ACCEPTED: i32 = 0;
/// The adapter itself failed; no verdict.
pub const EXIT_INTERNAL: i32 = 1;
/// The document was rejected; [`Output::rejection`] carries the layer code.
pub const EXIT_REJECTED: i32 = 10;
/// The stage or command is not supported; no verdict.
pub const EXIT_UNSUPPORTED: i32 = 20;
/// The adapter input did not parse.
pub const EXIT_MALFORMED: i32 = 30;

/// The version of the adapter wire contract, carried by every input.
pub const SCHEMA_VERSION: &str = "1";

/// The name this adapter reports in its capabilities.
pub const SDK_NAME: &str = "tinfoil-rs";

/// Full verification: envelope, provenance with freshness, quote, policy.
pub const STAGE_VERIFY: &str = "verify-attestation-v3";
/// Strict parse, nonce equality, endorsed-section hashes, report data.
pub const STAGE_CHECK_ENVELOPE: &str = "v3-check-envelope";
/// The code bundle: identity, digest and predicate.
pub const STAGE_AUTHENTICATE_PROVENANCE: &str = "v3-authenticate-provenance";
/// The platform bundle and the endorsements artifact that it carries.
pub const STAGE_ASSEMBLE_POLICY: &str = "v3-assemble-policy";
/// The CPU quote's signature chain to the vendor root.
pub const STAGE_AUTHENTICATE_QUOTE: &str = "v3-authenticate-quote";
/// A key-signed approval bundle under pinned keys.
pub const STAGE_AUTHENTICATE_APPROVAL: &str = "v3-authenticate-approval";
/// An RFC 3161 timestamp response against the trusted timestamp authorities.
pub const STAGE_VERIFY_TIMESTAMP: &str = "v3-verify-timestamp";
/// The runtime pin that the config of a document states.
pub const STAGE_READ_CONFIG_RUNTIME: &str = "v3-read-config-runtime";

/// Every stage name of the wire contract.
pub const STAGES: [&str; 8] = [
    STAGE_VERIFY,
    STAGE_CHECK_ENVELOPE,
    STAGE_AUTHENTICATE_PROVENANCE,
    STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_QUOTE,
    STAGE_AUTHENTICATE_APPROVAL,
    STAGE_VERIFY_TIMESTAMP,
    STAGE_READ_CONFIG_RUNTIME,
];

/// The stages that this build of the adapter implements, in the order of
/// [`STAGES`]: all of them, or none in a build without the verifier's
/// conformance seams.
pub fn stages_supported() -> Vec<&'static str> {
    if cfg!(tinfoil_conformance) {
        STAGES.to_vec()
    } else {
        Vec::new()
    }
}

/// The rejection code for an input that did not parse.
pub const CODE_MALFORMED_INPUT: &str = "MALFORMED_INPUT";
/// The rejection code of the envelope layer.
pub const CODE_ENVELOPE_REJECTED: &str = "ENVELOPE_REJECTED";
/// The rejection code of the provenance layer.
pub const CODE_PROVENANCE_REJECTED: &str = "PROVENANCE_REJECTED";
/// The rejection code of the quote layer.
pub const CODE_QUOTE_REJECTED: &str = "QUOTE_REJECTED";
/// The rejection code of the policy layer.
pub const CODE_POLICY_REJECTED: &str = "POLICY_REJECTED";

/// The stdin JSON of one adapter run.
///
/// Members that a stage does not read are left empty. An unknown member, a
/// `null` or a member of the wrong type makes the whole input malformed. An
/// empty trust-root member selects the embedded production root.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Input {
    /// Must equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// The attestation document, base64 (document stages).
    pub document_b64: String,
    /// The verifier's nonce, lowercase hex. Never the document's echoed nonce.
    pub nonce_hex: String,
    /// The pinned GitHub repository.
    pub repo: String,
    /// The pinned config registry project.
    #[serde(deserialize_with = "present")]
    pub project: Option<String>,

    /// The Sigstore bundle JSON, base64 (approval stage).
    pub bundle_json_b64: String,
    /// The pinned approval keys, one PEM public key each (approval stage).
    pub signing_keys_pem: Vec<String>,
    /// SHA-256 of the approved artifact, lowercase hex (approval stage).
    pub artifact_digest_hex: String,
    /// The DER timestamp response, base64 (timestamp stage).
    pub timestamp_response_b64: String,
    /// The bytes that the message imprint covers, base64 (timestamp stage).
    pub timestamp_input_b64: String,

    /// The AMD root certificate, PEM. Supplied together with `ask_pem`.
    pub amd_root_ca_pem: String,
    /// The AMD intermediate certificate, PEM.
    pub ask_pem: String,
    /// The Intel SGX root certificate, PEM.
    pub intel_sgx_root_pem: String,
    /// The Sigstore trusted-root JSON, base64.
    pub sigstore_trusted_root_json_b64: String,

    /// The appraisal time in seconds since the epoch, before it when
    /// negative; zero means now.
    pub verification_time_unix: i64,
}

/// Decodes a member that is present as a string, so that only an absent
/// member is `None`.
fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// The pin of an input. An absent or empty name leaves its part unset.
fn pin(repo: &str, project: Option<&str>) -> Pin {
    let part = |name: &str| {
        Some(name)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    };
    Pin {
        repo: part(repo),
        project: part(project.unwrap_or_default()),
    }
}

impl Input {
    /// The pin that the input names.
    pub fn pin(&self) -> Pin {
        pin(&self.repo, self.project.as_deref())
    }
}

/// The stdout JSON of one adapter run.
///
/// A run without a verdict ([`EXIT_UNSUPPORTED`], [`EXIT_INTERNAL`]) carries
/// neither `outputs` nor `rejection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Output {
    /// The stage that ran.
    pub stage: String,
    /// Whether the stage accepted its input.
    pub accepted: bool,
    /// The verified facts of an accepted run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<AcceptOutputs>,
    /// The reason for a rejected run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<Rejection>,
    /// The verifier's report, for the full-verification stage only. A
    /// malformed input has none, and neither does the adapter's own
    /// rejection of an accepted document that endorses no channel keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
}

/// The verified facts, in the shape that the suite compares across SDKs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AcceptOutputs {
    /// The digest of the verified code or runtime artifact.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub code_digest: String,
    /// The registers that the release fixes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_measurement: Option<Measurement>,
    /// The registers of the authenticated quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave_measurement: Option<Measurement>,
    /// The endorsed TLS public-key fingerprint.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_public_key_fp: String,
    /// The endorsed HPKE public key.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hpke_public_key: String,
    /// The channel check that a live run performed.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub channel_binding: String,
    /// The hint of the pinned key that verified an approval.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signing_key_hint: String,
    /// The authenticated timestamp, RFC 3339 in UTC at second precision.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub timestamp: String,
    /// The runtime pin that the document's config states.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<Runtime>,
}

/// A runtime pin on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Runtime {
    /// The repository that publishes the runtime.
    pub repo: String,
    /// The release tag: a full semantic version with a leading `v`.
    pub tag: String,
    /// The SHA-256 of the runtime manifest, lowercase hex.
    pub digest: String,
}

/// A measurement on the wire: its type and its registers as lowercase hex,
/// with an empty string for a register that is left unconstrained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Measurement {
    /// The measurement type identifier.
    #[serde(rename = "type")]
    pub kind: String,
    /// The registers in platform order.
    pub registers: Vec<String>,
}

/// A verification report on the wire, for the full-verification stage: the
/// outcome of each step and, for a rejection, the facts that the steps
/// before it established. Step messages are each SDK's own error text, so
/// the wire carries only the layer and the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The steps, one for each layer in layer order.
    pub steps: Vec<ReportStep>,
    /// What a rejected verification established.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_facts: Option<ReportPartialFacts>,
}

/// One step: a layer (`envelope`, `provenance`, `quote` or `policy`) and a
/// status (`passed`, `failed`, `skipped` or `not_run`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReportStep {
    /// The layer that the step covers.
    pub layer: String,
    /// The step's outcome.
    pub status: String,
}

/// What a rejected verification established. `expected` is absent unless
/// the provenance step passed or was skipped, and `measured` unless the
/// envelope step passed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReportPartialFacts {
    /// The accepted reference values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<ReportExpectedFacts>,
    /// What the document and its hardware claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured: Option<ReportMeasuredFacts>,
}

/// The accepted reference values. The code measurement is for the platform
/// that the document's evidence names, and the full expected measurement is
/// present only once the policy step resolved it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReportExpectedFacts {
    /// The digest of the code or runtime artifact.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub code_digest: String,
    /// The registers that the release fixes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_measurement: Option<Measurement>,
    /// Every register that the quote must attest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<Measurement>,
}

/// What the document and its hardware claim. The CPU measurement is present
/// only once the quote step passed. The key fingerprints are unverified in
/// a rejection; the HPKE one is the lowercase-hex SHA-256 of the key's
/// bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReportMeasuredFacts {
    /// The registers of the authenticated quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_measurement: Option<Measurement>,
    /// The TLS key fingerprint that the document endorses.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_public_key_fp: String,
    /// The fingerprint of the HPKE key that the document endorses.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hpke_public_key_fp: String,
}

impl Report {
    /// The layer of the step that failed, or `None` when none did.
    pub fn failed_step(&self) -> Option<&str> {
        self.steps
            .iter()
            .find(|step| step.status == STATUS_FAILED)
            .map(|step| step.layer.as_str())
    }
}

const STATUS_PASSED: &str = "passed";
const STATUS_FAILED: &str = "failed";
const STATUS_SKIPPED: &str = "skipped";
const STATUS_NOT_RUN: &str = "not_run";

/// The layers in the order that a report lists their steps, each with the
/// rejection code that names it.
const REPORT_LAYERS: [(&str, &str); 4] = [
    ("envelope", CODE_ENVELOPE_REJECTED),
    ("provenance", CODE_PROVENANCE_REJECTED),
    ("quote", CODE_QUOTE_REJECTED),
    ("policy", CODE_POLICY_REJECTED),
];

/// Checks that an output's report agrees with its verdict and keeps the
/// rules of a report:
///
/// - only the full-verification stage carries one, and it does unless the
///   input was malformed or the adapter itself rejected an accepted
///   document for its channel keys (an envelope rejection);
/// - the four layers, in order, with known statuses;
/// - on an accept, every step passed or was skipped, and there are no
///   partial facts;
/// - on a rejection, the failed step is the layer that the rejection code
///   names, no step after it ran, and each partial fact is present only
///   once the step that establishes it passed or was skipped. A step before
///   the failed one may be `not_run`, since checks do not always run in
///   layer order.
pub fn check_report(output: &Output) -> Result<(), String> {
    if output.accepted && output.rejection.is_some() {
        return Err("an accepted verdict carries a rejection".to_owned());
    }
    let report = match (&output.report, output.stage.as_str()) {
        (Some(_), stage) if stage != STAGE_VERIFY => {
            return Err(format!("stage {stage} carries a report"));
        }
        (Some(report), _) => report,
        (None, STAGE_VERIFY) => {
            let code = output.rejection.as_ref().map(|r| r.code.as_str());
            return match code {
                Some(CODE_ENVELOPE_REJECTED | CODE_MALFORMED_INPUT) => Ok(()),
                // A run without a verdict says nothing.
                None if !output.accepted => Ok(()),
                _ => Err(format!("verdict {code:?} has no report")),
            };
        }
        (None, _) => return Ok(()),
    };
    if report.steps.len() != REPORT_LAYERS.len() {
        return Err(format!(
            "the report has {} steps, want {}",
            report.steps.len(),
            REPORT_LAYERS.len()
        ));
    }
    let mut failed_at = None;
    for (index, (step, (layer, _))) in report.steps.iter().zip(REPORT_LAYERS).enumerate() {
        if step.layer != layer {
            return Err(format!("step {index} is {:?}, want {layer:?}", step.layer));
        }
        let status = step.status.as_str();
        if failed_at.is_some() {
            if status != STATUS_NOT_RUN {
                return Err(format!(
                    "step {layer} after the failure is {status:?}, want not_run"
                ));
            }
        } else if status == STATUS_FAILED {
            failed_at = Some(index);
        } else if ![STATUS_PASSED, STATUS_SKIPPED, STATUS_NOT_RUN].contains(&status) {
            return Err(format!("step {layer} has the unknown status {status:?}"));
        }
    }
    let ran = |layer: &str| {
        report.steps.iter().any(|step| {
            step.layer == layer && [STATUS_PASSED, STATUS_SKIPPED].contains(&step.status.as_str())
        })
    };
    if output.accepted {
        if let Some(step) = report.steps.iter().find(|step| !ran(&step.layer)) {
            return Err(format!(
                "an accepted report has step {} {}",
                step.layer, step.status
            ));
        }
        if report.partial_facts.is_some() {
            return Err("an accepted report has partial facts".to_owned());
        }
        return Ok(());
    }
    let (Some(rejection), Some(failed_at)) = (&output.rejection, failed_at) else {
        return Err("a rejection's report has no failed step".to_owned());
    };
    let (failed_layer, failed_code) = REPORT_LAYERS.get(failed_at).copied().unwrap_or_default();
    if rejection.code != failed_code {
        return Err(format!(
            "the failed step {failed_layer} does not match the rejection code {}",
            rejection.code
        ));
    }
    let Some(partial) = &report.partial_facts else {
        return Err("a rejection's report has no partial facts".to_owned());
    };
    if partial.measured.is_some() != ran("envelope") {
        return Err(format!(
            "measured facts present={}, but the envelope step passed={}",
            partial.measured.is_some(),
            ran("envelope")
        ));
    }
    if partial.expected.is_some() != ran("provenance") {
        return Err(format!(
            "expected facts present={}, but the provenance step passed={}",
            partial.expected.is_some(),
            ran("provenance")
        ));
    }
    if let Some(measured) = &partial.measured
        && measured.cpu_measurement.is_some() != ran("quote")
    {
        return Err(format!(
            "the CPU measurement is present={}, but the quote step passed={}",
            measured.cpu_measurement.is_some(),
            ran("quote")
        ));
    }
    if let Some(expected) = &partial.expected
        && expected.measurement.is_some()
        && failed_layer != "policy"
    {
        return Err(
            "the full expected measurement is present before the policy step ran".to_owned(),
        );
    }
    Ok(())
}

/// The layer-tagged reason for a rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rejection {
    /// One of the closed set of rejection codes.
    pub code: String,
}

/// Runs one stage over the raw stdin bytes and returns the output with the
/// adapter's exit code.
///
/// The input is parsed before the stage is looked at, so malformed input is
/// reported as such for every stage name.
pub fn run(stage: &str, stdin: &[u8]) -> (Output, i32) {
    if !is_object(stdin) {
        return malformed(stage);
    }
    let Ok(input) = serde_json::from_slice::<Input>(stdin) else {
        return malformed(stage);
    };
    if input.schema_version != SCHEMA_VERSION {
        return malformed(stage);
    }
    // The AMD root and its intermediate replace the embedded chain together.
    if input.amd_root_ca_pem.is_empty() != input.ask_pem.is_empty() {
        return malformed(stage);
    }
    if decode_base64(&input.sigstore_trusted_root_json_b64).is_none() {
        return malformed(stage);
    }
    #[cfg(tinfoil_conformance)]
    {
        stages::run(stage, &input)
    }
    #[cfg(not(tinfoil_conformance))]
    {
        unsupported(stage)
    }
}

/// Whether the input starts as a JSON object. A struct also deserialises
/// from an array, member by position, so an input is required to be an
/// object before it is decoded.
fn is_object(stdin: &[u8]) -> bool {
    stdin
        .iter()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        .is_some_and(|byte| *byte == b'{')
}

/// The adapter's self-description, which the suite reads to decide which
/// fixtures apply.
pub fn capabilities() -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "sdk": SDK_NAME,
        "v3": {
            "supported": true,
            "stages_supported": stages_supported(),
            "synthetic_roots": synthetic_roots(),
            "freshness_enforced": cfg!(tinfoil_conformance),
            "live_verify": true,
            "channel_binding": live::CHANNEL_BINDING,
            "verification_report": cfg!(tinfoil_conformance),
        },
    })
}

/// Which trust anchors a fixture may replace: all of them, in a build
/// with the verifier's conformance seams.
fn synthetic_roots() -> serde_json::Value {
    let supported = cfg!(tinfoil_conformance);
    serde_json::json!({ "amd": supported, "intel": supported, "sigstore": supported })
}

/// The output and exit code for a stage or command that is not supported.
pub fn unsupported(stage: &str) -> (Output, i32) {
    let output = Output {
        stage: stage.to_owned(),
        accepted: false,
        outputs: None,
        rejection: None,
        report: None,
    };
    (output, EXIT_UNSUPPORTED)
}

/// Standard base64 with padding, as input fields carry it. Unlike the
/// verifier's own decoding it is lenient about unused trailing bits.
const INPUT_BASE64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireCanonical),
);

/// Decodes a base64 input field, ignoring line breaks.
fn decode_base64(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let joined: String = value
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .collect();
    INPUT_BASE64.decode(joined).ok()
}

/// Decodes a hex input field of either case.
#[cfg_attr(not(tinfoil_conformance), allow(dead_code))]
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|pair| pair.bytes().all(|digit| digit.is_ascii_hexdigit()))
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

fn malformed(stage: &str) -> (Output, i32) {
    let output = Output {
        stage: stage.to_owned(),
        accepted: false,
        outputs: None,
        rejection: Some(Rejection {
            code: CODE_MALFORMED_INPUT.to_owned(),
        }),
        report: None,
    };
    (output, EXIT_MALFORMED)
}

mod facts;
pub mod live;
#[cfg(tinfoil_conformance)]
mod stages;

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{"schema_version":"1"}"#;

    fn exit_code(stage: &str, input: &str) -> i32 {
        run(stage, input.as_bytes()).1
    }

    #[test]
    fn a_build_without_the_stages_reports_every_stage_unsupported() {
        for stage in STAGES {
            let (output, code) = run(stage, MINIMAL.as_bytes());
            if cfg!(tinfoil_conformance) {
                assert_ne!(code, EXIT_UNSUPPORTED, "{stage}");
                continue;
            }
            assert_eq!(code, EXIT_UNSUPPORTED, "{stage}");
            assert_eq!(output.stage, stage);
            assert!(!output.accepted);
            assert_eq!(output.outputs, None);
            assert_eq!(output.rejection, None);
        }
    }

    #[test]
    fn an_unknown_stage_is_unsupported() {
        assert_eq!(exit_code("v3-no-such-stage", MINIMAL), EXIT_UNSUPPORTED);
    }

    #[test]
    fn malformed_input_is_reported_with_its_code() {
        let bad_root = br#"{"schema_version":"1","sigstore_trusted_root_json_b64":"*"}"#;
        assert_eq!(run(STAGE_VERIFY, bad_root).1, EXIT_MALFORMED);
        let (output, code) = run(STAGE_VERIFY, b"{");
        assert_eq!(code, EXIT_MALFORMED);
        assert!(!output.accepted);
        assert_eq!(
            output.rejection,
            Some(Rejection {
                code: CODE_MALFORMED_INPUT.to_owned()
            })
        );
    }

    #[test]
    fn input_that_is_not_one_well_formed_object_is_malformed() {
        let cases = [
            ("empty", ""),
            ("empty array", "[]"),
            ("array with the members by position", r#"["1"]"#),
            ("array after whitespace", " \n[\"1\"]"),
            ("string", r#""1""#),
            ("trailing data", r#"{"schema_version":"1"} {}"#),
            (
                "invalid UTF-8 escape",
                r#"{"schema_version":"1","repo":"\ud800"}"#,
            ),
            ("missing version", "{}"),
            ("wrong version", r#"{"schema_version":"2"}"#),
            ("numeric version", r#"{"schema_version":1}"#),
            ("unknown member", r#"{"schema_version":"1","extra":true}"#),
            (
                "duplicate member",
                r#"{"schema_version":"1","repo":"a","repo":"b"}"#,
            ),
            ("null member", r#"{"schema_version":"1","repo":null}"#),
            ("null project", r#"{"schema_version":"1","project":null}"#),
            (
                "mistyped member",
                r#"{"schema_version":"1","signing_keys_pem":"x"}"#,
            ),
            (
                "fractional time",
                r#"{"schema_version":"1","verification_time_unix":1.5}"#,
            ),
            (
                "time above a signed 64-bit integer",
                r#"{"schema_version":"1","verification_time_unix":9223372036854775808}"#,
            ),
            (
                "time below a signed 64-bit integer",
                r#"{"schema_version":"1","verification_time_unix":-9223372036854775809}"#,
            ),
        ];
        for (name, input) in cases {
            assert_eq!(
                exit_code(STAGE_CHECK_ENVELOPE, input),
                EXIT_MALFORMED,
                "{name}"
            );
        }
    }

    #[test]
    fn an_input_names_each_namespace_only_by_its_own_member() {
        let pin = |input: &str| serde_json::from_str::<Input>(input).unwrap().pin();
        assert_eq!(pin(MINIMAL), Pin::none());
        assert_eq!(
            pin(r#"{"schema_version":"1","repo":"o/r"}"#),
            Pin::repo("o/r")
        );
        assert_eq!(
            pin(r#"{"schema_version":"1","repo":"o/r","project":"o/p"}"#),
            Pin::repo("o/r").with_project("o/p")
        );
        assert_eq!(
            pin(r#"{"schema_version":"1","repo":"o/r","project":""}"#),
            Pin::repo("o/r")
        );
        assert_eq!(
            pin(r#"{"schema_version":"1","project":"o/p"}"#),
            Pin::project("o/p")
        );
    }

    #[test]
    fn the_amd_root_and_its_intermediate_are_supplied_together() {
        let root_only = r#"{"schema_version":"1","amd_root_ca_pem":"x"}"#;
        let intermediate_only = r#"{"schema_version":"1","ask_pem":"x"}"#;
        let both = r#"{"schema_version":"1","amd_root_ca_pem":"x","ask_pem":"y"}"#;
        assert_eq!(
            exit_code(STAGE_AUTHENTICATE_QUOTE, root_only),
            EXIT_MALFORMED
        );
        assert_eq!(
            exit_code(STAGE_AUTHENTICATE_QUOTE, intermediate_only),
            EXIT_MALFORMED
        );
        // Paired, the input is well formed: the stage answers, or is not
        // built.
        assert_ne!(exit_code(STAGE_AUTHENTICATE_QUOTE, both), EXIT_INTERNAL);
    }

    #[test]
    fn the_supported_stages_follow_the_build() {
        let envelope = stages_supported().contains(&STAGE_CHECK_ENVELOPE);
        assert_eq!(envelope, cfg!(tinfoil_conformance));
        let (_, code) = run(STAGE_CHECK_ENVELOPE, MINIMAL.as_bytes());
        // With the stage compiled in, the empty document of the minimal
        // input is rejected; without it, the stage is unsupported.
        let want = if envelope {
            EXIT_REJECTED
        } else {
            EXIT_UNSUPPORTED
        };
        assert_eq!(code, want);
    }

    #[test]
    fn output_omits_absent_members() {
        let (output, _) = run("v3-no-such-stage", MINIMAL.as_bytes());
        let json = serde_json::to_string(&output).unwrap();
        assert_eq!(json, r#"{"stage":"v3-no-such-stage","accepted":false}"#);
    }

    #[test]
    fn capabilities_list_only_implemented_stages() {
        let capabilities = capabilities();
        assert_eq!(capabilities["schema_version"], SCHEMA_VERSION);
        assert_eq!(capabilities["sdk"], SDK_NAME);
        let stages = capabilities["v3"]["stages_supported"].as_array().unwrap();
        assert_eq!(stages.len(), stages_supported().len());
        for stage in stages {
            assert!(STAGES.contains(&stage.as_str().unwrap()));
        }
    }

    fn steps(statuses: [&str; 4]) -> Vec<ReportStep> {
        REPORT_LAYERS
            .iter()
            .zip(statuses)
            .map(|((layer, _), status)| ReportStep {
                layer: (*layer).to_owned(),
                status: status.to_owned(),
            })
            .collect()
    }

    /// A consistent rejection at the provenance step.
    fn provenance_rejection() -> Output {
        Output {
            stage: STAGE_VERIFY.to_owned(),
            accepted: false,
            outputs: None,
            rejection: Some(Rejection {
                code: CODE_PROVENANCE_REJECTED.to_owned(),
            }),
            report: Some(Report {
                steps: steps(["passed", "failed", "not_run", "not_run"]),
                partial_facts: Some(ReportPartialFacts {
                    expected: None,
                    measured: Some(ReportMeasuredFacts {
                        tls_public_key_fp: "a".repeat(64),
                        ..ReportMeasuredFacts::default()
                    }),
                }),
            }),
        }
    }

    fn measurement() -> Measurement {
        Measurement {
            kind: "m".to_owned(),
            registers: Vec::new(),
        }
    }

    #[test]
    fn a_consistent_report_passes_its_check() {
        let rejected = provenance_rejection();
        assert_eq!(check_report(&rejected), Ok(()));
        assert_eq!(
            rejected.report.as_ref().and_then(Report::failed_step),
            Some("provenance")
        );
        let accepted = Output {
            accepted: true,
            rejection: None,
            report: Some(Report {
                steps: steps(["passed", "skipped", "passed", "passed"]),
                partial_facts: None,
            }),
            ..rejected
        };
        assert_eq!(check_report(&accepted), Ok(()));
    }

    #[test]
    fn a_report_that_disagrees_with_its_verdict_or_its_rules_fails_its_check() {
        type Mutation = fn(&mut Output);
        let cases: [(&str, Mutation); 9] = [
            ("wrong layer", |o| {
                o.rejection.as_mut().unwrap().code = CODE_QUOTE_REJECTED.to_owned();
            }),
            ("ran after", |o| {
                o.report.as_mut().unwrap().steps[2].status = "passed".to_owned();
            }),
            ("expected early", |o| {
                let partial = o.report.as_mut().unwrap().partial_facts.as_mut().unwrap();
                partial.expected = Some(ReportExpectedFacts::default());
            }),
            ("no measured", |o| {
                let partial = o.report.as_mut().unwrap().partial_facts.as_mut().unwrap();
                partial.measured = None;
            }),
            ("cpu early", |o| {
                let partial = o.report.as_mut().unwrap().partial_facts.as_mut().unwrap();
                partial.measured.as_mut().unwrap().cpu_measurement = Some(measurement());
            }),
            ("three steps", |o| {
                o.report.as_mut().unwrap().steps.truncate(3);
            }),
            ("no partial facts", |o| {
                o.report.as_mut().unwrap().partial_facts = None;
            }),
            ("accepted", |o| o.accepted = true),
            ("another stage", |o| {
                o.stage = STAGE_CHECK_ENVELOPE.to_owned()
            }),
        ];
        for (name, mutate) in cases {
            let mut output = provenance_rejection();
            mutate(&mut output);
            assert!(check_report(&output).is_err(), "{name}");
        }

        // A full expected measurement belongs to a failed policy step only.
        let mut output = provenance_rejection();
        output.rejection.as_mut().unwrap().code = CODE_QUOTE_REJECTED.to_owned();
        let report = output.report.as_mut().unwrap();
        report.steps = steps(["passed", "passed", "failed", "not_run"]);
        report.partial_facts.as_mut().unwrap().expected = Some(ReportExpectedFacts {
            measurement: Some(measurement()),
            ..ReportExpectedFacts::default()
        });
        assert!(check_report(&output).is_err());
    }

    #[test]
    fn only_a_rejection_of_the_adapter_or_of_the_input_has_no_report() {
        let mut output = provenance_rejection();
        output.report = None;
        assert!(check_report(&output).is_err());
        for code in [CODE_ENVELOPE_REJECTED, CODE_MALFORMED_INPUT] {
            output.rejection = Some(Rejection {
                code: code.to_owned(),
            });
            assert_eq!(check_report(&output), Ok(()), "{code}");
        }
        output.accepted = true;
        output.rejection = None;
        assert!(check_report(&output).is_err());
    }

    #[test]
    fn capabilities_report_the_live_command_in_every_build() {
        let capabilities = capabilities();
        assert_eq!(capabilities["v3"]["live_verify"], true);
        assert_eq!(capabilities["v3"]["channel_binding"], "tls-spki");
    }
}

#[cfg(all(test, tinfoil_conformance))]
mod stage_tests {
    use super::*;

    /// A well-formed document without keys or collateral, bound to
    /// [`NONCE_HEX`].
    const DOCUMENT_B64: &str = concat!(
        "eyJmb3JtYXQiOiJodHRwczovL3RpbmZvaWwuc2gvcHJlZGljYXRlL2F0dGVzdGF0aW9uL3YzIiwiY2hhbGxlbmdl",
        "Ijp7Im5vbmNlIjoiMDAwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGYxMDExMTIxMzE0MTUxNjE3MTgxOTFh",
        "MWIxYzFkMWUxZiIsInJlcG9ydF9kYXRhIjoiMGE1MzI2NmFlNWYxZGVkOWI3ZTlkZTQ3NjJkYWFiYTAzYTE2ZjI4",
        "ZmUyM2VlOTFkOTQ3MWQ2MDk4NWM1MjkxYjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
        "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJyZXBvcnRfZGF0YV9hbGdvcml0aG0iOiJodHRwczovL3RpbmZvaWwu",
        "c2gvcmVwb3J0LWRhdGEvdjEifSwiY3B1X2V2aWRlbmNlIjp7ImZvcm1hdCI6Imh0dHBzOi8vdGluZm9pbC5zaC9m",
        "b3JtYXQvc2V2LXNucC1yZXBvcnQvdjEiLCJyZXBvcnRfYmFzZTY0IjoiQVE9PSIsImVuZG9yc2VkIjp7ImNyeXB0",
        "b19tYXRlcmlhbF9oYXNoIjoiYzg0MzgyYzZjYTg5ODljOTE5YWFkYWQ2OTc5YTkxN2MyNDNmYzA1ZGNjNTQyNTM1",
        "ZjVmNjE4YzMxYzBjZWYxOSIsImRldmljZV9ldmlkZW5jZV9oYXNoIjoiNWU4NGY2MzJlMDEyOTNiZmY0NTk2Y2Y3",
        "MmM0NWRlMGY5ZTEwMzdlNWNkYTMyMzJiODUwYzQ3OGQxYTZiNTkyYiJ9fSwiY3J5cHRvX21hdGVyaWFsIjoiZXlK",
        "bWIzSnRZWFFpT2lKb2RIUndjem92TDNScGJtWnZhV3d1YzJndlkzSjVjSFJ2TFcxaGRHVnlhV0ZzTDNZeElpd2lh",
        "WFJsYlhNaU9sdGRmUT09IiwiZGV2aWNlX2V2aWRlbmNlIjoiZXlKbWIzSnRZWFFpT2lKb2RIUndjem92TDNScGJt",
        "WnZhV3d1YzJndlpHVjJhV05sTFdWMmFXUmxibU5sTDNZeElpd2lhWFJsYlhNaU9sdGRmUT09In0=",
    );
    const NONCE_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn check(document_b64: &str, nonce_hex: &str) -> (Output, i32) {
        let input = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "document_b64": document_b64,
            "nonce_hex": nonce_hex,
        });
        run(STAGE_CHECK_ENVELOPE, input.to_string().as_bytes())
    }

    #[test]
    fn a_well_formed_document_is_accepted() {
        let (output, code) = check(DOCUMENT_B64, NONCE_HEX);
        assert_eq!(code, EXIT_ACCEPTED);
        assert_eq!(
            serde_json::to_string(&output).unwrap(),
            r#"{"stage":"v3-check-envelope","accepted":true}"#
        );
        // Input fields are read leniently: either case of hex, and line
        // breaks in base64.
        assert_eq!(
            check(DOCUMENT_B64, &NONCE_HEX.to_uppercase()).1,
            EXIT_ACCEPTED
        );
        let wrapped = format!("{}\r\n{}", &DOCUMENT_B64[..76], &DOCUMENT_B64[76..]);
        assert_eq!(check(&wrapped, NONCE_HEX).1, EXIT_ACCEPTED);
    }

    #[test]
    fn a_rejection_carries_the_envelope_code() {
        let other_nonce = "ff".repeat(32);
        let truncated =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"{\"format\":");
        let cases = [
            ("another nonce", DOCUMENT_B64, other_nonce.as_str()),
            ("a short nonce", DOCUMENT_B64, &NONCE_HEX[..62]),
            ("an empty nonce", DOCUMENT_B64, ""),
            ("an empty document", "", NONCE_HEX),
            ("a truncated document", truncated.as_str(), NONCE_HEX),
        ];
        for (name, document_b64, nonce_hex) in cases {
            let (output, code) = check(document_b64, nonce_hex);
            assert_eq!(code, EXIT_REJECTED, "{name}");
            assert!(!output.accepted, "{name}");
            assert_eq!(
                output.rejection,
                Some(Rejection {
                    code: CODE_ENVELOPE_REJECTED.to_owned()
                }),
                "{name}"
            );
        }
    }

    #[test]
    fn undecodable_fields_are_malformed_input() {
        let cases = [
            ("base64 with another alphabet", "-_-_", NONCE_HEX),
            ("base64 without padding", "e30", NONCE_HEX),
            ("base64 with a stray character", "e30=*", NONCE_HEX),
            ("hex with an odd length", DOCUMENT_B64, "abc"),
            ("hex with another character", DOCUMENT_B64, "zz"),
            ("hex with a prefix", DOCUMENT_B64, "0x00"),
        ];
        for (name, document_b64, nonce_hex) in cases {
            let (output, code) = check(document_b64, nonce_hex);
            assert_eq!(code, EXIT_MALFORMED, "{name}");
            assert_eq!(
                output.rejection,
                Some(Rejection {
                    code: CODE_MALFORMED_INPUT.to_owned()
                }),
                "{name}"
            );
        }
    }

    #[test]
    fn input_fields_decode_leniently() {
        assert_eq!(decode_base64("YWJj"), Some(b"abc".to_vec()));
        assert_eq!(decode_base64("YW\nJj\r\n"), Some(b"abc".to_vec()));
        assert_eq!(decode_base64("YR=="), Some(b"a".to_vec()));
        assert_eq!(decode_base64(""), Some(Vec::new()));
        assert_eq!(decode_base64("YQ"), None);
        assert_eq!(decode_base64("YQ==YQ=="), None);
        assert_eq!(decode_base64("Y Q=="), None);
        assert_eq!(decode_hex("00fFAb"), Some(vec![0x00, 0xff, 0xab]));
        assert_eq!(decode_hex(""), Some(Vec::new()));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("+1"), None);
        assert_eq!(decode_hex("\u{e9}"), None);
    }

    const RUNTIME_DIGEST: &str = "abababababababababababababababababababababababababababababababab";

    /// [`DOCUMENT_B64`] with the given entries as its v3 collateral.
    fn document_with(entries: serde_json::Value) -> String {
        use base64::Engine as _;
        use tinfoil_verifier::conformance::document::collateral::FORMAT_V3;

        let mut document: serde_json::Map<String, serde_json::Value> = decode_base64(DOCUMENT_B64)
            .and_then(|document| serde_json::from_slice(&document).ok())
            .unwrap_or_default();
        document.insert("collateral_format".to_owned(), FORMAT_V3.into());
        document.insert("collateral".to_owned(), entries);
        let document = serde_json::Value::Object(document).to_string();
        base64::engine::general_purpose::STANDARD.encode(document)
    }

    /// A config entry of the given format and data.
    fn config_entry(format: &str, data: serde_json::Value) -> serde_json::Value {
        use tinfoil_verifier::conformance::document::collateral::{
            CONFIG_ID, ROLE_REFERENCE_VALUES,
        };

        serde_json::json!({
            "id": CONFIG_ID,
            "role": ROLE_REFERENCE_VALUES,
            "format": format,
            "data": data,
        })
    }

    /// An entry that carries the bytes of a config without an endorsement.
    fn plain_config(config: &str) -> serde_json::Value {
        use base64::Engine as _;
        use tinfoil_verifier::conformance::document::collateral::CONFIG_V1_FORMAT;

        let encoded = base64::engine::general_purpose::STANDARD.encode(config);
        config_entry(
            CONFIG_V1_FORMAT,
            serde_json::json!({ "config_base64": encoded }),
        )
    }

    fn read_runtime(document_b64: &str, nonce_hex: &str) -> (Output, i32) {
        let input = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "document_b64": document_b64,
            "nonce_hex": nonce_hex,
        });
        run(STAGE_READ_CONFIG_RUNTIME, input.to_string().as_bytes())
    }

    #[test]
    fn the_runtime_stage_reads_the_pin_that_a_config_states() {
        use tinfoil_verifier::conformance::document::collateral::CONFIG_ENDORSEMENT_V2_FORMAT;

        let json_config = format!("{{\"cvm-version\":\"0.15.5-rc.1@sha256:{RUNTIME_DIGEST}\"}}");
        let yaml_config = format!("cvm-version: 0.15.4@sha256:{RUNTIME_DIGEST}\n");
        let document = document_with(serde_json::json!([plain_config(&json_config)]));
        let (output, code) = read_runtime(&document, "");
        assert_eq!(code, EXIT_ACCEPTED);
        assert_eq!(
            serde_json::to_value(&output).unwrap(),
            serde_json::json!({
                "stage": "v3-read-config-runtime",
                "accepted": true,
                "outputs": {
                    "runtime": {
                        "repo": "tinfoilsh/cvmimage",
                        "tag": "v0.15.5-rc.1",
                        "digest": RUNTIME_DIGEST,
                    },
                },
            })
        );

        // The reference of a signed entry stands for a config that the
        // document does not carry.
        let reference_only = config_entry(
            CONFIG_ENDORSEMENT_V2_FORMAT,
            serde_json::json!({
                "endorsement_ref": format!("sha256:{RUNTIME_DIGEST}"),
                "sigstore_bundle": {},
            }),
        );
        for (name, entries) in [
            ("YAML config", vec![plain_config(&yaml_config)]),
            (
                "YAML for a JSON version",
                vec![plain_config(&yaml_config.replace("0.15.4", "0.15.5-rc.1"))],
            ),
            (
                "JSON before the first JSON version",
                vec![plain_config(&json_config.replace("0.15.5-rc.1", "0.15.4"))],
            ),
            (
                "JSON not in its one form",
                vec![plain_config(&json_config.replace("\":\"", "\": \""))],
            ),
            ("no pin", vec![plain_config("{\"cpus\":2}")]),
            ("no config", Vec::new()),
            ("no config bytes", vec![reference_only]),
        ] {
            let document = document_with(serde_json::Value::Array(entries));
            let (output, code) = read_runtime(&document, "");
            assert_eq!(code, EXIT_REJECTED, "{name}");
            assert_eq!(
                serde_json::to_value(&output).unwrap(),
                serde_json::json!({
                    "stage": "v3-read-config-runtime",
                    "accepted": false,
                    "rejection": { "code": "PROVENANCE_REJECTED" },
                }),
                "{name}"
            );
        }
    }

    #[test]
    fn the_runtime_stage_takes_what_does_not_decode_as_malformed_input() {
        use tinfoil_verifier::conformance::document::collateral::ROLE_ENDORSEMENT;

        let config = format!("{{\"cvm-version\":\"0.15.5-rc.1@sha256:{RUNTIME_DIGEST}\"}}");
        let document = document_with(serde_json::json!([plain_config(&config)]));
        assert_eq!(read_runtime(&document, NONCE_HEX).1, EXIT_ACCEPTED);

        // A config entry under another role is one that no document may
        // carry.
        let mut misfiled = plain_config(&config);
        misfiled["role"] = ROLE_ENDORSEMENT.into();
        let undecodable = document_with(serde_json::json!([misfiled]));
        let cases = [
            ("a document that does not decode", undecodable.as_str(), ""),
            ("an empty document", "", ""),
            ("base64 with a stray character", "e30=*", ""),
            ("hex with an odd length", document.as_str(), "abc"),
        ];
        for (name, document_b64, nonce_hex) in cases {
            let (output, code) = read_runtime(document_b64, nonce_hex);
            assert_eq!(code, EXIT_MALFORMED, "{name}");
            assert_eq!(
                output.rejection,
                Some(Rejection {
                    code: CODE_MALFORMED_INPUT.to_owned()
                }),
                "{name}"
            );
            assert_eq!(output.outputs, None, "{name}");
        }
    }
}
