//! The conformance adapter for the shared v3 vector suite.
//!
//! The suite invokes the `tinfoil-conformance` binary once per fixture as
//! `tinfoil-conformance <stage>`, with the fixture's input as JSON on stdin.
//! The adapter answers with JSON on stdout and an exit code; the exit code is
//! the verdict and the JSON carries the verified facts or the rejection code.
//!
//! A stage that is not implemented reports [`EXIT_UNSUPPORTED`] once its
//! input has parsed, so the suite skips its fixtures instead of failing them.
//!
//! The stages reach into the verifier's internal modules, which the verifier
//! exposes only to a build with `--cfg tinfoil_conformance`. Built without
//! that flag, the adapter implements no stage and says so in its
//! capabilities.

// Clippy has no test exemption for this lint; see the workspace lints.
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

use serde::{Deserialize, Serialize};

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

/// Every stage name of the wire contract.
pub const STAGES: [&str; 7] = [
    STAGE_VERIFY,
    STAGE_CHECK_ENVELOPE,
    STAGE_AUTHENTICATE_PROVENANCE,
    STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_QUOTE,
    STAGE_AUTHENTICATE_APPROVAL,
    STAGE_VERIFY_TIMESTAMP,
];

/// The stages that this build of the adapter implements.
#[cfg(tinfoil_conformance)]
pub const STAGES_SUPPORTED: &[&str] = &[STAGE_CHECK_ENVELOPE];

/// The stages that this build of the adapter implements: none, because the
/// verifier's internal modules are not exposed to it.
#[cfg(not(tinfoil_conformance))]
pub const STAGES_SUPPORTED: &[&str] = &[];

/// The rejection code for an input that did not parse.
pub const CODE_MALFORMED_INPUT: &str = "MALFORMED_INPUT";
/// The rejection code of the envelope layer.
pub const CODE_ENVELOPE_REJECTED: &str = "ENVELOPE_REJECTED";

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
    /// The pinned repository.
    pub repo: String,

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

    /// The appraisal time in seconds since the epoch; zero means now.
    pub verification_time_unix: u64,
}

/// The stdout JSON of one adapter run.
///
/// A run without a verdict ([`EXIT_UNSUPPORTED`], [`EXIT_INTERNAL`]) carries
/// neither `outputs` nor `rejection`.
#[derive(Debug, PartialEq, Eq, Serialize)]
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
}

/// The verified facts, in the shape that the suite compares across SDKs.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
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
}

/// A measurement on the wire: its type and its registers as lowercase hex,
/// with an empty string for a register that is left unconstrained.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Measurement {
    /// The measurement type identifier.
    #[serde(rename = "type")]
    pub kind: String,
    /// The registers in platform order.
    pub registers: Vec<String>,
}

/// The layer-tagged reason for a rejection.
#[derive(Debug, PartialEq, Eq, Serialize)]
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
    // A struct also deserialises from an array, member by position, so the
    // input is required to be an object before it is decoded.
    let is_object = stdin
        .iter()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        .is_some_and(|byte| *byte == b'{');
    if !is_object {
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
    match stage {
        #[cfg(tinfoil_conformance)]
        STAGE_CHECK_ENVELOPE => stages::check_envelope(&input),
        _ => unsupported(stage),
    }
}

/// The adapter's self-description, which the suite reads to decide which
/// fixtures apply.
pub fn capabilities() -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "sdk": SDK_NAME,
        "v3": {
            "supported": true,
            "stages_supported": STAGES_SUPPORTED,
            "synthetic_roots": { "amd": false, "intel": false, "sigstore": false },
            "freshness_enforced": false,
            "live_verify": false,
            "channel_binding": "none",
        },
    })
}

/// The output and exit code for a stage or command that is not supported.
pub fn unsupported(stage: &str) -> (Output, i32) {
    let output = Output {
        stage: stage.to_owned(),
        accepted: false,
        outputs: None,
        rejection: None,
    };
    (output, EXIT_UNSUPPORTED)
}

fn malformed(stage: &str) -> (Output, i32) {
    let output = Output {
        stage: stage.to_owned(),
        accepted: false,
        outputs: None,
        rejection: Some(Rejection {
            code: CODE_MALFORMED_INPUT.to_owned(),
        }),
    };
    (output, EXIT_MALFORMED)
}

#[cfg(tinfoil_conformance)]
mod stages {
    //! The stages, over the verifier's internal modules.

    use base64::Engine as _;
    use base64::alphabet;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    use tinfoil_verifier::conformance::document;

    use super::{
        CODE_ENVELOPE_REJECTED, EXIT_ACCEPTED, EXIT_REJECTED, Input, Output, Rejection,
        STAGE_CHECK_ENVELOPE, malformed,
    };

    /// Standard base64 with padding, as input fields carry it. Unlike the
    /// verifier's own decoding it is lenient about unused trailing bits.
    const INPUT_BASE64: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );

    /// Decodes a base64 input field, ignoring line breaks.
    pub(super) fn decode_base64(value: &str) -> Option<Vec<u8>> {
        let joined: String = value
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n'))
            .collect();
        INPUT_BASE64.decode(joined).ok()
    }

    /// Decodes a hex input field of either case.
    pub(super) fn decode_hex(value: &str) -> Option<Vec<u8>> {
        let digits = value.as_bytes().chunks_exact(2);
        if !digits.remainder().is_empty() {
            return None;
        }
        digits
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .filter(|pair| pair.bytes().all(|digit| digit.is_ascii_hexdigit()))
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            })
            .collect()
    }

    /// Strict parse, nonce equality, endorsed-section hashes and report
    /// data. The nonce is the one in the input, never the document's own.
    pub(super) fn check_envelope(input: &Input) -> (Output, i32) {
        let stage = STAGE_CHECK_ENVELOPE;
        let Some(doc) = decode_base64(&input.document_b64) else {
            return malformed(stage);
        };
        let Some(nonce) = decode_hex(&input.nonce_hex) else {
            return malformed(stage);
        };
        match document::parse(&doc, &nonce) {
            Ok(_) => {
                let output = Output {
                    stage: stage.to_owned(),
                    accepted: true,
                    outputs: None,
                    rejection: None,
                };
                (output, EXIT_ACCEPTED)
            }
            Err(_) => {
                let output = Output {
                    stage: stage.to_owned(),
                    accepted: false,
                    outputs: None,
                    rejection: Some(Rejection {
                        code: CODE_ENVELOPE_REJECTED.to_owned(),
                    }),
                };
                (output, EXIT_REJECTED)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{"schema_version":"1"}"#;

    fn exit_code(stage: &str, input: &str) -> i32 {
        run(stage, input.as_bytes()).1
    }

    #[test]
    fn a_stage_that_is_not_implemented_is_unsupported_once_its_input_parses() {
        for stage in STAGES {
            if STAGES_SUPPORTED.contains(&stage) {
                continue;
            }
            let (output, code) = run(stage, MINIMAL.as_bytes());
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
            (
                "mistyped member",
                r#"{"schema_version":"1","signing_keys_pem":"x"}"#,
            ),
            (
                "negative time",
                r#"{"schema_version":"1","verification_time_unix":-1}"#,
            ),
            (
                "fractional time",
                r#"{"schema_version":"1","verification_time_unix":1.5}"#,
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
        assert_eq!(exit_code(STAGE_AUTHENTICATE_QUOTE, both), EXIT_UNSUPPORTED);
    }

    #[test]
    fn the_supported_stages_follow_the_build() {
        let envelope = STAGES_SUPPORTED.contains(&STAGE_CHECK_ENVELOPE);
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
        let (output, _) = run(STAGE_VERIFY, MINIMAL.as_bytes());
        let json = serde_json::to_string(&output).unwrap();
        assert_eq!(
            json,
            r#"{"stage":"verify-attestation-v3","accepted":false}"#
        );
    }

    #[test]
    fn capabilities_list_only_implemented_stages() {
        let capabilities = capabilities();
        assert_eq!(capabilities["schema_version"], SCHEMA_VERSION);
        assert_eq!(capabilities["sdk"], SDK_NAME);
        let stages = capabilities["v3"]["stages_supported"].as_array().unwrap();
        assert_eq!(stages.len(), STAGES_SUPPORTED.len());
        for stage in stages {
            assert!(STAGES.contains(&stage.as_str().unwrap()));
        }
    }
}

#[cfg(all(test, tinfoil_conformance))]
mod stage_tests {
    use super::stages::{decode_base64, decode_hex};
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
}
