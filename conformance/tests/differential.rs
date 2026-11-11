//! Replays recorded approval bundles and timestamp responses through the
//! approval and timestamp stages.
//!
//! Each case is a single change to a well-formed input, with the verdict
//! that an independent implementation of the same rules gave it
//! (`reference`) and the verdict of this adapter (`exit`). The two differ
//! only where this verifier is the stricter one, and never the other way
//! round: no case that the other implementation turns down is accepted here.

// Test tooling: indexing a JSON value yields null for a missing member and
// never panics, and a panic is how a test fails.
#![cfg(tinfoil_conformance)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use tinfoil_conformance::{EXIT_ACCEPTED, EXIT_MALFORMED, EXIT_REJECTED};

const APPROVALS: &str =
    include_str!("../../crates/verifier/tests/data/sigstore/approval_differential.json");
const TIMESTAMPS: &str =
    include_str!("../../crates/verifier/tests/data/sigstore/timestamp_differential.json");

/// The bytes of a case: the base with the part between `prefix` and
/// `suffix` replaced by `middle`.
fn spliced(base: &[u8], case: &Value, middle: &[u8]) -> Vec<u8> {
    let prefix = usize::try_from(case["prefix"].as_u64().unwrap()).unwrap();
    let suffix = usize::try_from(case["suffix"].as_u64().unwrap()).unwrap();
    let mut out = base[..prefix].to_vec();
    out.extend_from_slice(middle);
    out.extend_from_slice(&base[base.len() - suffix..]);
    out
}

/// Checks one case's verdict against the record and returns whether the
/// adapter was stricter than the other implementation.
fn check(name: &str, case: &Value, code: i32, output: &Value, fact: &str) -> bool {
    let reference = i32::try_from(case["reference"].as_i64().unwrap()).unwrap();
    let recorded = i32::try_from(case["exit"].as_i64().unwrap()).unwrap();
    assert_eq!(code, recorded, "{name}: verdict differs from the record");
    assert!(
        [EXIT_ACCEPTED, EXIT_REJECTED, EXIT_MALFORMED].contains(&code),
        "{name}: no verdict"
    );
    assert!(
        code != EXIT_ACCEPTED || reference == EXIT_ACCEPTED,
        "{name}: accepted an input that the other implementation turns down"
    );
    if code == EXIT_ACCEPTED {
        assert_eq!(output["outputs"][fact], case[fact], "{name}: {fact}");
    }
    code != reference
}

#[test]
fn recorded_approval_bundles_get_their_recorded_verdicts() {
    let fixture: Value = serde_json::from_str(APPROVALS).unwrap();
    let bases = &fixture["bases"];
    let base = bases["bundle"].as_str().unwrap().as_bytes();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 400);
    let (mut accepted, mut stricter) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let bundle = spliced(base, case, case["middle"].as_str().unwrap().as_bytes());
        let member = |name: &str| {
            if case[name].is_null() {
                bases[name].clone()
            } else {
                case[name].clone()
            }
        };
        let input = json!({
            "schema_version": "1",
            "bundle_json_b64": STANDARD.encode(&bundle),
            "signing_keys_pem": member("keys"),
            "artifact_digest_hex": member("digest"),
            "sigstore_trusted_root_json_b64": STANDARD.encode(member("root").as_str().unwrap()),
        });
        let (output, code) =
            tinfoil_conformance::run("v3-authenticate-approval", input.to_string().as_bytes());
        let output = serde_json::to_value(&output).unwrap();
        // The recorded hint is named for the fact that carries it.
        let mut expected = case.clone();
        expected["signing_key_hint"] = case["hint"].clone();
        stricter += usize::from(check(name, &expected, code, &output, "signing_key_hint"));
        accepted += usize::from(code == EXIT_ACCEPTED);
    }
    assert_eq!((accepted, stricter), (94, 53));
}

#[test]
fn recorded_timestamp_responses_get_their_recorded_verdicts() {
    let fixture: Value = serde_json::from_str(TIMESTAMPS).unwrap();
    let bases = &fixture["bases"];
    let base = STANDARD
        .decode(bases["response"].as_str().unwrap())
        .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 250);
    let (mut accepted, mut stricter) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let middle = STANDARD.decode(case["middle"].as_str().unwrap()).unwrap();
        let response = spliced(&base, case, &middle);
        let covered = if let Some(count) = case["input_a_count"].as_u64() {
            STANDARD.encode(vec![b'a'; usize::try_from(count).unwrap()])
        } else if let Some(input) = case["input"].as_str() {
            input.to_owned()
        } else {
            bases["input"].as_str().unwrap().to_owned()
        };
        let now = if case["now"].is_null() {
            &bases["now"]
        } else {
            &case["now"]
        };
        let root = case["root"]
            .as_str()
            .unwrap_or(bases["root"].as_str().unwrap());
        let input = json!({
            "schema_version": "1",
            "timestamp_response_b64": STANDARD.encode(&response),
            "timestamp_input_b64": covered,
            "verification_time_unix": now,
            "sigstore_trusted_root_json_b64": STANDARD.encode(root),
        });
        let (output, code) =
            tinfoil_conformance::run("v3-verify-timestamp", input.to_string().as_bytes());
        let output = serde_json::to_value(&output).unwrap();
        stricter += usize::from(check(name, case, code, &output, "timestamp"));
        accepted += usize::from(code == EXIT_ACCEPTED);
    }
    assert_eq!((accepted, stricter), (81, 22));
}
