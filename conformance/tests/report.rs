//! The verification reports of chosen full-verification vectors: the step
//! that failed, and the facts that the steps before it established, in the
//! JSON form that the adapter writes. The golden files of that form, which
//! every Tinfoil SDK shares, are checked here for the cases that name a
//! vector.
//!
//! The vectors come from a checkout of the shared suite, named by
//! `TINFOIL_CONFORMANCE_VECTORS` (its `vectors/v3` directory); without one
//! the tests report a skip.

#![cfg(tinfoil_conformance)]
// Test tooling: indexing a JSON value yields null for a missing member and
// never panics, and a panic is how a test fails.
#![allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::path::{Path, PathBuf};

use serde_json::Value;
use tinfoil_conformance::{EXIT_ACCEPTED, EXIT_REJECTED, STAGE_VERIFY, check_report};
use tinfoil_verifier::conformance::instant::Instant;

const VECTORS_ENV: &str = "TINFOIL_CONFORMANCE_VECTORS";

/// The vectors directory, `vectors/v3` of the shared suite; `None`, with a
/// skip reported, when it is not set.
fn vectors() -> Option<PathBuf> {
    let root = std::env::var_os(VECTORS_ENV).map(PathBuf::from);
    if root.is_none() {
        eprintln!("skipped: {VECTORS_ENV} is not set");
    }
    root
}

/// The exit code and the report, in its JSON form, of the
/// full-verification vector at `path` under the vectors directory, once
/// the report passed its check; `None` without a vectors directory.
fn verify(path: &str) -> Option<(i32, Value)> {
    Some(verify_in(&vectors()?, path))
}

fn verify_in(root: &Path, path: &str) -> (i32, Value) {
    let fixture: Value = serde_json::from_slice(&std::fs::read(root.join(path)).unwrap()).unwrap();
    assert_eq!(fixture["stage"], STAGE_VERIFY);
    let (output, code) =
        tinfoil_conformance::run(STAGE_VERIFY, fixture["input"].to_string().as_bytes());
    check_report(&output).unwrap_or_else(|reason| panic!("{path}: {reason}"));
    let report = serde_json::to_value(output.report.expect("a verdict has a report")).unwrap();
    (code, report)
}

fn statuses(report: &Value) -> Vec<&str> {
    report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["status"].as_str().unwrap())
        .collect()
}

/// The report of a rejection at `layer`, with its partial facts.
fn rejected(path: &str, layer: &str) -> Option<Value> {
    let (code, report) = verify(path)?;
    assert_eq!(code, EXIT_REJECTED, "{path}");
    let failed = report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["status"] == "failed")
        .map(|step| step["layer"].clone());
    assert_eq!(failed, Some(Value::from(layer)), "{path}");
    assert!(report.get("partial_facts").is_some(), "{path}");
    Some(report)
}

fn expected(report: &Value) -> &Value {
    report["partial_facts"]
        .get("expected")
        .expect("expected facts")
}

fn measured(report: &Value) -> &Value {
    report["partial_facts"]
        .get("measured")
        .expect("measured facts")
}

#[test]
fn an_accepted_vector_passes_every_step_and_has_no_partial_facts() {
    let Some((code, report)) = verify("golden/golden-happy.json") else {
        return;
    };
    assert_eq!(code, EXIT_ACCEPTED);
    assert_eq!(statuses(&report), ["passed"; 4]);
    assert_eq!(report.get("partial_facts"), None);
    assert!(report.get("verified_facts").is_some());
}

#[test]
fn an_envelope_rejection_establishes_nothing() {
    let Some(report) = rejected("freshness/fr1-nonce-stale.json", "envelope") else {
        return;
    };
    assert_eq!(
        statuses(&report),
        ["failed", "not_run", "not_run", "not_run"]
    );
    assert_eq!(report["partial_facts"], serde_json::json!({}));
}

#[test]
fn a_provenance_rejection_has_the_claimed_keys_and_no_reference_values() {
    let Some(report) = rejected("freshness/fr2-stale.json", "provenance") else {
        return;
    };
    assert_eq!(
        statuses(&report),
        ["passed", "failed", "not_run", "not_run"]
    );
    assert_eq!(report["partial_facts"].get("expected"), None);
    let measured = measured(&report);
    assert_eq!(measured.get("cpu_measurement"), None);
    assert_eq!(measured["tls_public_key_fp"].as_str().unwrap().len(), 64);
    assert_eq!(measured["hpke_public_key_fp"].as_str().unwrap().len(), 64);
}

/// A launch measurement that the release does not fix fails the policy
/// step with both sides of the comparison in the report.
#[test]
fn a_measurement_mismatch_shows_the_expected_and_the_measured_registers() {
    let Some(report) = rejected("golden/s14-measurement.json", "policy") else {
        return;
    };
    assert_eq!(statuses(&report), ["passed", "passed", "passed", "failed"]);
    let expected = expected(&report);
    assert!(!expected["artifact"]["digest"].as_str().unwrap().is_empty());
    let code = &expected["code_measurement"];
    let full = expected
        .get("measurement")
        .expect("the policy step resolved the expectation before it compared");
    assert_eq!(code, full);
    let cpu = &measured(&report)["cpu_measurement"];
    assert_eq!(cpu["platform"], full["platform"]);
    assert_ne!(cpu["launch"], full["launch"]);
}

/// For a code release on TDX, the full expectation adds the platform
/// registers that the platform endorsements resolve for the quote's
/// machine; a register that none resolves fails the policy step before the
/// expectation is complete.
#[test]
fn a_tdx_register_mismatch_shows_the_platform_registers() {
    let Some(report) = rejected("golden-tdx/t18-rtmr1.json", "policy") else {
        return;
    };
    let expected = expected(&report);
    let code = &expected["code_measurement"];
    assert_eq!(
        code.get("mrtd"),
        None,
        "the release leaves MRTD to the platform"
    );
    let full = &expected["measurement"];
    let cpu = &measured(&report)["cpu_measurement"];
    for register in ["mrtd", "rtmr0"] {
        assert_eq!(
            full[register], cpu[register],
            "the platform endorses the machine's"
        );
    }
    assert_eq!(full["rtmr1"], code["rtmr1"]);
    assert_ne!(full["rtmr1"], cpu["rtmr1"]);

    let Some(report) = rejected("golden-tdx/t17-rtmr0.json", "policy") else {
        return;
    };
    let expected = self::expected(&report);
    assert_eq!(expected.get("measurement"), None);
    assert!(expected.get("code_measurement").is_some());
    assert!(measured(&report).get("cpu_measurement").is_some());
}

/// The members of the JSON form that hold a time.
const TIME_MEMBERS: [&str; 4] = [
    "approval_time",
    "signature_time",
    "freshness_expires_at",
    "verified_at",
];

/// `value`, a report's JSON form, as SDKs compare it: without the step
/// messages, which are each SDK's own text, and without `metadata`, which
/// describes the run; and with each time in one spelling of its instant.
fn comparable(mut value: Value) -> Value {
    fn times(value: &mut Value) {
        match value {
            Value::Object(members) => {
                for (name, member) in members.iter_mut() {
                    match member {
                        Value::String(text) if TIME_MEMBERS.contains(&name.as_str()) => {
                            *text = Instant::parse_rfc3339(text)
                                .unwrap_or_else(|error| panic!("{name}: {text}: {error}"))
                                .to_rfc3339();
                        }
                        _ => times(member),
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(times),
            _ => {}
        }
    }
    let members = value.as_object_mut().unwrap();
    members.remove("metadata");
    for step in members["steps"].as_array_mut().unwrap() {
        step.as_object_mut().unwrap().remove("message");
    }
    times(&mut value);
    value
}

/// The report of each full-verification vector that a golden file of the
/// common JSON form names is that file's report. The files are shared by
/// every Tinfoil SDK; the ones that name no vector are checked by the
/// verifier's own tests.
#[test]
fn the_json_form_of_a_vector_report_matches_its_golden_file() {
    let Some(root) = vectors() else {
        return;
    };
    // The vectors name their paths from the suite's `vectors` directory.
    let suite = root.parent().unwrap();
    let golden =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/verifier/tests/data/report-json");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&golden)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    let mut ran = 0;
    for file in files {
        let case: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let Some(vector) = case["vector"].as_str() else {
            continue;
        };
        let (_, report) = verify_in(suite, vector);
        assert_eq!(
            comparable(report.clone()),
            comparable(case["report"].clone()),
            "{}: {report}",
            file.display()
        );
        ran += 1;
    }
    assert!(ran > 0, "no golden file names a vector");
}
