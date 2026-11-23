//! The verification reports of chosen full-verification vectors: the step
//! that failed, and the facts that the steps before it established.
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

use std::path::PathBuf;

use serde_json::Value;
use tinfoil_conformance::{
    EXIT_ACCEPTED, EXIT_REJECTED, Output, Report, ReportExpectedFacts, ReportMeasuredFacts,
    STAGE_VERIFY, check_report,
};

const VECTORS_ENV: &str = "TINFOIL_CONFORMANCE_VECTORS";

/// The output of the full-verification vector at `path`, under the
/// vectors directory, once its report passed its check; `None` without a
/// vectors directory.
fn verify(path: &str) -> Option<(Output, i32)> {
    let Some(root) = std::env::var_os(VECTORS_ENV).map(PathBuf::from) else {
        eprintln!("skipped: {VECTORS_ENV} is not set");
        return None;
    };
    let fixture: Value = serde_json::from_slice(&std::fs::read(root.join(path)).unwrap()).unwrap();
    assert_eq!(fixture["stage"], STAGE_VERIFY);
    let (output, code) =
        tinfoil_conformance::run(STAGE_VERIFY, fixture["input"].to_string().as_bytes());
    check_report(&output).unwrap_or_else(|reason| panic!("{path}: {reason}"));
    Some((output, code))
}

fn statuses(report: &Report) -> Vec<&str> {
    report
        .steps
        .iter()
        .map(|step| step.status.as_str())
        .collect()
}

/// The report of a rejection, with its partial facts.
fn rejected(path: &str, layer: &str) -> Option<Report> {
    let (output, code) = verify(path)?;
    assert_eq!(code, EXIT_REJECTED, "{path}");
    let report = output.report.expect("a rejection has a report");
    assert_eq!(report.failed_step(), Some(layer), "{path}");
    assert!(report.partial_facts.is_some(), "{path}");
    Some(report)
}

fn expected(report: &Report) -> &ReportExpectedFacts {
    report
        .partial_facts
        .as_ref()
        .and_then(|partial| partial.expected.as_ref())
        .expect("expected facts")
}

fn measured(report: &Report) -> &ReportMeasuredFacts {
    report
        .partial_facts
        .as_ref()
        .and_then(|partial| partial.measured.as_ref())
        .expect("measured facts")
}

#[test]
fn an_accepted_vector_passes_every_step_and_has_no_partial_facts() {
    let Some((output, code)) = verify("golden/golden-happy.json") else {
        return;
    };
    assert_eq!(code, EXIT_ACCEPTED);
    let report = output.report.unwrap();
    assert_eq!(statuses(&report), ["passed"; 4]);
    assert_eq!(report.partial_facts, None);
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
    let partial = report.partial_facts.unwrap();
    assert_eq!((partial.expected, partial.measured), (None, None));
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
    assert_eq!(report.partial_facts.as_ref().unwrap().expected, None);
    let measured = measured(&report);
    assert_eq!(measured.cpu_measurement, None);
    assert_eq!(measured.tls_public_key_fp.len(), 64);
    assert_eq!(measured.hpke_public_key_fp.len(), 64);
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
    assert!(!expected.code_digest.is_empty());
    let code = expected.code_measurement.as_ref().unwrap();
    let full = expected
        .measurement
        .as_ref()
        .expect("the policy step resolved the expectation before it compared");
    assert_eq!(code.registers, full.registers);
    let cpu = measured(&report).cpu_measurement.as_ref().unwrap();
    assert_eq!(cpu.kind, full.kind);
    assert_ne!(cpu.registers, full.registers);
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
    // MRTD, RTMR0, RTMR1, RTMR2, RTMR3.
    let code = &expected.code_measurement.as_ref().unwrap().registers;
    assert_eq!(code[0], "", "the release leaves MRTD to the platform");
    let full = &expected.measurement.as_ref().unwrap().registers;
    let cpu = &measured(&report)
        .cpu_measurement
        .as_ref()
        .unwrap()
        .registers;
    assert_eq!(full[..2], cpu[..2], "the platform endorses the machine's");
    assert_eq!(full[2], code[2]);
    assert_ne!(full[2], cpu[2]);

    let Some(report) = rejected("golden-tdx/t17-rtmr0.json", "policy") else {
        return;
    };
    let expected = self::expected(&report);
    assert_eq!(expected.measurement, None);
    assert!(expected.code_measurement.is_some());
    assert!(measured(&report).cpu_measurement.is_some());
}
