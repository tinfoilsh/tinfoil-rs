//! Runs the adapter binary itself: argument dispatch, stdin, stdout and the
//! process exit code.

// Test helpers: a failure to spawn or parse is a test failure.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tinfoil_conformance::{EXIT_INTERNAL, EXIT_MALFORMED, EXIT_UNSUPPORTED};

fn adapter(arguments: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tinfoil-conformance"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The adapter may exit without reading, which closes the pipe.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    child.wait_with_output().unwrap()
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn capabilities_are_printed_as_json() {
    let output = adapter(&["capabilities"], "");
    assert_eq!(output.status.code(), Some(0));
    let capabilities = stdout_json(&output);
    assert_eq!(capabilities["sdk"], "tinfoil-rs");
    assert!(capabilities["v3"]["stages_supported"].is_array());
}

#[test]
fn a_stage_reads_stdin_and_reports_its_exit_code() {
    let output = adapter(&["v3-check-envelope"], r#"{"schema_version":"1"}"#);
    assert_eq!(output.status.code(), Some(EXIT_UNSUPPORTED));
    let json = stdout_json(&output);
    assert_eq!(json["stage"], "v3-check-envelope");
    assert_eq!(json["accepted"], false);
}

#[test]
fn malformed_stdin_exits_with_the_malformed_code() {
    let output = adapter(&["v3-check-envelope"], "{");
    assert_eq!(output.status.code(), Some(EXIT_MALFORMED));
    assert_eq!(stdout_json(&output)["rejection"]["code"], "MALFORMED_INPUT");
}

#[test]
fn live_verify_is_unsupported_whatever_its_input() {
    let output = adapter(
        &["live-verify"],
        r#"{"host":"example.com","repo":"org/repo"}"#,
    );
    assert_eq!(output.status.code(), Some(EXIT_UNSUPPORTED));
    assert_eq!(stdout_json(&output)["stage"], "live-verify");
}

#[test]
fn a_missing_command_is_an_adapter_error_without_output() {
    let output = adapter(&[], "");
    assert_eq!(output.status.code(), Some(EXIT_INTERNAL));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
