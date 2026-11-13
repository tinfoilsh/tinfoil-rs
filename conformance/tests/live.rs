//! Runs `live-verify` against Tinfoil's production router. The test uses
//! the network, so it is ignored unless asked for:
//!
//! ```sh
//! cargo test -p tinfoil-conformance --test live -- --ignored
//! ```
//!
//! It needs no API key.

// Test helpers: a failure to spawn or parse is a test failure.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

/// The production router and the repository that its code comes from.
const HOST: &str = "inference.tinfoil.sh";
const REPO: &str = "tinfoilsh/confidential-model-router";

#[test]
#[ignore = "uses the network"]
fn the_production_router_is_verified_and_its_connection_is_bound() {
    // The command bounds its own network steps, so the wait is bounded too.
    let mut child = Command::new(env!("CARGO_BIN_EXE_tinfoil-conformance"))
        .arg("live-verify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = serde_json::json!({ "host": HOST, "repo": REPO }).to_string();
    let _ = child.stdin.take().unwrap().write_all(request.as_bytes());
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["stage"], "live-verify");
    assert_eq!(json["accepted"], true);
    let facts = &json["outputs"];
    assert_eq!(facts["channel_binding"], "tls-spki");
    for fact in ["code_digest", "tls_public_key_fp", "hpke_public_key"] {
        assert!(!facts[fact].as_str().unwrap().is_empty(), "{fact}");
    }
    for measurement in ["code_measurement", "enclave_measurement"] {
        assert!(facts[measurement]["type"].is_string(), "{measurement}");
        assert!(facts[measurement]["registers"].is_array(), "{measurement}");
    }
}
