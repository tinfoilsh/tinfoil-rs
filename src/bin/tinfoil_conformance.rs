//! Tinfoil-flavored conformance binary for tinfoil-rs.
//!
//! Implements the CLI contract defined in tinfoil-conformance/schemas/.
//! Distinct from `conformance` (which speaks the upstream sigstore-conformance
//! protocol); this one covers the Tinfoil policy layer plus future SEV/TDX/TLS/EHBP stages.
//!
//! Subcommands:
//!   tinfoil-conformance capabilities                # stdin: none, stdout: JSON
//!   tinfoil-conformance verify-sigstore             # stdin: JSON, stdout: JSON
//!
//! Exit codes:
//!   0  accepted
//!   10 rejected (rejection.code populated)
//!   20 stage/capability not supported
//!   30 malformed input
//!   1  internal error

use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

use serde_json::json;

const EXIT_ACCEPT: u8 = 0;
#[allow(dead_code)] // used once verify-sigstore is wired up
const EXIT_REJECT: u8 = 10;
const EXIT_UNSUPPORTED: u8 = 20;
const EXIT_BAD_INPUT: u8 = 30;
const EXIT_INTERNAL: u8 = 1;

const SDK_NAME: &str = "tinfoil-rs";
const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    match sub {
        "capabilities" => exit(cmd_capabilities()),
        "verify-sigstore" => exit(cmd_verify_sigstore()),
        "--help" | "-h" | "help" | "" => {
            print_help();
            ExitCode::from(0)
        }
        other => {
            eprintln!("tinfoil-conformance: unknown subcommand '{other}'");
            print_help();
            ExitCode::from(EXIT_BAD_INPUT)
        }
    }
}

fn print_help() {
    eprintln!(
        "tinfoil-conformance: Tinfoil cross-SDK conformance binary ({SDK_NAME} {SDK_VERSION})\n\n\
         Subcommands:\n  \
           capabilities      Print SDK capabilities JSON\n  \
           verify-sigstore   Verify a Sigstore bundle (SPEC §5)\n\n\
         I/O contract: stdin JSON, stdout JSON. See tinfoil-conformance/schemas/."
    );
}

fn exit(code: u8) -> ExitCode {
    ExitCode::from(code)
}

// -----------------------------------------------------------------------------
// capabilities
// -----------------------------------------------------------------------------

fn cmd_capabilities() -> u8 {
    // NOTE: keep this in lockstep with what the verify-* subcommands actually
    // implement. `stages_supported` is authoritative — fixtures targeting stages
    // not listed here are auto-skipped by the harness.
    let caps = json!({
        "schema_version": "1",
        "sdk": SDK_NAME,
        "sdk_version": SDK_VERSION,
        // verify-sigstore is intentionally NOT listed yet — this is the stub
        // commit. Adding it requires plumbing through the verifier::sigstore
        // module to accept inline trust roots and verification time.
        "stages_supported": [],
        "sigstore": {
            "trust_root_loading": "embedded-only",
            "verification_time_override": "system-clock-only",
            "policy_fields_configurable": {
                "oidc_issuer": false,
                "workflow_ref_prefix": false,
                "workflow_repository": true,
                "predicate_types_allowed": false,
                "in_toto_statement_types_allowed": false,
                "payload_type": false,
                "tlog_entries_min": false,
                "tlog_entries_max": false,
                "sct_min": false,
                "observer_timestamps_min": false
            },
            "predicate_types_understood": [
                "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
            ]
        },
        "platforms_supported": ["sev-snp"],
        "transport_modes_supported": ["tls-pinning"],
        "flow_modes_supported": ["standard"],
        "known_quirks": {
            "sigstore.tlog_entries_exactly_one": true,
            "sigstore.in_toto_statement_type_strict": true,
            "sigstore.digest_compare_lowercase_normalize": true,
            "sigstore.dcode_label_strict": true
        }
    });
    println!("{}", serde_json::to_string_pretty(&caps).unwrap());
    EXIT_ACCEPT
}

// -----------------------------------------------------------------------------
// verify-sigstore (stub — see TODO below)
// -----------------------------------------------------------------------------

fn cmd_verify_sigstore() -> u8 {
    // Read stdin to validate the input is at least well-formed JSON. We do
    // this even in the stub so misbehaving callers get a precise error.
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("error reading stdin: {e}");
        return EXIT_INTERNAL;
    }
    let parsed: serde_json::Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => {
            emit_unsupported_or_rejection(format!("input is not valid JSON: {e}"), EXIT_BAD_INPUT);
            return EXIT_BAD_INPUT;
        }
    };
    if parsed.get("schema_version").and_then(|v| v.as_str()) != Some("1") {
        emit_unsupported_or_rejection(
            "input.schema_version != \"1\"".into(),
            EXIT_BAD_INPUT,
        );
        return EXIT_BAD_INPUT;
    }

    // TODO(tinfoil-conformance): wire this to verifier::sigstore. Doing so
    // requires either exposing a lower-level entry point that accepts:
    //   - inline bundle bytes (not GitHub-fetched),
    //   - inline trust root JSON (not the embedded one),
    //   - a fixed verification time (not system clock),
    //   - policy parameters (workflow_ref_prefix, predicate_types_allowed, etc.).
    //
    // The current `verifier::sigstore::verify_repo(repo)` is too high-level —
    // it fetches the digest and bundle from GitHub. The next PR splits that
    // into:
    //   1) verifier::sigstore::verify_bundle_with_policy(...)
    //   2) verifier::sigstore::extract_measurement(...)
    // and this binary calls those. For now we declare the stage unsupported
    // in `capabilities` so the harness auto-skips.
    eprintln!(
        "verify-sigstore not wired up yet in tinfoil-rs's tinfoil-conformance binary; \
         capabilities.stages_supported should already cause the harness to skip."
    );
    let body = json!({
        "stage": "verify-sigstore",
        "accepted": false,
        "rejection": {
            "code": "TRUST_ROOT_INVALID",
            "spec_ref": "5.1",
            "message": "stub: verify-sigstore not yet implemented in tinfoil-rs conformance binary"
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_UNSUPPORTED
}

fn emit_unsupported_or_rejection(message: String, _exit: u8) {
    let body = json!({
        "stage": "verify-sigstore",
        "accepted": false,
        "rejection": {
            "code": "BUNDLE_MALFORMED",
            "spec_ref": "5.2",
            "message": message
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}
