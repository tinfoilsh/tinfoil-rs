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

use serde::Deserialize;
use serde_json::{json, Value};

use tinfoil::verifier::sigstore::{verify_bundle_with_policy, Policy, SigstoreResult};

const EXIT_ACCEPT: u8 = 0;
const EXIT_REJECT: u8 = 10;
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
    let caps = json!({
        "schema_version": "1",
        "sdk": SDK_NAME,
        "sdk_version": SDK_VERSION,
        "stages_supported": ["verify-sigstore"],
        "sigstore": {
            "trust_root_loading": "configurable",
            // tinfoil-rs uses bundle-supplied cert NotBefore for chain-validity
            // scoping, not the system clock. The supplied verification_time_unix
            // is informational and not currently consulted — fixtures still
            // run hermetically.
            "verification_time_override": "supported",
            "policy_fields_configurable": {
                "oidc_issuer": true,
                "workflow_ref_prefix": true,
                "workflow_repository": true,
                "predicate_types_allowed": true,
                "in_toto_statement_types_allowed": true,
                "payload_type": true,
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
            "sigstore.tlog_entries_exactly_one":
                "rekor::verify_rekor_entry rejects bundles with !=1 tlog entries",
            "sigstore.in_toto_statement_type_strict":
                "default Policy pins to in-toto v0.1/v1; can be overridden",
            "sigstore.digest_compare_lowercase_normalize":
                "digest comparison is to_lowercase() on both sides",
            "sigstore.verification_time_supplied_but_ignored":
                "rust uses cert NotBefore from bundle for CA/key validity scoping",
            "sigstore.dcode_label_strict": true
        }
    });
    println!("{}", serde_json::to_string_pretty(&caps).unwrap());
    EXIT_ACCEPT
}

// -----------------------------------------------------------------------------
// verify-sigstore
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InputPolicy {
    oidc_issuer: String,
    workflow_ref_prefix: String,
    #[serde(default)]
    predicate_types_allowed: Option<Vec<String>>,
    #[serde(default)]
    in_toto_statement_types_allowed: Option<Vec<String>>,
    payload_type: String,
}

#[derive(Debug, Deserialize)]
struct Input {
    schema_version: String,
    bundle_b64: String,
    expected_digest_sha256_hex: String,
    repo: String,
    policy: InputPolicy,
    trust_root_b64: String,
    #[serde(default)]
    #[allow(dead_code)]
    verification_time_unix: Option<u64>,
}

fn cmd_verify_sigstore() -> u8 {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("error reading stdin: {e}");
        return EXIT_INTERNAL;
    }
    let parsed: Value = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => return emit_rejection_and_exit(
            "BUNDLE_MALFORMED",
            "5.2",
            &format!("input is not valid JSON: {e}"),
            EXIT_BAD_INPUT,
        ),
    };

    let input: Input = match serde_json::from_value(parsed) {
        Ok(i) => i,
        Err(e) => return emit_rejection_and_exit(
            "BUNDLE_MALFORMED",
            "5.2",
            &format!("input schema violation: {e}"),
            EXIT_BAD_INPUT,
        ),
    };
    if input.schema_version != "1" {
        return emit_rejection_and_exit(
            "BUNDLE_MALFORMED",
            "5.2",
            "input.schema_version != \"1\"",
            EXIT_BAD_INPUT,
        );
    }

    let bundle_bytes = match base64_decode(&input.bundle_b64) {
        Ok(b) => b,
        Err(e) => return emit_rejection_and_exit(
            "BUNDLE_MALFORMED",
            "5.2",
            &format!("bundle_b64 is not valid base64: {e}"),
            EXIT_BAD_INPUT,
        ),
    };
    let trust_root_bytes = match base64_decode(&input.trust_root_b64) {
        Ok(b) => b,
        Err(e) => return emit_rejection_and_exit(
            "TRUST_ROOT_INVALID",
            "5.1",
            &format!("trust_root_b64 is not valid base64: {e}"),
            EXIT_BAD_INPUT,
        ),
    };
    let trust_root_json = match std::str::from_utf8(&trust_root_bytes) {
        Ok(s) => s.to_string(),
        Err(e) => return emit_rejection_and_exit(
            "TRUST_ROOT_INVALID",
            "5.1",
            &format!("trust_root is not valid UTF-8: {e}"),
            EXIT_BAD_INPUT,
        ),
    };

    let policy = Policy {
        oidc_issuer: input.policy.oidc_issuer,
        workflow_ref_prefix: input.policy.workflow_ref_prefix,
        workflow_repository: input.repo.clone(),
        predicate_types_allowed: input.policy.predicate_types_allowed,
        in_toto_statement_types_allowed: input.policy.in_toto_statement_types_allowed,
        payload_type: input.policy.payload_type,
    };

    match verify_bundle_with_policy(
        &bundle_bytes,
        &input.expected_digest_sha256_hex,
        &policy,
        &trust_root_json,
    ) {
        Ok(result) => emit_accept_and_exit(result),
        Err(e) => {
            let (code, spec_ref) = classify_error(&e.to_string());
            emit_rejection_and_exit(code, spec_ref, &e.to_string(), EXIT_REJECT)
        }
    }
}

fn emit_accept_and_exit(r: SigstoreResult) -> u8 {
    let body = json!({
        "stage": "verify-sigstore",
        "accepted": true,
        "outputs": {
            "predicate_type": r.predicate_type,
            "in_toto_statement_type": r.in_toto_statement_type,
            "subject_name": r.subject_name,
            "subject_digest_sha256_hex": r.subject_digest_sha256_hex,
            "measurement": {
                "type": match r.measurement.type_ {
                    tinfoil::verifier::PredicateType::SnpTdxMultiPlatformV1 =>
                        "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
                    tinfoil::verifier::PredicateType::SevGuestV2 =>
                        "https://tinfoil.sh/predicate/sev-snp-guest/v2",
                    tinfoil::verifier::PredicateType::TdxGuestV2 =>
                        "https://tinfoil.sh/predicate/tdx-guest/v2",
                    _ => "https://tinfoil.sh/predicate/unknown",
                },
                "registers": r.measurement.registers,
            },
            "cert_oidc_issuer": r.cert_oidc_issuer,
            "cert_workflow_repository": r.cert_workflow_repository,
            "cert_workflow_signer_uri": r.cert_workflow_signer_uri,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_ACCEPT
}

fn emit_rejection_and_exit(code: &str, spec_ref: &str, message: &str, exit_code: u8) -> u8 {
    let body = json!({
        "stage": "verify-sigstore",
        "accepted": false,
        "rejection": {
            "code": code,
            "spec_ref": spec_ref,
            "message": message,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    exit_code
}

/// Map a `SigstoreVerification(msg)` error message to a (rejection_code, spec_ref).
///
/// Until structured error variants land, we string-match the prefix the lib
/// helpers emit (e.g. "OIDC_ISSUER_MISMATCH:", "SUBJECT_DIGEST_MISMATCH:").
/// Unprefixed messages from the inner sub-modules fall through to coarse
/// pattern matching on stable substrings.
fn classify_error(msg: &str) -> (&'static str, &'static str) {
    // Stable prefixes inserted by mod.rs helpers.
    for (prefix, code, sref) in PREFIX_MAP {
        if msg.starts_with(prefix) {
            return (code, sref);
        }
    }
    // Coarse substring matching for messages emitted by rekor/fulcio/dsse/cert/transparency.
    // Order matters — more specific patterns are tested first.
    if msg.contains("outside certificate validity window")
        || msg.contains("outside of the certificate validity")
        || msg.contains("certificate is expired")
        || msg.contains("certificate has expired")
    {
        ("CERT_EXPIRED", "5.2")
    } else if msg.contains("Expected exactly 1 tlog entry") || msg.contains("No tlogEntries") {
        ("TLOG_COUNT_OUT_OF_RANGE", "5.2")
    } else if msg.contains("No Rekor key valid")
        || msg.contains("Trusted log IDs:")
        || msg.contains("Unknown Rekor log")
        || (msg.contains("Rekor") && msg.contains("log ID"))
    {
        ("REKOR_KEY_NOT_TRUSTED", "5.1")
    } else if msg.contains("Rekor entry integrated time")
        || msg.contains("inclusion proof")
        || msg.contains("Inclusion proof")
        || msg.contains("Rekor key")
        || msg.contains("checkpoint")
    {
        ("REKOR_INCLUSION_INVALID", "5.2")
    } else if msg.contains("Duplicate SCT") {
        ("SCT_DUPLICATE_LOG", "5.2")
    } else if msg.contains("No valid SCT") || msg.contains("Failed to extract SCT") {
        ("SCT_INSUFFICIENT", "5.2")
    } else if msg.contains("Certificate not issued by any trusted Fulcio CA")
        || msg.contains("Could not find issuer certificate")
        || msg.contains("Fulcio chain")
    {
        ("FULCIO_CHAIN_INVALID", "5.2")
    } else if msg.contains("DSSE signature verification failed")
        || msg.contains("Invalid public key")
        || msg.contains("Invalid DER signature")
        || msg.contains("Invalid raw signature")
    {
        ("DSSE_SIGNATURE_INVALID", "5.2")
    } else if msg.contains("Failed to parse trusted root") {
        ("TRUST_ROOT_INVALID", "5.1")
    } else if msg.contains("Failed to parse bundle")
        || msg.contains("Failed to parse certificate")
        || msg.contains("No certificate in bundle")
        || msg.contains("No dsseEnvelope")
        || msg.contains("No payloadType")
        || msg.contains("No payload in DSSE")
    {
        ("BUNDLE_MALFORMED", "5.2")
    } else {
        ("BUNDLE_MALFORMED", "5.2")
    }
}

const PREFIX_MAP: &[(&str, &str, &str)] = &[
    ("OIDC_ISSUER_MISMATCH:", "OIDC_ISSUER_MISMATCH", "5.3"),
    ("WORKFLOW_REPOSITORY_MISMATCH:", "WORKFLOW_REPOSITORY_MISMATCH", "5.3"),
    ("WORKFLOW_REF_PREFIX_MISMATCH:", "WORKFLOW_REF_PREFIX_MISMATCH", "5.3"),
    ("PAYLOAD_TYPE_MISMATCH:", "PAYLOAD_TYPE_MISMATCH", "5.4"),
    ("IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED:", "IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED", "5.4"),
    ("PREDICATE_TYPE_NOT_ALLOWED:", "PREDICATE_TYPE_NOT_ALLOWED", "5.5"),
    ("SUBJECT_DIGEST_MISMATCH:", "SUBJECT_DIGEST_MISMATCH", "5.4"),
    ("SUBJECT_MISSING:", "SUBJECT_MISSING", "5.4"),
    ("PREDICATE_MEASUREMENT_INVALID:", "PREDICATE_MEASUREMENT_INVALID", "5.5"),
    ("BUNDLE_MALFORMED:", "BUNDLE_MALFORMED", "5.2"),
];

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}
