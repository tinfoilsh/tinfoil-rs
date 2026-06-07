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

use tinfoil::verifier::attestation::types::{Measurement, MeasurementError, PredicateType};
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
        "verify-measurement" => exit(cmd_verify_measurement()),
        "verify-hardware-measurements" => exit(cmd_verify_hardware_measurements()),
        "verify-attestation-sev" => exit(cmd_verify_attestation_sev()),
        "verify-full" => exit(cmd_verify_full()),
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
        "stages_supported": [
            "verify-sigstore",
            "verify-measurement",
            "verify-hardware-measurements",
            "verify-attestation-sev",
            "verify-full",
        ],
        "sigstore": {
            "trust_root_loading": "configurable",
            // tinfoil-rs scopes cert/CA/Rekor-key validity to bundle-supplied
            // times (cert NotBefore, Rekor integratedTime) — hermetic on the
            // system clock by construction. The fixture-supplied
            // verification_time_unix isn't consulted; declaring honestly.
            "verification_time_override": "bundle-supplied-only",
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
            ],
            "legacy_bundle_format_supported": false,
            "accepts_multi_tlog_entries": true,
            "oidc_issuer_v2_preferred": true,
            "scts_count_distinguish_missing_vs_duplicate": true,
            "rejects_duplicate_sct_log": true,
            "checks_only_subject_0": true,
            "in_toto_statement_tolerates_extra_fields": true
        },
        "measurement": {
            "compare_multiplatform_to_tdx_supported": true
        },
        "attestation_tdx": {
            // tinfoil-rs doesn't ship a native TDX quote verifier today
            // (only SEV-SNP via verifier/attestation). Declared false so
            // attestation-tdx fixtures skip cleanly. When a TDX verifier
            // lands, flip to true and add the conformance wrapper.
            "supported": false,
            "injected_collateral_supported": false
        },
        "attestation_sev": {
            // cmd_verify_attestation_sev wraps verifier::attestation::sev::
            // verify_with_inline_collateral with VCEK supplied inline.
            "supported": true,
            "injected_collateral_supported": true,
            // The conformance binary enforces SPEC §3.7 / §3.8 / §8.2-3
            // policy pins (measurement, host_data, report_data, etc.) and
            // enforce_spec_defaults checks (DEBUG/MIGRATE/reserved bits).
            "extended_checks_supported": true,
            // verify_with_inline_collateral itself doesn't take a `now`
            // override — the lib uses SystemTime::now() under the hood.
            // Fixture 240-vcek-expired gates on supported and skips here.
            "verification_time_override": "system-clock-only",
            // The lib's verify_cert_chain_crypto_with_override path accepts
            // a synthetic ARK SPKI fingerprint when input.amd_root_ca_pem +
            // ask_pem are present, enabling Phase 4B-SEV synth fixtures.
            "amd_root_ca_injection_supported": true,
        },
        "platforms_supported": ["sev-snp"],
        "transport_modes_supported": ["tls-pinning"],
        "flow_modes_supported": ["standard", "pinned"],
        "known_quirks": {
            "sigstore.in_toto_statement_type_strict":
                "default Policy pins to in-toto v0.1/v1; can be overridden",
            "sigstore.digest_compare_lowercase_normalize":
                "digest comparison is to_lowercase() on both sides",
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

fn default_schema_version() -> String {
    "1".to_string()
}

#[derive(Debug, Deserialize)]
struct Input {
    // Top-level: schema_version is required by the verify-sigstore contract.
    // Verify-full's nested sigstore block omits it (the parent envelope
    // carries it); default to "1" so this struct serves both call sites.
    #[serde(default = "default_schema_version")]
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

/// Verify the sigstore inputs and return the SigstoreResult. Factored so
/// cmd_verify_sigstore and cmd_verify_full can share the same parsing +
/// verification path.
fn run_verify_sigstore_inner(input: &Input) -> Result<SigstoreResult, (String, String, String)> {
    if input.schema_version != "1" {
        return Err(("BUNDLE_MALFORMED".into(), "5.2".into(), "input.schema_version != \"1\"".into()));
    }
    let bundle_bytes = base64_decode(&input.bundle_b64)
        .map_err(|e| ("BUNDLE_MALFORMED".to_string(), "5.2".to_string(),
                      format!("bundle_b64 is not valid base64: {e}")))?;
    let trust_root_bytes = base64_decode(&input.trust_root_b64)
        .map_err(|e| ("TRUST_ROOT_INVALID".to_string(), "5.1".to_string(),
                      format!("trust_root_b64 is not valid base64: {e}")))?;
    let trust_root_json = std::str::from_utf8(&trust_root_bytes)
        .map_err(|e| ("TRUST_ROOT_INVALID".to_string(), "5.1".to_string(),
                      format!("trust_root is not valid UTF-8: {e}")))?
        .to_string();
    let policy = Policy {
        oidc_issuer: input.policy.oidc_issuer.clone(),
        workflow_ref_prefix: input.policy.workflow_ref_prefix.clone(),
        workflow_repository: input.repo.clone(),
        predicate_types_allowed: input.policy.predicate_types_allowed.clone(),
        in_toto_statement_types_allowed: input.policy.in_toto_statement_types_allowed.clone(),
        payload_type: input.policy.payload_type.clone(),
    };
    verify_bundle_with_policy(&bundle_bytes, &input.expected_digest_sha256_hex, &policy, &trust_root_json)
        .map_err(|e| {
            let (code, spec_ref) = classify_error(&e.to_string());
            (code.to_string(), spec_ref.to_string(), e.to_string())
        })
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

    let bundle_bytes = match base64_decode(&input.bundle_b64) {
        Ok(b) => b,
        Err(_) => Vec::new(),
    };
    match run_verify_sigstore_inner(&input) {
        Ok(result) => emit_accept_and_exit(result, &bundle_bytes),
        Err((code, spec_ref, msg)) => {
            let exit_code = if msg.starts_with("input.schema_version") {
                EXIT_BAD_INPUT
            } else {
                EXIT_REJECT
            };
            emit_rejection_and_exit(&code, &spec_ref, &msg, exit_code)
        }
    }
}

fn emit_accept_and_exit(r: SigstoreResult, bundle_bytes: &[u8]) -> u8 {
    // Extract bundle-observed metadata fields (rekor log id, integrated time,
    // tlog entry count, SCT count) for the harness to compare across SDKs.
    // These are bundle-derived, not policy-driven — same parse work both SDKs
    // do during verification, surfaced here for diffability.
    let (rekor_log_id_hex, rekor_integrated_time_unix, tlog_entry_count, sct_count) =
        extract_bundle_observables(bundle_bytes);

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
            "rekor_log_id_hex": rekor_log_id_hex,
            "rekor_integrated_time_unix": rekor_integrated_time_unix,
            "tlog_entry_count": tlog_entry_count,
            "sct_count": sct_count,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_ACCEPT
}

/// Parse the bundle and return (rekor_log_id_hex, integrated_time, tlog_entry_count, sct_count).
/// Each field is `None` if the bundle doesn't carry it. Pure observation — no
/// verification, since the caller has already verified.
fn extract_bundle_observables(
    bundle_bytes: &[u8],
) -> (Option<String>, Option<u64>, Option<usize>, Option<usize>) {
    let Ok(bundle) = serde_json::from_slice::<serde_json::Value>(bundle_bytes) else {
        return (None, None, None, None);
    };
    let tlogs = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("tlogEntries"))
        .and_then(|t| t.as_array());
    let tlog_count = tlogs.map(|t| t.len());
    let (log_id_hex, integrated) = if let Some(entries) = tlogs.and_then(|t| t.first()) {
        let log_id_b64 = entries
            .get("logId")
            .and_then(|l| l.get("keyId"))
            .and_then(|k| k.as_str());
        let log_id = log_id_b64.and_then(|s| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .ok()
                .map(|b| hex::encode(b))
        });
        let it = entries.get("integratedTime").and_then(|t| {
            t.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| t.as_u64())
        });
        (log_id, it)
    } else {
        (None, None)
    };

    // SCT count: parse the leaf cert, find the SCT extension, count entries.
    let sct_count: Option<usize> = (|| -> Option<usize> {
        use base64::Engine;
        use der::Decode;
        use x509_cert::Certificate;
        let cert_b64 = bundle
            .get("verificationMaterial")?
            .get("certificate")?
            .get("rawBytes")?
            .as_str()?;
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .ok()?;
        let cert = Certificate::from_der(&cert_der).ok()?;
        // SCT OID 1.3.6.1.4.1.11129.2.4.2; the extension value is OCTET STRING
        // wrapping SerializedSCTList (2-byte total len, then per-SCT 2-byte len+body).
        let exts = cert.tbs_certificate.extensions.as_ref()?;
        let sct_oid = "1.3.6.1.4.1.11129.2.4.2";
        for ext in exts {
            if ext.extn_id.to_string() != sct_oid {
                continue;
            }
            let raw = ext.extn_value.as_bytes();
            // Outer DER OCTET STRING (tag 0x04, length, contents).
            if raw.len() < 2 || raw[0] != 0x04 {
                return None;
            }
            let (inner_offset, _inner_len) = parse_der_length(&raw[1..])?;
            let inner = &raw[1 + inner_offset..];
            if inner.len() < 2 {
                return None;
            }
            // SerializedSCTList: 2-byte big-endian total length, then SCT entries.
            let total_len = u16::from_be_bytes([inner[0], inner[1]]) as usize;
            let list = &inner[2..2 + total_len.min(inner.len() - 2)];
            let mut count = 0usize;
            let mut i = 0usize;
            while i + 2 <= list.len() {
                let sct_len = u16::from_be_bytes([list[i], list[i + 1]]) as usize;
                i += 2;
                if i + sct_len > list.len() {
                    return None;
                }
                i += sct_len;
                count += 1;
            }
            return Some(count);
        }
        None
    })();

    (log_id_hex, integrated, tlog_count, sct_count)
}

/// Parse a DER length octet pair: returns (bytes_consumed, length_value).
fn parse_der_length(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first < 0x80 {
        return Some((1, first as usize));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > std::mem::size_of::<usize>() || b.len() < 1 + n {
        return None;
    }
    let mut val: usize = 0;
    for &byte in &b[1..1 + n] {
        val = (val << 8) | byte as usize;
    }
    Some((1 + n, val))
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
    ("TLOG_COUNT_OUT_OF_RANGE:", "TLOG_COUNT_OUT_OF_RANGE", "5.2"),
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

// -----------------------------------------------------------------------------
// verify-measurement (SPEC §7)
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MeasurementInput {
    #[serde(rename = "type")]
    type_: String,
    registers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyMeasurementInput {
    schema_version: String,
    source: MeasurementInput,
    #[serde(default)]
    target: Option<MeasurementInput>,
}

const SEV_URI: &str = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const TDX_URI: &str = "https://tinfoil.sh/predicate/tdx-guest/v2";
const MP_URI: &str = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";

fn parse_predicate_type(uri: &str) -> Option<PredicateType> {
    match uri {
        SEV_URI => Some(PredicateType::SevGuestV2),
        TDX_URI => Some(PredicateType::TdxGuestV2),
        MP_URI => Some(PredicateType::SnpTdxMultiPlatformV1),
        _ => None,
    }
}

/// SPEC §7.1 register count for a predicate type.
fn expected_register_count(t: &PredicateType) -> Option<usize> {
    match t {
        PredicateType::SevGuestV2 => Some(1),
        PredicateType::TdxGuestV2 => Some(5),
        PredicateType::SnpTdxMultiPlatformV1 => Some(3),
        _ => None,
    }
}

fn normalize_measurement(m: &MeasurementInput) -> Result<Measurement, (&'static str, &'static str)> {
    let Some(t) = parse_predicate_type(&m.type_) else {
        return Err(("MEASUREMENT_TYPE_UNKNOWN", "2.3"));
    };
    let Some(expected) = expected_register_count(&t) else {
        return Err(("MEASUREMENT_TYPE_UNKNOWN", "7.1"));
    };
    if m.registers.len() != expected {
        return Err(("MEASUREMENT_REGISTER_COUNT_INVALID", "7.1"));
    }
    Ok(Measurement {
        type_: t,
        // SPEC §7.3: normalize register values to lowercase before any
        // comparison or storage.
        registers: m.registers.iter().map(|r| r.to_lowercase()).collect(),
    })
}

fn classify_measurement_error(e: &MeasurementError) -> (&'static str, &'static str) {
    match e {
        MeasurementError::FormatMismatch => ("MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED", "7.3.5"),
        MeasurementError::RegisterMismatch => ("MEASUREMENT_MISMATCH", "7.3.1"),
        MeasurementError::TooFewRegisters => ("MEASUREMENT_REGISTER_COUNT_INVALID", "7.1"),
        MeasurementError::SnpMismatch => ("MEASUREMENT_MISMATCH", "7.3.3"),
        MeasurementError::Rtmr1Mismatch | MeasurementError::Rtmr2Mismatch => {
            ("MEASUREMENT_MISMATCH", "7.3.2")
        }
        MeasurementError::Rtmr3Mismatch => ("MEASUREMENT_RTMR3_NONZERO", "7.3.2"),
        _ => ("MEASUREMENT_MISMATCH", "7.3"),
    }
}

fn emit_measurement_rejection(code: &str, spec_ref: &str, message: &str) -> u8 {
    let body = json!({
        "stage": "verify-measurement",
        "accepted": false,
        "rejection": {
            "code": code,
            "spec_ref": spec_ref,
            "message": message,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_REJECT
}

fn cmd_verify_measurement() -> u8 {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("error reading stdin: {e}");
        return EXIT_INTERNAL;
    }
    let input: VerifyMeasurementInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("input schema violation: {e}");
            return EXIT_BAD_INPUT;
        }
    };
    if input.schema_version != "1" {
        eprintln!("schema_version must be \"1\"");
        return EXIT_BAD_INPUT;
    }

    let source = match normalize_measurement(&input.source) {
        Ok(m) => m,
        Err((code, spec_ref)) => {
            return emit_measurement_rejection(code, spec_ref, "source measurement invalid")
        }
    };
    let target = match input.target.as_ref().map(normalize_measurement).transpose() {
        Ok(t) => t,
        Err((code, spec_ref)) => {
            return emit_measurement_rejection(code, spec_ref, "target measurement invalid")
        }
    };

    let source_fp = source.fingerprint();
    let target_fp = target.as_ref().map(|t| t.fingerprint());

    if let Some(t) = target.as_ref() {
        if let Err(e) = source.equals(t) {
            let (code, spec_ref) = classify_measurement_error(&e);
            return emit_measurement_rejection(code, spec_ref, &e.to_string());
        }
    }

    let body = json!({
        "stage": "verify-measurement",
        "accepted": true,
        "outputs": {
            "source_fingerprint_hex": source_fp,
            "target_fingerprint_hex": target_fp,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_ACCEPT
}

// -----------------------------------------------------------------------------
// verify-hardware-measurements (SPEC §6)
// -----------------------------------------------------------------------------
//
// tinfoil-rs's verifier crate doesn't expose a dedicated SPEC §6.3 hardware-
// measurement matching function today (the algorithm is trivial enough to be
// inlined at the application layer). The conformance binary implements §6.3
// directly here so the SPEC behavior is testable cross-SDK; if/when a lib
// helper lands, swap this in.

#[derive(Debug, Deserialize)]
struct HardwareMeasurementInput {
    id: String,
    mrtd: String,
    rtmr0: String,
}

#[derive(Debug, Deserialize)]
struct VerifyHardwareInput {
    schema_version: String,
    enclave_measurement: MeasurementInput,
    hardware_measurements: Vec<HardwareMeasurementInput>,
}

fn emit_hardware_rejection(code: &str, spec_ref: &str, message: &str) -> u8 {
    let body = json!({
        "stage": "verify-hardware-measurements",
        "accepted": false,
        "rejection": {
            "code": code,
            "spec_ref": spec_ref,
            "message": message,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_REJECT
}

fn cmd_verify_hardware_measurements() -> u8 {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("error reading stdin: {e}");
        return EXIT_INTERNAL;
    }
    let input: VerifyHardwareInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("input schema violation: {e}");
            return EXIT_BAD_INPUT;
        }
    };
    if input.schema_version != "1" {
        eprintln!("schema_version must be \"1\"");
        return EXIT_BAD_INPUT;
    }

    // SPEC §6.3 step 1: enclave_measurement MUST be TdxGuestV2 with exactly 5
    // registers.
    if input.enclave_measurement.type_ != TDX_URI {
        return emit_hardware_rejection(
            "ENCLAVE_MEASUREMENT_TYPE_INVALID",
            "6.3",
            "enclave measurement type is not TdxGuestV2",
        );
    }
    if input.enclave_measurement.registers.len() != 5 {
        return emit_hardware_rejection(
            "ENCLAVE_REGISTER_COUNT_INVALID",
            "6.3",
            &format!(
                "TDX enclave measurement must have 5 registers, got {}",
                input.enclave_measurement.registers.len()
            ),
        );
    }

    // SPEC §7.3 lowercase normalization.
    let enclave_mrtd = input.enclave_measurement.registers[0].to_lowercase();
    let enclave_rtmr0 = input.enclave_measurement.registers[1].to_lowercase();

    // SPEC §6.3 step 3: return the FIRST matching hardware measurement.
    for hw in &input.hardware_measurements {
        if hw.mrtd.to_lowercase() == enclave_mrtd
            && hw.rtmr0.to_lowercase() == enclave_rtmr0
        {
            let body = json!({
                "stage": "verify-hardware-measurements",
                "accepted": true,
                "outputs": {
                    "matched_id": hw.id,
                    "matched_mrtd": hw.mrtd.to_lowercase(),
                    "matched_rtmr0": hw.rtmr0.to_lowercase(),
                }
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
            return EXIT_ACCEPT;
        }
    }
    emit_hardware_rejection("HARDWARE_NO_MATCH", "6.3", "no matching hardware platform found")
}

// =============================================================================
// verify-attestation-sev (SPEC §3 / AMD SEV-SNP)
// =============================================================================
//
// Wraps verifier::attestation::sev::verify_with_inline_collateral. The
// fixture's VCEK is supplied inline; if the fixture also supplies a
// synthetic ARK/ASK chain (Phase 4B-SEV), the SDK's pinned ARK SPKI
// fingerprint is overridden with the synthetic ARK's fingerprint so the
// chain accepts.
//
// Body fields are decoded locally (the lib only returns measurement +
// TLS/HPKE keys) so the output JSON matches the cross-SDK contract.

const SEV_GUEST_V2_URI: &str = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
const SEV_REPORT_LEN: usize = 1184;

#[derive(Debug, Deserialize, Default)]
struct SevPolicyInput {
    #[serde(default)]
    expected_measurement_hex: Option<String>,
    #[serde(default)]
    expected_host_data_hex: Option<String>,
    #[serde(default)]
    expected_report_data_hex: Option<String>,
    #[serde(default)]
    expected_id_key_digest_hex: Option<String>,
    #[serde(default)]
    expected_author_key_digest_hex: Option<String>,
    #[serde(default)]
    min_tcb_bl_spl: Option<u32>,
    #[serde(default)]
    min_tcb_tee_spl: Option<u32>,
    #[serde(default)]
    min_tcb_snp_spl: Option<u32>,
    #[serde(default)]
    min_tcb_ucode_spl: Option<u32>,
    #[serde(default)]
    enforce_spec_defaults: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyAttestationSevInput {
    // Same nested-vs-toplevel story as `Input.schema_version` — defaults to
    // "1" so the verify-full attestation_sev sub-block can omit it.
    #[serde(default = "default_schema_version")]
    schema_version: String,
    attestation_doc_b64: String,
    vcek_der_b64: String,
    #[serde(default)]
    amd_root_ca_pem: Option<String>,
    #[serde(default)]
    ask_pem: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    expiration_check_date_unix: Option<i64>,
    #[serde(default)]
    policy: Option<SevPolicyInput>,
}

fn emit_sev_rejection(code: &str, spec_ref: &str, message: &str) -> u8 {
    let body = json!({
        "stage": "verify-attestation-sev",
        "accepted": false,
        "rejection": {
            "code": code,
            "spec_ref": spec_ref,
            "message": message,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_REJECT
}

fn classify_sev_lib_error(msg: &str) -> (&'static str, &'static str) {
    let low = msg.to_lowercase();
    // Order matters — specific patterns before generic.

    // SPEC §3.2.2: guest_policy reserved-bit violations. tinfoil-rs's
    // report parser emits a few different phrasings depending on which
    // bit range is bad.
    if (low.contains("policy[") || low.contains("guest policy") || low.contains("policy bit"))
        && (low.contains("reserved") || low.contains("mbz") || low.contains("must be"))
    {
        return ("GUEST_POLICY_RESERVED_BIT_SET", "3.2.2");
    }
    // Report-format MBZ violations from the v2-style version-byte mutation:
    // "MBZ field reserved_v2 at [0x188:0x1a0] contains non-zero bytes".
    if low.contains("mbz field") || (low.contains("mbz") && low.contains("non-zero")) {
        return ("REPORT_FORMAT_UNSUPPORTED", "3.1");
    }

    // Truncated report: "Report too small: expected at least 1184 bytes, got N".
    if low.contains("report too small")
        || low.contains("report too short")
        || low.contains("truncated")
        || (low.contains("at least") && low.contains("bytes"))
    {
        return ("REPORT_TRUNCATED", "3.1");
    }

    if low.contains("expired") || low.contains("not yet valid") {
        return ("VCEK_EXPIRED", "3.3.3");
    }
    if low.contains("hwid") || (low.contains("chip_id") && low.contains("does not match")) {
        return ("VCEK_HWID_MISMATCH", "3.4.4");
    }
    // tinfoil-rs phrases TCB mismatches as e.g. "VCEK BL_SPL (5) does not
    // match report (10)" — match VCEK + SPL.
    if low.contains("vcek")
        && (low.contains("tcb") || low.contains("spl") || low.contains("does not match report"))
    {
        return ("VCEK_TCB_MISMATCH", "3.4.3");
    }
    if (low.contains("ark") || low.contains("amd root"))
        && (low.contains("fingerprint") || low.contains("mismatch") || low.contains("self-sign"))
    {
        return ("ARK_UNTRUSTED", "3.3.1");
    }
    if low.contains("ask") && (low.contains("not signed") || low.contains("invalid")) {
        return ("ASK_INVALID", "3.3.2");
    }
    // VCEK signature mismatch (cert-chain step) — phrased "VCEK signature
    // verification failed". Order matters: must come BEFORE the generic
    // "signature verification failed" → REPORT_SIGNATURE_INVALID branch.
    if low.contains("vcek") && low.contains("signature") {
        return ("VCEK_CHAIN_INVALID", "3.3.5");
    }
    // Plain "Signature verification failed: signature error" is the
    // report-signature step (verify_report_signature in the lib).
    if low.contains("signature verification failed") || low.contains("report signature") {
        return ("REPORT_SIGNATURE_INVALID", "3.6");
    }
    if low.contains("vcek")
        && (low.contains("chain") || low.contains("signed") || low.contains("malformed") || low.contains("verify"))
    {
        return ("VCEK_CHAIN_INVALID", "3.3.5");
    }
    if low.contains("certificate chain") || low.contains("malformed certificate") {
        return ("VCEK_CHAIN_INVALID", "3.3.5");
    }
    if low.contains("debug") {
        return ("GUEST_POLICY_DEBUG_SET", "3.7");
    }
    if low.contains("migration") || low.contains("migrate") {
        return ("GUEST_POLICY_MIGRATE_MA_SET", "3.7");
    }
    if low.contains("format")
        || low.contains("parse")
        || low.contains("decompress")
        || low.contains("decode")
        || low.contains("structure")
    {
        return ("REPORT_FORMAT_UNSUPPORTED", "3.1");
    }
    ("QV_RESULT_TERMINAL_UNSPECIFIED", "3")
}

fn parse_pem_certificate_to_der(pem: &str) -> Result<Vec<u8>, String> {
    // Strip the PEM headers and base64-decode.
    let trimmed = pem.trim();
    let mut in_body = false;
    let mut body = String::new();
    for line in trimmed.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN ") {
            in_body = true;
            continue;
        }
        if t.starts_with("-----END ") {
            break;
        }
        if in_body {
            body.push_str(t);
        }
    }
    if body.is_empty() {
        return Err("no PEM body found".to_string());
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("invalid PEM base64: {e}"))
}

fn spki_sha256_fingerprint(cert_der: &[u8]) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use x509_cert::Certificate;
    use der::{Decode, Encode};
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse cert DER: {e}"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("failed to re-encode SPKI: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&spki_der);
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Clone, Copy)]
struct SevBodyFields<'a> {
    bytes: &'a [u8],
}

impl<'a> SevBodyFields<'a> {
    fn new(report: &'a [u8]) -> Self {
        Self { bytes: report }
    }
    fn u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.bytes[off..off + 4].try_into().unwrap())
    }
    fn u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.bytes[off..off + 8].try_into().unwrap())
    }
    fn slice(&self, off: usize, n: usize) -> &'a [u8] {
        &self.bytes[off..off + n]
    }
    fn hex(&self, off: usize, n: usize) -> String {
        hex::encode(self.slice(off, n))
    }
    fn measurement_hex(&self) -> String {
        self.hex(0x90, 48)
    }
    fn host_data_hex(&self) -> String {
        self.hex(0xC0, 32)
    }
    fn report_data_hex(&self) -> String {
        self.hex(0x50, 64)
    }
    fn id_key_digest_hex(&self) -> String {
        self.hex(0xE0, 48)
    }
    fn author_key_digest_hex(&self) -> String {
        self.hex(0x110, 48)
    }
    fn current_tcb(&self) -> u64 {
        self.u64(0x38)
    }
    fn guest_policy(&self) -> u64 {
        self.u64(0x08)
    }
    fn json(&self) -> Value {
        let policy = self.guest_policy();
        let current_tcb = self.current_tcb();
        let platform_info = self.u64(0x40);
        let bit = |v: u64, i: u32| (v >> i) & 1 != 0;
        json!({
            "version": self.u32(0x00),
            "guest_svn": self.u32(0x04),
            "policy_hex": format!("{:016x}", policy),
            "policy_decoded": {
                "abi_minor": policy & 0xff,
                "abi_major": (policy >> 8) & 0xff,
                "smt": bit(policy, 16),
                "reserved_mbo": bit(policy, 17),
                "migrate_ma": bit(policy, 18),
                "debug": bit(policy, 19),
                "single_socket": bit(policy, 20),
                "cxl_allow": bit(policy, 21),
                "mem_aes_256_xts": bit(policy, 22),
                "raplmsr_dis": bit(policy, 23),
                "ciphertext_hiding_dram": bit(policy, 24),
            },
            "family_id_hex": self.hex(0x10, 16),
            "image_id_hex": self.hex(0x20, 16),
            "vmpl": self.u32(0x30),
            "signature_algo": self.u32(0x34),
            "current_tcb_hex": format!("{:016x}", current_tcb),
            "current_tcb_decoded": {
                "bl_spl": current_tcb & 0xff,
                "tee_spl": (current_tcb >> 8) & 0xff,
                "snp_spl": (current_tcb >> 48) & 0xff,
                "ucode_spl": (current_tcb >> 56) & 0xff,
            },
            "platform_info_hex": format!("{:016x}", platform_info),
            "platform_info_decoded": {
                "smt_en": bit(platform_info, 0),
                "tsme_en": bit(platform_info, 1),
                "ecc_en": bit(platform_info, 2),
                "rapl_dis": bit(platform_info, 3),
                "ciphertext_hiding": bit(platform_info, 4),
            },
            "signer_info_hex": format!("{:08x}", self.u32(0x48)),
            "report_data_hex": self.report_data_hex(),
            "measurement_hex": self.measurement_hex(),
            "host_data_hex": self.host_data_hex(),
            "id_key_digest_hex": self.id_key_digest_hex(),
            "author_key_digest_hex": self.author_key_digest_hex(),
            "report_id_hex": self.hex(0x140, 32),
            "report_id_ma_hex": self.hex(0x160, 32),
            "reported_tcb_hex": self.hex(0x180, 8),
            "chip_id_hex": self.hex(0x1A0, 64),
            "committed_tcb_hex": self.hex(0x1E8, 8),
            "current_build": self.bytes[0x1F0],
            "current_minor": self.bytes[0x1F1],
            "current_major": self.bytes[0x1F2],
            "committed_build": self.bytes[0x1F4],
            "committed_minor": self.bytes[0x1F5],
            "committed_major": self.bytes[0x1F6],
            "launch_tcb_hex": self.hex(0x1F8, 8),
        })
    }
}

fn enforce_sev_policy(report: &[u8], policy: Option<&SevPolicyInput>) -> Option<(&'static str, &'static str, String)> {
    // Run unconditional structural checks first — independent of fixture
    // policy — to catch what validate_report would have rejected.
    let guest_policy = u64::from_le_bytes(report[0x08..0x10].try_into().unwrap());
    if (guest_policy >> 18) & 1 != 0 {
        return Some((
            "GUEST_POLICY_MIGRATE_MA_SET",
            "3.7",
            format!("guest_policy MIGRATE_MA bit (18) is set (policy={:016x})", guest_policy),
        ));
    }
    let policy = match policy {
        Some(p) => p,
        None => return None,
    };
    let cmp = |label: &str, code: &'static str, spec_ref: &'static str, actual: &[u8], expected: Option<&str>| -> Option<(&'static str, &'static str, String)> {
        let exp = expected?.trim().to_lowercase();
        if exp.is_empty() {
            return None;
        }
        let actual_hex = hex::encode(actual);
        if actual_hex != exp {
            return Some((code, spec_ref, format!("{label} {actual_hex} != policy expected {exp}")));
        }
        None
    };
    if let Some(v) = cmp("measurement", "MEASUREMENT_MISMATCH", "3.8",
        &report[0x90..0x90 + 48], policy.expected_measurement_hex.as_deref()) { return Some(v); }
    if let Some(v) = cmp("host_data", "HOST_DATA_MISMATCH", "8.3",
        &report[0xC0..0xC0 + 32], policy.expected_host_data_hex.as_deref()) { return Some(v); }
    if let Some(v) = cmp("report_data", "REPORT_DATA_MISMATCH", "8.2",
        &report[0x50..0x90], policy.expected_report_data_hex.as_deref()) { return Some(v); }
    if let Some(v) = cmp("id_key_digest", "ID_KEY_DIGEST_MISMATCH", "3.1.1",
        &report[0xE0..0xE0 + 48], policy.expected_id_key_digest_hex.as_deref()) { return Some(v); }
    if let Some(v) = cmp("author_key_digest", "AUTHOR_KEY_DIGEST_MISMATCH", "3.1.1",
        &report[0x110..0x110 + 48], policy.expected_author_key_digest_hex.as_deref()) { return Some(v); }

    let current_tcb = u64::from_le_bytes(report[0x38..0x40].try_into().unwrap());
    let tcb_pairs = [
        ("bl_spl", (current_tcb & 0xff) as u32, policy.min_tcb_bl_spl),
        ("tee_spl", ((current_tcb >> 8) & 0xff) as u32, policy.min_tcb_tee_spl),
        ("snp_spl", ((current_tcb >> 48) & 0xff) as u32, policy.min_tcb_snp_spl),
        ("ucode_spl", ((current_tcb >> 56) & 0xff) as u32, policy.min_tcb_ucode_spl),
    ];
    for (name, actual, min) in tcb_pairs {
        if let Some(m) = min {
            if actual < m {
                return Some((
                    "TCB_OUT_OF_DATE",
                    "3.7",
                    format!("tcb.{name}={actual} below minimum {m}"),
                ));
            }
        }
    }

    if policy.enforce_spec_defaults {
        if (guest_policy >> 19) & 1 != 0 {
            return Some((
                "GUEST_POLICY_DEBUG_SET",
                "3.7",
                format!("guest_policy DEBUG bit (19) is set (policy={:016x})", guest_policy),
            ));
        }
        if (guest_policy >> 17) & 1 == 0 {
            return Some((
                "GUEST_POLICY_RESERVED_BIT_SET",
                "3.7",
                format!("guest_policy reserved-MBO bit (17) is clear (policy={:016x})", guest_policy),
            ));
        }
        if guest_policy & 0xFFFFFFFF_FE000000 != 0 {
            return Some((
                "GUEST_POLICY_RESERVED_BIT_SET",
                "3.7",
                format!("guest_policy reserved-MBZ bit (>=25) set (policy={:016x})", guest_policy),
            ));
        }
    }
    None
}

/// Parse + verify the SEV input; on success returns the decoded report bytes.
/// Factored so verify-full can re-use it.
fn run_verify_attestation_sev_inner(input: &VerifyAttestationSevInput) -> Result<Vec<u8>, (String, String, String)> {
    use base64::Engine as _;
    use tinfoil::verifier::attestation::sev as sevlib;
    use tinfoil::verifier::attestation::types::ValidationOptions;

    if input.schema_version != "1" {
        return Err(("REPORT_FORMAT_UNSUPPORTED".to_string(), "3.1".to_string(),
                    "schema_version != \"1\"".to_string()));
    }

    // The lib's verify_with_inline_collateral takes the gzipped+base64
    // body string and the VCEK DER bytes directly.
    let vcek_der = match base64::engine::general_purpose::STANDARD.decode(&input.vcek_der_b64) {
        Ok(b) => b,
        Err(e) => return Err(("VCEK_CHAIN_INVALID".to_string(), "3.3".to_string(),
                              format!("vcek_der_b64 not valid base64: {e}"))),
    };

    // Build the ASK || ARK cert chain PEM. If the fixture provides synth
    // ARK + ASK, use those + derive the synth ARK SPKI fingerprint so the
    // lib's pinned-ARK check accepts the synthetic root. Otherwise fall
    // back to the lib's embedded production AMD Genoa chain.
    let (cert_chain_pem, trusted_ark_fp) = match (input.amd_root_ca_pem.as_deref(), input.ask_pem.as_deref()) {
        (Some(ark), Some(ask)) => {
            let ark_der = match parse_pem_certificate_to_der(ark) {
                Ok(d) => d,
                Err(e) => return Err(("ARK_UNTRUSTED".to_string(), "3.3.1".to_string(),
                                      format!("could not parse fixture amd_root_ca_pem: {e}"))),
            };
            let fp = match spki_sha256_fingerprint(&ark_der) {
                Ok(s) => s,
                Err(e) => return Err(("ARK_UNTRUSTED".to_string(), "3.3.1".to_string(),
                                      format!("could not compute synth ARK SPKI fingerprint: {e}"))),
            };
            // Lib expects ASK || ARK PEM concatenation.
            let chain = format!("{}\n{}\n", ask.trim(), ark.trim());
            (chain.into_bytes(), Some(fp))
        }
        _ => {
            // Embedded production Genoa chain. The lib's pinned-ARK check
            // applies — fixtures asserting the real-Genoa chain pass; synth
            // chains would only get here if they forgot to set the PEMs
            // and they'd correctly fail the pinned-ARK check.
            (tinfoil::verifier::embedded::GENOA_CERT_CHAIN.to_vec(), None)
        }
    };

    let options = ValidationOptions::default();
    match sevlib::verify_with_inline_collateral(
        &input.attestation_doc_b64,
        &vcek_der,
        &cert_chain_pem,
        &options,
        trusted_ark_fp.as_deref(),
    ) {
        Ok(_v) => {
            // The lib returns a Verification but we want the raw decoded
            // report bytes for body-field decoding and policy enforcement.
            // Re-decode locally — the lib has the same logic but the bytes
            // aren't exposed.
            use flate2::read::GzDecoder;
            use std::io::Read as _;
            let gz_bytes = base64::engine::general_purpose::STANDARD
                .decode(&input.attestation_doc_b64)
                .map_err(|e| ("REPORT_FORMAT_UNSUPPORTED".to_string(), "3.1".to_string(),
                              format!("attestation_doc_b64 not valid base64: {e}")))?;
            let mut dec = GzDecoder::new(&gz_bytes[..]);
            let mut report = Vec::new();
            dec.read_to_end(&mut report)
                .map_err(|e| ("REPORT_FORMAT_UNSUPPORTED".to_string(), "3.1".to_string(),
                              format!("gzip decompress failed: {e}")))?;
            if report.len() < SEV_REPORT_LEN {
                return Err(("REPORT_TRUNCATED".to_string(), "3.1".to_string(),
                            format!("SEV report is {} bytes, expected >= {SEV_REPORT_LEN}", report.len())));
            }
            if let Some((code, spec_ref, msg)) = enforce_sev_policy(&report, input.policy.as_ref()) {
                return Err((code.to_string(), spec_ref.to_string(), msg));
            }
            Ok(report)
        }
        Err(e) => {
            let msg = format!("{e}");
            let (code, spec_ref) = classify_sev_lib_error(&msg);
            Err((code.to_string(), spec_ref.to_string(), msg))
        }
    }
}

fn cmd_verify_attestation_sev() -> u8 {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("error reading stdin: {e}");
        return EXIT_INTERNAL;
    }
    let input: VerifyAttestationSevInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("input schema violation: {e}");
            return EXIT_BAD_INPUT;
        }
    };
    let report = match run_verify_attestation_sev_inner(&input) {
        Ok(r) => r,
        Err((code, spec_ref, msg)) => return emit_sev_rejection(&code, &spec_ref, &msg),
    };

    // Policy enforcement (Phase 4 pins + 4B normative checks).
    if let Some((code, spec_ref, msg)) = enforce_sev_policy(&report, input.policy.as_ref()) {
        return emit_sev_rejection(code, spec_ref, &msg);
    }

    let fields = SevBodyFields::new(&report);
    let body = json!({
        "stage": "verify-attestation-sev",
        "accepted": true,
        "outputs": {
            "measurement": {
                "type": SEV_GUEST_V2_URI,
                "registers": [fields.measurement_hex()],
            },
            "body_fields": fields.json(),
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_ACCEPT
}

// =============================================================================
// verify-full (SPEC §11)
// =============================================================================
//
// Chains verify-sigstore + verify-attestation-sev + a Measurement::equals
// cross-stage comparison. Mirrors the Go conformance binary's verify-full
// orchestration.

#[derive(Debug, Deserialize)]
struct VerifyFullInput {
    schema_version: String,
    mode: String,
    #[serde(default)]
    sigstore: Option<Input>,
    #[serde(default)]
    attestation_sev: Option<VerifyAttestationSevInput>,
    #[serde(default)]
    pinned_measurement: Option<MeasurementInput>,
}

fn emit_full_rejection(code: &str, stage: &str, spec_ref: &str, message: &str) -> u8 {
    let body = json!({
        "stage": "verify-full",
        "accepted": false,
        "rejection": {
            "code": code,
            "stage": stage,
            "spec_ref": spec_ref,
            "message": message,
        }
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    EXIT_REJECT
}

fn measurement_from_sigstore_result(r: &SigstoreResult) -> Result<Measurement, String> {
    // PredicateType is #[non_exhaustive]; clone via as_url() lookup keeps us
    // forward-compatible. If a new variant lands, the harness sees the URL
    // and a future Measurement::equals would handle it.
    let pt = match r.measurement.type_ {
        PredicateType::SevGuestV2 => PredicateType::SevGuestV2,
        PredicateType::TdxGuestV2 => PredicateType::TdxGuestV2,
        PredicateType::SnpTdxMultiPlatformV1 => PredicateType::SnpTdxMultiPlatformV1,
        _ => return Err(format!("unknown predicate type: {}", r.measurement.type_.as_url())),
    };
    Ok(Measurement {
        type_: pt,
        registers: r.measurement.registers.clone(),
    })
}

fn cmd_verify_full() -> u8 {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("error reading stdin: {e}");
        return EXIT_INTERNAL;
    }
    let input: VerifyFullInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => {
            return emit_full_rejection("BUNDLE_MALFORMED", "verify-full", "11",
                &format!("input is not valid JSON: {e}"));
        }
    };
    if input.schema_version != "1" {
        return emit_full_rejection("BUNDLE_MALFORMED", "verify-full", "11",
            "input.schema_version != \"1\"");
    }

    match input.mode.as_str() {
        "standard" | "bundle" => {
            // Step 1: Sigstore.
            let sig_in = match input.sigstore {
                Some(s) => s,
                None => return emit_full_rejection("BUNDLE_MALFORMED", "verify-full", "11.1",
                    "mode=\"standard\"/\"bundle\" requires \"sigstore\" input block"),
            };
            let sigstore_result = match run_verify_sigstore_inner(&sig_in) {
                Ok(r) => r,
                Err((code, spec_ref, msg)) =>
                    return emit_full_rejection(&code, "verify-sigstore", &spec_ref, &msg),
            };
            let sigstore_m = match measurement_from_sigstore_result(&sigstore_result) {
                Ok(m) => m,
                Err(e) => return emit_full_rejection("PREDICATE_MEASUREMENT_INVALID",
                    "verify-sigstore", "5.5", &e),
            };

            // Step 2: SEV attestation.
            let sev_in = match input.attestation_sev {
                Some(s) => s,
                None => return emit_full_rejection("BUNDLE_MALFORMED", "verify-full", "11.1",
                    "mode=\"standard\"/\"bundle\" requires attestation_sev"),
            };
            let report = match run_verify_attestation_sev_inner(&sev_in) {
                Ok(r) => r,
                Err((code, spec_ref, msg)) =>
                    return emit_full_rejection(&code, "verify-attestation-sev", &spec_ref, &msg),
            };
            let fields = SevBodyFields::new(&report);
            let att_m = Measurement {
                type_: PredicateType::SevGuestV2,
                registers: vec![fields.measurement_hex()],
            };

            // Step 3: cross-stage measurement comparison (SPEC §7.3).
            if let Err(e) = sigstore_m.equals(&att_m) {
                let (code, spec_ref) = classify_measurement_error(&e);
                return emit_full_rejection(code, "verify-measurement", spec_ref, &e.to_string());
            }

            let fp = att_m.fingerprint();
            let body = json!({
                "stage": "verify-full",
                "accepted": true,
                "outputs": {
                    "mode": input.mode,
                    "platform": "sev-snp",
                    "sigstore_measurement": {
                        "type": sigstore_m.type_.as_url(),
                        "registers": sigstore_m.registers,
                    },
                    "attestation_measurement": {
                        "type": att_m.type_.as_url(),
                        "registers": att_m.registers,
                    },
                    "final_measurement_fingerprint_hex": fp,
                }
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
            EXIT_ACCEPT
        }
        "pinned" => {
            let pin = match input.pinned_measurement {
                Some(p) => p,
                None => return emit_full_rejection("BUNDLE_MALFORMED", "verify-full", "11.3",
                    "mode=\"pinned\" requires \"pinned_measurement\""),
            };
            let pin_m = match normalize_measurement(&pin) {
                Ok(m) => m,
                Err((code, spec_ref)) =>
                    return emit_full_rejection(code, "verify-full", spec_ref,
                        "pinned_measurement invalid"),
            };
            let sev_in = match input.attestation_sev {
                Some(s) => s,
                None => return emit_full_rejection("BUNDLE_MALFORMED", "verify-full", "11.3",
                    "mode=\"pinned\" requires attestation_sev"),
            };
            let report = match run_verify_attestation_sev_inner(&sev_in) {
                Ok(r) => r,
                Err((code, spec_ref, msg)) =>
                    return emit_full_rejection(&code, "verify-attestation-sev", &spec_ref, &msg),
            };
            let fields = SevBodyFields::new(&report);
            let att_m = Measurement {
                type_: PredicateType::SevGuestV2,
                registers: vec![fields.measurement_hex()],
            };
            if let Err(e) = pin_m.equals(&att_m) {
                let (code, spec_ref) = classify_measurement_error(&e);
                return emit_full_rejection(code, "verify-measurement", spec_ref, &e.to_string());
            }
            let fp = att_m.fingerprint();
            let body = json!({
                "stage": "verify-full",
                "accepted": true,
                "outputs": {
                    "mode": "pinned",
                    "platform": "sev-snp",
                    "attestation_measurement": {
                        "type": att_m.type_.as_url(),
                        "registers": att_m.registers,
                    },
                    "final_measurement_fingerprint_hex": fp,
                }
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
            EXIT_ACCEPT
        }
        other => emit_full_rejection("BUNDLE_MALFORMED", "verify-full", "11",
            &format!("unknown mode {other:?} (allowed: standard, bundle, pinned)")),
    }
}
