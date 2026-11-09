//! Strict parse of a Sigstore bundle: only the canonical protobuf JSON encoding is accepted
//! (lowerCamelCase names from sigstore/protobuf-specs, int64 as decimal strings, bytes as padded
//! standard base64, no unknown fields, no duplicate keys). serde's derive rejects unknown and
//! repeated fields; the newtypes below check the string encodings. The verifier keeps working on
//! the untyped `Value` this returns, so these types exist for validation only.
#![allow(dead_code)]

use crate::error::{Error, Result};
use base64::Engine;
use serde::Deserialize;

/// Canonical base64: standard alphabet, padded, no whitespace, so re-encoding reproduces the input.
#[derive(Deserialize)]
#[serde(try_from = "String")]
struct B64(String);

impl TryFrom<String> for B64 {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, String> {
        let engine = base64::engine::general_purpose::STANDARD;
        match engine.decode(&s) {
            Ok(bytes) if engine.encode(&bytes) == s => Ok(B64(s)),
            _ => Err(format!("non-canonical base64: {}", s.chars().take(16).collect::<String>())),
        }
    }
}

/// Non-negative int64 as protojson prints it: a decimal string.
#[derive(Deserialize)]
#[serde(try_from = "String")]
struct Int64(String);

impl TryFrom<String> for Int64 {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, String> {
        if !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<i64>().is_ok() {
            Ok(Int64(s))
        } else {
            Err(format!("expected a non-negative int64 string, got {s:?}"))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    media_type: String,
    verification_material: VerificationMaterial,
    message_signature: Option<MessageSignature>,
    dsse_envelope: Option<DsseEnvelope>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationMaterial {
    public_key: Option<PublicKeyIdentifier>,
    x509_certificate_chain: Option<X509CertificateChain>,
    certificate: Option<X509Certificate>,
    #[serde(default)]
    tlog_entries: Vec<TransparencyLogEntry>,
    timestamp_verification_data: Option<TimestampVerificationData>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyIdentifier {
    hint: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X509CertificateChain {
    #[serde(default)]
    certificates: Vec<X509Certificate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct X509Certificate {
    raw_bytes: B64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransparencyLogEntry {
    log_index: Int64,
    log_id: LogId,
    kind_version: KindVersion,
    integrated_time: Option<Int64>,
    inclusion_promise: Option<InclusionPromise>,
    inclusion_proof: Option<InclusionProof>,
    canonicalized_body: Option<B64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogId {
    key_id: B64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KindVersion {
    kind: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InclusionPromise {
    signed_entry_timestamp: B64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InclusionProof {
    log_index: Int64,
    root_hash: B64,
    tree_size: Int64,
    #[serde(default)]
    hashes: Vec<B64>,
    checkpoint: Checkpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    envelope: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TimestampVerificationData {
    #[serde(default)]
    rfc3161_timestamps: Vec<Rfc3161SignedTimestamp>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Rfc3161SignedTimestamp {
    signed_timestamp: B64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MessageSignature {
    message_digest: Option<MessageDigest>,
    signature: B64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageDigest {
    algorithm: String,
    digest: B64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DsseEnvelope {
    payload: B64,
    payload_type: String,
    #[serde(default)]
    signatures: Vec<DsseSignature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DsseSignature {
    sig: B64,
    keyid: Option<String>,
}

/// Parse bundle JSON, rejecting anything but the canonical protobuf JSON encoding.
pub fn parse_bundle(json: &[u8]) -> Result<serde_json::Value> {
    let parse_err = |e: serde_json::Error| Error::SigstoreVerification(format!("Failed to parse bundle: {e}"));
    serde_json::from_slice::<Bundle>(json).map_err(parse_err)?;
    serde_json::from_slice(json).map_err(parse_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const V1: &str = include_str!("../../../assets/rekor_test_bundle.json");
    const V2: &str = include_str!("../../../assets/rekor2_dsse_test_bundle.json");

    fn rejects(json: &str, what: &str) {
        let err = parse_bundle(json.as_bytes()).expect_err(what).to_string();
        assert!(err.starts_with("Failed to parse bundle"), "{what}: {err}");
    }

    /// The fixture with one value replaced, re-serialized (serde_json emits canonical protojson).
    fn mutated(json: &str, f: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        f(&mut v);
        v.to_string()
    }

    #[test]
    fn canonical_fixtures_parse() {
        for json in [V1, V2] {
            let v = parse_bundle(json.as_bytes()).unwrap();
            assert!(v["verificationMaterial"]["tlogEntries"].is_array());
        }
    }

    #[test]
    fn rejects_non_canonical_encodings() {
        rejects(&V1.replacen('{', "{\"zzz\": 1,", 1), "unknown top-level field");
        rejects(&V1.replacen("\"kindVersion\": {", "\"kindVersion\": {\"zzz\": 1,", 1), "unknown nested field");
        rejects(&V1.replacen('{', "{\"mediaType\": \"x\",", 1), "duplicate key");
        rejects(&V1.replacen("\"logIndex\"", "\"log_index\"", 1), "snake_case key");
        fn entry(v: &mut serde_json::Value) -> &mut serde_json::Value {
            &mut v["verificationMaterial"]["tlogEntries"][0]
        }
        rejects(&mutated(V1, |v| entry(v)["logIndex"] = json!(845420855)), "int64 as number");
        rejects(&mutated(V1, |v| entry(v)["logIndex"] = json!("-1")), "negative int64");
        rejects(&mutated(V1, |v| entry(v)["logIndex"] = json!("9223372036854775808")), "int64 overflow");
        for bad in ["AA", "AA==\n", "-_8=", "AB=="] {
            rejects(&mutated(V1, |v| v["dsseEnvelope"]["payload"] = json!(bad)), "non-canonical base64");
        }
        rejects(&mutated(V1, |v| v["dsseEnvelope"]["payloadType"] = json!(5)), "string as number");
        rejects(&mutated(V1, |v| v["verificationMaterial"] = json!(null)), "required message null");
        rejects(&mutated(V1, |v| v["dsseEnvelope"]["signatures"][0]["sig"] = json!(null)), "required bytes null");
        rejects("not json", "malformed");
    }

    #[test]
    fn accepts_absent_optional_fields_and_public_key_hint() {
        let v = mutated(V2, |v| {
            let vm = &mut v["verificationMaterial"];
            vm["publicKey"] = json!({"hint": "k"});
            vm.as_object_mut().unwrap().remove("certificate");
        });
        parse_bundle(v.as_bytes()).unwrap();
        parse_bundle(mutated(V2, |v| v["dsseEnvelope"]["signatures"][0]["keyid"] = json!(null)).as_bytes()).unwrap();
    }
}
