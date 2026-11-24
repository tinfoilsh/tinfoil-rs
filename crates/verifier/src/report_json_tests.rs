//! Tests of the JSON form of a report against the golden files in
//! `tests/data/report-json`, which every Tinfoil SDK shares.
//!
//! A golden file that names a conformance vector is checked by the
//! conformance adapter's tests, which have the vectors. The others are
//! built here, from the same inputs as the SDK that wrote them.

use std::time::SystemTime;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::encode_lower_hex;
use crate::document::collateral::FORMAT_V3;
use crate::document::tests::TestDocument;
use crate::error::{Error, Layer};
use crate::instant::Instant;
use crate::measurement::{Expected, Measurement, REGISTER_SIZE, Register};
use crate::report::{ReportBuilder, VerificationReport};
use crate::verification::{
    ArtifactVerification, ConfigVerification, ReferenceSource, SoftwareIdentity,
    VerificationMetadata, VerifiedFacts,
};
use crate::{
    ArtifactTrust, CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, CRYPTO_MATERIAL_V1_FORMAT,
    ConfigTrust, CryptoMaterialItem, EmbeddedConfig, KEY_SPKI_FP_SHA256_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE, Pin, Policy, Verifier,
};

/// The members of the form that hold a time.
const TIME_MEMBERS: [&str; 4] = [
    "approval_time",
    "signature_time",
    "freshness_expires_at",
    "verified_at",
];

/// The golden file `name`.
fn golden(name: &str) -> Value {
    let path = format!(
        "{}/tests/data/report-json/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// `value`, a report's JSON form, as the golden files are compared across
/// SDKs: without the step messages, which are each SDK's own text, and
/// without `metadata`, which describes the run; and with each time in one
/// spelling of its instant.
fn comparable(mut value: Value) -> Value {
    fn times(value: &mut Value) {
        match value {
            Value::Object(members) => {
                for (name, member) in members.iter_mut() {
                    if let (true, Value::String(text)) =
                        (TIME_MEMBERS.contains(&name.as_str()), &mut *member)
                    {
                        *text = Instant::parse_rfc3339(text).unwrap().to_rfc3339();
                    } else {
                        times(member);
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

/// Checks the JSON form of `report` against the golden file `name`, and
/// that the form keeps its encoding rules.
fn assert_golden(name: &str, report: &VerificationReport) {
    let text = report.to_json();
    let got: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        comparable(got.clone()),
        comparable(golden(name)["report"].clone()),
        "{name}: {text}"
    );
    assert_no_null_or_empty_string(&got);
    #[cfg(feature = "serde")]
    assert_eq!(serde_json::to_value(report).unwrap(), got, "{name}");
}

/// The form never holds `null` or `""`.
fn assert_no_null_or_empty_string(value: &Value) {
    match value {
        Value::Null => panic!("null in the JSON form"),
        Value::String(text) => assert!(!text.is_empty(), "\"\" in the JSON form"),
        Value::Array(items) => items.iter().for_each(assert_no_null_or_empty_string),
        Value::Object(members) => members.values().for_each(assert_no_null_or_empty_string),
        _ => {}
    }
}

/// The appraisal instant of the built cases.
fn golden_at() -> SystemTime {
    Instant::parse_rfc3339("2026-01-02T02:04:05Z")
        .unwrap()
        .to_system_time()
        .unwrap()
}

fn time(text: &str) -> Option<SystemTime> {
    Instant::parse_rfc3339(text).unwrap().to_system_time()
}

/// The verified facts of a config-based verification on SEV-SNP, with
/// every record member: the facts that the golden file
/// `acceptance-config-facts` was written from.
fn golden_config_facts() -> VerifiedFacts {
    let mut launch = [0; REGISTER_SIZE];
    launch[..2].copy_from_slice(&[0xab, 0xcd]);
    let launch = Register::new(launch);
    let approved = time("2026-09-20T08:00:00.0000005Z");
    VerifiedFacts {
        config_repo: "tinfoilsh/cvmimage".to_owned(),
        code_digest: "0a".repeat(32),
        code_tag: "v0.15.0".to_owned(),
        code_measurement: Expected::SevSnp {
            launch: Some(launch),
        },
        enclave_measurement: Measurement::SevSnp { launch },
        config: Some(ConfigVerification {
            source: ReferenceSource::Endorsement,
            name: Some("/org/project/v1".to_owned()),
            digest: "0c".repeat(32),
            reference: Some("org/project@v1".to_owned()),
            signing_key_hint: Some("hint".to_owned()),
            approval_time: approved,
            registry_id: Some("registry".to_owned()),
            signature_time: time("2026-09-20T08:01:00.0000005Z"),
        }),
        runtime: Some(ArtifactVerification {
            source: ReferenceSource::Endorsement,
            repo: Some("tinfoilsh/cvmimage".to_owned()),
            tag: Some("v0.15.0".to_owned()),
            digest: "0a".repeat(32),
            name: Some("runtime".to_owned()),
            commit: Some("0e".repeat(20)),
            approval_time: approved,
        }),
        platform: Some(ArtifactVerification {
            source: ReferenceSource::Embedded,
            repo: None,
            tag: None,
            digest: "0f".repeat(32),
            name: None,
            commit: None,
            approval_time: None,
        }),
        crypto_material: vec![
            CryptoMaterialItem {
                id: CRYPTO_MATERIAL_ID_TLS.to_owned(),
                format: KEY_SPKI_FP_SHA256_V1_FORMAT.to_owned(),
                data: "ab".repeat(32),
            },
            CryptoMaterialItem {
                id: CRYPTO_MATERIAL_ID_HPKE.to_owned(),
                format: KEY_X25519_HPKE_V1_FORMAT.to_owned(),
                data: "11".repeat(32),
            },
        ],
        freshness_expires_at: time("2026-10-03T12:00:00Z"),
    }
}

fn golden_metadata() -> VerificationMetadata {
    VerificationMetadata {
        verifier: SoftwareIdentity {
            name: "tinfoil-rs".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        verified_at: golden_at(),
    }
}

/// A document with an SEV-SNP quote that isn't authentic, that endorses no
/// keys, and whose collateral is empty.
fn document_without_keys() -> (Vec<u8>, Vec<u8>) {
    let nonce = vec![0; NONCE_SIZE];
    let document = TestDocument::new(&nonce)
        .with_crypto_material(&format!(
            r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}","items":[]}}"#
        ))
        .with_collateral(Some(FORMAT_V3), "[]")
        .render();
    (document.into_bytes(), nonce)
}

/// The report of the rejection that verifying `document` with `verifier`
/// and `pin` must be, at `layer`.
fn rejected(verifier: &Verifier, pin: &Pin, layer: Layer) -> VerificationReport {
    let (document, nonce) = document_without_keys();
    match verifier.verify_v3_at(&document, &nonce, pin, golden_at()) {
        Err(Error::Verification(rejected)) => {
            assert_eq!(rejected.layer(), layer, "{rejected}");
            rejected.report().clone()
        }
        other => panic!("want a rejection at {layer}, got {other:?}"),
    }
}

/// A config-based verification's facts, which no shared vector produces:
/// every record member, and times with a fraction of a second.
#[test]
fn the_facts_of_a_config_based_verification_match_the_golden_file() {
    let mut steps = ReportBuilder::new();
    for layer in [
        Layer::Envelope,
        Layer::Provenance,
        Layer::Quote,
        Layer::Policy,
    ] {
        steps.passed(layer);
    }
    let report = steps.passed_all(golden_config_facts(), golden_metadata());
    assert_golden("acceptance-config-facts", &report);
}

/// A document that endorses no keys passes the envelope step with nothing
/// to measure, so the report holds `"measured": {}`.
#[test]
fn a_provenance_rejection_without_keys_matches_the_golden_file() {
    let verifier = Verifier::new(ConfigTrust::default(), Policy::default()).unwrap();
    let report = rejected(&verifier, &Pin::project("org/project"), Layer::Provenance);
    assert_golden("rejection-provenance-no-keys", &report);
}

/// Every reference value is embedded, so provenance is skipped, and the
/// quote step rejects a quote that isn't authentic: expected facts without
/// the full measurement, and measured facts without a CPU measurement.
#[test]
fn a_quote_rejection_after_a_skipped_provenance_matches_the_golden_file() {
    let zero = "00".repeat(REGISTER_SIZE);
    let runtime = format!(
        r#"{{"version":"v0.15.0","igvm":{{"format_version":1,"snp_launch":{{"measurement":"{}"}},"tdx_launch":{{"mrtd":"{}","rtmr0":"{zero}","rtmr1":"{zero}","rtmr2":"{zero}","rtmr3":"{zero}"}}}}}}"#,
        "ab".repeat(REGISTER_SIZE),
        "cd".repeat(REGISTER_SIZE),
    )
    .into_bytes();
    let config = format!(
        "cvm-version: 0.15.0@sha256:{}\n",
        encode_lower_hex(&Sha256::digest(&runtime))
    )
    .into_bytes();
    let platform = br#"{"format":"https://tinfoil.sh/predicate/platform-endorsements/v2","machines":{},"policies":{}}"#;
    let verifier = Verifier::new(
        ConfigTrust::Embedded(EmbeddedConfig::Bytes {
            bytes: config,
            name: Some("/org/project/v1".to_owned()),
        }),
        Policy {
            artifacts: ArtifactTrust::Embedded {
                runtime: Some(runtime),
                platform: Some(platform.to_vec()),
                freshness_keys: None,
            },
            ..Policy::default()
        },
    )
    .unwrap();
    let report = rejected(&verifier, &Pin::none(), Layer::Quote);
    assert_golden("rejection-quote-skipped-provenance", &report);
}

/// The verified facts on their own are the `verified_facts` member of the
/// report, and hold the channel keys only in `crypto_material`.
#[test]
fn the_verified_facts_are_the_member_of_the_report() {
    let facts = golden_config_facts();
    let report: Value = serde_json::from_str(
        &ReportBuilder::new()
            .passed_all(facts.clone(), golden_metadata())
            .to_json(),
    )
    .unwrap();
    let member = &report["verified_facts"];
    assert_eq!(
        *member,
        serde_json::from_str::<Value>(&facts.to_json()).unwrap()
    );
    #[cfg(feature = "serde")]
    assert_eq!(serde_json::to_value(&facts).unwrap(), *member);
    let text = member.to_string();
    assert!(!text.contains("tls_public_key_fp"), "{text}");
    assert!(!text.contains("hpke_public_key"), "{text}");
    assert_eq!(report["schema_version"], VerificationReport::SCHEMA_VERSION);
    assert_eq!(VerificationReport::SCHEMA_VERSION, 1);
    assert_eq!(report["metadata"]["verifier"]["name"], "tinfoil-rs");
}

/// A rejection keeps an established but empty fact, as `{}`, and leaves
/// out what was not established and a verifier without a name.
#[test]
fn a_rejection_keeps_empty_facts_and_leaves_out_absent_ones() {
    let mut metadata = golden_metadata();
    metadata.verifier.name = String::new();
    let report = ReportBuilder::new().failed(Layer::Envelope, "bad".to_owned(), metadata);
    let value: Value = serde_json::from_str(&report.to_json()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "schema_version": 1,
            "steps": [
                {"layer": "envelope", "status": "failed", "message": "bad"},
                {"layer": "provenance", "status": "not_run"},
                {"layer": "quote", "status": "not_run"},
                {"layer": "policy", "status": "not_run"}
            ],
            "partial_facts": {},
            "metadata": {"verified_at": "2026-01-02T02:04:05Z"}
        })
    );
    #[cfg(feature = "serde")]
    {
        let partial = report.partial_facts().unwrap();
        assert_eq!(
            serde_json::to_value(partial).unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::to_value(&report.steps()[1]).unwrap(),
            serde_json::json!({"layer": "provenance", "status": "not_run"})
        );
        assert_eq!(
            serde_json::to_value(report.metadata()).unwrap(),
            serde_json::json!({"verified_at": "2026-01-02T02:04:05Z"})
        );
    }
}
