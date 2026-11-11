//! Replays recorded bundles through the provenance functions.
//!
//! `provenance_cases.json` holds bundles minted under a synthetic trusted
//! root: code releases, platform policy artifacts, freshness witnesses and
//! runtime releases, each one change away from a well-formed case in its
//! statement, its signing certificate or the values that it is verified
//! against. A case stores the parts of its bundle that differ from case to
//! case; the rest of the bundle follows from them. Each case records the
//! outcome of a second, independent implementation of the same rules
//! (`reference`). The outcome here must be the same, except where a case
//! names the rule by which this module is the `stricter` one; no case that
//! the other implementation turns down is accepted here.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::provenance::ProvenanceClient;
use super::reference::{AuthenticatedArtifact, Reference, parse_reference};
use crate::canonical::encode_lower_hex;
use crate::document::collateral::{Runtime, RuntimeReference};
use crate::instant::Instant;
use crate::json::{self, Object, Value};

const CASES: &[u8] = include_bytes!("../../tests/data/endorsement/provenance_cases.json");

fn text<'a>(object: &'a Object, name: &str) -> &'a str {
    object
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no text member {name}"))
}

fn optional_text<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

fn integer(value: &Value) -> i64 {
    value.as_number().unwrap().as_str().parse().unwrap()
}

fn member<'a>(object: &'a Object, name: &str) -> &'a Object {
    object.get(name).and_then(Value::as_object).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_lower_hex(&Sha256::digest(bytes))
}

/// The bundle of a case: a version 0.3 bundle with one `dsse` log entry
/// that carries a signed entry timestamp and an inclusion proof in a log of
/// one entry.
fn bundle(case: &Object, certificates: &[Value], log_id: &str) -> Value {
    let statement = text(case, "statement").as_bytes();
    let certificate = certificates
        [usize::try_from(integer(case.get("certificate").unwrap())).unwrap()]
    .as_str()
    .unwrap();
    let signature = text(case, "signature");
    let payload = STANDARD.encode(statement);
    let envelope = format!(
        r#"{{"payload":"{payload}","payloadType":"application/vnd.in-toto+json","signatures":[{{"sig":"{signature}"}}]}}"#
    );
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in certificate.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    let body = format!(
        concat!(
            r#"{{"apiVersion":"0.0.1","spec":{{"envelopeHash":{{"algorithm":"sha256","value":"{}"}},"#,
            r#""payloadHash":{{"algorithm":"sha256","value":"{}"}},"#,
            r#""signatures":[{{"signature":"{}","verifier":"{}"}}]}},"kind":"dsse"}}"#
        ),
        sha256_hex(envelope.as_bytes()),
        sha256_hex(statement),
        signature,
        STANDARD.encode(pem),
    );
    let mut leaf = vec![0u8];
    leaf.extend_from_slice(body.as_bytes());
    let root_hash = STANDARD.encode(Sha256::digest(&leaf));
    let bundle = format!(
        concat!(
            r#"{{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","#,
            r#""verificationMaterial":{{"certificate":{{"rawBytes":"{certificate}"}},"tlogEntries":[{{"#,
            r#""logIndex":"0","logId":{{"keyId":"{log_id}"}},"kindVersion":{{"kind":"dsse","version":"0.0.1"}},"#,
            r#""integratedTime":"{time}","inclusionPromise":{{"signedEntryTimestamp":"{promise}"}},"#,
            r#""inclusionProof":{{"logIndex":"0","rootHash":"{root_hash}","treeSize":"1","hashes":[],"#,
            r#""checkpoint":{{"envelope":"rekor.synthetic - 1\n1\n{root_hash}\n\n— rekor.synthetic {checkpoint}\n"}}}},"#,
            r#""canonicalizedBody":"{body}"}}]}},"dsseEnvelope":{envelope}}}"#
        ),
        certificate = certificate,
        log_id = log_id,
        time = integer(case.get("integrated_time").unwrap()),
        promise = text(case, "promise"),
        root_hash = root_hash,
        checkpoint = text(case, "checkpoint"),
        body = STANDARD.encode(&body),
        envelope = envelope,
    );
    json::parse(bundle.as_bytes()).unwrap()
}

fn artifact(object: &Object) -> AuthenticatedArtifact {
    AuthenticatedArtifact {
        repo: text(object, "repo").to_string(),
        tag: text(object, "tag").to_string(),
        commit: text(object, "commit").to_string(),
        subject_name: text(object, "subject_name").to_string(),
        digest: text(object, "digest").to_string(),
    }
}

fn runtime_reference(object: &Object) -> RuntimeReference {
    RuntimeReference {
        repo: text(object, "repo").to_string(),
        tag: text(object, "tag").to_string(),
        digest: text(object, "digest").to_string(),
    }
}

fn integers(value: &Value) -> Vec<i64> {
    value.as_array().unwrap().iter().map(integer).collect()
}

/// Runs one case and returns whether it was accepted. The facts of an
/// accepted case are compared with the recorded ones.
fn run(client: &ProvenanceClient, case: &Object, bundle: Value) -> bool {
    let id = text(case, "id");
    let reference = member(case, "reference");
    let recorded = |name: &str| {
        reference
            .get(name)
            .unwrap_or_else(|| panic!("{id}: accepted here, but the record has no {name}"))
    };
    let recorded_artifact = || artifact(recorded("artifact").as_object().unwrap());
    match text(case, "kind") {
        "code" => {
            let pin = match optional_text(case, "pin") {
                Some(pin) => parse_reference(pin).unwrap(),
                None => Reference {
                    repo: optional_text(case, "pin_repo").unwrap_or_default().into(),
                    tag: optional_text(case, "pin_tag").map(str::to_string),
                    digest: optional_text(case, "pin_digest").map(str::to_string),
                },
            };
            let Ok(code) =
                client.authenticate_code(&bundle, &pin, text(case, "tag"), text(case, "digest"))
            else {
                return false;
            };
            assert_eq!(code.artifact, recorded_artifact(), "{id}");
            let registers: Vec<String> = [code.sev_snp_launch, code.tdx_rtmr1, code.tdx_rtmr2]
                .iter()
                .map(ToString::to_string)
                .collect();
            let expected: Vec<&str> = recorded("registers")
                .as_array()
                .unwrap()
                .iter()
                .map(|register| register.as_str().unwrap())
                .collect();
            assert_eq!(registers, expected, "{id}");
            let shape = code.shape;
            assert_eq!(
                vec![
                    shape.cpus,
                    shape.memory_mb,
                    shape.gpus.unwrap(),
                    shape.disks
                ],
                integers(recorded("shape")),
                "{id}"
            );
            true
        }
        "platform" => {
            let Ok(platform) = client.authenticate_platform_endorsements(
                &bundle,
                text(case, "repo"),
                text(case, "tag"),
                text(case, "digest"),
                text(case, "format"),
            ) else {
                return false;
            };
            assert_eq!(platform.artifact, recorded_artifact(), "{id}");
            assert_eq!(platform.policy.format, text(reference, "format"), "{id}");
            let count = |count: usize| i64::try_from(count).unwrap();
            assert_eq!(
                count(platform.policy.machines.len()),
                integer(recorded("machines"))
            );
            assert_eq!(
                count(platform.policy.policies.len()),
                integer(recorded("policies"))
            );
            let vectors: Vec<String> = platform
                .policy
                .policies
                .get("sev-policy")
                .and_then(|policy| policy.as_sev_snp())
                .map(|policy| {
                    [
                        policy.minimum_launch_mitigation_vector,
                        policy.minimum_current_mitigation_vector,
                    ]
                    .map(|vector| vector.unwrap_or_default().to_string())
                    .to_vec()
                })
                .unwrap_or_default();
            let expected: Vec<&str> = recorded("vectors")
                .as_array()
                .unwrap()
                .iter()
                .map(|vector| vector.as_number().unwrap().as_str())
                .collect();
            assert_eq!(vectors, expected, "{id}");
            true
        }
        "freshness" => {
            let now = Instant::from_unix(
                integer(case.get("now").unwrap()),
                u32::try_from(integer(case.get("now_nanos").unwrap())).unwrap(),
            )
            .unwrap();
            let max_age = case
                .get("max_age")
                .filter(|age| !age.is_null())
                .map(|age| Duration::from_secs(u64::try_from(integer(age)).unwrap()));
            let Ok(logged_at) = client.authenticate_freshness(
                &bundle,
                &artifact(member(case, "expected")),
                now,
                max_age,
            ) else {
                return false;
            };
            assert_eq!(logged_at.unix_seconds(), integer(recorded("time")), "{id}");
            assert_eq!(logged_at.subsec_nanos(), 0, "{id}");
            true
        }
        "runtime" => {
            let material = Runtime {
                reference: runtime_reference(member(case, "material")),
                manifest: STANDARD.decode(text(case, "manifest_b64")).unwrap(),
                bundle,
            };
            let expected = runtime_reference(member(case, "expected"));
            let Ok(runtime) = client.authenticate_runtime(&material, &expected) else {
                return false;
            };
            assert_eq!(runtime.artifact, recorded_artifact(), "{id}");
            assert_eq!(runtime.manifest.version, text(reference, "version"), "{id}");
            true
        }
        other => panic!("{id}: unknown kind {other}"),
    }
}

#[test]
fn recorded_bundles_get_their_recorded_outcomes() {
    let document = json::parse(CASES).unwrap();
    let document = document.as_object().unwrap();
    let client =
        ProvenanceClient::from_trusted_root_json(text(document, "root").as_bytes()).unwrap();
    let certificates = document.get("certificates").unwrap().as_array().unwrap();
    let log_id = text(document, "log_id");
    let cases = document.get("cases").unwrap().as_array().unwrap();
    assert!(cases.len() > 400);

    let (mut accepted, mut stricter) = (0, 0);
    let mut differences = Vec::new();
    for case in cases {
        let case = case.as_object().unwrap();
        let id = text(case, "id");
        let reference = member(case, "reference")
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap();
        let verdict = run(&client, case, bundle(case, certificates, log_id));
        let declared_stricter = optional_text(case, "stricter").is_some();
        accepted += usize::from(verdict);
        stricter += usize::from(declared_stricter);
        if verdict && !reference {
            differences.push(format!("{id}: accepted, but the record turns it down"));
        } else if (reference && !verdict) != declared_stricter {
            differences.push(format!(
                "{id}: verdict {verdict}, recorded {reference}, declared stricter {declared_stricter}"
            ));
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    assert_eq!((accepted, stricter), (121, 5));
}

/// The verdict here on the recorded case called `id`.
fn verdict_on(id: &str) -> bool {
    let document = json::parse(CASES).unwrap();
    let document = document.as_object().unwrap();
    let client =
        ProvenanceClient::from_trusted_root_json(text(document, "root").as_bytes()).unwrap();
    let certificates = document.get("certificates").unwrap().as_array().unwrap();
    let case = document
        .get("cases")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|case| case.as_object().unwrap())
        .find(|case| text(case, "id") == id)
        .unwrap_or_else(|| panic!("no case {id}"));
    run(
        &client,
        case,
        bundle(case, certificates, text(document, "log_id")),
    )
}

#[test]
fn the_statement_type_is_judged_only_where_a_profile_requires_it() {
    // A code release and a platform artifact are identified by their
    // predicate type alone.
    for id in [
        "code/type-wrong",
        "code/type-absent",
        "platform/type-wrong",
        "platform/type-absent",
    ] {
        assert!(verdict_on(id), "{id}");
    }
    // A freshness witness and runtime provenance are in-toto v1 statements.
    for id in [
        "freshness/stmt-type-wrong",
        "freshness/stmt-type-absent",
        "runtime/stmt-type-wrong",
        "runtime/stmt-type-absent",
    ] {
        assert!(!verdict_on(id), "{id}");
    }
}

#[test]
fn a_witness_is_dated_by_the_log_within_closed_bounds() {
    for (id, accepted) in [
        ("freshness/time-age-edge", true),
        ("freshness/time-age-edge-nano1", false),
        ("freshness/time-age-over", false),
        ("freshness/time-now-skew-edge", true),
        ("freshness/time-now-skew-over", false),
        ("freshness/time-custom-edge", true),
        ("freshness/time-custom-over", false),
    ] {
        assert_eq!(verdict_on(id), accepted, "{id}");
    }
}

#[test]
fn the_runtime_repository_is_pinned_by_its_identifiers() {
    assert!(verdict_on("code/cvmimage-ids-right"));
    for id in [
        "code/cvmimage-ids-absent",
        "code/cvmimage-ids-wrong-repo",
        "code/cvmimage-ids-wrong-owner",
        "code/cvmimage-ids-no-owner",
        "platform/cert-ids-absent",
        "platform/cert-ids-wrong-repo",
        "platform/cert-ids-wrong-owner",
        "runtime/cert-ids-absent",
        "runtime/cert-ids-wrong-repo",
        "runtime/cert-ids-wrong-owner",
    ] {
        assert!(!verdict_on(id), "{id}");
    }
    // Another repository has no pinned identifiers.
    assert!(verdict_on("code/cert-ids-present"));
}
