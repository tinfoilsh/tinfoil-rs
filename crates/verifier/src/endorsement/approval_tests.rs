//! Replays recorded approvals, signing certificates and approval
//! statements.
//!
//! `approval_cases.json` holds material minted under test trust roots:
//! config endorsements signed with pinned keys and with registry
//! certificates, artifact freshness approvals, registry signing
//! certificates, and unsigned statement payloads. Each case is one change
//! away from a well-formed one, or the same material appraised at another
//! time. A case records the outcome of a second, independent
//! implementation of the same rules (`reference`). The outcome here must
//! be the same, except where a case names the rule by which this module is
//! the `stricter` one; no case that the other implementation turns down is
//! accepted here.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::EndorsementError;
use super::approval::{
    Artifact, ArtifactKind, ArtifactStatement, ConfigPolicy, ConfigPredicate, ConfigStatement,
    ConfigVerifier, FreshnessPolicy, FreshnessVerifier, verify_signing_certificate,
};
use crate::canonical::encode_lower_hex;
use crate::instant::Instant;
use crate::json::{self, Object, Value};
use crate::sigstore::trusted_root::TrustedRoot;
use crate::x509::PublicKey;

const CASES: &[u8] = include_bytes!("../../tests/data/endorsement/approval_cases.json");

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

fn count(object: &Object, name: &str) -> usize {
    object
        .get(name)
        .map(|value| usize::try_from(integer(value)).unwrap())
        .unwrap_or(0)
}

fn flag(object: &Object, name: &str) -> bool {
    object.get(name).and_then(Value::as_bool).unwrap()
}

fn member<'a>(object: &'a Object, name: &str) -> &'a Object {
    object.get(name).and_then(Value::as_object).unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect()
}

/// An instant recorded as `[seconds, nanoseconds]`.
fn instant(value: &Value) -> Instant {
    let [seconds, nanos] = value.as_array().unwrap() else {
        panic!("an instant is [seconds, nanoseconds]");
    };
    Instant::from_unix(integer(seconds), u32::try_from(integer(nanos)).unwrap()).unwrap()
}

/// A duration recorded in seconds, where zero selects the default.
fn seconds(object: &Object, name: &str) -> Option<Duration> {
    match integer(object.get(name).unwrap()) {
        0 => None,
        seconds => Some(Duration::from_secs(u64::try_from(seconds).unwrap())),
    }
}

fn keys(case: &Object, name: &str) -> Vec<PublicKey> {
    match case.get(name) {
        None | Some(Value::Null) => Vec::new(),
        Some(pems) => strings(pems)
            .iter()
            .map(|pem| PublicKey::from_pem(pem).unwrap())
            .collect(),
    }
}

struct Fixture {
    document: Value,
    roots: Vec<Arc<TrustedRoot>>,
}

impl Fixture {
    fn load() -> Self {
        let document = json::parse(CASES).unwrap();
        let roots = strings(document.as_object().unwrap().get("roots").unwrap())
            .iter()
            .map(|root| Arc::new(TrustedRoot::from_json(root.as_bytes()).unwrap()))
            .collect();
        Self { document, roots }
    }

    fn cases(&self, kind: &str) -> impl Iterator<Item = &Object> {
        self.document
            .as_object()
            .unwrap()
            .get(kind)
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|case| case.as_object().unwrap())
    }

    fn root(&self, case: &Object) -> Arc<TrustedRoot> {
        Arc::clone(&self.roots[count(case, "root")])
    }
}

/// Compares the verdicts of a kind of case with the record and returns how
/// many cases were accepted and how many are declared stricter.
fn replay(
    fixture: &Fixture,
    kind: &str,
    run: impl Fn(&Object, &Object) -> Result<(), EndorsementError>,
) -> (usize, usize) {
    let (mut accepted, mut stricter) = (0, 0);
    let mut differences = Vec::new();
    for case in fixture.cases(kind) {
        let id = text(case, "id");
        let reference = member(case, "reference");
        let recorded = flag(reference, "ok");
        let verdict = run(case, reference);
        let declared_stricter = optional_text(case, "stricter").is_some();
        accepted += usize::from(verdict.is_ok());
        stricter += usize::from(declared_stricter);
        if verdict.is_ok() && !recorded {
            differences.push(format!("{id}: accepted, but the record turns it down"));
        } else if (recorded && verdict.is_err()) != declared_stricter {
            differences.push(format!(
                "{id}: {verdict:?}, recorded {recorded}, declared stricter {declared_stricter}"
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "{kind}:\n{}",
        differences.join("\n")
    );
    (accepted, stricter)
}

/// The payload of a statement case: the text with its fill and its padding.
fn payload(case: &Object) -> Vec<u8> {
    let mut payload = text(case, "payload").replacen("@FILL@", &"A".repeat(count(case, "fill")), 1);
    payload.push_str(&" ".repeat(count(case, "pad")));
    payload.into_bytes()
}

fn kind_of(kind: &str) -> ArtifactKind {
    match kind {
        "platform" => ArtifactKind::Platform,
        "runtime" => ArtifactKind::Runtime,
        other => panic!("unknown artifact kind {other}"),
    }
}

fn artifact_of(fields: &[String]) -> Artifact {
    let [kind, repo, tag, name, digest] = fields else {
        panic!("an artifact is [kind, repo, tag, name, digest]");
    };
    Artifact {
        kind: kind_of(kind),
        repo: repo.clone(),
        tag: tag.clone(),
        name: name.clone(),
        digest: digest.clone(),
    }
}

#[test]
fn recorded_statements_decode_as_recorded() {
    let fixture = Fixture::load();
    let outcome = replay(&fixture, "statement", |case, reference| {
        let id = text(case, "id");
        let payload = payload(case);
        let (input, timestamp) = match text(case, "kind") {
            "config" => {
                let statement = ConfigStatement::from_payload(&payload)?;
                assert_eq!(statement.name, text(reference, "name"), "{id}");
                assert_eq!(statement.digest, text(reference, "digest"), "{id}");
                let (registry_id, runtime) = match &statement.predicate {
                    ConfigPredicate::V1 => ("", None),
                    ConfigPredicate::V2 {
                        registry_id,
                        runtime,
                    } => (
                        registry_id.as_str(),
                        Some(vec![
                            runtime.repo.clone(),
                            runtime.tag.clone(),
                            runtime.digest.clone(),
                        ]),
                    ),
                };
                assert_eq!(registry_id, text(reference, "registry_id"), "{id}");
                assert_eq!(runtime, reference.get("runtime").map(strings), "{id}");
                (statement.timestamp_input()?, statement.timestamp)
            }
            "artifact" => {
                let statement = ArtifactStatement::from_payload(&payload)?;
                let recorded = artifact_of(&strings(reference.get("artifact").unwrap()));
                assert_eq!(statement.artifact, recorded, "{id}");
                (statement.timestamp_input()?, statement.timestamp)
            }
            other => panic!("{id}: unknown kind {other}"),
        };
        assert_eq!(input, text(reference, "input").as_bytes(), "{id}");
        assert_eq!(
            encode_lower_hex(&Sha256::digest(&timestamp)),
            text(reference, "timestamp_sha256"),
            "{id}"
        );
        Ok(())
    });
    assert_eq!(outcome, (30, 3));
}

#[test]
fn recorded_signing_certificates_get_their_recorded_verdicts() {
    let fixture = Fixture::load();
    let outcome = replay(&fixture, "certificate", |case, reference| {
        let der = |name: &str| STANDARD.decode(text(case, name)).unwrap();
        // A key that cannot be pinned is an error of the verification, as
        // it is for the recorded outcome.
        let roots = keys(case, "roots");
        let (certificate, _) = verify_signing_certificate(
            &der("certificate_b64"),
            &der("issuer_b64"),
            &roots,
            instant(case.get("at").unwrap()),
        )?;
        let (uris, _) = certificate.subject_alternative_uris()?;
        assert_eq!(uris, [text(reference, "uri")], "{}", text(case, "id"));
        Ok(())
    });
    assert_eq!(outcome, (12, 0));
}

#[test]
fn recorded_config_endorsements_get_their_recorded_outcomes() {
    let fixture = Fixture::load();
    let outcome = replay(&fixture, "config", |case, reference| {
        let id = text(case, "id");
        let pinned = keys(case, "keys");
        let verifier = if flag(case, "registry") {
            ConfigVerifier::for_registry(fixture.root(case), &pinned)
        } else {
            ConfigVerifier::new(fixture.root(case), &pinned)
        }
        .unwrap();
        let config = match (
            optional_text(case, "config_b64"),
            count(case, "config_zeros"),
        ) {
            (Some(config), _) => Some(STANDARD.decode(config).unwrap()),
            (None, 0) => None,
            (None, zeros) => Some(vec![0; zeros]),
        };
        let recorded_policy = member(case, "policy");
        let pin = |name: &str| {
            Some(text(recorded_policy, name).to_string()).filter(|pin| !pin.is_empty())
        };
        let policy = ConfigPolicy {
            identity: pin("identity"),
            revision: pin("revision"),
            digest: pin("digest"),
            now: Instant::from_unix(
                integer(recorded_policy.get("now").unwrap()),
                u32::try_from(integer(recorded_policy.get("now_nanos").unwrap())).unwrap(),
            )
            .unwrap(),
            max_age: seconds(recorded_policy, "max_age"),
            future_skew: seconds(recorded_policy, "future_skew"),
            registry_ids: recorded_policy
                .get("registry_ids")
                .filter(|list| !list.is_null())
                .map(strings),
        };
        let bundle = case.get("bundle").unwrap();
        let verified = if flag(case, "certified") {
            let issuer = STANDARD.decode(text(case, "issuer_b64")).unwrap();
            verifier.verify_certified(config.as_deref(), bundle, &issuer, &policy)?
        } else {
            verifier.verify(config.as_deref(), bundle, &policy)?
        };
        assert_eq!(verified.name, text(reference, "name"), "{id}");
        assert_eq!(verified.digest, text(reference, "digest"), "{id}");
        assert_eq!(verified.reference, text(reference, "reference"), "{id}");
        assert_eq!(verified.signing_key_hint, text(reference, "hint"), "{id}");
        assert_eq!(
            verified.approval_time,
            instant(reference.get("approval_time").unwrap()),
            "{id}"
        );
        assert_eq!(
            verified.registry_id.as_deref().unwrap_or_default(),
            text(reference, "registry_id"),
            "{id}"
        );
        assert_eq!(
            verified
                .runtime
                .map(|runtime| vec![runtime.repo, runtime.tag, runtime.digest]),
            reference.get("runtime").map(strings),
            "{id}"
        );
        assert_eq!(
            verified.signature_time,
            reference.get("signature_time").map(instant),
            "{id}"
        );
        Ok(())
    });
    assert_eq!(outcome, (45, 0));
}

#[test]
fn recorded_artifact_approvals_get_their_recorded_outcomes() {
    let fixture = Fixture::load();
    let outcome = replay(&fixture, "artifact", |case, reference| {
        let id = text(case, "id");
        let verifier = FreshnessVerifier::new(fixture.root(case), &keys(case, "keys")).unwrap();
        let policy = FreshnessPolicy {
            artifact: artifact_of(&strings(case.get("artifact").unwrap())),
            now: instant(case.get("now").unwrap()),
            max_age: seconds(case, "max_age"),
            future_skew: seconds(case, "future_skew"),
        };
        let verified = verifier.verify(case.get("bundle").unwrap(), &policy)?;
        assert_eq!(verified.artifact, policy.artifact, "{id}");
        assert_eq!(verified.reference, text(reference, "reference"), "{id}");
        assert_eq!(verified.signing_key_hint, text(reference, "hint"), "{id}");
        assert_eq!(
            verified.approval_time,
            instant(reference.get("approval_time").unwrap()),
            "{id}"
        );
        Ok(())
    });
    assert_eq!(outcome, (17, 0));
}

#[test]
fn a_registry_signing_certificate_has_its_profile() {
    let fixture = Fixture::load();
    let verdict = |id: &str| {
        let case = fixture
            .cases("certificate")
            .find(|case| text(case, "id") == id)
            .unwrap_or_else(|| panic!("no case {id}"));
        let der = |name: &str| STANDARD.decode(text(case, name)).unwrap();
        verify_signing_certificate(
            &der("certificate_b64"),
            &der("issuer_b64"),
            &keys(case, "roots"),
            instant(case.get("at").unwrap()),
        )
        .is_ok()
    };
    for accepted in [
        "happy",
        "private",
        "leaf-lifetime-edge",
        "at-not-before",
        "at-not-after",
    ] {
        assert!(verdict(accepted), "{accepted}");
    }
    for rejected in [
        "leaf-ca",
        "leaf-ca-flag-only",
        "leaf-no-basic-constraints",
        "leaf-no-key-usage",
        "leaf-key-usage-extra",
        "leaf-key-usage-encipher",
        "leaf-tls-purpose",
        "leaf-two-purposes",
        "leaf-any-purpose",
        "leaf-no-purpose",
        "leaf-sha384",
        "leaf-lifetime-over",
        "leaf-long-lifetime",
        "leaf-subject",
        "leaf-dns",
        "leaf-email",
        "leaf-no-uri",
        "leaf-two-uris",
        "leaf-uri-other",
        "leaf-noncritical-san",
        "leaf-hidden-san-identity",
        "leaf-unknown-critical-extension",
        "untrusted-root",
        "root-key-as-leaf",
        "issuer-not-ca",
        "issuer-signed-by-other",
        "at-before-not-before",
        "at-after-not-after",
        "unset-clock",
    ] {
        assert!(!verdict(rejected), "{rejected}");
    }
}
