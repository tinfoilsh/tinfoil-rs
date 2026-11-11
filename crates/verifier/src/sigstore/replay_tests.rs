//! Tests of approval bundles and timestamps over recorded cases: the same
//! records that the conformance adapter replays, driven here through the
//! module functions.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::bundle::{Bundle, KeyMaterial};
use super::keyed::{check_approval_layout, verify_keyed_bundle};
use super::statement::{Canonical, Statement, key_hint, timestamp_input};
use super::timestamp::{SIGSTORE_TIMESTAMP_POLICY, parse_response, verify_timestamp};
use super::trusted_root::TrustedRoot;
use crate::canonical::decode_hex;
use crate::endorsement::approval::{
    ApprovalVerifier, parse_approval_bundle_json, verify_approval_timestamp,
};
use crate::endorsement::approval_window;
use crate::instant::Instant;
use crate::json::{self, Value};
use crate::x509::PublicKey;

const APPROVALS: &str = include_str!("../../tests/data/sigstore/approval_differential.json");
const TIMESTAMPS: &str = include_str!("../../tests/data/sigstore/timestamp_differential.json");

const ACCEPTED: u64 = 0;
const REJECTED: u64 = 10;
const MALFORMED: u64 = 30;

fn member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object().unwrap().get(name)
}

fn text<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    member(value, name).and_then(Value::as_str)
}

fn number(value: &Value, name: &str) -> Option<u64> {
    member(value, name)
        .and_then(Value::as_number)
        .and_then(|number| number.to_u64())
}

fn spliced(base: &[u8], case: &Value, middle: &[u8]) -> Vec<u8> {
    let prefix = number(case, "prefix").unwrap() as usize;
    let suffix = number(case, "suffix").unwrap() as usize;
    let mut out = base[..prefix].to_vec();
    out.extend_from_slice(middle);
    out.extend_from_slice(&base[base.len() - suffix..]);
    out
}

/// The verdict of the approval stage for one case, from the module
/// functions: what cannot be set up is malformed, everything about the
/// bundle is a rejection.
fn approve(root: &str, keys: &[&str], bundle: &[u8], digest: &str) -> (u64, String) {
    let Some(digest) = decode_hex(digest) else {
        return (MALFORMED, String::new());
    };
    let Ok(root) = TrustedRoot::from_json(root.as_bytes()) else {
        return (MALFORMED, String::new());
    };
    if keys.is_empty() {
        return (MALFORMED, String::new());
    }
    let Ok(keys) = keys
        .iter()
        .map(|pem| PublicKey::from_pem(pem))
        .collect::<Result<Vec<_>, _>>()
    else {
        return (MALFORMED, String::new());
    };
    if root.rekor_logs().is_empty() {
        return (REJECTED, String::new());
    }
    let Ok(verifier) = ApprovalVerifier::new(Arc::new(root), &keys) else {
        return (MALFORMED, String::new());
    };
    let Ok(digest) = <[u8; 32]>::try_from(digest) else {
        return (REJECTED, String::new());
    };
    match parse_approval_bundle_json(bundle).and_then(|bundle| verifier.verify(&bundle, &digest)) {
        Ok(hint) => (ACCEPTED, hint),
        Err(_) => (REJECTED, String::new()),
    }
}

struct Approvals {
    fixture: Value,
}

impl Approvals {
    fn load() -> Self {
        Self {
            fixture: json::parse(APPROVALS.as_bytes()).unwrap(),
        }
    }

    fn bases(&self) -> &Value {
        member(&self.fixture, "bases").unwrap()
    }

    fn root(&self) -> &str {
        text(self.bases(), "root").unwrap()
    }

    fn digest(&self) -> [u8; 32] {
        decode_hex(text(self.bases(), "digest").unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn keys(&self) -> Vec<&str> {
        let keys = member(self.bases(), "keys").unwrap().as_array().unwrap();
        keys.iter().map(|key| key.as_str().unwrap()).collect()
    }

    fn bundle_text(&self) -> &str {
        text(self.bases(), "bundle").unwrap()
    }

    fn trusted_root(&self) -> TrustedRoot {
        TrustedRoot::from_json(self.root().as_bytes()).unwrap()
    }

    fn bundle(&self) -> Bundle {
        Bundle::from_json(self.bundle_text().as_bytes()).unwrap()
    }

    fn key(&self, index: usize) -> PublicKey {
        PublicKey::from_pem(self.keys()[index]).unwrap()
    }
}

#[test]
fn recorded_approval_bundles_get_their_recorded_verdicts() {
    let approvals = Approvals::load();
    let base = approvals.bundle_text().as_bytes();
    let cases = member(&approvals.fixture, "cases")
        .unwrap()
        .as_array()
        .unwrap();
    let mut accepted = 0;
    for case in cases {
        let name = text(case, "name").unwrap();
        let bundle = spliced(base, case, text(case, "middle").unwrap().as_bytes());
        let keys: Vec<&str> = match member(case, "keys") {
            Some(keys) => keys
                .as_array()
                .unwrap()
                .iter()
                .map(|key| key.as_str().unwrap())
                .collect(),
            None => approvals.keys(),
        };
        let root = text(case, "root").unwrap_or(approvals.root());
        let digest = text(case, "digest").unwrap_or(text(approvals.bases(), "digest").unwrap());
        let (verdict, hint) = approve(root, &keys, &bundle, digest);
        assert_eq!(Some(verdict), number(case, "exit"), "{name}");
        if verdict == ACCEPTED {
            accepted += 1;
            assert_eq!(number(case, "reference"), Some(ACCEPTED), "{name}");
            assert_eq!(Some(hint.as_str()), text(case, "hint"), "{name}");
        }
    }
    assert_eq!(accepted, 94);
}

#[test]
fn a_recorded_approval_verifies_under_its_pinned_key() {
    let approvals = Approvals::load();
    let (root, bundle, key) = (
        approvals.trusted_root(),
        approvals.bundle(),
        approvals.key(0),
    );
    check_approval_layout(&bundle).unwrap();
    assert_eq!(bundle.key_hint(), Some(key_hint(&key).unwrap().as_str()));
    verify_keyed_bundle(&root, &bundle, &key, &approvals.digest()).unwrap();

    // Another pinned key did not sign it, and another digest is not named.
    assert!(verify_keyed_bundle(&root, &bundle, &approvals.key(1), &approvals.digest()).is_err());
    assert!(verify_keyed_bundle(&root, &bundle, &key, &[0; 32]).is_err());
}

#[test]
fn an_approval_needs_a_listed_log_and_a_key_hint() {
    let approvals = Approvals::load();
    let (bundle, key) = (approvals.bundle(), approvals.key(0));
    let empty = TrustedRoot::from_json(
        br#"{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}"#,
    )
    .unwrap();
    let error = verify_keyed_bundle(&empty, &bundle, &key, &approvals.digest()).unwrap_err();
    assert_eq!(error.to_string(), "Rekor trust is required");

    let mut certified = bundle.clone();
    certified.key_material = KeyMaterial::Certificate(vec![0x30, 0x00]);
    let root = approvals.trusted_root();
    assert!(verify_keyed_bundle(&root, &certified, &key, &approvals.digest()).is_err());
}

#[test]
fn a_key_identifier_is_empty_or_the_ssh_fingerprint_of_the_key() {
    let approvals = Approvals::load();
    let (root, key, digest) = (
        approvals.trusted_root(),
        approvals.key(0),
        approvals.digest(),
    );
    let mut bundle = approvals.bundle();

    // The hint passes the layout and fails the signature.
    bundle.envelope.key_id = key_hint(&key).unwrap();
    check_approval_layout(&bundle).unwrap();
    assert!(verify_keyed_bundle(&root, &bundle, &key, &digest).is_err());

    // The fingerprint fails the layout and passes the signature.
    let cases = member(&approvals.fixture, "cases")
        .unwrap()
        .as_array()
        .unwrap();
    let fingerprint = cases
        .iter()
        .filter_map(|case| text(case, "name"))
        .find_map(|name| name.strip_prefix("keyid 'SHA256:"))
        .map(|rest| format!("SHA256:{}", rest.trim_end_matches('\'')))
        .unwrap();
    bundle.envelope.key_id = fingerprint;
    assert!(check_approval_layout(&bundle).is_err());
    verify_keyed_bundle(&root, &bundle, &key, &digest).unwrap();
}

#[test]
fn the_approval_layout_bounds_entries_and_forbids_times() {
    let approvals = Approvals::load();
    let bundle = approvals.bundle();
    let broken = |change: fn(&mut Bundle)| {
        let mut changed = bundle.clone();
        change(&mut changed);
        check_approval_layout(&changed).unwrap_err().to_string()
    };
    assert!(
        broken(|b| b.media_type = super::bundle::BUNDLE_V03_LEGACY_MEDIA_TYPE.into())
            .contains("v0.3 approval")
    );
    assert!(broken(|b| b.envelope.payload_type.push('x')).contains("v0.3 approval"));
    assert!(broken(|b| b.envelope.key_id = "x".into()).contains("key ID"));
    assert!(broken(|b| b.tlog_entries.clear()).contains("bounded"));
    assert!(
        broken(|b| {
            let entry = b.tlog_entries[0].clone();
            b.tlog_entries = vec![entry; 9];
        })
        .contains("bounded")
    );
    assert!(broken(|b| b.tlog_entries[0].integrated_time = 1).contains("inclusion proofs"));
    assert!(
        broken(|b| b.tlog_entries[0].inclusion_promise = Some(Vec::new()))
            .contains("inclusion proofs")
    );
    assert!(broken(|b| b.tlog_entries[0].version = "0.0.1".into()).contains("inclusion proofs"));
    assert!(broken(|b| b.tlog_entries[0].inclusion_proof = None).contains("inclusion proofs"));
    assert!(broken(|b| b.timestamps.push(vec![1])).contains("observer timestamps"));
    assert!(
        broken(|b| b.key_material = KeyMaterial::PublicKey {
            hint: String::new()
        })
        .contains("hint")
    );
}

#[test]
fn a_verifier_needs_logs_and_distinct_p256_keys() {
    let approvals = Approvals::load();
    let root = Arc::new(approvals.trusted_root());
    let (first, second) = (approvals.key(0), approvals.key(1));
    ApprovalVerifier::new(Arc::clone(&root), &[first.clone(), second.clone()]).unwrap();
    assert!(ApprovalVerifier::new(Arc::clone(&root), &[]).is_err());
    assert!(ApprovalVerifier::new(Arc::clone(&root), &[first.clone(), first.clone()]).is_err());
    let log_key = root.rekor_logs()[1].key.clone();
    assert!(ApprovalVerifier::new(Arc::clone(&root), &[log_key]).is_err());

    // A key that is not pinned is not looked for anywhere else.
    let verifier = ApprovalVerifier::new(root, &[second]).unwrap();
    let error = verifier
        .verify(&approvals.bundle(), &approvals.digest())
        .unwrap_err();
    assert_eq!(error.to_string(), "untrusted approval signing key");
}

#[test]
fn a_trusted_root_keeps_its_logs_in_order_with_their_names() {
    let root = Approvals::load().trusted_root();
    let names: Vec<&str> = root
        .rekor_logs()
        .iter()
        .map(|log| log.checkpoint_name().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "rekor.tinfoil-conformance.test",
            "rekor-ed25519.tinfoil-conformance.test"
        ]
    );
    assert!(root.ct_logs().is_empty());
    assert!(root.certificate_authorities().is_empty());
    let first = &root.rekor_logs()[0];
    assert_eq!(root.rekor_log(&first.log_id), Some(first));
    assert!(root.rekor_log(b"other").is_none());
}

#[test]
fn the_embedded_and_recorded_trusted_roots_parse() {
    let embedded = TrustedRoot::from_json(crate::trust::SIGSTORE_TRUSTED_ROOT_JSON).unwrap();
    assert!(!embedded.rekor_logs().is_empty());
    assert!(!embedded.ct_logs().is_empty());
    assert!(!embedded.certificate_authorities().is_empty());
    assert!(!embedded.timestamp_authorities().is_empty());
    for authority in embedded.timestamp_authorities() {
        assert!(authority.leaf.is_some() && authority.root.is_some());
    }
    for log in embedded.rekor_logs() {
        log.checkpoint_name().unwrap();
    }
    for text in [
        super::testutil::PRODUCTION_TRUSTED_ROOT,
        super::testutil::STAGING_TRUSTED_ROOT,
    ] {
        TrustedRoot::from_json(text.as_bytes()).unwrap();
    }
}

#[test]
fn a_log_name_is_the_host_of_its_base_url() {
    let mut log = Approvals::load().trusted_root().rekor_logs()[0].clone();
    for (url, name) in [
        ("https://rekor.sigstore.dev", Some("rekor.sigstore.dev")),
        ("https://rekor.sigstore.dev/", Some("rekor.sigstore.dev")),
        (
            "https://rekor.sigstore.dev:443/api",
            Some("rekor.sigstore.dev"),
        ),
        ("http://log.example?x", Some("log.example")),
        ("rekor.sigstore.dev", None),
        ("https://", None),
        ("https://user@log.example", None),
        ("https://[::1]", None),
        ("https://log.example:port", None),
        ("", None),
    ] {
        log.base_url = url.to_string();
        assert_eq!(log.checkpoint_name().ok(), name, "{url:?}");
    }
}

#[test]
fn the_recorded_bundles_decode_strictly() {
    for text in [
        super::testutil::REKOR_V1_BUNDLE,
        super::testutil::REKOR_V2_BUNDLE,
    ] {
        let strict = Bundle::from_json(text.as_bytes()).unwrap();
        assert_eq!(strict, super::testutil::bundle(text));
        assert_eq!(
            Bundle::from_value(&json::parse(text.as_bytes()).unwrap()).unwrap(),
            strict
        );
    }
    assert!(Bundle::from_json(b"").is_err());
    let padded = format!(
        "{}{}",
        super::testutil::REKOR_V1_BUNDLE,
        " ".repeat(4 << 20)
    );
    let error = Bundle::from_json(padded.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("size"), "{error}");
}

#[test]
fn a_statement_decodes_with_its_subjects_and_raw_predicate() {
    let payload = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"ab","sha512":"cd"}},{"digest":null}],"predicateType":"p","predicate":{"n":18446744073709551615}}"#;
    let statement = Statement::from_payload(payload).unwrap();
    assert_eq!(statement.statement_type, super::statement::STATEMENT_TYPE);
    assert_eq!(statement.predicate_type, "p");
    assert_eq!(statement.subjects.len(), 2);
    assert_eq!(statement.first_subject_digest(), Some("ab"));
    assert!(statement.subjects[1].name.is_empty());
    let n = member(&statement.predicate, "n").unwrap();
    assert_eq!(n.as_number().unwrap().as_str(), "18446744073709551615");

    // The type is carried, not judged; a predicate may be absent.
    let untyped = Statement::from_payload(br#"{"subject":[]}"#).unwrap();
    assert!(untyped.statement_type.is_empty());
    assert!(untyped.predicate.as_object().unwrap().is_empty());

    for bad in [
        &br#"{"subject":[],"extra":1}"#[..],
        br#"{"subject":[{"name":"a","uri":"x"}]}"#,
        br#"{"subject":{}}"#,
        br#"{"subject":[{"digest":{"sha256":5}}]}"#,
        br#"{"predicate":[]}"#,
        br#"{"_type":"a","_type":"b"}"#,
        br#"[]"#,
        b"",
    ] {
        assert!(Statement::from_payload(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_timestamp_input_is_the_domain_and_canonical_json() {
    let core = Canonical::Object(vec![
        ("name", Canonical::String("/org/project/r1")),
        ("digest", Canonical::String("ab")),
        (
            "list",
            Canonical::Array(vec![Canonical::String("\"\\\n\u{1}\u{e9}")]),
        ),
        ("\u{20ac}", Canonical::String("")),
        ("\u{10000}", Canonical::String("")),
    ]);
    let input = timestamp_input("domain/v1\0", &core).unwrap();
    // Names sort by UTF-16 code units: U+20AC comes before the surrogates
    // of the supplementary character.
    let expected = "domain/v1\0{\"digest\":\"ab\",\"list\":[\"\\\"\\\\\\n\\u0001\u{e9}\"],\"name\":\"/org/project/r1\",\"\u{20ac}\":\"\",\"\u{10000}\":\"\"}";
    assert_eq!(String::from_utf8(input).unwrap(), expected);

    let repeated = Canonical::Object(vec![
        ("a", Canonical::String("1")),
        ("a", Canonical::String("2")),
    ]);
    assert!(timestamp_input("", &repeated).is_err());
    let mut deep = Canonical::String("");
    for _ in 0..40 {
        deep = Canonical::Array(vec![deep]);
    }
    assert!(timestamp_input("", &deep).is_err());
}

struct Timestamps {
    fixture: Value,
}

impl Timestamps {
    fn load() -> Self {
        Self {
            fixture: json::parse(TIMESTAMPS.as_bytes()).unwrap(),
        }
    }

    fn bases(&self) -> &Value {
        member(&self.fixture, "bases").unwrap()
    }

    fn root(&self) -> TrustedRoot {
        TrustedRoot::from_json(text(self.bases(), "root").unwrap().as_bytes()).unwrap()
    }

    fn response(&self) -> Vec<u8> {
        STANDARD
            .decode(text(self.bases(), "response").unwrap())
            .unwrap()
    }

    fn input(&self) -> Vec<u8> {
        STANDARD
            .decode(text(self.bases(), "input").unwrap())
            .unwrap()
    }
}

/// The verdict of the timestamp stage for one case, from the module
/// functions.
fn stamp(root: &str, response: &[u8], input: &[u8], now: u64) -> (u64, String) {
    if now == 0 {
        return (MALFORMED, String::new());
    }
    let now = Instant::from_unix(i64::try_from(now).unwrap(), 0).unwrap();
    let root = if root.is_empty() {
        TrustedRoot::from_json(crate::trust::SIGSTORE_TRUSTED_ROOT_JSON)
    } else {
        TrustedRoot::from_json(root.as_bytes())
    };
    let Ok(root) = root else {
        return (MALFORMED, String::new());
    };
    let window = approval_window(now, None, None).unwrap();
    match verify_approval_timestamp(&root, response, input, &window) {
        Ok(at) => (ACCEPTED, at.to_rfc3339_seconds()),
        Err(_) => (REJECTED, String::new()),
    }
}

#[test]
fn recorded_timestamp_responses_get_their_recorded_verdicts() {
    let timestamps = Timestamps::load();
    let base = timestamps.response();
    let cases = member(&timestamps.fixture, "cases")
        .unwrap()
        .as_array()
        .unwrap();
    let mut accepted = 0;
    for case in cases {
        let name = text(case, "name").unwrap();
        let middle = STANDARD.decode(text(case, "middle").unwrap()).unwrap();
        let response = spliced(&base, case, &middle);
        let input = match (number(case, "input_a_count"), text(case, "input")) {
            (Some(count), _) => vec![b'a'; count as usize],
            (None, Some(input)) => STANDARD.decode(input).unwrap(),
            (None, None) => timestamps.input(),
        };
        let now = number(case, "now")
            .or(number(timestamps.bases(), "now"))
            .unwrap();
        let root = text(case, "root").unwrap_or(text(timestamps.bases(), "root").unwrap());
        let (verdict, at) = stamp(root, &response, &input, now);
        assert_eq!(Some(verdict), number(case, "exit"), "{name}");
        if verdict == ACCEPTED {
            accepted += 1;
            assert_eq!(number(case, "reference"), Some(ACCEPTED), "{name}");
            assert_eq!(Some(at.as_str()), text(case, "timestamp"), "{name}");
        }
    }
    assert_eq!(accepted, 81);
}

#[test]
fn a_timestamp_is_authenticated_without_a_clock_and_bounded_by_a_window() {
    let timestamps = Timestamps::load();
    let (root, response, input) = (timestamps.root(), timestamps.response(), timestamps.input());
    let at = verify_timestamp(&root, &response, &input, Some(SIGSTORE_TIMESTAMP_POLICY)).unwrap();
    assert_eq!(at.to_rfc3339(), "2025-03-01T12:00:00Z");
    assert_eq!(parse_response(&response).unwrap().gen_time, at);
    assert_eq!(
        verify_timestamp(&root, &response, &input, None).unwrap(),
        at
    );

    // The window is inclusive at both ends: seven days back, five minutes
    // ahead.
    let week = Duration::from_secs(7 * 24 * 60 * 60);
    let appraise = |now: Instant| {
        let window = approval_window(now, None, None).unwrap();
        verify_approval_timestamp(&root, &response, &input, &window)
    };
    assert_eq!(appraise(at.checked_add(week).unwrap()).unwrap(), at);
    let late = at.checked_add(week + Duration::from_secs(1)).unwrap();
    assert_eq!(
        appraise(late).unwrap_err().to_string(),
        "approval is too old"
    );
    let skew = Duration::from_secs(300);
    assert_eq!(appraise(at.checked_sub(skew).unwrap()).unwrap(), at);
    let early = at.checked_sub(skew + Duration::from_secs(1)).unwrap();
    assert_eq!(
        appraise(early).unwrap_err().to_string(),
        "timestamp is in the future"
    );
}

#[test]
fn a_timestamp_covers_its_input_under_the_required_policy() {
    let timestamps = Timestamps::load();
    let (root, response, input) = (timestamps.root(), timestamps.response(), timestamps.input());
    let mut other = input.clone();
    other.push(b'x');
    assert!(verify_timestamp(&root, &response, &other, None).is_err());
    let policy = ::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.3");
    let error = verify_timestamp(&root, &response, &input, Some(policy)).unwrap_err();
    assert_eq!(error.to_string(), "unexpected timestamp policy");

    let window =
        approval_window(Instant::from_unix(1_740_830_400, 0).unwrap(), None, None).unwrap();
    for size in [0, super::statement::MAX_STATEMENT_SIZE + 1] {
        let error =
            verify_approval_timestamp(&root, &response, &vec![0; size], &window).unwrap_err();
        assert!(error.to_string().contains("size"), "{error}");
    }
}

#[test]
fn a_root_without_authorities_authenticates_no_timestamp() {
    let timestamps = Timestamps::load();
    let empty = TrustedRoot::from_json(
        br#"{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}"#,
    )
    .unwrap();
    let error =
        verify_timestamp(&empty, &timestamps.response(), &timestamps.input(), None).unwrap_err();
    assert!(
        error.to_string().contains("no trusted timestamp authority"),
        "{error}"
    );
}
