//! Certificate-signed bundle verification over a recorded case set.
//!
//! The fixture holds trusted roots and bundles by name, and cases that each
//! name a bundle and a root, optionally changed by text edits. A case
//! records the verdict of this crate (`accept`), the outcome of an
//! independent second verifier (`reference`), and, where the two differ,
//! the reason this crate is the stricter one (`class`). No case may be
//! accepted here and rejected by the second verifier.
//!
//! The synthetic material is issued by one certificate authority (a root
//! and an intermediate), one certificate transparency log, one log that
//! signs entry timestamps and sharded checkpoints, one log of a single
//! tree, and one timestamp authority. Its certificates are valid for ten
//! minutes from `minted_now`.

use sha2::{Digest, Sha256};

use super::SigstoreError;
use super::bundle::Bundle;
use super::certificate::{
    TimeSource, VerifiedBundle, verify_certified_bundle, verify_fulcio_bundle,
};
use super::trusted_root::TrustedRoot;
use crate::canonical::{decode_hex, encode_lower_hex};
use crate::json::{self, Object, Value};
use crate::x509::Certificate;

const FIXTURE: &str = include_str!("../../tests/data/sigstore/certificate_bundle_cases.json");

/// One verified time: whether it comes from a log, and the instant.
type Time = (bool, i64, u32);

struct Fixture {
    document: Value,
}

struct Case<'a> {
    fixture: &'a Fixture,
    fields: &'a Object,
}

fn member<'a>(object: &'a Object, name: &str) -> Option<&'a Value> {
    object.get(name).filter(|value| !value.is_null())
}

fn text<'a>(object: &'a Object, name: &str) -> &'a str {
    member(object, name).and_then(Value::as_str).unwrap_or("")
}

fn integer(value: &Value) -> i64 {
    value.as_number().unwrap().to_i64().unwrap()
}

/// Applies `[offset, deleted, inserted]` edits, whose offsets refer to
/// `base`, and checks the result against the recorded digest.
fn edited(base: &str, edits: Option<&Value>, sha256_prefix: Option<&str>) -> String {
    let mut out = base.to_string();
    let mut list: Vec<(usize, usize, &str)> = edits
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|edit| {
            let edit = edit.as_array().unwrap();
            (
                usize::try_from(integer(&edit[0])).unwrap(),
                usize::try_from(integer(&edit[1])).unwrap(),
                edit[2].as_str().unwrap(),
            )
        })
        .collect();
    list.sort_by_key(|(at, _, _)| std::cmp::Reverse(*at));
    for (at, deleted, inserted) in list {
        out.replace_range(at..at + deleted, inserted);
    }
    if let Some(prefix) = sha256_prefix {
        let digest = encode_lower_hex(&Sha256::digest(out.as_bytes()));
        assert!(
            digest.starts_with(prefix),
            "an edited text is not the recorded one"
        );
    }
    out
}

impl Fixture {
    fn load() -> Self {
        Fixture {
            document: json::parse(FIXTURE.as_bytes()).unwrap(),
        }
    }

    fn object(&self, name: &str) -> &Object {
        self.document
            .as_object()
            .unwrap()
            .get(name)
            .unwrap()
            .as_object()
            .unwrap()
    }

    /// The instant from which the synthetic certificates are valid.
    fn minted_now(&self) -> i64 {
        integer(
            self.document
                .as_object()
                .unwrap()
                .get("minted_now")
                .unwrap(),
        )
    }

    fn cases(&self) -> impl Iterator<Item = Case<'_>> {
        let cases = self.document.as_object().unwrap().get("cases").unwrap();
        cases.as_array().unwrap().iter().map(move |case| Case {
            fixture: self,
            fields: case.as_object().unwrap(),
        })
    }

    fn case(&self, name: &str) -> Case<'_> {
        self.cases()
            .find(|case| case.name() == name)
            .unwrap_or_else(|| panic!("no case {name}"))
    }
}

impl Case<'_> {
    fn name(&self) -> &str {
        text(self.fields, "name")
    }

    fn bundle_text(&self) -> String {
        let base = text(self.fixture.object("bases"), text(self.fields, "base"));
        let prefix = text(self.fields, "sha256_prefix");
        edited(base, member(self.fields, "edits"), Some(prefix))
    }

    fn root_text(&self) -> String {
        let base = text(self.fixture.object("roots"), text(self.fields, "root"));
        edited(base, member(self.fields, "root_edits"), None)
    }

    /// Verifies the case as its caller would: the trusted root and the
    /// bundle decode, the bundle verifies for the case's digest, and for a
    /// registry certificate the subject alternative name is the expected
    /// one.
    fn verify(&self) -> Result<VerifiedBundle, SigstoreError> {
        let root = TrustedRoot::from_json(self.root_text().as_bytes())
            .map_err(|cause| cause.within("trusted root"))?;
        let bundle = Bundle::from_json(self.bundle_text().as_bytes())?;
        let digest: [u8; 32] = decode_hex(text(self.fields, "digest"))
            .and_then(|digest| digest.try_into().ok())
            .ok_or_else(|| SigstoreError::new("digest is not 32 bytes of hex"))?;
        if text(self.fields, "mode") != "certified" {
            return verify_fulcio_bundle(&root, &bundle, &digest);
        }
        let issuer = crate::canonical::decode_base64("issuer", text(self.fields, "issuer"))?;
        let issuer = Certificate::from_der(&issuer)?;
        let verified = verify_certified_bundle(&root, &bundle, &issuer, &digest)?;
        if verified.identity.subject_alternative_name != text(self.fields, "san") {
            return Err(SigstoreError::new("certificate names another registry"));
        }
        Ok(verified)
    }

    fn reference(&self) -> &Object {
        member(self.fields, "reference")
            .unwrap()
            .as_object()
            .unwrap()
    }

    fn reference_times(&self) -> Vec<Time> {
        member(self.reference(), "times")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .map(|time| {
                let time = time.as_object().unwrap();
                (
                    text(time, "source") == "log",
                    integer(time.get("unix").unwrap()),
                    u32::try_from(integer(time.get("nanos").unwrap())).unwrap(),
                )
            })
            .collect()
    }
}

fn times(verified: &VerifiedBundle) -> Vec<Time> {
    verified
        .times
        .iter()
        .map(|time| {
            (
                time.source == TimeSource::TransparencyLog,
                time.at.unix_seconds(),
                time.at.subsec_nanos(),
            )
        })
        .collect()
}

fn verify(name: &str) -> Result<VerifiedBundle, SigstoreError> {
    Fixture::load().case(name).verify()
}

/// The verified times of an accepted case, as seconds after the instant
/// from which the synthetic certificates are valid.
fn offsets(name: &str) -> Vec<(TimeSource, i64)> {
    let fixture = Fixture::load();
    let verified = fixture.case(name).verify().unwrap();
    verified
        .times
        .iter()
        .map(|time| (time.source, time.at.unix_seconds() - fixture.minted_now()))
        .collect()
}

fn rejected(name: &str) -> String {
    verify(name).unwrap_err().to_string()
}

const LOG: TimeSource = TimeSource::TransparencyLog;
const AUTHORITY: TimeSource = TimeSource::TimestampAuthority;

#[test]
fn every_recorded_case_has_its_recorded_verdict() {
    let fixture = Fixture::load();
    let mut problems = Vec::new();
    let mut count = 0;
    for case in fixture.cases() {
        count += 1;
        let name = case.name();
        let recorded = member(case.fields, "accept")
            .and_then(Value::as_bool)
            .unwrap();
        let reference = member(case.reference(), "accept")
            .and_then(Value::as_bool)
            .unwrap();
        let outcome = case.verify();
        let verdict = |accept: bool| if accept { "accept" } else { "reject" };
        if outcome.is_ok() != recorded {
            let message = outcome.as_ref().err().map(ToString::to_string);
            problems.push(format!(
                "VERDICT\t{name}\t{}\t{}",
                verdict(outcome.is_ok()),
                message.unwrap_or_default()
            ));
        }
        if outcome.is_ok() && !reference {
            problems.push(format!("LOOSER\t{name}"));
        }
        if recorded != reference && text(case.fields, "class").is_empty() {
            problems.push(format!("UNCLASSIFIED\t{name}"));
        }
        if let (Ok(verified), true) = (&outcome, reference) {
            if times(verified) != case.reference_times() {
                problems.push(format!("TIMES\t{name}\t{:?}", times(verified)));
            }
            // The second verifier reports a normalised form of the name; a case
            // whose certificate spells it otherwise says so.
            let identity = &verified.identity;
            let same_name = identity.subject_alternative_name == text(case.reference(), "san");
            let name_differs = member(case.fields, "san_differs").is_some();
            if same_name == name_differs
                || identity.extensions.issuer != text(case.reference(), "issuer")
            {
                problems.push(format!("IDENTITY\t{name}"));
            }
        }
    }
    assert!(count > 1000, "the case set is incomplete: {count} cases");
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

#[test]
fn a_recorded_production_bundle_proves_its_log_time_and_identity() {
    let verified = verify("r-rekor-v1").unwrap();
    assert_eq!(times(&verified), [(true, 1_774_548_286, 0)]);
    assert_eq!(
        verified.earliest_log_time().unwrap().unix_seconds(),
        1_774_548_286
    );
    let identity = &verified.identity;
    assert_eq!(
        identity.extensions.issuer,
        "https://token.actions.githubusercontent.com"
    );
    assert_eq!(identity.extensions.runner_environment, "github-hosted");
    assert!(
        identity
            .subject_alternative_name
            .starts_with("https://github.com/tinfoilsh/"),
        "{}",
        identity.subject_alternative_name
    );
    assert!(
        identity
            .extensions
            .source_repository_ref
            .starts_with("refs/tags/")
    );
    assert_eq!(identity.extensions.source_repository_digest.len(), 40);
    assert!(!verified.statement.predicate_type.is_empty());
    assert_eq!(verified.statement.subjects.len(), 1);
}

#[test]
fn a_recorded_bundle_of_a_tiled_log_is_dated_by_its_timestamp() {
    let verified = verify("r-rekor-v2").unwrap();
    assert_eq!(times(&verified), [(false, 1_778_700_213, 0)]);
    assert_eq!(verified.earliest_log_time(), None);
    assert!(!verified.identity.subject_alternative_name.is_empty());
}

#[test]
fn a_time_outside_the_certificate_window_is_rejected() {
    assert!(rejected("m-v1-time-after-cert").contains("certificate validity"));
    assert!(rejected("m-v1-time-before-cert").contains("certificate validity"));
    // The last second of the certificate is inside its window.
    assert_eq!(offsets("m-v1-at-not-after"), [(LOG, 600)]);
    assert_eq!(offsets("m-v2-ts-at-not-before"), [(AUTHORITY, 0)]);
}

#[test]
fn several_entries_each_contribute_what_they_prove() {
    assert_eq!(offsets("m-both"), [(LOG, 60), (AUTHORITY, 120)]);
    // Log times come first whatever the order of the entries.
    assert_eq!(offsets("m-both-v2-first"), [(LOG, 60), (AUTHORITY, 120)]);
    // One log contributes one time, its first.
    assert_eq!(offsets("m-two-v1"), [(LOG, 60)]);
    // An entry that cannot verify in a listed log fails the bundle, even
    // beside one that verifies.
    verify("m-both/proof-root-hash-flipped").unwrap_err();
    // An entry of a log that the trusted root does not list is passed over.
    assert_eq!(
        offsets("m-both/unknown-log-entry-first"),
        [(LOG, 60), (AUTHORITY, 120)]
    );
}

#[test]
fn an_entry_without_a_promise_proves_no_time() {
    let message = rejected("m-v1-no-promise-no-ts");
    assert!(message.contains("timestamps"), "{message}");
    // With a timestamp over the signature, the same entry is enough.
    assert_eq!(offsets("m-v1-no-promise-ts"), [(AUTHORITY, 60)]);
    // Its unsigned integrated time is still held to the certificate.
    assert!(rejected("m-v1-no-promise-time-out+ts").contains("certificate validity"));
}

#[test]
fn an_entry_of_a_tiled_log_needs_a_timestamp() {
    let message = rejected("m-v2-no-ts");
    assert!(message.contains("timestamps"), "{message}");
    assert_eq!(offsets("m-v2-ts"), [(AUTHORITY, 60)]);
    // Such a log issues no entry timestamps: an entry that carries one is
    // passed over, which leaves no verified entry.
    assert!(rejected("m-v2-with-promise").contains("not enough verified log entries"));
}

#[test]
fn an_invalid_extra_timestamp_is_ignored() {
    assert_eq!(offsets("m-v2-bad-then-good-ts"), [(AUTHORITY, 60)]);
    assert_eq!(offsets("m-v2-good-then-bad-ts"), [(AUTHORITY, 60)]);
    // A second timestamp of the same authority adds nothing, even one
    // outside the certificate's validity.
    assert_eq!(offsets("m-v2-two-ts"), [(AUTHORITY, 60)]);
    assert_eq!(offsets("m-v2-two-ts-second-out"), [(AUTHORITY, 60)]);
    // Alone, the invalid timestamp leaves the bundle without a time.
    verify("m-v2-bad-ts").unwrap_err();
}

#[test]
fn a_timestamp_outside_the_certificate_validity_is_rejected() {
    for name in [
        "m-v2-ts-after-cert",
        "m-v2-ts-before-cert",
        // Every verified time must fall inside the certificate, not only
        // one of them.
        "m-v1-good+ts-after",
    ] {
        let message = rejected(name);
        assert!(message.contains("leaf certificate"), "{name}: {message}");
    }
    assert_eq!(offsets("m-v2-ts-at-not-after"), [(AUTHORITY, 600)]);
}

#[test]
fn a_time_outside_an_authority_window_is_rejected() {
    // The certificate authority is not trusted at the verified time.
    for name in [
        "m-v2-ts/root-ca-window-before",
        "m-v2-ts/root-ca-window-after",
    ] {
        let message = rejected(name);
        assert!(message.contains("leaf certificate"), "{name}: {message}");
    }
    // The timestamp authority is not trusted at the time that it states,
    // so the timestamp proves nothing.
    for name in [
        "m-v2-ts/root-tsa-window-before",
        "m-v2-ts/root-tsa-window-after",
    ] {
        let message = rejected(name);
        assert!(message.contains("timestamps"), "{name}: {message}");
    }
    // The log's key is not trusted at the integrated time, so the entry
    // timestamp is not accepted and the entry is passed over; the other
    // entry and the timestamp still carry the bundle.
    assert_eq!(offsets("m-both/root-log-window-after"), [(AUTHORITY, 120)]);
    verify("m-both/root-ctlog-window-after").unwrap_err();
}

#[test]
fn a_bundle_without_timestamps_relies_on_its_log_time() {
    assert_eq!(offsets("m-both/timestamps-removed"), [(LOG, 60)]);
    verify("m-v2-ts/timestamps-removed").unwrap_err();
    verify("m-v2-ts/timestamps-empty-list").unwrap_err();
}

#[test]
fn a_certificate_whose_signature_algorithms_differ_is_rejected() {
    let message = rejected("m-algorithm-mismatch");
    assert!(message.contains("signature algorithm differs"), "{message}");
}

#[test]
fn a_p384_certificate_signs_with_either_hash() {
    for name in [
        "m-p384-sha384-v1",
        "m-p384-sha256-v1",
        "m-p384-sha384-v2",
        "m-p384-sha256-v2",
    ] {
        verify(name).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    // A P-256 certificate signs with SHA-256 only.
    verify("m-p256-sha384-v1").unwrap_err();
}

#[test]
fn embedded_certificate_timestamps_must_verify_under_a_listed_log() {
    for name in [
        "m-no-sct",
        "m-sct-unknown-log",
        "m-sct-bad-signature",
        "m-sct-before-ct-start",
        "m-sct-dup",
    ] {
        verify(name).unwrap_err();
    }
    // A timestamp of an unlisted log beside a good one does no harm.
    verify("m-sct-known+unknown").unwrap();
}

#[test]
fn the_whole_path_must_permit_code_signing() {
    verify("m-eku-serverauth").unwrap_err();
    verify("m-restricted-intermediate").unwrap_err();
    // A certificate that lists no purpose is not restricted.
    verify("m-eku-none").unwrap();
}

#[test]
fn the_statement_must_name_the_digest() {
    verify("s-second-subject").unwrap();
    verify("s-upper-hex").unwrap();
    for name in [
        "s-no-match",
        "s-digest-under-sha512-name",
        "s-no-subject",
        "s-non-hex-other-subject",
        "s-non-hex-other-algorithm",
        "s-1025-subjects",
        "s-33-digests",
        "m-payload-type-other",
        "m-v2-ts/digest-other",
    ] {
        verify(name).unwrap_err();
    }
    verify("s-1024-subjects").unwrap();
    verify("s-32-digests").unwrap();
}

#[test]
fn a_registry_certificate_bundle_is_dated_by_its_timestamp() {
    let verified = verify("c-happy").unwrap();
    assert_eq!(offsets("c-happy"), [(AUTHORITY, 60)]);
    assert_eq!(verified.identity.extensions.issuer, "");
    assert_eq!(
        verified.identity.subject_alternative_name,
        "https://registry.tinfoil.sh/scopes/public"
    );
}

#[test]
fn a_registry_certificate_with_an_issuer_claim_is_rejected() {
    assert!(rejected("c-issuer-claim").contains("issuer claim"));
}

#[test]
fn a_registry_certificate_of_another_issuer_is_rejected() {
    assert!(rejected("c-wrong-issuer").contains("leaf certificate"));
    assert!(rejected("c-timestamp-after-cert").contains("leaf certificate"));
}

#[test]
fn a_registry_certificate_bundle_needs_a_timestamp() {
    assert!(rejected("c-no-timestamp").contains("timestamps"));
}

#[test]
fn a_log_time_does_not_date_a_registry_certificate_bundle() {
    assert!(rejected("c-log-time-only").contains("timestamps"));
    // Beside a timestamp, the log's time is still not a verified time.
    assert_eq!(offsets("c-log-time-and-timestamp"), [(AUTHORITY, 120)]);
}
