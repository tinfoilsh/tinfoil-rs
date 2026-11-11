//! Recorded probe sets for the strict decoders and for path verification.
//!
//! `der_probes.json` holds encodings of certificates, revocation lists,
//! timestamp responses and ECDSA signatures, most of them made by changing
//! one detail of a well-formed value. Each case records the verdict of this
//! crate (`rust`) and the verdict of a second, independent decoder
//! (`reference`). Where
//! the two differ this crate is the stricter one, and the case names the
//! `class` of the difference.
//!
//! `path_cases.json` holds certificates and revocation lists minted for the
//! path and issuer rules, with the same two verdicts per case.

use crate::canonical::decode_hex;
use crate::instant::Instant;
use crate::json::{self, Object, Value};
use crate::sigstore::timestamp::parse_response;
use crate::x509::der::ecdsa_der_to_raw;
use crate::x509::{Certificate, Crl, KeyPurpose, verify_chain};

const DER_PROBES: &[u8] = include_bytes!("../../tests/data/x509/der_probes.json");
const PATH_CASES: &[u8] = include_bytes!("../../tests/data/x509/path_cases.json");

fn object(value: &Value) -> &Object {
    value.as_object().unwrap()
}

fn text<'a>(case: &'a Object, name: &str) -> &'a str {
    case.get(name).and_then(Value::as_str).unwrap()
}

fn flag(case: &Object, name: &str) -> bool {
    case.get(name).and_then(Value::as_bool).unwrap()
}

fn hex(value: &Value) -> Vec<u8> {
    decode_hex(value.as_str().unwrap()).unwrap()
}

fn index(value: &Value) -> usize {
    value.as_number().unwrap().as_str().parse().unwrap()
}

/// The bytes of a case: its own `hex`, or a named base with `edits` applied,
/// each edit replacing `del` bytes at offset `at` of the base.
fn input(case: &Object, bases: &Object) -> Vec<u8> {
    if let Some(own) = case.get("hex") {
        return hex(own);
    }
    let mut bytes = hex(bases.get(text(case, "base")).unwrap());
    let edits = case.get("edits").and_then(Value::as_array).unwrap();
    // Offsets refer to the base, so the edits are applied from the end.
    for edit in edits.iter().rev() {
        let [at, del, ins] = edit.as_array().unwrap() else {
            panic!("an edit is [at, del, ins]");
        };
        let at = index(at);
        bytes.splice(at..at + index(del), hex(ins));
    }
    bytes
}

fn accepts(kind: &str, der: &[u8]) -> bool {
    match kind {
        "cert" => Certificate::from_der(der).is_ok(),
        "crl" => Crl::from_der(der).is_ok(),
        "tsr" => parse_response(der).is_ok(),
        "ecdsa" => ecdsa_der_to_raw(der, 32).is_ok(),
        other => panic!("unknown kind {other}"),
    }
}

#[test]
fn every_recorded_encoding_gets_its_recorded_verdict() {
    let document = json::parse(DER_PROBES).unwrap();
    let bases = object(object(&document).get("bases").unwrap());
    let cases = object(&document)
        .get("cases")
        .and_then(Value::as_array)
        .unwrap();
    assert!(cases.len() >= 400, "{} cases", cases.len());
    let mut wrong = Vec::new();
    for case in cases.iter().map(object) {
        let got = accepts(text(case, "kind"), &input(case, bases));
        if got != flag(case, "rust") {
            wrong.push(format!("{}: got {got}", text(case, "name")));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn no_recorded_verdict_is_looser_than_the_independent_one() {
    for (data, lists) in [
        (DER_PROBES, &["cases"][..]),
        (PATH_CASES, &["paths", "list_issuers"]),
    ] {
        let document = json::parse(data).unwrap();
        for list in lists {
            let cases = object(&document).get(list).and_then(Value::as_array);
            for case in cases.unwrap().iter().map(object) {
                let (rust, reference) = (flag(case, "rust"), flag(case, "reference"));
                assert!(reference || !rust, "{} is accepted", text(case, "name"));
                // A difference is always explained.
                assert_eq!(rust != reference, case.get("class").is_some());
            }
        }
    }
}

struct Minted {
    document: Value,
}

impl Minted {
    fn load() -> Self {
        Self {
            document: json::parse(PATH_CASES).unwrap(),
        }
    }

    fn certificate(&self, name: &str) -> Certificate {
        let certificates = object(object(&self.document).get("certificates").unwrap());
        Certificate::from_der(&hex(certificates.get(name).unwrap())).unwrap()
    }

    fn certificates(&self, names: &Value) -> Vec<Certificate> {
        let names = names.as_array().unwrap().iter();
        names
            .map(|name| self.certificate(name.as_str().unwrap()))
            .collect()
    }

    fn list_der(&self, name: &str) -> Vec<u8> {
        let lists = object(object(&self.document).get("lists").unwrap());
        hex(lists.get(name).unwrap())
    }

    fn list(&self, name: &str) -> Crl {
        Crl::from_der(&self.list_der(name)).unwrap()
    }

    fn cases(&self, list: &str) -> impl Iterator<Item = &Object> {
        let cases = object(&self.document).get(list).and_then(Value::as_array);
        cases.unwrap().iter().map(object)
    }
}

fn at(text: &str) -> Instant {
    Instant::parse_rfc3339(text).unwrap()
}

#[test]
fn every_recorded_path_gets_its_recorded_verdict() {
    let minted = Minted::load();
    let mut wrong = Vec::new();
    let mut count = 0;
    for case in minted.cases("paths") {
        count += 1;
        let leaf = minted.certificate(text(case, "leaf"));
        let intermediates = minted.certificates(case.get("intermediates").unwrap());
        let roots = minted.certificates(case.get("roots").unwrap());
        let seconds: i64 = index(case.get("at").unwrap()).try_into().unwrap();
        let purpose = match text(case, "purpose") {
            "any" => KeyPurpose::Any,
            "server_auth" => KeyPurpose::ServerAuth,
            "code_signing" => KeyPurpose::CodeSigning,
            "time_stamping" => KeyPurpose::TimeStamping,
            other => panic!("unknown purpose {other}"),
        };
        let verdict = verify_chain(
            &leaf,
            &intermediates,
            &roots,
            Instant::from_unix(seconds, 0).unwrap(),
            purpose,
        );
        if verdict.is_ok() != flag(case, "rust") {
            wrong.push(format!("{}: got {verdict:?}", text(case, "name")));
        }
    }
    assert!(count >= 45, "{count} cases");
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn every_recorded_list_issuer_gets_its_recorded_verdict() {
    let minted = Minted::load();
    let mut wrong = Vec::new();
    for case in minted.cases("list_issuers") {
        let issuer = minted.certificate(text(case, "issuer"));
        let verdict = Crl::from_der(&minted.list_der(text(case, "crl")))
            .and_then(|list| list.verify_issued_by(&issuer));
        if verdict.is_ok() != flag(case, "rust") {
            wrong.push(format!("{}: got {verdict:?}", text(case, "name")));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn a_verified_path_runs_from_the_leaf_to_the_root() {
    let minted = Minted::load();
    let (leaf, inter, root) = (
        minted.certificate("leaf"),
        minted.certificate("inter"),
        minted.certificate("root"),
    );
    let intermediates = [minted.certificate("p0"), inter.clone()];
    let roots = [minted.certificate("root_crit"), root.clone()];
    let path = verify_chain(
        &leaf,
        &intermediates,
        &roots,
        at("2026-01-01T12:00:00Z"),
        KeyPurpose::CodeSigning,
    )
    .unwrap();
    assert_eq!(path, [&leaf, &inter, &root]);

    // A trust anchor is taken as given: the path ends at it.
    let path = verify_chain(
        &leaf,
        &[],
        std::slice::from_ref(&inter),
        at("2026-01-01T12:00:00Z"),
        KeyPurpose::Any,
    )
    .unwrap();
    assert_eq!(path, [&leaf, &inter]);
    let alone = std::slice::from_ref(&leaf);
    let path = verify_chain(&leaf, &[], alone, leaf.not_before(), KeyPurpose::Any).unwrap();
    assert_eq!(path, [&leaf]);
}

#[test]
fn a_path_is_judged_at_the_instant_to_the_nanosecond() {
    let minted = Minted::load();
    let leaf = minted.certificate("leaf");
    let intermediates = [minted.certificate("inter")];
    let roots = [minted.certificate("root")];
    let verify =
        |instant| verify_chain(&leaf, &intermediates, &roots, instant, KeyPurpose::Any).is_ok();
    assert_eq!(leaf.not_before(), at("2026-01-01T00:00:00Z"));
    assert_eq!(leaf.not_after(), at("2026-01-02T00:00:00Z"));
    assert!(verify(at("2026-01-01T00:00:00Z")));
    assert!(!verify(at("2025-12-31T23:59:59.999999999Z")));
    assert!(verify(at("2026-01-02T00:00:00Z")));
    assert!(!verify(at("2026-01-02T00:00:00.000000001Z")));
}

#[test]
fn a_search_among_many_candidates_gives_up_within_its_bound() {
    let minted = Minted::load();
    let leaf = minted.certificate("leaf_xa");
    // Two authorities that certify each other, offered many times over, and
    // no trust anchor that either leads to.
    let pair = [
        minted.certificate("xa_by_xb"),
        minted.certificate("xb_by_xa"),
    ];
    let intermediates: Vec<Certificate> = pair.iter().cycle().take(400).cloned().collect();
    let roots = [minted.certificate("root")];
    let verdict = verify_chain(
        &leaf,
        &intermediates,
        &roots,
        at("2026-01-01T12:00:00Z"),
        KeyPurpose::Any,
    );
    assert!(verdict.is_err());
}

#[test]
fn a_list_is_current_from_this_update_to_next_update() {
    let list = Minted::load().list("crl");
    assert_eq!(list.this_update(), at("2026-01-01T00:00:00Z"));
    assert_eq!(list.next_update(), at("2026-02-01T00:00:00Z"));
    list.check_validity(at("2026-01-01T00:00:00Z")).unwrap();
    list.check_validity(at("2026-02-01T00:00:00Z")).unwrap();
    list.check_validity(at("2026-01-15T00:00:00Z")).unwrap();
    assert!(
        list.check_validity(at("2025-12-31T23:59:59.999999999Z"))
            .is_err()
    );
    assert!(
        list.check_validity(at("2026-02-01T00:00:00.000000001Z"))
            .is_err()
    );
}

#[test]
fn a_serial_number_is_revoked_whatever_its_leading_zeros() {
    let minted = Minted::load();
    let list = minted.list("crl");
    // The list revokes 0x1234 and 0x80; the second is encoded with a sign
    // byte.
    assert!(list.is_revoked(&[0x12, 0x34]));
    assert!(list.is_revoked(&[0x00, 0x12, 0x34]));
    assert!(list.is_revoked(&[0x80]));
    assert!(list.is_revoked(&[0x00, 0x80]));
    assert!(!list.is_revoked(&[0x12, 0x35]));
    assert!(!list.is_revoked(&[0x12]));
    assert!(!list.is_revoked(&[]));
    assert!(!minted.list("crl_empty").is_revoked(&[0x12, 0x34]));
    assert_eq!(list.issuer_der(), minted.certificate("root").subject_der());
    assert_eq!(list.der(), minted.list_der("crl"));
}

#[test]
fn a_list_verifies_under_its_issuer_only() {
    let minted = Minted::load();
    let list = minted.list("crl");
    list.verify_issued_by(&minted.certificate("root")).unwrap();
    // Another authority, and a certificate that has the issuer's key under
    // another name.
    assert!(
        list.verify_issued_by(&minted.certificate("other_root"))
            .is_err()
    );
    let renamed = list.verify_issued_by(&minted.certificate("root_twin_renamed"));
    assert!(renamed.unwrap_err().to_string().contains("issuer"));
    assert!(
        minted
            .list("crl_badsig")
            .verify_issued_by(&minted.certificate("root"))
            .is_err()
    );
}
