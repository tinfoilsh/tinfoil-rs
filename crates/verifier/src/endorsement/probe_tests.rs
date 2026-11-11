//! Recorded probes for the string rules of this module.
//!
//! `pure_probes.json` holds inputs for the rules that involve no
//! signature: workflow identities, release references, config names and
//! registry identifiers, artifact forms and release tags. Most inputs are
//! one edit away from a well-formed value. Each row ends in the verdict of
//! a second, independent implementation of the same rules, which this
//! module must reproduce exactly.

use super::approval::{
    Artifact, ArtifactKind, parse_name, validate_identity, validate_registry_id, validate_revision,
};
use super::reference::{AuthenticatedArtifact, WorkflowIdentity, parse_reference};
use super::runtime::release_tag;
use crate::json::{self, Value};

const PROBES: &[u8] = include_bytes!("../../tests/data/endorsement/pure_probes.json");

fn rows(document: &Value, name: &str) -> Vec<Vec<Value>> {
    let rows = document.as_object().unwrap().get(name).unwrap();
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| {
            row.as_array()
                .unwrap()
                .iter()
                .map(|cell| match cell {
                    Value::String(text) => Value::String(text.clone()),
                    Value::Bool(flag) => Value::Bool(*flag),
                    other => panic!("unexpected cell {other:?}"),
                })
                .collect()
        })
        .collect()
}

fn text(cell: &Value) -> &str {
    cell.as_str().unwrap()
}

fn flag(cell: &Value) -> bool {
    cell.as_bool().unwrap()
}

#[test]
fn workflow_identities_match_the_recorded_names() {
    let document = json::parse(PROBES).unwrap();
    let rows = rows(&document, "san");
    assert!(rows.len() > 300);
    let mut matched = 0;
    for row in &rows {
        let [kind, argument, name, expected] = row.as_slice() else {
            panic!("a row is [kind, argument, name, verdict]");
        };
        let identity = match text(kind) {
            "release" => WorkflowIdentity::tagged_release(text(argument)).unwrap(),
            "platform" => WorkflowIdentity::platform_endorsements(),
            "witness" => WorkflowIdentity::freshness_witness(),
            "runtime" => WorkflowIdentity::runtime_release(text(argument)),
            other => panic!("unknown identity {other}"),
        };
        assert_eq!(
            identity.matches(text(name)),
            flag(expected),
            "{} {:?}: {:?}",
            text(kind),
            text(argument),
            text(name)
        );
        matched += usize::from(flag(expected));
    }
    assert!(matched > 100 && matched < rows.len());
}

#[test]
fn release_references_parse_as_recorded() {
    let document = json::parse(PROBES).unwrap();
    let rows = rows(&document, "references");
    assert!(rows.len() > 300);
    for row in &rows {
        let [reference, ok, repo, tag, digest] = row.as_slice() else {
            panic!("a row is [reference, verdict, repo, tag, digest]");
        };
        let parsed = parse_reference(text(reference));
        assert_eq!(parsed.is_ok(), flag(ok), "{:?}", text(reference));
        if let Ok(parsed) = parsed {
            let absent_or = |part: Option<String>| part.unwrap_or_default();
            assert_eq!(parsed.repo, text(repo));
            assert_eq!(absent_or(parsed.tag), text(tag), "{:?}", text(reference));
            assert_eq!(
                absent_or(parsed.digest),
                text(digest),
                "{:?}",
                text(reference)
            );
        }
    }
}

#[test]
fn names_and_identifiers_validate_as_recorded() {
    let document = json::parse(PROBES).unwrap();
    let rows_of_strings = rows(&document, "strings");
    assert!(rows_of_strings.len() > 300);
    for row in &rows_of_strings {
        let [kind, input, ok] = row.as_slice() else {
            panic!("a row is [kind, input, verdict]");
        };
        let input = text(input);
        let verdict = match text(kind) {
            "registry_id" => validate_registry_id(input).is_ok(),
            "identity" => validate_identity(input).is_ok(),
            "revision" => validate_revision(input).is_ok(),
            "name" => parse_name(input).is_ok(),
            other => panic!("unknown rule {other}"),
        };
        assert_eq!(verdict, flag(ok), "{} {input:?}", text(kind));
    }
    for row in &rows(&document, "names") {
        let [name, ok, identity, revision] = row.as_slice() else {
            panic!("a row is [name, verdict, identity, revision]");
        };
        match parse_name(text(name)) {
            Ok(parts) => {
                assert!(flag(ok));
                assert_eq!(parts, (text(identity), text(revision)));
            }
            Err(_) => assert!(!flag(ok), "{:?}", text(name)),
        }
    }
}

#[test]
fn artifacts_validate_as_recorded() {
    let document = json::parse(PROBES).unwrap();
    let rows_of_artifacts = rows(&document, "artifacts");
    assert!(rows_of_artifacts.len() > 300);
    let mut valid = 0;
    for row in &rows_of_artifacts {
        let [kind, repo, tag, name, digest, ok] = row.as_slice() else {
            panic!("a row is [kind, repo, tag, name, digest, verdict]");
        };
        let artifact = Artifact {
            kind: match text(kind) {
                "platform" => ArtifactKind::Platform,
                "runtime" => ArtifactKind::Runtime,
                other => panic!("unknown kind {other}"),
            },
            repo: text(repo).to_string(),
            tag: text(tag).to_string(),
            name: text(name).to_string(),
            digest: text(digest).to_string(),
        };
        assert_eq!(artifact.validate().is_ok(), flag(ok), "{artifact:?}");
        valid += usize::from(flag(ok));
    }
    assert!(valid > 5);

    for row in &rows(&document, "authenticated") {
        let [repo, tag, commit, subject_name, digest, ok] = row.as_slice() else {
            panic!("a row is [repo, tag, commit, subject, digest, verdict]");
        };
        let artifact = AuthenticatedArtifact {
            repo: text(repo).to_string(),
            tag: text(tag).to_string(),
            commit: text(commit).to_string(),
            subject_name: text(subject_name).to_string(),
            digest: text(digest).to_string(),
        };
        assert_eq!(artifact.validate().is_ok(), flag(ok), "{artifact:?}");
    }
}

#[test]
fn release_tags_are_derived_as_recorded() {
    let document = json::parse(PROBES).unwrap();
    for row in &rows(&document, "release_tags") {
        let [version, tag] = row.as_slice() else {
            panic!("a row is [version, tag]");
        };
        assert_eq!(release_tag(text(version)), text(tag), "{:?}", text(version));
    }
}
