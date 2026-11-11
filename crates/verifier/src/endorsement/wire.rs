//! Reading signed statements whose members form a closed set.
//!
//! A member that the statement's profile does not define is an error at
//! every level, names are compared exactly, and `null` reads as absent.

use super::EndorsementError;
use crate::json::{Object, Value};

fn mismatch(path: &str, found: &Value, expected: &str) -> EndorsementError {
    EndorsementError::new(format!(
        "{path}: cannot decode JSON {} as {expected}",
        found.kind()
    ))
}

/// Reads `value` as an object at `path` whose members are all among
/// `allowed`. An absent or `null` value is `None`.
pub(super) fn object<'a>(
    value: Option<&'a Value>,
    path: &str,
    allowed: &[&str],
) -> Result<Option<&'a Object>, EndorsementError> {
    let object = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(object)) => object,
        Some(other) => return Err(mismatch(path, other, "an object")),
    };
    if let Some((name, _)) = object.iter().find(|(name, _)| !allowed.contains(name)) {
        return Err(EndorsementError::new(format!(
            "{path}: unknown member {name:?}"
        )));
    }
    Ok(Some(object))
}

/// The string member `name` of `object`; absent or `null` is the empty
/// string, and so is every member of an absent object.
pub(super) fn text<'a>(
    object: Option<&'a Object>,
    name: &str,
) -> Result<&'a str, EndorsementError> {
    match object.and_then(|object| object.get(name)) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(text)) => Ok(text),
        Some(other) => Err(mismatch(name, other, "a string")),
    }
}

/// The array member `name` of `object`; absent or `null` is the empty
/// array.
pub(super) fn array<'a>(
    object: Option<&'a Object>,
    name: &str,
) -> Result<&'a [Value], EndorsementError> {
    match object.and_then(|object| object.get(name)) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(other) => Err(mismatch(name, other, "an array")),
    }
}

/// One subject of a statement: its name and its digests as written.
#[derive(Debug, Default)]
pub(super) struct Subject<'a> {
    /// The name; empty when absent.
    pub(super) name: &'a str,
    /// The digests by algorithm, in the order of the statement.
    pub(super) digests: Vec<(&'a str, &'a str)>,
}

impl<'a> Subject<'a> {
    /// The digest of the subject when it has exactly one, under the
    /// algorithm `algorithm`.
    pub(super) fn only_digest(&self, algorithm: &str) -> Option<&'a str> {
        match self.digests.as_slice() {
            [(name, digest)] if *name == algorithm => Some(digest),
            _ => None,
        }
    }
}

/// The parts of a statement that every profile shares.
#[derive(Debug)]
pub(super) struct Statement<'a> {
    /// `_type`; empty when absent.
    pub(super) statement_type: &'a str,
    /// The subjects, in order.
    pub(super) subjects: Vec<Subject<'a>>,
    /// `predicateType`; empty when absent.
    pub(super) predicate_type: &'a str,
    /// `predicate`, with members among those that the profile defines;
    /// `None` when absent.
    pub(super) predicate: Option<&'a Object>,
}

/// Reads a parsed statement whose predicate has members among
/// `predicate_members`.
///
/// The statement is an object with `_type`, `subject`, `predicateType` and
/// `predicate` only; a subject is an object with `name` and `digest` only,
/// and a digest maps algorithm names to strings. A `null` subject reads as
/// one without a name or digests.
pub(super) fn statement<'a>(
    value: &'a Value,
    predicate_members: &[&str],
) -> Result<Statement<'a>, EndorsementError> {
    let top = object(
        Some(value),
        "statement",
        &["_type", "subject", "predicateType", "predicate"],
    )?;
    let mut subjects = Vec::new();
    for item in array(top, "subject")? {
        let subject = object(Some(item), "subject", &["name", "digest"])?;
        // The digest map is open: every name is an algorithm.
        let digest = match subject.and_then(|subject| subject.get("digest")) {
            None | Some(Value::Null) => None,
            Some(Value::Object(digest)) => Some(digest),
            Some(other) => return Err(mismatch("digest", other, "an object")),
        };
        let mut digests = Vec::new();
        for (algorithm, _) in digest.iter().flat_map(|digest| digest.iter()) {
            digests.push((algorithm, text(digest, algorithm)?));
        }
        subjects.push(Subject {
            name: text(subject, "name")?,
            digests,
        });
    }
    Ok(Statement {
        statement_type: text(top, "_type")?,
        subjects,
        predicate_type: text(top, "predicateType")?,
        predicate: object(
            top.and_then(|top| top.get("predicate")),
            "predicate",
            predicate_members,
        )?,
    })
}
