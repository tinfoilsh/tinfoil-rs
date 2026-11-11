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
    text_of(name, object.and_then(|object| object.get(name)))
}

/// The string that the member `name` holds, given the member's value;
/// absent or `null` is the empty string.
fn text_of<'a>(name: &str, value: Option<&'a Value>) -> Result<&'a str, EndorsementError> {
    match value {
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
        // Each entry is read where the walk finds it: the map is as large
        // as the statement allows, so no entry is looked up by name.
        let digests = digest
            .iter()
            .flat_map(|digest| digest.iter())
            .map(|(algorithm, value)| Ok((algorithm, text_of(algorithm, Some(value))?)))
            .collect::<Result<Vec<_>, EndorsementError>>()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn subject_with(digests: &str) -> String {
        format!(r#"{{"subject":[{{"name":"n","digest":{{{digests}}}}}]}}"#)
    }

    #[test]
    fn digests_are_read_in_order_with_their_own_values() {
        let value = json::parse(subject_with(r#""b":"2","a":"1","c":null"#).as_bytes()).unwrap();
        let statement = statement(&value, &[]).unwrap();
        let [subject] = statement.subjects.as_slice() else {
            panic!("one subject");
        };
        assert_eq!(subject.name, "n");
        assert_eq!(subject.digests, [("b", "2"), ("a", "1"), ("c", "")]);
        assert_eq!(subject.only_digest("b"), None);

        let value = json::parse(subject_with(r#""a":"1","b":2"#).as_bytes()).unwrap();
        assert!(super::statement(&value, &[]).is_err());
    }

    #[test]
    fn a_digest_map_of_any_size_is_read_in_one_pass() {
        // As many entries as a statement of the greatest size can hold.
        const ENTRIES: usize = 12_000;
        let digests: Vec<String> = (0..ENTRIES)
            .map(|index| format!(r#""{index}":"""#))
            .collect();
        let payload = subject_with(&digests.join(","));
        assert!(payload.len() < crate::sigstore::statement::MAX_STATEMENT_SIZE);
        let value = json::parse(payload.as_bytes()).unwrap();
        let statement = statement(&value, &[]).unwrap();
        let digests = &statement.subjects[0].digests;
        assert_eq!(digests.len(), ENTRIES);
        // Every entry is the one at its own place in the map.
        for (index, (algorithm, digest)) in digests.iter().enumerate() {
            assert_eq!(*algorithm, index.to_string());
            assert_eq!(*digest, "");
        }
    }
}
