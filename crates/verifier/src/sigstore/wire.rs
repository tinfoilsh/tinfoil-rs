//! Reading the JSON forms of bundles and trusted roots.
//!
//! Every object is read with a closed set of member names, `null` reads as
//! absent, byte strings are canonical base64 and 64-bit integers are decimal
//! strings or integer literals.

use super::SigstoreError;
use crate::canonical::decode_base64;
use crate::instant::Instant;
use crate::json::{Object, Value};

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

/// An object whose members are restricted to a closed set of names.
#[derive(Debug, Clone, Copy)]
pub(super) struct Members<'a> {
    path: &'a str,
    object: &'a Object,
}

impl<'a> Members<'a> {
    /// Reads `value` as an object at `path` whose members are all among
    /// `allowed`. `null` is `None`.
    pub(super) fn of(
        value: &'a Value,
        path: &'a str,
        allowed: &[&str],
    ) -> Result<Option<Self>, SigstoreError> {
        let object = match value {
            Value::Null => return Ok(None),
            Value::Object(object) => object,
            other => {
                return Err(error(format!(
                    "{path}: cannot decode JSON {} as an object",
                    other.kind()
                )));
            }
        };
        if let Some((name, _)) = object.iter().find(|(name, _)| !allowed.contains(name)) {
            return Err(error(format!("{path}: unknown member {name:?}")));
        }
        Ok(Some(Self { path, object }))
    }

    /// As [`Members::of`], where the object must be present.
    pub(super) fn required(
        value: Option<&'a Value>,
        path: &'a str,
        allowed: &[&str],
    ) -> Result<Self, SigstoreError> {
        value
            .map(|value| Self::of(value, path, allowed))
            .transpose()?
            .flatten()
            .ok_or_else(|| error(format!("{path} is missing")))
    }

    /// The member called `name`, unless it is absent or `null`.
    pub(super) fn get(&self, name: &str) -> Option<&'a Value> {
        self.object.get(name).filter(|value| !value.is_null())
    }

    fn missing(&self, name: &str) -> SigstoreError {
        error(format!("{}.{name} is missing", self.path))
    }

    fn mismatch(&self, name: &str, found: &Value, expected: &str) -> SigstoreError {
        error(format!(
            "{}.{name}: cannot decode JSON {} as {expected}",
            self.path,
            found.kind()
        ))
    }

    /// A string member; absent is `None`.
    pub(super) fn string(&self, name: &str) -> Result<Option<&'a str>, SigstoreError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(other) => Err(self.mismatch(name, other, "a string")),
        }
    }

    /// A string member that must be present and not empty.
    pub(super) fn required_string(&self, name: &str) -> Result<&'a str, SigstoreError> {
        self.string(name)?
            .filter(|text| !text.is_empty())
            .ok_or_else(|| self.missing(name))
    }

    /// A byte-string member in canonical base64; absent is `None`.
    pub(super) fn bytes(&self, name: &str) -> Result<Option<Vec<u8>>, SigstoreError> {
        self.string(name)?
            .map(|text| decode_base64(&format!("{}.{name}", self.path), text))
            .transpose()
            .map_err(Into::into)
    }

    /// A byte-string member that must be present and not empty.
    pub(super) fn required_bytes(&self, name: &str) -> Result<Vec<u8>, SigstoreError> {
        self.bytes(name)?
            .filter(|bytes| !bytes.is_empty())
            .ok_or_else(|| self.missing(name))
    }

    /// An array member; absent is the empty array.
    pub(super) fn array(&self, name: &str) -> Result<&'a [Value], SigstoreError> {
        match self.get(name) {
            None => Ok(&[]),
            Some(Value::Array(items)) => Ok(items),
            Some(other) => Err(self.mismatch(name, other, "an array")),
        }
    }

    /// A signed 64-bit integer member, as a decimal string or an integer
    /// literal; absent is zero.
    pub(super) fn int64(&self, name: &str) -> Result<i64, SigstoreError> {
        let literal = match self.get(name) {
            None => return Ok(0),
            Some(Value::String(text)) => text.as_str(),
            Some(Value::Number(number)) => number.as_str(),
            Some(other) => return Err(self.mismatch(name, other, "an integer")),
        };
        let digits = literal.strip_prefix('-').unwrap_or(literal);
        let plain = !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        literal
            .parse::<i64>()
            .ok()
            .filter(|_| plain)
            .ok_or_else(|| {
                error(format!(
                    "{}.{name}: {literal:?} is not a 64-bit integer",
                    self.path
                ))
            })
    }

    /// An integer member that must be present and not negative.
    pub(super) fn required_index(&self, name: &str) -> Result<u64, SigstoreError> {
        if self.get(name).is_none() {
            return Err(self.missing(name));
        }
        u64::try_from(self.int64(name)?)
            .map_err(|_| error(format!("{}.{name} is negative", self.path)))
    }

    /// A time member in RFC 3339; absent is `None`.
    pub(super) fn time(&self, name: &str) -> Result<Option<Instant>, SigstoreError> {
        self.string(name)?
            .map(|text| {
                Instant::parse_rfc3339(text)
                    .map_err(|cause| error(format!("{}.{name}: {cause}", self.path)))
            })
            .transpose()
    }
}

/// A lower bound on the size of the compact JSON encoding of `value`: the
/// bytes of its strings, names and number literals, and one byte for every
/// value. The walk uses no recursion.
pub(super) fn encoded_size(value: &Value) -> usize {
    let mut size = 0usize;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        size = size.saturating_add(1);
        match value {
            Value::Null | Value::Bool(_) => {}
            Value::Number(number) => size = size.saturating_add(number.as_str().len()),
            Value::String(text) => size = size.saturating_add(text.len()),
            Value::Array(items) => pending.extend(items),
            Value::Object(object) => {
                for (name, member) in object.iter() {
                    size = size.saturating_add(name.len());
                    pending.push(member);
                }
            }
        }
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn members<'a>(value: &'a Value, allowed: &[&str]) -> Result<Members<'a>, SigstoreError> {
        Members::required(Some(value), "x", allowed)
    }

    #[test]
    fn an_object_is_read_with_a_closed_set_of_names() {
        let value = json::parse(br#"{"a":"1","b":null}"#).unwrap();
        let read = members(&value, &["a", "b"]).unwrap();
        assert_eq!(read.string("a").unwrap(), Some("1"));
        assert_eq!(read.string("b").unwrap(), None);
        assert_eq!(read.string("c").unwrap(), None);
        assert!(members(&value, &["a"]).is_err());
        assert!(Members::required(None, "x", &[]).is_err());
        assert!(Members::required(Some(&Value::Null), "x", &[]).is_err());
        assert!(Members::of(&json::parse(b"[]").unwrap(), "x", &[]).is_err());
    }

    #[test]
    fn integers_are_decimal_strings_or_integer_literals() {
        let value = json::parse(
            br#"{"a":"12","b":34,"c":"-5","d":"1.0","e":1e2,"f":"+1","g":"","h":true,"i":"9223372036854775808","j":"007"}"#,
        )
        .unwrap();
        let read = members(&value, &["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]).unwrap();
        assert_eq!(read.int64("a").unwrap(), 12);
        assert_eq!(read.int64("b").unwrap(), 34);
        assert_eq!(read.int64("c").unwrap(), -5);
        assert_eq!(read.int64("absent").unwrap(), 0);
        for bad in ["d", "e", "f", "g", "h", "i", "j"] {
            assert!(read.int64(bad).is_err(), "{bad}");
        }
        assert_eq!(read.required_index("a").unwrap(), 12);
        assert!(read.required_index("c").is_err());
        assert!(read.required_index("absent").is_err());
    }

    #[test]
    fn byte_strings_are_canonical_base64() {
        let value = json::parse(br#"{"a":"AQID","b":"AQI","c":"AQJ=","d":"","e":"A-_="}"#).unwrap();
        let read = members(&value, &["a", "b", "c", "d", "e"]).unwrap();
        assert_eq!(read.required_bytes("a").unwrap(), [1, 2, 3]);
        assert!(read.bytes("b").is_err());
        assert!(read.bytes("c").is_err());
        assert!(read.bytes("e").is_err());
        assert_eq!(read.bytes("d").unwrap(), Some(Vec::new()));
        assert!(read.required_bytes("d").is_err());
    }

    #[test]
    fn the_size_estimate_counts_text_at_any_depth() {
        let value = json::parse(br#"{"ab":["cd",12,{"e":null}]}"#).unwrap();
        // Six values, two names of 2 + 1 bytes, "cd" and "12".
        assert_eq!(encoded_size(&value), 6 + 3 + 4);
        let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
        assert_eq!(encoded_size(&json::parse(deep.as_bytes()).unwrap()), 5000);
    }
}
