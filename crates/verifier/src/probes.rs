//! Test support for recorded probe sets.
//!
//! A probe set is a JSON object with a `cases` array and, optionally, named
//! `bases`. Each case records an input and the outcome that a strict
//! implementation gives for it. The input is spelled in one of four ways:
//!
//! - `input`: the text itself;
//! - `input_hex`: the bytes in hex, for input that is not UTF-8;
//! - `parts`: a list of `{text, count}`, each text repeated `count` times;
//! - `base`, `at`, `del`, `ins`: the named base with `del` bytes at offset
//!   `at` replaced by `ins`.
//!
//! `pad` appends that many spaces. `sha256_prefix` pins the assembled bytes.

use sha2::{Digest, Sha256};

use crate::canonical;
use crate::json::{self, Object, Value, decode};

/// A parsed probe set.
pub struct Probes {
    document: Value,
}

impl Probes {
    pub fn parse(data: &[u8]) -> Self {
        Probes {
            document: json::parse(data).unwrap(),
        }
    }

    fn object(&self) -> &Object {
        self.document.as_object().unwrap()
    }

    /// The text of the base called `name`.
    pub fn base(&self, name: &str) -> &str {
        let bases = self.object().get("bases").and_then(Value::as_object);
        bases.unwrap().get(name).unwrap().as_str().unwrap()
    }

    pub fn cases(&self) -> impl Iterator<Item = Case<'_>> {
        let bases = self.object().get("bases").and_then(Value::as_object);
        self.object()
            .get("cases")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(move |case| Case {
                fields: case.as_object().unwrap(),
                bases,
            })
    }
}

/// One recorded case.
#[derive(Clone, Copy)]
pub struct Case<'a> {
    fields: &'a Object,
    bases: Option<&'a Object>,
}

impl<'a> Case<'a> {
    /// A record nested in a case, read with the same accessors.
    pub fn of(fields: &'a Object) -> Self {
        Case {
            fields,
            bases: None,
        }
    }

    pub fn get(&self, name: &str) -> Option<&'a Value> {
        self.fields.get(name)
    }

    /// A string field, or the empty string.
    pub fn text(&self, name: &str) -> &'a str {
        self.get(name).and_then(Value::as_str).unwrap_or("")
    }

    /// A boolean field, which must be present.
    pub fn flag(&self, name: &str) -> bool {
        self.get(name).and_then(Value::as_bool).unwrap()
    }

    /// A non-negative integer field, or zero.
    pub fn count(&self, name: &str) -> usize {
        self.get(name).map_or(0, count)
    }

    pub fn name(&self) -> &'a str {
        self.text("name")
    }

    /// Assembles the input and checks it against the recorded digest.
    pub fn input(&self) -> Vec<u8> {
        let mut input = if let Some(text) = self.get("input") {
            text.as_str().unwrap().as_bytes().to_vec()
        } else if let Some(hex) = self.get("input_hex") {
            canonical::decode_hex(hex.as_str().unwrap()).unwrap()
        } else if let Some(parts) = self.get("parts") {
            let mut out = Vec::new();
            for part in parts.as_array().unwrap() {
                let part = part.as_object().unwrap();
                let text = part.get("text").unwrap().as_str().unwrap();
                out.extend(text.as_bytes().repeat(count(part.get("count").unwrap())));
            }
            out
        } else {
            let base = self.bases.unwrap().get(self.text("base")).unwrap();
            let base = base.as_str().unwrap().as_bytes();
            let (at, del) = (self.count("at"), self.count("del"));
            let mut out = base[..at].to_vec();
            out.extend_from_slice(self.text("ins").as_bytes());
            out.extend_from_slice(&base[at + del..]);
            out
        };
        input.resize(input.len() + self.count("pad"), b' ');
        let digest = canonical::encode_lower_hex(&Sha256::digest(&input));
        assert!(
            digest.starts_with(self.text("sha256_prefix"))
                && !self.text("sha256_prefix").is_empty(),
            "{}: the assembled input differs from the recorded one",
            self.name()
        );
        input
    }
}

/// A non-negative integer.
pub fn count(value: &Value) -> usize {
    usize::try_from(decode::u64(value, "count").unwrap()).unwrap()
}
