//! Strict JSON parsing for attestation material.
//!
//! [`parse`] accepts exactly one JSON value per RFC 8259 with the additional
//! rules of RFC 7493: the input is valid UTF-8, escaped surrogates come in
//! pairs, and no object repeats a member name. Numbers keep their literal
//! text, so that an integer is never rounded through a float. Nesting is
//! limited to [`MAX_DEPTH`] containers.
//!
//! Neither the parser nor any operation on a [`Value`] recurses, so the depth
//! of an untrusted document cannot exhaust the caller's stack. `Value`
//! deliberately does not implement `Clone`.
//!
//! The [`decode`] functions turn values into typed fields with one rule for
//! every decoder in the crate: `null` leaves a field at its empty value, and
//! any other value of the wrong type is an error.

use std::collections::HashSet;
use std::fmt;

/// The deepest nesting of arrays and objects that [`parse`] accepts.
pub const MAX_DEPTH: usize = 10_000;

/// Objects with fewer members than this are checked for duplicate names by
/// comparing against each earlier member; larger ones use a hash set.
const LINEAR_DUPLICATE_CHECK: usize = 16;

/// A parsed JSON value.
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, kept as its literal.
    Number(RawNumber),
    /// A string, with its escapes decoded.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Object),
}

impl Value {
    /// The JSON type of the value, for error messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    /// Whether the value is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The boolean, if the value is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The number, if the value is one.
    pub fn as_number(&self) -> Option<&RawNumber> {
        match self {
            Value::Number(number) => Some(number),
            _ => None,
        }
    }

    /// The string, if the value is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(string) => Some(string),
            _ => None,
        }
    }

    /// The elements, if the value is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The object, if the value is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(object) => Some(object),
            _ => None,
        }
    }
}

/// Frees nested values with an explicit work list. The compiler's own drop
/// would recurse once per nesting level.
impl Drop for Value {
    fn drop(&mut self) {
        let mut pending = match self {
            Value::Array(items) => std::mem::take(items),
            Value::Object(object) => object.take_values(),
            _ => return,
        };
        while let Some(mut value) = pending.pop() {
            match &mut value {
                Value::Array(items) => pending.append(items),
                Value::Object(object) => pending.append(&mut object.take_values()),
                _ => {}
            }
            // `value` has no children left, so dropping it here goes one
            // level deep at most.
        }
    }
}

/// Compares without recursion. Objects are equal when they have the same
/// members in the same order; numbers are equal when their literals are.
impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        while let Some(pair) = pending.pop() {
            match pair {
                (Value::Null, Value::Null) => {}
                (Value::Bool(a), Value::Bool(b)) if a == b => {}
                (Value::Number(a), Value::Number(b)) if a == b => {}
                (Value::String(a), Value::String(b)) if a == b => {}
                (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
                    pending.extend(a.iter().zip(b));
                }
                (Value::Object(a), Value::Object(b)) if a.len() == b.len() => {
                    for ((name_a, value_a), (name_b, value_b)) in a.iter().zip(b.iter()) {
                        if name_a != name_b {
                            return false;
                        }
                        pending.push((value_a, value_b));
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

impl Eq for Value {}

/// Shows scalars in full and containers by their size, so that formatting a
/// deeply nested value does not recurse.
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("Null"),
            Value::Bool(value) => write!(f, "Bool({value})"),
            Value::Number(number) => write!(f, "Number({})", number.as_str()),
            Value::String(string) => write!(f, "String({string:?})"),
            Value::Array(items) => write!(f, "Array(len {})", items.len()),
            Value::Object(object) => write!(f, "Object(len {})", object.len()),
        }
    }
}

/// A JSON object: its members in document order. Names are unique.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Object {
    members: Vec<(String, Value)>,
}

impl Object {
    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The value of the member called `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.members
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, value)| value)
    }

    /// The members in document order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.members
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// The members in document order, by value.
    pub fn into_members(self) -> Vec<(String, Value)> {
        self.members
    }

    fn take_values(&mut self) -> Vec<Value> {
        self.members.drain(..).map(|(_, value)| value).collect()
    }
}

/// A JSON number as it was written.
///
/// The integer accessors read the literal itself: a fraction or an exponent
/// is not an integer even when its value is whole, and a value outside the
/// target type is not rounded or wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNumber(Box<str>);

impl RawNumber {
    /// The literal.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The value as a `u64`. A literal with a sign, including `-0`, has none.
    pub fn to_u64(&self) -> Option<u64> {
        if !self.0.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        self.0.parse().ok()
    }

    /// The value as a `u32`, under the rules of [`RawNumber::to_u64`].
    pub fn to_u32(&self) -> Option<u32> {
        self.to_u64().and_then(|value| u32::try_from(value).ok())
    }

    /// The value as a `u8`, under the rules of [`RawNumber::to_u64`].
    pub fn to_u8(&self) -> Option<u8> {
        self.to_u64().and_then(|value| u8::try_from(value).ok())
    }

    /// The value as an `i64`. `-0` is zero.
    pub fn to_i64(&self) -> Option<i64> {
        let digits = self.0.strip_prefix('-').unwrap_or(&self.0);
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        self.0.parse().ok()
    }
}

/// Why [`parse`] rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonErrorKind {
    /// The input ended inside a value, or was empty.
    UnexpectedEnd,
    /// A byte that the grammar does not allow at its position.
    UnexpectedByte,
    /// Data after the top-level value.
    TrailingData,
    /// A malformed number literal.
    InvalidNumber,
    /// An unescaped control character inside a string.
    ControlCharacter,
    /// A malformed escape sequence.
    InvalidEscape,
    /// An escaped surrogate without its partner.
    UnpairedSurrogate,
    /// Bytes that are not UTF-8.
    InvalidUtf8,
    /// A member name that the object already has.
    DuplicateName,
    /// More than [`MAX_DEPTH`] nested containers.
    DepthExceeded,
}

/// A rejection by [`parse`], with the byte offset at which it was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError {
    kind: JsonErrorKind,
    offset: usize,
}

impl JsonError {
    /// Why the input was rejected.
    pub fn kind(&self) -> JsonErrorKind {
        self.kind
    }

    /// The byte offset at which the problem was detected.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            JsonErrorKind::UnexpectedEnd => "unexpected end of input",
            JsonErrorKind::UnexpectedByte => "unexpected character",
            JsonErrorKind::TrailingData => "data after the top-level value",
            JsonErrorKind::InvalidNumber => "invalid number",
            JsonErrorKind::ControlCharacter => "control character in string",
            JsonErrorKind::InvalidEscape => "invalid escape sequence",
            JsonErrorKind::UnpairedSurrogate => "unpaired surrogate escape",
            JsonErrorKind::InvalidUtf8 => "invalid UTF-8",
            JsonErrorKind::DuplicateName => "duplicate object member name",
            JsonErrorKind::DepthExceeded => "exceeded the maximum nesting depth",
        };
        write!(f, "invalid JSON: {reason} at offset {}", self.offset)
    }
}

impl std::error::Error for JsonError {}

/// Parses `data` as exactly one JSON value, with nothing but whitespace
/// around it.
pub fn parse(data: &[u8]) -> Result<Value, JsonError> {
    let mut parser = Parser { data, pos: 0 };
    let mut stack: Vec<Frame> = Vec::new();
    loop {
        // A value starts here.
        parser.skip_whitespace();
        let mut value = match parser.peek() {
            Some(b'{') => {
                if stack.len() >= MAX_DEPTH {
                    return Err(parser.error(JsonErrorKind::DepthExceeded));
                }
                parser.bump();
                parser.skip_whitespace();
                if parser.peek() == Some(b'}') {
                    parser.bump();
                    Value::Object(Object::default())
                } else {
                    let mut frame = ObjectFrame::default();
                    frame.name = parser.member_name(&mut frame)?;
                    stack.push(Frame::Object(frame));
                    continue;
                }
            }
            Some(b'[') => {
                if stack.len() >= MAX_DEPTH {
                    return Err(parser.error(JsonErrorKind::DepthExceeded));
                }
                parser.bump();
                parser.skip_whitespace();
                if parser.peek() == Some(b']') {
                    parser.bump();
                    Value::Array(Vec::new())
                } else {
                    stack.push(Frame::Array(Vec::new()));
                    continue;
                }
            }
            Some(b'"') => Value::String(parser.string()?),
            Some(b'-' | b'0'..=b'9') => Value::Number(parser.number()?),
            Some(b't') => parser.literal(b"true", Value::Bool(true))?,
            Some(b'f') => parser.literal(b"false", Value::Bool(false))?,
            Some(b'n') => parser.literal(b"null", Value::Null)?,
            Some(_) => return Err(parser.error(JsonErrorKind::UnexpectedByte)),
            None => return Err(parser.error(JsonErrorKind::UnexpectedEnd)),
        };

        // A value is complete. It goes into the innermost open container,
        // which may end here and so complete in turn.
        loop {
            parser.skip_whitespace();
            match stack.last_mut() {
                None => {
                    if parser.peek().is_some() {
                        return Err(parser.error(JsonErrorKind::TrailingData));
                    }
                    return Ok(value);
                }
                Some(Frame::Array(items)) => {
                    items.push(value);
                    match parser.peek() {
                        Some(b',') => {
                            parser.bump();
                            break;
                        }
                        Some(b']') => {
                            parser.bump();
                            value = Value::Array(std::mem::take(items));
                            stack.pop();
                        }
                        other => return Err(parser.unexpected(other)),
                    }
                }
                Some(Frame::Object(frame)) => {
                    let name = std::mem::take(&mut frame.name);
                    frame.members.push((name, value));
                    match parser.peek() {
                        Some(b',') => {
                            parser.bump();
                            parser.skip_whitespace();
                            frame.name = parser.member_name(frame)?;
                            break;
                        }
                        Some(b'}') => {
                            parser.bump();
                            value = Value::Object(Object {
                                members: std::mem::take(&mut frame.members),
                            });
                            stack.pop();
                        }
                        other => return Err(parser.unexpected(other)),
                    }
                }
            }
        }
    }
}

/// A container that is still open.
enum Frame {
    Array(Vec<Value>),
    Object(ObjectFrame),
}

#[derive(Default)]
struct ObjectFrame {
    members: Vec<(String, Value)>,
    /// The name whose value is being parsed.
    name: String,
    /// Every name so far, once the object is large enough to need a set.
    seen: Option<HashSet<String>>,
}

impl ObjectFrame {
    /// Whether the object already has, or is about to get, a member `name`.
    fn has_name(&mut self, name: &str) -> bool {
        if self.seen.is_none() && self.members.len() < LINEAR_DUPLICATE_CHECK {
            return self.members.iter().any(|(member, _)| member == name);
        }
        let members = &self.members;
        let seen = self
            .seen
            .get_or_insert_with(|| members.iter().map(|(member, _)| member.clone()).collect());
        !seen.insert(name.to_owned())
    }
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.advance(1);
    }

    fn advance(&mut self, count: usize) {
        self.pos = self.pos.saturating_add(count);
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.bump();
        Some(byte)
    }

    fn rest(&self) -> &[u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }

    fn error(&self, kind: JsonErrorKind) -> JsonError {
        JsonError {
            kind,
            offset: self.pos,
        }
    }

    /// The error for a byte, or the end of input, where something else was
    /// required.
    fn unexpected(&self, found: Option<u8>) -> JsonError {
        match found {
            Some(_) => self.error(JsonErrorKind::UnexpectedByte),
            None => self.error(JsonErrorKind::UnexpectedEnd),
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    /// Parses a member name and the colon after it, and rejects a name that
    /// the object already has.
    fn member_name(&mut self, frame: &mut ObjectFrame) -> Result<String, JsonError> {
        let start = self.pos;
        if self.peek() != Some(b'"') {
            return Err(self.unexpected(self.peek()));
        }
        let name = self.string()?;
        if frame.has_name(&name) {
            return Err(JsonError {
                kind: JsonErrorKind::DuplicateName,
                offset: start,
            });
        }
        self.skip_whitespace();
        if self.peek() != Some(b':') {
            return Err(self.unexpected(self.peek()));
        }
        self.bump();
        Ok(name)
    }

    fn literal(&mut self, text: &[u8], value: Value) -> Result<Value, JsonError> {
        let rest = self.rest();
        if rest.starts_with(text) {
            self.advance(text.len());
            return Ok(value);
        }
        if text.starts_with(rest) {
            self.advance(rest.len());
            return Err(self.error(JsonErrorKind::UnexpectedEnd));
        }
        Err(self.error(JsonErrorKind::UnexpectedByte))
    }

    /// Parses a string that starts at the current position, which holds its
    /// opening quote.
    fn string(&mut self) -> Result<String, JsonError> {
        self.bump();
        let mut out = String::new();
        loop {
            // Everything up to the next quote, backslash or control
            // character is literal text. None of those bytes occurs inside a
            // multi-byte sequence, so the run is checked as a whole.
            let rest = self.rest();
            let run = rest
                .iter()
                .position(|&byte| byte == b'"' || byte == b'\\' || byte < 0x20)
                .unwrap_or(rest.len());
            let literal = rest.get(..run).unwrap_or_default();
            match std::str::from_utf8(literal) {
                Ok(text) => out.push_str(text),
                Err(error) => {
                    self.advance(error.valid_up_to());
                    return Err(self.error(JsonErrorKind::InvalidUtf8));
                }
            }
            self.advance(run);
            match self.peek() {
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    out.push(self.escape()?);
                }
                Some(_) => return Err(self.error(JsonErrorKind::ControlCharacter)),
                None => return Err(self.error(JsonErrorKind::UnexpectedEnd)),
            }
        }
    }

    /// Decodes the escape sequence after a backslash.
    fn escape(&mut self) -> Result<char, JsonError> {
        let start = self.pos;
        let escaped = match self.next() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let first = self.hex4()?;
                let mut units = vec![first];
                if (0xD800..=0xDBFF).contains(&first) {
                    // A high surrogate is half of a pair; the low half must
                    // follow as its own escape.
                    if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                        return Err(JsonError {
                            kind: JsonErrorKind::UnpairedSurrogate,
                            offset: start,
                        });
                    }
                    units.push(self.hex4()?);
                }
                let mut decoded = char::decode_utf16(units);
                match (decoded.next(), decoded.next()) {
                    (Some(Ok(character)), None) => character,
                    _ => {
                        return Err(JsonError {
                            kind: JsonErrorKind::UnpairedSurrogate,
                            offset: start,
                        });
                    }
                }
            }
            Some(_) => {
                return Err(JsonError {
                    kind: JsonErrorKind::InvalidEscape,
                    offset: start,
                });
            }
            None => return Err(self.error(JsonErrorKind::UnexpectedEnd)),
        };
        Ok(escaped)
    }

    /// Reads the four hex digits of a `\u` escape.
    fn hex4(&mut self) -> Result<u16, JsonError> {
        let digits = self.rest().get(..4).unwrap_or_default();
        let unit = std::str::from_utf8(digits)
            .ok()
            .filter(|text| text.len() == 4 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .and_then(|text| u16::from_str_radix(text, 16).ok());
        match unit {
            Some(unit) => {
                self.advance(4);
                Ok(unit)
            }
            None if self.rest().len() < 4 && self.rest().iter().all(u8::is_ascii_hexdigit) => {
                self.advance(self.rest().len());
                Err(self.error(JsonErrorKind::UnexpectedEnd))
            }
            None => Err(self.error(JsonErrorKind::InvalidEscape)),
        }
    }

    fn number(&mut self) -> Result<RawNumber, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.next() {
            // A leading zero stands alone.
            Some(b'0') => {}
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.error(JsonErrorKind::InvalidNumber)),
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if !self.digits() {
                return Err(self.error(JsonErrorKind::InvalidNumber));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !self.digits() {
                return Err(self.error(JsonErrorKind::InvalidNumber));
            }
        }
        let literal = self.data.get(start..self.pos).unwrap_or_default();
        match std::str::from_utf8(literal) {
            Ok(text) => Ok(RawNumber(text.into())),
            Err(_) => Err(self.error(JsonErrorKind::InvalidNumber)),
        }
    }

    /// Consumes a run of digits and reports whether there was at least one.
    fn digits(&mut self) -> bool {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        self.pos > start
    }
}

/// Typed decoding of parsed values.
///
/// Each function takes the value of one member and the member's path for the
/// error message. `null` decodes to the empty value of the target type, as an
/// absent member does; any other value of the wrong type is an error.
pub mod decode {
    use std::fmt;

    use super::{Object, Value};

    /// A value that does not fit the field it was decoded into, or a member
    /// that the enclosing object does not define.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecodeError {
        message: String,
    }

    impl fmt::Display for DecodeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for DecodeError {}

    fn mismatch(path: &str, found: &Value, expected: &str) -> DecodeError {
        DecodeError {
            message: format!("{path}: cannot decode JSON {} as {expected}", found.kind()),
        }
    }

    /// The error for a member that the object at `path` does not define.
    pub fn unknown_member(path: &str, name: &str) -> DecodeError {
        DecodeError {
            message: format!("{path}: unknown member {name:?}"),
        }
    }

    /// A string; `null` is the empty string.
    pub fn string(mut value: Value, path: &str) -> Result<String, DecodeError> {
        match &mut value {
            Value::Null => Ok(String::new()),
            Value::String(string) => Ok(std::mem::take(string)),
            other => Err(mismatch(path, other, "a string")),
        }
    }

    /// A boolean; `null` is `false`.
    pub fn bool(value: &Value, path: &str) -> Result<bool, DecodeError> {
        match value {
            Value::Null => Ok(false),
            Value::Bool(value) => Ok(*value),
            other => Err(mismatch(path, other, "a boolean")),
        }
    }

    /// An object; `null` is `None`.
    pub fn object(mut value: Value, path: &str) -> Result<Option<Object>, DecodeError> {
        match &mut value {
            Value::Null => Ok(None),
            Value::Object(object) => Ok(Some(std::mem::take(object))),
            other => Err(mismatch(path, other, "an object")),
        }
    }

    /// An array; `null` is `None`.
    pub fn array(mut value: Value, path: &str) -> Result<Option<Vec<Value>>, DecodeError> {
        match &mut value {
            Value::Null => Ok(None),
            Value::Array(items) => Ok(Some(std::mem::take(items))),
            other => Err(mismatch(path, other, "an array")),
        }
    }

    /// An array of strings; `null` is `None`, and a `null` element is the
    /// empty string.
    pub fn strings(value: Value, path: &str) -> Result<Option<Vec<String>>, DecodeError> {
        let Some(items) = array(value, path)? else {
            return Ok(None);
        };
        items
            .into_iter()
            .map(|item| string(item, path))
            .collect::<Result<_, _>>()
            .map(Some)
    }

    fn integer<T>(
        value: &Value,
        path: &str,
        expected: &str,
        convert: impl FnOnce(&super::RawNumber) -> Option<T>,
        zero: T,
    ) -> Result<T, DecodeError> {
        match value {
            Value::Null => Ok(zero),
            Value::Number(number) => convert(number).ok_or_else(|| DecodeError {
                message: format!("{path}: JSON number {} is not {expected}", number.as_str()),
            }),
            other => Err(mismatch(path, other, expected)),
        }
    }

    /// A `u64`; `null` is zero.
    pub fn u64(value: &Value, path: &str) -> Result<u64, DecodeError> {
        integer(
            value,
            path,
            "an unsigned 64-bit integer",
            super::RawNumber::to_u64,
            0,
        )
    }

    /// A `u32`; `null` is zero.
    pub fn u32(value: &Value, path: &str) -> Result<u32, DecodeError> {
        integer(
            value,
            path,
            "an unsigned 32-bit integer",
            super::RawNumber::to_u32,
            0,
        )
    }

    /// A `u8`; `null` is zero.
    pub fn u8(value: &Value, path: &str) -> Result<u8, DecodeError> {
        integer(
            value,
            path,
            "an unsigned 8-bit integer",
            super::RawNumber::to_u8,
            0,
        )
    }

    /// An `i64`; `null` is zero.
    pub fn i64(value: &Value, path: &str) -> Result<i64, DecodeError> {
        integer(
            value,
            path,
            "a signed 64-bit integer",
            super::RawNumber::to_i64,
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(text: &str) -> Result<Value, JsonError> {
        parse(text.as_bytes())
    }

    fn kind_of(text: &str) -> JsonErrorKind {
        parse_str(text).unwrap_err().kind()
    }

    fn from_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn nested_arrays(depth: usize) -> String {
        "[".repeat(depth) + &"]".repeat(depth)
    }

    fn nested_objects(depth: usize) -> String {
        "{\"a\":".repeat(depth) + "1" + &"}".repeat(depth)
    }

    #[test]
    fn builds_values_in_document_order() {
        let value = parse_str(r#"{"z":[1,"x",null,true],"a":{"n":-1.50e3},"b":false}"#).unwrap();
        let object = value.as_object().unwrap();
        let names: Vec<&str> = object.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["z", "a", "b"]);
        let z = object.get("z").unwrap().as_array().unwrap();
        assert_eq!(z.len(), 4);
        assert_eq!(z[0].as_number().unwrap().as_str(), "1");
        assert_eq!(z[1].as_str(), Some("x"));
        assert!(z[2].is_null());
        assert_eq!(z[3].as_bool(), Some(true));
        let n = object.get("a").unwrap().as_object().unwrap().get("n");
        assert_eq!(n.unwrap().as_number().unwrap().as_str(), "-1.50e3");
        assert_eq!(object.get("b").unwrap().as_bool(), Some(false));
        assert!(object.get("missing").is_none());
        assert_eq!(object.len(), 3);
        assert!(!object.is_empty());
    }

    #[test]
    fn decodes_escapes() {
        let value = parse_str(r#""\"\\\/\b\f\n\r\tAé😀""#).unwrap();
        assert_eq!(
            value.as_str(),
            Some("\"\\/\u{8}\u{c}\n\r\tA\u{e9}\u{1f600}")
        );
    }

    #[test]
    fn reports_the_reason_and_offset() {
        assert_eq!(kind_of(""), JsonErrorKind::UnexpectedEnd);
        assert_eq!(kind_of("[1"), JsonErrorKind::UnexpectedEnd);
        assert_eq!(kind_of("nul"), JsonErrorKind::UnexpectedEnd);
        assert_eq!(kind_of("{} x"), JsonErrorKind::TrailingData);
        assert_eq!(kind_of("01"), JsonErrorKind::TrailingData);
        assert_eq!(kind_of("-"), JsonErrorKind::InvalidNumber);
        assert_eq!(kind_of("1."), JsonErrorKind::InvalidNumber);
        assert_eq!(kind_of("1e+"), JsonErrorKind::InvalidNumber);
        assert_eq!(kind_of("+1"), JsonErrorKind::UnexpectedByte);
        assert_eq!(kind_of("{a:1}"), JsonErrorKind::UnexpectedByte);
        assert_eq!(kind_of("\"a\nb\""), JsonErrorKind::ControlCharacter);
        assert_eq!(kind_of(r#""\x""#), JsonErrorKind::InvalidEscape);
        assert_eq!(kind_of(r#""\u00g0""#), JsonErrorKind::InvalidEscape);
        assert_eq!(kind_of(r#""\u00"#), JsonErrorKind::UnexpectedEnd);
        assert_eq!(kind_of(r#""\ud800""#), JsonErrorKind::UnpairedSurrogate);
        assert_eq!(kind_of(r#""\udc00""#), JsonErrorKind::UnpairedSurrogate);
        assert_eq!(kind_of(r#""\ud800A""#), JsonErrorKind::UnpairedSurrogate);
        assert_eq!(kind_of(r#"{"a":1,"a":2}"#), JsonErrorKind::DuplicateName);
        assert_eq!(
            parse(b"\"\xff\"").unwrap_err().kind(),
            JsonErrorKind::InvalidUtf8
        );
        assert_eq!(
            kind_of(&nested_arrays(MAX_DEPTH + 1)),
            JsonErrorKind::DepthExceeded
        );

        let error = parse_str(r#"{"a":1,"a":2}"#).unwrap_err();
        assert_eq!(error.offset(), 7);
        assert_eq!(
            error.to_string(),
            "invalid JSON: duplicate object member name at offset 7"
        );
    }

    #[test]
    fn rejects_duplicate_names_in_large_objects() {
        let member = |index: usize| format!("\"k{index}\":{index}");
        for size in [2, LINEAR_DUPLICATE_CHECK, LINEAR_DUPLICATE_CHECK + 1, 500] {
            let members: Vec<String> = (0..size).map(member).collect();
            let unique = format!("{{{}}}", members.join(","));
            assert_eq!(parse_str(&unique).unwrap().as_object().unwrap().len(), size);
            for repeated in [0, size / 2, size - 1] {
                let duplicate = format!("{{{},{}}}", members.join(","), member(repeated));
                assert_eq!(
                    kind_of(&duplicate),
                    JsonErrorKind::DuplicateName,
                    "{size} members, repeating {repeated}"
                );
            }
        }
    }

    #[test]
    fn enforces_the_nesting_limit() {
        assert!(parse_str(&nested_arrays(MAX_DEPTH)).is_ok());
        assert!(parse_str(&nested_objects(MAX_DEPTH)).is_ok());
        assert!(parse_str(&nested_arrays(MAX_DEPTH + 1)).is_err());
        assert!(parse_str(&nested_objects(MAX_DEPTH + 1)).is_err());
        assert!(parse_str(&"[".repeat(1_000_000)).is_err());
    }

    /// Runs `work` on a thread whose stack is far smaller than recursion over
    /// the deepest accepted document would need.
    fn on_small_stack(work: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(work)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn deep_values_parse_compare_format_and_drop_on_a_small_stack() {
        on_small_stack(|| {
            for text in [nested_arrays(MAX_DEPTH), nested_objects(MAX_DEPTH)] {
                let value = parse(text.as_bytes()).unwrap();
                let same = parse(text.as_bytes()).unwrap();
                assert!(value == same);
                assert!(!format!("{value:?}").is_empty());
                drop(value);
                drop(same);
            }
            assert!(parse(nested_arrays(MAX_DEPTH + 1).as_bytes()).is_err());
            // A failed parse drops the containers that were still open.
            assert!(parse("[".repeat(MAX_DEPTH).as_bytes()).is_err());
        });
    }

    #[test]
    fn a_deep_value_moved_out_of_its_parent_drops_on_a_small_stack() {
        on_small_stack(|| {
            let text = format!("{{\"deep\":{}}}", nested_arrays(MAX_DEPTH - 1));
            let object = decode::object(parse(text.as_bytes()).unwrap(), "")
                .unwrap()
                .unwrap();
            let mut members = object.into_members();
            let (_, deep) = members.pop().unwrap();
            drop(members);
            drop(deep);
        });
    }

    #[test]
    fn equality_is_structural_and_ordered() {
        let same = |a: &str, b: &str| parse_str(a).unwrap() == parse_str(b).unwrap();
        assert!(same(
            r#"{"a":[1,{"b":null}],"c":"x"}"#,
            r#" { "a" : [ 1 , { "b" : null } ] , "c" : "x" } "#
        ));
        assert!(same(r#""a""#, r#""a""#));
        assert!(!same(r#"{"a":1,"b":2}"#, r#"{"b":2,"a":1}"#));
        assert!(!same("[1,2]", "[1,3]"));
        assert!(!same("[1,2]", "[1,2,3]"));
        assert!(!same("1", "1.0"));
        assert!(!same("null", "false"));
        assert!(!same(r#"{"a":1}"#, r#"{"b":1}"#));
        assert!(!same(r#"[[[1]]]"#, r#"[[[2]]]"#));
    }

    #[test]
    fn integers_are_read_from_the_literal() {
        let number = |text: &str| match parse_str(text).unwrap() {
            Value::Number(ref number) => number.clone(),
            ref other => panic!("{other:?}"),
        };
        assert_eq!(number("18446744073709551615").to_u64(), Some(u64::MAX));
        assert_eq!(number("9007199254740993").to_u64(), Some(9007199254740993));
        assert_eq!(number("18446744073709551616").to_u64(), None);
        assert_eq!(number("-0").to_u64(), None);
        assert_eq!(number("-1").to_u64(), None);
        assert_eq!(number("1.0").to_u64(), None);
        assert_eq!(number("1e2").to_u64(), None);
        assert_eq!(number("4294967295").to_u32(), Some(u32::MAX));
        assert_eq!(number("4294967296").to_u32(), None);
        assert_eq!(number("255").to_u8(), Some(u8::MAX));
        assert_eq!(number("256").to_u8(), None);
        assert_eq!(number("-0").to_i64(), Some(0));
        assert_eq!(number("-9223372036854775808").to_i64(), Some(i64::MIN));
        assert_eq!(number("9223372036854775808").to_i64(), None);
        assert_eq!(number("-1.0").to_i64(), None);
        assert_eq!(number("-1e0").to_i64(), None);
    }

    #[test]
    fn decode_treats_null_as_the_empty_value() {
        assert_eq!(decode::string(Value::Null, "f").unwrap(), "");
        assert_eq!(decode::object(Value::Null, "f").unwrap(), None);
        assert_eq!(decode::array(Value::Null, "f").unwrap(), None);
        assert_eq!(decode::strings(Value::Null, "f").unwrap(), None);
        assert_eq!(decode::u64(&Value::Null, "f").unwrap(), 0);
        assert!(!decode::bool(&Value::Null, "f").unwrap());
        assert!(decode::bool(&Value::Bool(true), "f").unwrap());
        assert_eq!(
            decode::strings(parse_str(r#"["a",null]"#).unwrap(), "f").unwrap(),
            Some(vec!["a".to_owned(), String::new()])
        );
    }

    #[test]
    fn decode_rejects_other_types() {
        let value = |text: &str| parse_str(text).unwrap();
        assert_eq!(
            decode::string(value("1"), "a.b").unwrap_err().to_string(),
            "a.b: cannot decode JSON number as a string"
        );
        assert!(decode::string(value("[]"), "f").is_err());
        assert!(decode::object(value("[]"), "f").is_err());
        assert!(decode::object(value("\"x\""), "f").is_err());
        assert!(decode::array(value("{}"), "f").is_err());
        assert!(decode::strings(value("[1]"), "f").is_err());
        assert!(decode::u64(&value("\"1\""), "f").is_err());
        assert!(decode::bool(&value("1"), "f").is_err());
        assert!(decode::bool(&value("\"true\""), "f").is_err());
        assert_eq!(
            decode::u8(&value("256"), "f").unwrap_err().to_string(),
            "f: JSON number 256 is not an unsigned 8-bit integer"
        );
        assert_eq!(
            decode::unknown_member("doc", "x").to_string(),
            "doc: unknown member \"x\""
        );
    }

    /// The probe set records, for each input, whether a strict decoder
    /// accepts it and what it decodes to. The kinds are `value` (any JSON
    /// value), `string`, and the integer types. An input is given as hex, or
    /// as a list of parts that are each repeated a number of times.
    #[test]
    fn agrees_with_the_recorded_probes() {
        let probes = parse(include_bytes!("../tests/data/json_probes.json")).unwrap();
        let probes = probes.as_array().unwrap();
        assert!(probes.len() >= 150, "{} probes", probes.len());
        let mut failures = Vec::new();
        for probe in probes {
            let probe = probe.as_object().unwrap();
            let field = |name: &str| probe.get(name).and_then(Value::as_str).unwrap_or("");
            let (name, kind) = (field("name"), field("kind"));
            let input = match probe.get("input_parts").and_then(Value::as_array) {
                None => from_hex(field("input_hex")),
                Some(parts) => parts
                    .iter()
                    .flat_map(|part| {
                        let part = part.as_object().unwrap();
                        let bytes = from_hex(part.get("hex").unwrap().as_str().unwrap());
                        let count = decode::u64(part.get("count").unwrap(), "count").unwrap();
                        bytes.repeat(count as usize)
                    })
                    .collect(),
            };
            let accept = probe.get("accept").unwrap().as_bool().unwrap();

            let parsed = parse(&input).map_err(|error| error.to_string());
            let outcome: Result<String, String> = parsed.and_then(|value| {
                let decoded = match kind {
                    "value" => Ok(String::new()),
                    "string" => decode::string(value, name).map(|s| to_hex(s.as_bytes())),
                    "u64" => decode::u64(&value, name).map(|n| n.to_string()),
                    "u32" => decode::u32(&value, name).map(|n| n.to_string()),
                    "u8" => decode::u8(&value, name).map(|n| n.to_string()),
                    "i64" => decode::i64(&value, name).map(|n| n.to_string()),
                    other => panic!("unknown probe kind {other}"),
                };
                decoded.map_err(|error| error.to_string())
            });
            match (&outcome, accept) {
                (Ok(decoded), true) => {
                    // A string that decodes to nothing has no recorded value.
                    if kind != "value" && decoded != field("value") {
                        failures.push(format!(
                            "{name}: decoded {decoded}, want {}",
                            field("value")
                        ));
                    }
                }
                (Err(_), false) => {}
                (Ok(_), false) => failures.push(format!("{name}: accepted, want a rejection")),
                (Err(error), true) => failures.push(format!("{name}: rejected ({error})")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
