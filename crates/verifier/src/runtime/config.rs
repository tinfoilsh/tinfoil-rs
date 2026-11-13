//! The runtime pin of a workload config.
//!
//! A config is a YAML document whose `cvm-version` member names a runtime
//! release and the SHA-256 of its manifest, as `VERSION@sha256:DIGEST`. This
//! module reads that one member and nothing else: the publisher and the
//! guest own the validation of every other field.
//!
//! The whole config must still parse as a single YAML document whose
//! top-level keys are scalars and do not repeat. A few constructs that a
//! general YAML decoder would interpret are refused instead, so that the pin
//! is always spelled out in the config itself: a merge key (`<<`) or an
//! alias as a top-level key, and a `!!binary` or core scalar type tag
//! (`!!int`, `!!float`, `!!bool`, `!!null`, `!!timestamp`) on a top-level
//! key or on the pin. So are the three characters that are a line break to
//! some YAML parsers and ordinary text to others, since such a config has no
//! single reading.
//!
//! The parser hands out events and builds no document tree, and nothing
//! here recurses.

use std::collections::{HashMap, HashSet};
use std::fmt;

use saphyr_parser::{Event, Parser, ScalarStyle, StrInput, Tag};

use super::RuntimeReference;
use crate::document::collateral::RUNTIME_REPO;

/// The largest config that is read, in bytes.
pub const MAX_CONFIG_SIZE: usize = 1 << 20;

/// The deepest nesting of sequences and mappings that is read.
const MAX_DEPTH: usize = 10_000;

/// The key that holds the runtime pin.
const VERSION_KEY: &str = "cvm-version";

/// What separates the release from the manifest digest in a pin.
const DIGEST_SEPARATOR: &str = "@sha256:";

/// The prefix of the tags that YAML itself defines, written `!!` in short.
const CORE_TAG_PREFIX: &str = "tag:yaml.org,2002:";

/// A config that does not state a usable runtime pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigError {
    message: String,
}

impl RuntimeConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The config is not a document that this module reads.
    fn parsing(reason: impl fmt::Display) -> Self {
        Self::new(format!("parsing config runtime pin: {reason}"))
    }
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RuntimeConfigError {}

/// Extracts the runtime pin from the bytes of a config.
///
/// The pin's release may be written with or without a leading `v`; the
/// returned tag always has one. The reference is validated before it is
/// returned: a full semantic version and a lowercase SHA-256 digest.
pub fn runtime_from_config(data: &[u8]) -> Result<RuntimeReference, RuntimeConfigError> {
    let pin = read_version(data)?;
    let Some((version, digest)) = pin.split_once(DIGEST_SEPARATOR) else {
        return Err(RuntimeConfigError::new(
            "cvm-version must pin a runtime manifest SHA-256 digest",
        ));
    };
    let reference = RuntimeReference {
        repo: RUNTIME_REPO.to_owned(),
        tag: format!("v{}", version.strip_prefix('v').unwrap_or(version)),
        digest: digest.to_owned(),
    };
    reference
        .validate()
        .map_err(|error| RuntimeConfigError::new(error.to_string()))?;
    Ok(reference)
}

/// A scalar node.
#[derive(Clone)]
struct Scalar {
    value: String,
    plain: bool,
    /// The tag in full, or empty when there is none.
    tag: String,
}

/// How a scalar's tag bears on reading it as a string.
enum TagKind {
    /// No tag, or the non-specific `!`: the scalar means what it looks like.
    None,
    /// `!!str`, or a tag that names no scalar type: the text as written.
    Text,
    /// `!!merge`.
    Merge,
    /// A tag that would have to be interpreted: `!!binary` or a core scalar
    /// type.
    Typed,
}

impl Scalar {
    fn tag_kind(&self) -> TagKind {
        // A core tag is known by its short name, however it was spelled.
        let short = self
            .tag
            .strip_prefix(CORE_TAG_PREFIX)
            .or_else(|| self.tag.strip_prefix("!!"));
        match (self.tag.as_str(), short) {
            ("" | "!", _) => TagKind::None,
            (_, Some("merge")) => TagKind::Merge,
            (_, Some("binary" | "bool" | "int" | "float" | "null" | "timestamp")) => TagKind::Typed,
            _ => TagKind::Text,
        }
    }

    /// Whether the scalar is a merge key: `<<`, unquoted or tagged as one.
    fn is_merge(&self) -> bool {
        self.value == "<<"
            && match self.tag_kind() {
                TagKind::None => self.plain,
                TagKind::Merge => true,
                TagKind::Text | TagKind::Typed => false,
            }
    }

    /// The string that the scalar stands for, or `None` when it is a null.
    fn string(&self) -> Result<Option<&str>, RuntimeConfigError> {
        match self.tag_kind() {
            TagKind::None if self.plain && is_null(&self.value) => Ok(None),
            TagKind::None | TagKind::Text | TagKind::Merge => Ok(Some(&self.value)),
            TagKind::Typed => Err(RuntimeConfigError::parsing(format_args!(
                "the tag {} is not supported on a top-level key or on cvm-version",
                self.tag
            ))),
        }
    }
}

/// Whether an untagged plain scalar is a null.
fn is_null(value: &str) -> bool {
    matches!(value, "" | "~" | "null" | "Null" | "NULL")
}

/// A node as far as the read cares.
enum Node {
    Scalar(Scalar),
    /// A reference to the anchor with that id.
    Alias(usize),
    /// The start of a sequence or a mapping.
    Start,
    /// The end of the enclosing collection.
    End,
}

/// The event source, with the bookkeeping that every position needs: the
/// nesting depth and the scalars that carry an anchor.
struct Reader<'a> {
    parser: Parser<'a, StrInput<'a>>,
    depth: usize,
    /// Anchored scalars by anchor id. An anchor on a sequence or a mapping
    /// has no entry.
    anchored: HashMap<usize, Scalar>,
}

impl<'a> Reader<'a> {
    fn event(&mut self) -> Result<Event<'a>, RuntimeConfigError> {
        match self.parser.next_event() {
            Some(Ok((event, _))) => Ok(event),
            Some(Err(error)) => Err(RuntimeConfigError::parsing(format_args!("yaml: {error}"))),
            None => Err(RuntimeConfigError::parsing("unexpected end of stream")),
        }
    }

    /// Reads the next node event. An anchored scalar is remembered, and the
    /// start of a collection counts against the depth limit.
    fn node(&mut self) -> Result<Node, RuntimeConfigError> {
        match self.event()? {
            Event::Scalar(value, style, anchor, tag) => {
                let scalar = Scalar {
                    value: value.into_owned(),
                    plain: style == ScalarStyle::Plain,
                    tag: tag.map_or_else(String::new, |tag| full_tag(&tag)),
                };
                if anchor != 0 {
                    self.anchored.insert(anchor, scalar.clone());
                }
                Ok(Node::Scalar(scalar))
            }
            Event::Alias(anchor) => Ok(Node::Alias(anchor)),
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                self.depth = self.depth.saturating_add(1);
                if self.depth > MAX_DEPTH {
                    return Err(RuntimeConfigError::parsing(format_args!(
                        "exceeded max depth of {MAX_DEPTH}"
                    )));
                }
                Ok(Node::Start)
            }
            Event::SequenceEnd | Event::MappingEnd => {
                self.depth = self.depth.saturating_sub(1);
                Ok(Node::End)
            }
            _ => Err(RuntimeConfigError::parsing("unexpected parser event")),
        }
    }

    /// Reads past the rest of the collection whose start was just read.
    fn skip_collection(&mut self) -> Result<(), RuntimeConfigError> {
        let outside = self.depth.saturating_sub(1);
        while self.depth > outside {
            self.node()?;
        }
        Ok(())
    }
}

fn full_tag(tag: &Tag) -> String {
    format!("{}{}", tag.handle, tag.suffix)
}

/// Reads the config as far as its runtime pin: the string value of the
/// top-level `cvm-version` key, or the empty string when there is none.
fn read_version(data: &[u8]) -> Result<String, RuntimeConfigError> {
    if data.len() > MAX_CONFIG_SIZE {
        return Err(RuntimeConfigError::parsing(format_args!(
            "the config is larger than {MAX_CONFIG_SIZE} bytes"
        )));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| RuntimeConfigError::parsing("the config is not UTF-8"))?;
    if text.contains(['\u{85}', '\u{2028}', '\u{2029}']) {
        return Err(RuntimeConfigError::parsing(
            "the config contains a line break other than a line feed or a carriage return",
        ));
    }

    let mut reader = Reader {
        parser: Parser::new_from_str(text),
        depth: 0,
        anchored: HashMap::new(),
    };
    let unexpected = || RuntimeConfigError::parsing("unexpected parser event");
    if !matches!(reader.event()?, Event::StreamStart) {
        return Err(unexpected());
    }
    match reader.event()? {
        Event::DocumentStart(_) => {}
        Event::StreamEnd => return Err(RuntimeConfigError::parsing("the config is empty")),
        _ => return Err(unexpected()),
    }
    let version = match reader.event()? {
        Event::MappingStart(..) => {
            reader.depth = 1;
            read_mapping(&mut reader)?
        }
        // A document that is not a mapping has no pin.
        _ => return Ok(String::new()),
    };
    if !matches!(reader.event()?, Event::DocumentEnd) {
        return Err(unexpected());
    }
    match reader.event()? {
        Event::StreamEnd => Ok(version),
        _ => Err(RuntimeConfigError::new(
            "config must contain exactly one YAML document",
        )),
    }
}

/// Reads the members of the top-level mapping, whose start was just read,
/// and returns the pin.
fn read_mapping(reader: &mut Reader<'_>) -> Result<String, RuntimeConfigError> {
    let mut version = String::new();
    let mut version_seen = false;
    // Keys repeat when their text does, however each is quoted or tagged.
    let mut keys: HashSet<String> = HashSet::new();
    loop {
        let key = match reader.node()? {
            Node::End => return Ok(version),
            Node::Scalar(key) => key,
            Node::Alias(_) => {
                return Err(RuntimeConfigError::parsing(
                    "a top-level key cannot be an alias",
                ));
            }
            Node::Start => {
                return Err(RuntimeConfigError::parsing(
                    "a top-level key must be a scalar",
                ));
            }
        };
        if keys.contains(&key.value) {
            return Err(RuntimeConfigError::parsing(
                "a top-level mapping key is already defined",
            ));
        }
        if key.is_merge() {
            return Err(RuntimeConfigError::parsing(
                "merge keys are not supported at the top level",
            ));
        }
        // A null key names nothing.
        let is_version = key.string()? == Some(VERSION_KEY);
        keys.insert(key.value);

        let value = reader.node()?;
        if !is_version {
            match value {
                Node::Start => reader.skip_collection()?,
                Node::End => return Err(RuntimeConfigError::parsing("unexpected parser event")),
                Node::Scalar(_) | Node::Alias(_) => {}
            }
            continue;
        }
        if version_seen {
            return Err(RuntimeConfigError::parsing("cvm-version is already set"));
        }
        version_seen = true;
        let pin = match &value {
            Node::Scalar(scalar) => Some(scalar),
            Node::Alias(anchor) => reader.anchored.get(anchor),
            Node::Start | Node::End => None,
        };
        let Some(pin) = pin else {
            return Err(RuntimeConfigError::parsing("cvm-version must be a scalar"));
        };
        // A null leaves the pin unset.
        if let Some(pin) = pin.string()? {
            version = pin.to_owned();
        }
    }
}
