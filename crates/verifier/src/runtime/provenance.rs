//! The container build requirements of a workload config.
//!
//! A container of a config may name the GitHub Actions workflow that must
//! have built its image:
//!
//! ```yaml
//! containers:
//!   - name: app
//!     image: ghcr.io/example/app@sha256:<digest>
//!     provenance:
//!       github:
//!         repository: example/app
//!         repository_id: 123456789
//!         workflow: release.yml
//!         ref: refs/tags/v*
//! ```
//!
//! This module reads those requirements and nothing else. A requirement
//! that it cannot read in full is an error, so that a verifier never treats
//! an unknown kind of requirement as met.
//!
//! The config is the one that the runtime pin is read from
//! ([`runtime_from_config`](super::runtime_from_config)), and the rules of
//! that read hold for the document and its top level here too. Below the
//! top level a container is read the way a general YAML decoder fills a
//! record from a mapping:
//!
//! - wherever a value is read, an alias stands for the node that it names;
//! - a merge key (`<<`) of a container brings the members of the mappings
//!   that it names. A member that the container states itself comes first,
//!   then the named mappings in order, each before the ones that it merges
//!   in turn;
//! - the keys of a container, and of a mapping that it merges, are scalars
//!   that do not repeat;
//! - a tag on a sequence or on a container is ignored.
//!
//! What would have to be interpreted beyond that is refused: an alias as a
//! key, and a `!!binary` or core scalar type tag on a scalar that is read.
//! A requirement is read more strictly still, since YAML decoders disagree
//! on the rest: its mappings carry no tag but the mapping tag, and its
//! `repository_id` is an untagged plain scalar in decimal, as it is
//! written, without a sign or a leading zero.
//!
//! The document is held as a flat list of nodes, and nothing here recurses.

use std::collections::{HashMap, HashSet};

use saphyr_parser::{Event, Parser, ScalarStyle};

use super::config::{MAX_DEPTH, Scalar, TagKind, config_text, core_tag, full_tag, is_null};
use crate::canonical;
use crate::stub::message_error;

/// The character of a ref pattern that stands for any run of characters
/// within one segment of a ref.
pub const REF_WILDCARD: char = '*';

/// The longest repository that a requirement names, in bytes.
const MAX_REPOSITORY_LENGTH: usize = 140;
/// The longest workflow file name that a requirement names, in bytes.
const MAX_WORKFLOW_LENGTH: usize = 255;
/// The longest ref pattern that a requirement names, in bytes.
const MAX_REF_LENGTH: usize = 255;
/// The most digits of the repository identifier that a requirement names.
const MAX_REPOSITORY_ID_DIGITS: usize = 18;

/// The top-level key that holds the containers.
const CONTAINERS_KEY: &str = "containers";
/// The key of a container that holds its name.
const NAME_KEY: &str = "name";
/// The key of a container that holds its image reference.
const IMAGE_KEY: &str = "image";
/// The key of a container that holds its build requirement.
const PROVENANCE_KEY: &str = "provenance";
/// The key of the one kind of build requirement: a GitHub Actions workflow
/// run.
const GITHUB_KEY: &str = "github";
/// The key of a requirement that holds the repository.
const REPOSITORY_KEY: &str = "repository";
/// The key of a requirement that holds the repository's identifier.
const REPOSITORY_ID_KEY: &str = "repository_id";
/// The key of a requirement that holds the workflow's file name.
const WORKFLOW_KEY: &str = "workflow";
/// The key of a requirement that holds the ref pattern.
const REF_KEY: &str = "ref";

/// The short name of the tag that YAML itself defines for a mapping.
const MAPPING_TAG: &str = "map";
/// What separates the name of an image from its digest.
const IMAGE_DIGEST_SEPARATOR: &str = "@sha256:";
/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;
/// The extensions of a workflow file.
const WORKFLOW_EXTENSIONS: [&str; 2] = [".yml", ".yaml"];
/// The prefixes of the refs that a requirement may name: tags and branches.
const REF_PREFIXES: [&str; 2] = ["refs/tags/", "refs/heads/"];
/// What separates the segments of a ref, and a repository's owner from its
/// name.
const PATH_SEPARATOR: char = '/';
/// The characters that an image name cannot contain: the digest separator's
/// first character and ASCII white space.
const IMAGE_NAME_EXCLUDED: [char; 6] = ['@', '\t', '\n', '\u{c}', '\r', ' '];

/// The build that a config requires of one container image: a GitHub
/// Actions workflow run in a named repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerProvenance {
    /// The container's name.
    pub container: String,
    /// The SHA-256 of the image, lowercase hex.
    pub digest: String,
    /// The repository of the workflow, `owner/name`.
    pub repository: String,
    /// The immutable identifier of the repository on GitHub, in decimal.
    pub repository_id: String,
    /// The file name of the workflow.
    pub workflow: String,
    /// A tag or branch ref pattern, in which [`REF_WILDCARD`] stands for
    /// any run of characters other than `/`.
    pub git_ref: String,
}

message_error! {
    /// A config whose container build requirements cannot be read.
    pub struct ContainerProvenanceError;
}

/// The config is not a document that this module reads.
fn parsing(reason: impl std::fmt::Display) -> ContainerProvenanceError {
    ContainerProvenanceError::new(format!("parsing config provenance: {reason}"))
}

/// Reads the build requirements that a config declares, in container
/// order.
///
/// A container without a `provenance` member, or with a null scalar as
/// one, requires nothing. Any other `provenance` is a mapping with the one
/// key `github`, itself a mapping with exactly these keys:
///
/// - `repository`: `owner/name`, each one or more of ASCII letters, digits,
///   `_`, `.` and `-`, in at most 140 bytes;
/// - `repository_id`: a digit other than zero and at most 17 more digits;
/// - `workflow`: a file name of those characters that ends in `.yml` or
///   `.yaml`, in at most 255 bytes;
/// - `ref`: `refs/tags/` or `refs/heads/` and one or more segments of those
///   characters and [`REF_WILDCARD`], separated by `/`, in at most 255
///   bytes.
///
/// The `image` of such a container is a name without `@` or white space,
/// `@sha256:` and 64 lowercase hex digits, which are the digest of the
/// requirement.
pub fn container_provenance_from_config(
    data: &[u8],
) -> Result<Vec<ContainerProvenance>, ContainerProvenanceError> {
    let text = config_text(data).map_err(parsing)?;
    let config = Config {
        nodes: read_nodes(text)?,
    };
    let Some(containers) = config.containers()? else {
        return Ok(Vec::new());
    };
    let mut requirements = Vec::new();
    let mut merged = HashMap::new();
    // A null item is no container, and the ones after it are not counted
    // from it.
    let mut index = 0_usize;
    for container in containers {
        let path = format!("{CONTAINERS_KEY}[{index}]");
        let container = config.resolve(*container);
        let members = match config.nodes.get(container) {
            Some(Node::Mapping(_)) => config.members(container, &mut merged)?,
            Some(Node::Scalar(scalar)) if string(scalar)?.is_none() => continue,
            _ => return Err(parsing(format_args!("{path} must be a mapping"))),
        };
        index = index.saturating_add(1);
        let text = |member: Option<usize>, key: &str| match member {
            Some(value) => config.text(value, &format!("{path}.{key}")),
            None => Ok(""),
        };
        let name = text(members.name, NAME_KEY)?;
        let image = text(members.image, IMAGE_KEY)?;
        let Some(provenance) = members.provenance else {
            continue;
        };
        if config.is_null(provenance)? {
            continue;
        }
        let mut requirement = config.requirement(provenance, &path)?;
        let Some(digest) = image_digest(image) else {
            return Err(ContainerProvenanceError::new(format!(
                "{path}.{IMAGE_KEY} must pin a SHA-256 digest to declare provenance"
            )));
        };
        requirement.container = name.to_owned();
        requirement.digest = digest.to_owned();
        requirements.push(requirement);
    }
    Ok(requirements)
}

/// A node of the document.
enum Node {
    Scalar(Scalar),
    /// The items of a sequence, by index.
    Sequence(Vec<usize>),
    Mapping(Mapping),
    /// A reference to the node at that index.
    Alias(usize),
}

/// A mapping node.
struct Mapping {
    /// The keys and values, by index and in order.
    members: Vec<(usize, usize)>,
    /// Whether the mapping carries a tag other than the mapping tag.
    retagged: bool,
}

/// Whether a tag on a mapping, empty when there is none, leaves it a plain
/// mapping: no tag, the non-specific `!`, or the mapping tag itself.
fn is_mapping_tag(tag: &str) -> bool {
    matches!(tag, "" | "!") || core_tag(tag) == Some(MAPPING_TAG)
}

/// A sequence or a mapping whose end has not been read.
struct Open {
    node: usize,
    /// The key of a mapping that awaits its value.
    key: Option<usize>,
}

/// Reads the one document of a config into its nodes. The first node is the
/// root.
fn read_nodes(text: &str) -> Result<Vec<Node>, ContainerProvenanceError> {
    let mut parser = Parser::new_from_str(text);
    let mut event = || match parser.next_event() {
        Some(Ok((event, _))) => Ok(event),
        Some(Err(error)) => Err(parsing(format_args!("yaml: {error}"))),
        None => Err(parsing("unexpected end of stream")),
    };
    let unexpected = || parsing("unexpected parser event");
    if !matches!(event()?, Event::StreamStart) {
        return Err(unexpected());
    }
    match event()? {
        Event::DocumentStart(_) => {}
        Event::StreamEnd => return Err(parsing("the config is empty")),
        _ => return Err(unexpected()),
    }

    let mut nodes = Vec::new();
    // Anchored nodes by anchor id.
    let mut anchored: HashMap<usize, usize> = HashMap::new();
    let mut open: Vec<Open> = Vec::new();
    loop {
        let (node, anchor) = match event()? {
            Event::Scalar(value, style, anchor, tag) => {
                let scalar = Scalar {
                    value: value.into_owned(),
                    plain: style == ScalarStyle::Plain,
                    tag: tag.map_or_else(String::new, |tag| full_tag(&tag)),
                };
                (Node::Scalar(scalar), anchor)
            }
            Event::Alias(anchor) => {
                let target = anchored.get(&anchor).ok_or_else(unexpected)?;
                (Node::Alias(*target), 0)
            }
            Event::SequenceStart(anchor, _) => (Node::Sequence(Vec::new()), anchor),
            Event::MappingStart(anchor, tag) => {
                let mapping = Mapping {
                    members: Vec::new(),
                    retagged: tag.is_some_and(|tag| !is_mapping_tag(&full_tag(&tag))),
                };
                (Node::Mapping(mapping), anchor)
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if open.pop().is_none() {
                    return Err(unexpected());
                }
                if open.is_empty() {
                    break;
                }
                continue;
            }
            _ => return Err(unexpected()),
        };
        let index = nodes.len();
        let is_collection = matches!(node, Node::Sequence(_) | Node::Mapping(_));
        nodes.push(node);
        if anchor != 0 {
            anchored.insert(anchor, index);
        }
        if let Some(parent) = open.last_mut() {
            match (nodes.get_mut(parent.node), parent.key.take()) {
                (Some(Node::Sequence(items)), _) => items.push(index),
                (Some(Node::Mapping(mapping)), Some(key)) => mapping.members.push((key, index)),
                (Some(Node::Mapping(_)), None) => parent.key = Some(index),
                _ => return Err(unexpected()),
            }
        }
        if is_collection {
            if open.len() >= MAX_DEPTH {
                return Err(parsing(format_args!("exceeded max depth of {MAX_DEPTH}")));
            }
            open.push(Open {
                node: index,
                key: None,
            });
        } else if open.is_empty() {
            break;
        }
    }

    if !matches!(event()?, Event::DocumentEnd) {
        return Err(unexpected());
    }
    match event()? {
        Event::StreamEnd => Ok(nodes),
        _ => Err(ContainerProvenanceError::new(
            "config must contain exactly one YAML document",
        )),
    }
}

/// The string that a scalar stands for, or `None` when it is a null.
fn string(scalar: &Scalar) -> Result<Option<&str>, ContainerProvenanceError> {
    match scalar.tag_kind() {
        TagKind::None if scalar.plain && is_null(&scalar.value) => Ok(None),
        TagKind::None | TagKind::Text | TagKind::Merge => Ok(Some(&scalar.value)),
        TagKind::Typed => Err(parsing(format_args!(
            "the tag {} is not supported where container provenance is read",
            scalar.tag
        ))),
    }
}

/// The members of a container that are read, each as the index of its
/// value.
#[derive(Clone, Copy, Default)]
struct Members {
    name: Option<usize>,
    image: Option<usize>,
    provenance: Option<usize>,
}

impl Members {
    /// These members, and those of `other` that are not among them.
    fn or(self, other: Members) -> Members {
        Members {
            name: self.name.or(other.name),
            image: self.image.or(other.image),
            provenance: self.provenance.or(other.provenance),
        }
    }
}

/// A mapping whose merged mappings are being read.
struct Merging {
    mapping: usize,
    members: Members,
    /// The mappings that its merge key names and that are yet to be read.
    sources: std::vec::IntoIter<usize>,
}

/// The nodes of a config's document.
struct Config {
    nodes: Vec<Node>,
}

impl Config {
    /// The index of the node that the one at `index` stands for: the node
    /// that an alias names, and any other node itself.
    fn resolve(&self, index: usize) -> usize {
        match self.nodes.get(index) {
            Some(Node::Alias(target)) => *target,
            _ => index,
        }
    }

    /// The scalar at `index`, or the one that an alias there names.
    fn scalar(&self, index: usize) -> Option<&Scalar> {
        match self.nodes.get(self.resolve(index)) {
            Some(Node::Scalar(scalar)) => Some(scalar),
            _ => None,
        }
    }

    /// Whether the node at `index` is a null scalar.
    fn is_null(&self, index: usize) -> Result<bool, ContainerProvenanceError> {
        match self.scalar(index) {
            Some(scalar) => Ok(string(scalar)?.is_none()),
            None => Ok(false),
        }
    }

    /// The string of the scalar at `index`, which is empty for a null.
    fn text(&self, index: usize, path: &str) -> Result<&str, ContainerProvenanceError> {
        match self.scalar(index) {
            Some(scalar) => Ok(string(scalar)?.unwrap_or_default()),
            None => Err(ContainerProvenanceError::new(format!(
                "{path} must be a scalar"
            ))),
        }
    }

    /// The items of the top-level `containers` sequence, or `None` when
    /// the config has none.
    fn containers(&self) -> Result<Option<&[usize]>, ContainerProvenanceError> {
        let members = match self.nodes.first() {
            Some(Node::Mapping(mapping)) => &mapping.members,
            Some(Node::Scalar(scalar)) if string(scalar)?.is_none() => return Ok(None),
            _ => return Err(parsing("the config must be a mapping")),
        };
        // Keys repeat when their text does, however each is quoted or tagged.
        let mut keys: HashSet<&str> = HashSet::new();
        let mut containers = None;
        for (key, value) in members {
            let key = match self.nodes.get(*key) {
                Some(Node::Scalar(key)) => key,
                Some(Node::Alias(_)) => return Err(parsing("a top-level key cannot be an alias")),
                _ => return Err(parsing("a top-level key must be a scalar")),
            };
            if !keys.insert(&key.value) {
                return Err(parsing("a top-level mapping key is already defined"));
            }
            if key.is_merge() {
                return Err(parsing("merge keys are not supported at the top level"));
            }
            if string(key)? == Some(CONTAINERS_KEY) {
                containers = Some(*value);
            }
        }
        let Some(containers) = containers else {
            return Ok(None);
        };
        if self.is_null(containers)? {
            return Ok(None);
        }
        match self.nodes.get(self.resolve(containers)) {
            Some(Node::Sequence(items)) => Ok(Some(items)),
            _ => Err(parsing(format_args!("{CONTAINERS_KEY} must be a sequence"))),
        }
    }

    /// The members that the mapping at `mapping` states itself, and the
    /// mappings that its merge key names.
    fn own_members(&self, mapping: usize) -> Result<Merging, ContainerProvenanceError> {
        let Some(Node::Mapping(stated)) = self.nodes.get(mapping) else {
            return Err(parsing("a container must be a mapping"));
        };
        let mut keys: HashSet<&str> = HashSet::new();
        let mut members = Members::default();
        let mut sources = Vec::new();
        for (key, value) in &stated.members {
            let Some(Node::Scalar(key)) = self.nodes.get(*key) else {
                return Err(parsing("a container key must be a scalar"));
            };
            if !keys.insert(&key.value) {
                return Err(parsing("a container key is already defined"));
            }
            if key.is_merge() {
                sources = self.merge_sources(*value)?;
                continue;
            }
            match string(key)? {
                Some(NAME_KEY) => members.name = Some(*value),
                Some(IMAGE_KEY) => members.image = Some(*value),
                Some(PROVENANCE_KEY) => members.provenance = Some(*value),
                _ => {}
            }
        }
        Ok(Merging {
            mapping,
            members,
            sources: sources.into_iter(),
        })
    }

    /// The mappings that a merge key with the value at `value` names: one
    /// mapping, or each item of a sequence of mappings.
    fn merge_sources(&self, value: usize) -> Result<Vec<usize>, ContainerProvenanceError> {
        let mapping = |index: usize| {
            let index = self.resolve(index);
            match self.nodes.get(index) {
                Some(Node::Mapping(_)) => Ok(index),
                _ => Err(parsing(
                    "a merge key requires a mapping or a sequence of mappings",
                )),
            }
        };
        match self.nodes.get(value) {
            Some(Node::Sequence(items)) => items.iter().map(|item| mapping(*item)).collect(),
            _ => Ok(vec![mapping(value)?]),
        }
    }

    /// The members of the container at `container`, a mapping, with those
    /// that its merge keys bring. `merged` holds the members of the
    /// mappings that have been read in full.
    fn members(
        &self,
        container: usize,
        merged: &mut HashMap<usize, Members>,
    ) -> Result<Members, ContainerProvenanceError> {
        if let Some(members) = merged.get(&container) {
            return Ok(*members);
        }
        let mut reading = vec![self.own_members(container)?];
        let mut unfinished = HashSet::from([container]);
        let mut members = Members::default();
        while let Some(mapping) = reading.last_mut() {
            let Some(source) = mapping.sources.next() else {
                // Read in full: the mapping that merges this one takes the
                // members that it leaves unset.
                let read = mapping.mapping;
                members = mapping.members;
                reading.pop();
                unfinished.remove(&read);
                merged.insert(read, members);
                if let Some(merging) = reading.last_mut() {
                    merging.members = merging.members.or(members);
                }
                continue;
            };
            if let Some(known) = merged.get(&source) {
                mapping.members = mapping.members.or(*known);
            } else if unfinished.insert(source) {
                reading.push(self.own_members(source)?);
            } else {
                return Err(parsing("a merge key names a mapping that contains it"));
            }
        }
        Ok(members)
    }

    /// The values of the mapping at `index` by key, where every key is one
    /// of `allowed` and none repeats. A mapping under another tag is not
    /// read as one.
    fn known_fields(
        &self,
        index: usize,
        path: &str,
        allowed: &[&str],
    ) -> Result<Vec<(&str, usize)>, ContainerProvenanceError> {
        let error = |message: String| Err(ContainerProvenanceError::new(message));
        let mapping = match self.nodes.get(self.resolve(index)) {
            Some(Node::Mapping(mapping)) if !mapping.retagged => mapping,
            _ => return error(format!("{path} must be a mapping")),
        };
        let mut fields: Vec<(&str, usize)> = Vec::new();
        for (key, value) in &mapping.members {
            let Some(Node::Scalar(key)) = self.nodes.get(*key) else {
                return error(format!("{path} has a key that is not a scalar"));
            };
            let field = key.value.as_str();
            if fields.iter().any(|(seen, _)| *seen == field) {
                return error(format!("{path} has duplicate field {field:?}"));
            }
            if !allowed.contains(&field) {
                return error(format!("{path} has unknown field {field:?}"));
            }
            string(key)?;
            fields.push((field, *value));
        }
        Ok(fields)
    }

    /// The requirement that the `provenance` member at `provenance` of the
    /// container at `path` states, without the container's name and its
    /// image digest.
    fn requirement(
        &self,
        provenance: usize,
        path: &str,
    ) -> Result<ContainerProvenance, ContainerProvenanceError> {
        let error = |message: String| Err(ContainerProvenanceError::new(message));
        let path = format!("{path}.{PROVENANCE_KEY}");
        let kinds = self.known_fields(provenance, &path, &[GITHUB_KEY])?;
        let path = format!("{path}.{GITHUB_KEY}");
        let Some((_, github)) = kinds.first() else {
            return error(format!("{path} is required"));
        };
        let fields = self.known_fields(
            *github,
            &path,
            &[REPOSITORY_KEY, REPOSITORY_ID_KEY, WORKFLOW_KEY, REF_KEY],
        )?;
        let field = |key: &str| {
            fields
                .iter()
                .find(|(field, _)| *field == key)
                .map(|(_, value)| *value)
        };
        let text = |key: &str| match field(key) {
            Some(value) => self.text(value, &format!("{path}.{key}")),
            None => Ok(""),
        };
        let (repository, workflow, git_ref) =
            (text(REPOSITORY_KEY)?, text(WORKFLOW_KEY)?, text(REF_KEY)?);
        let repository_id = field(REPOSITORY_ID_KEY)
            .and_then(|value| self.scalar(value))
            .and_then(decimal_identifier);
        if !is_repository(repository) {
            return error(format!(
                "{path}.{REPOSITORY_KEY} {repository:?} must be owner/name"
            ));
        }
        let Some(repository_id) = repository_id else {
            return error(format!(
                "{path}.{REPOSITORY_ID_KEY} must be the repository's numeric ID"
            ));
        };
        if !is_workflow(workflow) {
            return error(format!(
                "{path}.{WORKFLOW_KEY} {workflow:?} must be a workflow file name"
            ));
        }
        if !is_ref_pattern(git_ref) {
            return error(format!(
                "{path}.{REF_KEY} {git_ref:?} must be a tag or branch ref pattern"
            ));
        }
        Ok(ContainerProvenance {
            container: String::new(),
            digest: String::new(),
            repository: repository.to_owned(),
            repository_id: repository_id.to_owned(),
            workflow: workflow.to_owned(),
            git_ref: git_ref.to_owned(),
        })
    }
}

/// The identifier that a `repository_id` scalar states, as it is written:
/// an untagged plain scalar of at most [`MAX_REPOSITORY_ID_DIGITS`] decimal
/// digits, the first of which is not zero.
fn decimal_identifier(scalar: &Scalar) -> Option<&str> {
    let digits = scalar.value.as_str();
    let decimal = matches!(scalar.tag_kind(), TagKind::None)
        && scalar.plain
        && !digits.is_empty()
        && digits.len() <= MAX_REPOSITORY_ID_DIGITS
        && !digits.starts_with('0')
        && digits.bytes().all(|digit| digit.is_ascii_digit());
    decimal.then_some(digits)
}

/// Whether `text` is one or more of ASCII letters, digits, `_`, `.` and
/// `-`, and of [`REF_WILDCARD`] when `wildcard` is set.
fn is_name(text: &str, wildcard: bool) -> bool {
    !text.is_empty()
        && text.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '.' | '-')
                || (wildcard && character == REF_WILDCARD)
        })
}

/// Whether `repository` is `owner/name` within the length bound.
fn is_repository(repository: &str) -> bool {
    repository.len() <= MAX_REPOSITORY_LENGTH
        && repository
            .split_once(PATH_SEPARATOR)
            .is_some_and(|(owner, name)| is_name(owner, false) && is_name(name, false))
}

/// Whether `workflow` is the name of a workflow file within the length
/// bound.
fn is_workflow(workflow: &str) -> bool {
    workflow.len() <= MAX_WORKFLOW_LENGTH
        && WORKFLOW_EXTENSIONS.iter().any(|extension| {
            workflow
                .strip_suffix(extension)
                .is_some_and(|stem| is_name(stem, false))
        })
}

/// Whether `pattern` is a tag or branch ref pattern within the length
/// bound.
fn is_ref_pattern(pattern: &str) -> bool {
    pattern.len() <= MAX_REF_LENGTH
        && REF_PREFIXES.iter().any(|prefix| {
            pattern.strip_prefix(prefix).is_some_and(|rest| {
                rest.split(PATH_SEPARATOR)
                    .all(|segment| is_name(segment, true))
            })
        })
}

/// The digest of an image reference that pins one: lowercase hex.
fn image_digest(image: &str) -> Option<&str> {
    let (name, digest) = image.split_once(IMAGE_DIGEST_SEPARATOR)?;
    let pinned = !name.is_empty()
        && !name.contains(IMAGE_NAME_EXCLUDED)
        && canonical::decode_lower_hex("image digest", digest, SHA256_SIZE).is_ok();
    pinned.then_some(digest)
}
