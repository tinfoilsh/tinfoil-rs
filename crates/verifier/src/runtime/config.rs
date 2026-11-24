//! The runtime pin of a workload config.
//!
//! The `cvm-version` member of a config names a runtime release and the
//! SHA-256 of its manifest, as `VERSION@sha256:DIGEST`. This module reads
//! that one member and nothing else: the publisher and the guest own the
//! validation of every other field.
//!
//! A config is JSON in one byte form: RFC 8785 canonical JSON without
//! `null`, whose numbers are integers of at most 2^53-1 in absolute value.
//! Any other spelling of the same JSON is refused. It pins
//! [`JSON_CONFIG_MIN_VERSION`] or a later release. Earlier releases measure
//! a YAML config, which this module does not read.

use std::cmp::Ordering;
use std::fmt;

use super::RuntimeReference;
use crate::document::collateral::RUNTIME_REPO;
use crate::json::{self, Value};
use crate::semver;
use crate::sigstore::statement::canonical_json;

/// The largest config that is read, in bytes.
pub const MAX_CONFIG_SIZE: usize = 1 << 20;

/// The first release whose config is JSON. A config that pins it or a later
/// release is canonical JSON. Earlier releases measure YAML, which is not
/// read.
pub const JSON_CONFIG_MIN_VERSION: &str = "v0.15.5-rc.1";

/// The key that holds the runtime pin.
const VERSION_KEY: &str = "cvm-version";

/// What separates the release from the manifest digest in a pin.
const DIGEST_SEPARATOR: &str = "@sha256:";

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
///
/// The config is JSON in its one byte form and pins
/// [`JSON_CONFIG_MIN_VERSION`] or a later release. Anything else is an
/// error, the YAML config of an earlier release included.
pub fn runtime_from_config(data: &[u8]) -> Result<RuntimeReference, RuntimeConfigError> {
    if data.len() > MAX_CONFIG_SIZE {
        return Err(RuntimeConfigError::parsing(format_args!(
            "the config is larger than {MAX_CONFIG_SIZE} bytes"
        )));
    }
    let not_json = |cause: &dyn fmt::Display| {
        RuntimeConfigError::parsing(format_args!(
            "not a JSON config that states cvm-version ({cause}); the YAML configs of versions before {JSON_CONFIG_MIN_VERSION} are not read"
        ))
    };
    let config = json::parse(data).map_err(|cause| not_json(&cause))?;
    let pin = config
        .as_object()
        .and_then(|members| members.get(VERSION_KEY))
        .and_then(Value::as_str)
        .ok_or_else(|| not_json(&"no cvm-version string member"))?;
    let reference = reference_from_pin(pin)?;
    if !requires_json(pin) {
        return Err(RuntimeConfigError::new(format!(
            "a JSON config pins cvm-version {JSON_CONFIG_MIN_VERSION} or later"
        )));
    }
    check_json_form(&config, data)?;
    Ok(reference)
}

/// The reference that a pin states, validated.
fn reference_from_pin(pin: &str) -> Result<RuntimeReference, RuntimeConfigError> {
    let Some((version, digest)) = pin.split_once(DIGEST_SEPARATOR) else {
        return Err(RuntimeConfigError::new(
            "cvm-version must pin a runtime manifest SHA-256 digest",
        ));
    };
    let reference = RuntimeReference {
        repo: RUNTIME_REPO.to_owned(),
        tag: release_tag(version),
        digest: digest.to_owned(),
    };
    reference
        .validate()
        .map_err(|error| RuntimeConfigError::new(error.to_string()))?;
    Ok(reference)
}

/// The tag of the release that a pin names with or without a leading `v`.
fn release_tag(version: &str) -> String {
    format!("v{}", version.strip_prefix('v').unwrap_or(version))
}

/// Whether a config with this pin must be JSON: the release is
/// [`JSON_CONFIG_MIN_VERSION`] or a later one by semantic version
/// precedence, in which a prerelease counts and build metadata does not. A
/// release that is not a valid version is below every valid one.
fn requires_json(pin: &str) -> bool {
    let version = pin
        .split_once(DIGEST_SEPARATOR)
        .map_or(pin, |(version, _)| version);
    let tag = release_tag(version);
    match (semver::parse(&tag), semver::parse(JSON_CONFIG_MIN_VERSION)) {
        (Some(release), Some(first)) => release.precedence(&first) != Ordering::Less,
        _ => false,
    }
}

/// Requires the one byte form of a JSON config: RFC 8785 canonical JSON
/// without `null`, whose numbers are integers that every implementation
/// reads exactly. No two parsers can then read the bytes differently, and a
/// config has one digest. The walk uses no recursion.
fn check_json_form(config: &Value, data: &[u8]) -> Result<(), RuntimeConfigError> {
    let mut pending = vec![config];
    while let Some(value) = pending.pop() {
        match value {
            Value::Null => {
                return Err(RuntimeConfigError::parsing(
                    "null is not allowed in a JSON config",
                ));
            }
            Value::Number(number) if number.to_safe_integer().is_none() => {
                return Err(RuntimeConfigError::parsing(format_args!(
                    "number {} in a JSON config is not an integer between -(2^53-1) and 2^53-1",
                    number.as_str()
                )));
            }
            Value::Array(items) => pending.extend(items),
            Value::Object(members) => pending.extend(members.iter().map(|(_, member)| member)),
            Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    if canonical_json(config).as_deref() != Some(data) {
        return Err(RuntimeConfigError::parsing(
            "JSON config is not in canonical form (RFC 8785)",
        ));
    }
    Ok(())
}
