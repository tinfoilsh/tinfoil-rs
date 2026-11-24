//! The runtime pin of a workload config.
//!
//! A config is a JSON object whose `cvm-version` member names a runtime
//! release and the SHA-256 of its manifest, as `VERSION@sha256:DIGEST`. This
//! module reads that one member and nothing else: the publisher and the
//! guest own the validation of every other field.

use std::fmt;

use super::RuntimeReference;
use crate::document::collateral::RUNTIME_REPO;
use crate::json::{self, Value};

/// The largest config that is read, in bytes.
pub const MAX_CONFIG_SIZE: usize = 1 << 20;

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
pub fn runtime_from_config(data: &[u8]) -> Result<RuntimeReference, RuntimeConfigError> {
    if data.len() > MAX_CONFIG_SIZE {
        return Err(RuntimeConfigError::parsing(format_args!(
            "the config is larger than {MAX_CONFIG_SIZE} bytes"
        )));
    }
    let value = json::parse(data).map_err(RuntimeConfigError::parsing)?;
    let pin = match value.as_object().and_then(|object| object.get(VERSION_KEY)) {
        None | Some(Value::Null) => "",
        Some(Value::String(pin)) => pin,
        Some(_) => return Err(RuntimeConfigError::parsing("cvm-version must be a string")),
    };
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
