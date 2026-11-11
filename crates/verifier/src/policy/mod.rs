//! The platform policy artifact: which machines are endorsed, which platform
//! configurations they may run, and the policy that each must satisfy.
//!
//! The artifact is what a verified quote is appraised against. Its bytes must
//! come from a verified reference-values source; this module performs no
//! cryptography.
//!
//! Parsing is fail-closed: an unknown member, a malformed identifier, a
//! dangling reference or a platform mismatch is an error. A policy that
//! cannot be enforced in full is never applied in part.

mod artifact;
mod sev;
mod shape;
mod tdx;

use std::collections::BTreeMap;
use std::fmt;

use crate::canonical;
use crate::json::decode::{self, DecodeError};
use crate::json::{JsonError, Value};

pub use artifact::{Artifact, PlatformMeasurement, Policy, parse, parse_value};
pub use sev::{GuestPolicy, SevSnpPolicy, SnpPlatform, Tcb, parse_policy_version};
pub use shape::{Shape, Stack, satisfies};
pub use tdx::TdxPolicy;

/// Artifact format that carries workload measurements alongside the machine
/// policy.
pub const ARTIFACT_FORMAT: &str = "https://tinfoil.sh/predicate/platform-endorsements/v1";
/// Artifact format that carries machine policy only.
pub const ARTIFACT_FORMAT_V2: &str = "https://tinfoil.sh/predicate/platform-endorsements/v2";

/// Platform label of AMD SEV-SNP policies.
pub const PLATFORM_SEV_SNP: &str = "sev-snp";
/// Platform label of Intel TDX policies.
pub const PLATFORM_TDX: &str = "tdx";

/// A policy artifact that does not parse, does not validate, or does not
/// endorse what it was asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    message: String,
}

impl PolicyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The same error with `context` in front of its message.
    fn within(self, context: impl fmt::Display) -> Self {
        Self::new(format!("{context}: {}", self.message))
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PolicyError {}

impl From<JsonError> for PolicyError {
    fn from(error: JsonError) -> Self {
        Self::new(format!("parsing policy artifact: {error}"))
    }
}

impl From<DecodeError> for PolicyError {
    fn from(error: DecodeError) -> Self {
        Self::new(format!("parsing policy artifact: {error}"))
    }
}

/// Decodes the hex policy value `name`, of either case, which must hold
/// exactly `want_len` bytes.
pub fn decode_hex(name: &str, value: &str, want_len: usize) -> Result<Vec<u8>, PolicyError> {
    let Some(bytes) = canonical::decode_hex(value) else {
        let reason = if value.len() % 2 == 1 {
            "odd number of digits"
        } else {
            "invalid digit"
        };
        return Err(PolicyError::new(format!("{name} is not hex: {reason}")));
    };
    if bytes.len() != want_len {
        return Err(PolicyError::new(format!(
            "{name} must be {want_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Checks that the policy value `name` is lowercase hex of exactly
/// `byte_len` bytes.
fn validate_policy_hex(name: &str, value: &str, byte_len: usize) -> Result<(), PolicyError> {
    let hex_len = byte_len.saturating_mul(2);
    if value.len() != hex_len {
        return Err(PolicyError::new(format!(
            "{name} must be {hex_len} hex chars, got {}",
            value.len()
        )));
    }
    if value != value.to_lowercase() {
        return Err(PolicyError::new(format!("{name} must be lowercase hex")));
    }
    decode_hex(name, value, byte_len).map(|_| ())
}

/// The first 16 bytes of an identifier, for error messages.
fn truncated(id: &str) -> &str {
    (0..=16).rev().find_map(|end| id.get(..end)).unwrap_or(id)
}

/// An integer member that may be left out: `null` is `None`, as an absent
/// member is.
fn optional<T>(
    value: &Value,
    path: &str,
    integer: fn(&Value, &str) -> Result<T, DecodeError>,
) -> Result<Option<T>, DecodeError> {
    if value.is_null() {
        return Ok(None);
    }
    integer(value, path).map(Some)
}

/// An object whose member values all decode the same way; `null` is the
/// empty map.
fn map<T>(
    value: Value,
    path: &str,
    mut element: impl FnMut(Value, &str) -> Result<T, DecodeError>,
) -> Result<BTreeMap<String, T>, DecodeError> {
    let mut out = BTreeMap::new();
    let Some(object) = decode::object(value, path)? else {
        return Ok(out);
    };
    for (name, value) in object.into_members() {
        let decoded = element(value, &name)?;
        out.insert(name, decoded);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
