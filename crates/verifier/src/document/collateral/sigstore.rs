//! Sigstore reference-values collateral: bundles and freshness witnesses.

use super::{CheckedEntry, CollateralError, present};
use crate::json::Value;
use crate::json::decode;

/// A decoded reference-values entry: a Sigstore bundle and the release that
/// it names. `repo` and `tag` are informational; trust comes from verifying
/// `bundle` against the expected signing identity and `digest`.
#[derive(Debug, PartialEq, Eq)]
pub struct SigstoreRef {
    /// The repository that the entry names.
    pub repo: String,
    /// The release tag that the entry names; may be empty.
    pub tag: String,
    /// The digest of the signed artifact; never empty.
    pub digest: String,
    /// The bundle; never `null`.
    pub bundle: Value,
}

/// A decoded freshness witness: the independently signed bundle attesting
/// that a reference-values artifact was recently published.
#[derive(Debug, PartialEq, Eq)]
pub struct Freshness {
    /// The format of the entry that carried the witness.
    pub format: String,
    /// The bundle; never `null`.
    pub bundle: Value,
}

fn missing_bundle(format: &str, id: &str) -> CollateralError {
    CollateralError::invalid(format!(
        "{format} collateral entry {id:?} is missing sigstore_bundle"
    ))
}

pub(super) fn decode_ref(entry: CheckedEntry) -> Result<SigstoreRef, CollateralError> {
    let CheckedEntry {
        id, format, data, ..
    } = entry;
    let (mut repo, mut tag, mut digest) = (String::new(), String::new(), String::new());
    let mut bundle = None;
    for (name, value) in data.into_members() {
        let decoded = match name.as_str() {
            "repo" => decode::string(value, &name).map(|v| repo = v),
            "tag" => decode::string(value, &name).map(|v| tag = v),
            "digest" => decode::string(value, &name).map(|v| digest = v),
            "sigstore_bundle" => {
                bundle = Some(value);
                Ok(())
            }
            _ => Err(decode::unknown_member("data", &name)),
        };
        decoded.map_err(|error| CollateralError::parsing(&format, &id, &error))?;
    }
    // The tag is an optional hint, and the repository is checked by
    // provenance where it matters; the digest and the bundle are what
    // verification needs.
    if digest.is_empty() {
        return Err(CollateralError::invalid(format!(
            "{format} collateral entry {id:?} is missing digest"
        )));
    }
    let bundle = present(bundle).ok_or_else(|| missing_bundle(&format, &id))?;
    Ok(SigstoreRef {
        repo,
        tag,
        digest,
        bundle,
    })
}

/// Decodes a freshness witness and returns it with its entry id.
pub(super) fn decode_freshness(
    entry: CheckedEntry,
) -> Result<(String, Freshness), CollateralError> {
    let CheckedEntry {
        id, format, data, ..
    } = entry;
    let mut bundle = None;
    for (name, value) in data.into_members() {
        match name.as_str() {
            "sigstore_bundle" => bundle = Some(value),
            _ => {
                let error = decode::unknown_member("data", &name);
                return Err(CollateralError::parsing(&format, &id, &error));
            }
        }
    }
    let bundle = present(bundle).ok_or_else(|| missing_bundle(&format, &id))?;
    Ok((id, Freshness { format, bundle }))
}
