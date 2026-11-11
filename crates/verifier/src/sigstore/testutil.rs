//! Test fixtures: recorded bundles and trusted roots, read leniently so
//! that the tests of the verification steps do not depend on the strict
//! decoders.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::bundle::{Bundle, DsseEnvelope, InclusionProof, KeyMaterial, TlogEntry};
use crate::json::{self, Value};
use crate::x509::{Certificate, PublicKey};

/// A production bundle logged in Rekor v1: a `dsse` 0.0.1 entry with a
/// signed entry timestamp, signed in March 2026.
pub const REKOR_V1_BUNDLE: &str =
    include_str!("../../tests/data/sigstore/rekor_v1_dsse_bundle.json");
/// A staging bundle logged in Rekor v2: a `hashedrekord` 0.0.2 entry and an
/// RFC 3161 timestamp, signed in May 2026.
pub const REKOR_V2_BUNDLE: &str =
    include_str!("../../tests/data/sigstore/rekor_v2_dsse_bundle.json");
/// The production trusted root as of the production bundle.
pub const PRODUCTION_TRUSTED_ROOT: &str =
    include_str!("../../tests/data/sigstore/production_trusted_root.json");
/// The staging trusted root as of the staging bundle.
pub const STAGING_TRUSTED_ROOT: &str =
    include_str!("../../tests/data/sigstore/rekor_v2_staging_trusted_root.json");

pub fn b64(text: &str) -> Vec<u8> {
    STANDARD.decode(text).unwrap()
}

pub fn to_b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object().unwrap().get(name)
}

fn string(value: &Value, name: &str) -> String {
    member(value, name).unwrap().as_str().unwrap().to_string()
}

fn bytes(value: &Value, name: &str) -> Vec<u8> {
    b64(&string(value, name))
}

fn integer(value: &Value, name: &str) -> u64 {
    string(value, name).parse().unwrap()
}

/// Reads a recorded bundle.
pub fn bundle(text: &str) -> Bundle {
    let root = json::parse(text.as_bytes()).unwrap();
    let material = member(&root, "verificationMaterial").unwrap();
    let certificate = member(material, "certificate").unwrap();
    let tlog_entries = member(material, "tlogEntries")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let kind_version = member(entry, "kindVersion").unwrap();
            TlogEntry {
                log_index: integer(entry, "logIndex"),
                log_id: bytes(member(entry, "logId").unwrap(), "keyId"),
                kind: string(kind_version, "kind"),
                version: string(kind_version, "version"),
                integrated_time: member(entry, "integratedTime")
                    .map(|time| time.as_str().unwrap().parse().unwrap())
                    .unwrap_or(0),
                inclusion_promise: member(entry, "inclusionPromise")
                    .map(|promise| bytes(promise, "signedEntryTimestamp")),
                inclusion_proof: member(entry, "inclusionProof").map(|proof| InclusionProof {
                    log_index: integer(proof, "logIndex"),
                    root_hash: bytes(proof, "rootHash").try_into().unwrap(),
                    tree_size: integer(proof, "treeSize"),
                    hashes: member(proof, "hashes")
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|hash| b64(hash.as_str().unwrap()).try_into().unwrap())
                        .collect(),
                    checkpoint: string(member(proof, "checkpoint").unwrap(), "envelope"),
                }),
                canonicalized_body: bytes(entry, "canonicalizedBody"),
            }
        })
        .collect();
    let timestamps = member(material, "timestampVerificationData")
        .and_then(|data| member(data, "rfc3161Timestamps"))
        .map(|list| {
            list.as_array()
                .unwrap()
                .iter()
                .map(|timestamp| bytes(timestamp, "signedTimestamp"))
                .collect()
        })
        .unwrap_or_default();
    let envelope = member(&root, "dsseEnvelope").unwrap();
    let signature = member(envelope, "signatures")
        .unwrap()
        .as_array()
        .unwrap()
        .first()
        .unwrap();
    Bundle {
        media_type: super::bundle::BUNDLE_V03_MEDIA_TYPE.to_string(),
        key_material: KeyMaterial::Certificate(bytes(certificate, "rawBytes")),
        tlog_entries,
        timestamps,
        envelope: DsseEnvelope {
            payload: bytes(envelope, "payload"),
            payload_type: string(envelope, "payloadType"),
            signature: bytes(signature, "sig"),
            key_id: String::new(),
        },
    }
}

/// A log of a recorded trusted root.
pub struct TestLog {
    pub key: PublicKey,
    /// The host of the log's base URL.
    pub name: String,
}

fn find_log(root_text: &str, list: &str, log_id: &[u8]) -> TestLog {
    let root = json::parse(root_text.as_bytes()).unwrap();
    let log = member(&root, list)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|log| bytes(member(log, "logId").unwrap(), "keyId") == log_id)
        .unwrap();
    let key = PublicKey::from_spki_der(&bytes(member(log, "publicKey").unwrap(), "rawBytes"));
    let name = string(log, "baseUrl")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();
    TestLog {
        key: key.unwrap(),
        name,
    }
}

/// The Rekor log of a recorded trusted root with the given identifier.
pub fn log(root_text: &str, log_id: &[u8]) -> TestLog {
    find_log(root_text, "tlogs", log_id)
}

/// The first timestamp authority's certificates in a recorded trusted
/// root, signing certificate first.
pub fn timestamp_authority(root_text: &str) -> Vec<Certificate> {
    let root = json::parse(root_text.as_bytes()).unwrap();
    let authority = member(&root, "timestampAuthorities")
        .unwrap()
        .as_array()
        .unwrap()
        .first()
        .unwrap();
    member(member(authority, "certChain").unwrap(), "certificates")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|certificate| Certificate::from_der(&bytes(certificate, "rawBytes")).unwrap())
        .collect()
}
