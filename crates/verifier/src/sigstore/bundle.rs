//! The Sigstore bundle: a DSSE envelope with the material that verifies it.

use super::SigstoreError;
use super::merkle::Hash;
use super::wire::{Members, encoded_size};
use crate::json::{self, Value};

/// The media type of version 0.3 bundles.
pub const BUNDLE_V03_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
/// The older spelling of the media type of version 0.3 bundles.
pub const BUNDLE_V03_LEGACY_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.bundle+json;version=0.3";
/// The largest bundle that is read, in bytes of its JSON text.
pub const MAX_BUNDLE_SIZE: usize = 4 << 20;
/// The most transparency-log entries in a bundle.
pub const MAX_TLOG_ENTRIES: usize = 32;
/// The most RFC 3161 timestamps in a bundle.
pub const MAX_TIMESTAMPS: usize = 32;
/// The most hashes in an inclusion proof.
pub const MAX_PROOF_HASHES: usize = 64;
/// The largest checkpoint envelope that is read, in bytes.
pub const MAX_CHECKPOINT_SIZE: usize = 64 << 10;

/// A decoded bundle. Decoding establishes its form only; nothing in it is
/// trusted until one of the verification functions has accepted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The media type: [`BUNDLE_V03_MEDIA_TYPE`] or
    /// [`BUNDLE_V03_LEGACY_MEDIA_TYPE`].
    pub media_type: String,
    /// What identifies the signing key.
    pub key_material: KeyMaterial,
    /// The transparency-log entries, in order.
    pub tlog_entries: Vec<TlogEntry>,
    /// The RFC 3161 timestamp responses over the signature, in order, each
    /// as DER.
    pub timestamps: Vec<Vec<u8>>,
    /// The signed envelope.
    pub envelope: DsseEnvelope,
}

/// What a bundle says about its signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterial {
    /// The DER signing certificate.
    Certificate(Vec<u8>),
    /// The hint of a key that the verifier must already hold.
    PublicKey {
        /// The key's hint.
        hint: String,
    },
}

/// A DSSE envelope with exactly one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsseEnvelope {
    /// The signed payload.
    pub payload: Vec<u8>,
    /// The type of the payload.
    pub payload_type: String,
    /// The signature over the pre-authentication encoding of the payload.
    pub signature: Vec<u8>,
    /// The key identifier of the signature; empty when absent.
    pub key_id: String,
}

/// One transparency-log entry of a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlogEntry {
    /// The entry's index in the log.
    pub log_index: u64,
    /// The identifier of the log.
    pub log_id: Vec<u8>,
    /// The kind of the entry, such as `dsse` or `hashedrekord`.
    pub kind: String,
    /// The version of the kind, such as `0.0.1`.
    pub version: String,
    /// The log's claim of when it integrated the entry, in seconds since
    /// the Unix epoch. Zero means that the entry states no time; the bundle
    /// format does not distinguish an absent member from a zero. It is
    /// authenticated only by the inclusion promise.
    pub integrated_time: i64,
    /// The signed entry timestamp of the entry's inclusion promise, if the
    /// entry carries a promise. A promise may be present with an empty
    /// timestamp; [`TlogEntry::signed_entry_timestamp`] reads only a
    /// timestamp that is there.
    pub inclusion_promise: Option<Vec<u8>>,
    /// The inclusion proof, if the entry carries one.
    pub inclusion_proof: Option<InclusionProof>,
    /// The entry as the log stores it.
    pub canonicalized_body: Vec<u8>,
}

impl TlogEntry {
    /// The log's signed entry timestamp, when the entry carries a promise
    /// with a timestamp that is not empty.
    pub fn signed_entry_timestamp(&self) -> Option<&[u8]> {
        self.inclusion_promise
            .as_deref()
            .filter(|timestamp| !timestamp.is_empty())
    }
}

/// A proof that an entry is in a log at a signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// The index of the entry's leaf in the tree.
    pub log_index: u64,
    /// The root hash that the proof leads to.
    pub root_hash: Hash,
    /// The size of the tree that the proof is for.
    pub tree_size: u64,
    /// The proof hashes, from the leaf upwards.
    pub hashes: Vec<Hash>,
    /// The checkpoint envelope.
    pub checkpoint: String,
}

impl Bundle {
    /// Decodes a bundle from its parsed JSON.
    ///
    /// Every object is read with a closed set of member names, in the JSON
    /// names of the bundle format (`logIndex`, not `log_index`): an unknown
    /// member is an error at any depth. `null` reads as absent. Rules, each
    /// an error when broken:
    ///
    /// - the value is an object whose strings, names and numbers together
    ///   are at most [`MAX_BUNDLE_SIZE`] bytes. This bounds the content of
    ///   a value that is already in memory; it is not the size of the text
    ///   that the value was parsed from, which only [`Bundle::from_json`]
    ///   sees and bounds;
    /// - `mediaType` is [`BUNDLE_V03_MEDIA_TYPE`] or
    ///   [`BUNDLE_V03_LEGACY_MEDIA_TYPE`];
    /// - `verificationMaterial` has exactly one of `certificate` (with
    ///   non-empty `rawBytes`) and `publicKey` (with a non-empty `hint`).
    ///   The certificate chain form of older bundles (`x509CertificateChain`)
    ///   is an error;
    /// - `tlogEntries` has 1 to [`MAX_TLOG_ENTRIES`] entries, and no two
    ///   share a log identifier and log index. Each has `logIndex`,
    ///   `logId.keyId`, a `kindVersion` object and `canonicalizedBody`; a
    ///   missing `kind` or `version` reads as the empty string, which no
    ///   verification function accepts; `integratedTime`, `inclusionPromise` (with
    ///   `signedEntryTimestamp`) and `inclusionProof` are optional, but one
    ///   of the last two is present, and at least one entry of the bundle
    ///   has an inclusion proof. An inclusion promise with an empty
    ///   `signedEntryTimestamp` does not count as present for this rule;
    /// - an inclusion proof has `logIndex`, `treeSize`, a 32-byte
    ///   `rootHash`, at most [`MAX_PROOF_HASHES`] 32-byte `hashes`, and a
    ///   non-empty `checkpoint.envelope` of at most [`MAX_CHECKPOINT_SIZE`]
    ///   bytes;
    /// - `timestampVerificationData.rfc3161Timestamps`, when present, has at
    ///   most [`MAX_TIMESTAMPS`] entries, each with a non-empty
    ///   `signedTimestamp`;
    /// - `dsseEnvelope` is present (a `messageSignature` bundle is an
    ///   error) with exactly one entry in `signatures`, whose `sig` is not
    ///   empty and whose `keyid` is optional. A missing `payload` or
    ///   `payloadType` reads as empty, which no verification function
    ///   accepts;
    /// - `logIndex` and `treeSize` are not negative: JSON strings of decimal
    ///   digits or JSON integer literals, without fraction, exponent or
    ///   leading zero, below 2^63. A minus sign is accepted in front of
    ///   zero only;
    /// - `integratedTime` is a signed 64-bit integer in the same two forms,
    ///   where a leading `-` is allowed. An absent `integratedTime` and an
    ///   explicit zero are the same thing: both decode to zero, and "no
    ///   integrated time" means zero;
    /// - byte strings are canonical padded standard base64.
    pub fn from_value(value: &Value) -> Result<Self, SigstoreError> {
        if encoded_size(value) > MAX_BUNDLE_SIZE {
            return Err(error("bundle size is outside allowed bounds"));
        }
        let bundle = Members::required(
            Some(value),
            "bundle",
            &[
                "mediaType",
                "verificationMaterial",
                "dsseEnvelope",
                "messageSignature",
            ],
        )?;
        let media_type = bundle.string("mediaType")?.unwrap_or_default();
        if media_type != BUNDLE_V03_MEDIA_TYPE && media_type != BUNDLE_V03_LEGACY_MEDIA_TYPE {
            return Err(error(format!(
                "unsupported bundle media type {media_type:?}"
            )));
        }
        if bundle.get("messageSignature").is_some() {
            return Err(error(
                "bundle carries a message signature, want a DSSE envelope",
            ));
        }
        let material = Members::required(
            bundle.get("verificationMaterial"),
            "verificationMaterial",
            &[
                "publicKey",
                "x509CertificateChain",
                "certificate",
                "tlogEntries",
                "timestampVerificationData",
            ],
        )?;
        if material.get("x509CertificateChain").is_some() {
            return Err(error(
                "bundle carries a certificate chain, want a single certificate",
            ));
        }
        let key_material = match (material.get("certificate"), material.get("publicKey")) {
            (Some(certificate), None) => KeyMaterial::Certificate(
                Members::required(Some(certificate), "certificate", &["rawBytes"])?
                    .required_bytes("rawBytes")?,
            ),
            (None, Some(key)) => KeyMaterial::PublicKey {
                hint: Members::required(Some(key), "publicKey", &["hint"])?
                    .required_string("hint")?
                    .to_string(),
            },
            _ => {
                return Err(error(
                    "bundle must carry exactly one of a certificate and a public key hint",
                ));
            }
        };

        let entries = material.array("tlogEntries")?;
        if entries.is_empty() || entries.len() > MAX_TLOG_ENTRIES {
            return Err(error(format!(
                "bundle has {} log entries, want 1 to {MAX_TLOG_ENTRIES}",
                entries.len()
            )));
        }
        let mut tlog_entries: Vec<TlogEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = tlog_entry(entry)?;
            if tlog_entries.iter().any(|earlier| {
                earlier.log_id == entry.log_id && earlier.log_index == entry.log_index
            }) {
                return Err(error("bundle carries the same log entry twice"));
            }
            tlog_entries.push(entry);
        }
        if !tlog_entries
            .iter()
            .any(|entry| entry.inclusion_proof.is_some())
        {
            return Err(error("no log entry of the bundle has an inclusion proof"));
        }

        let mut timestamps = Vec::new();
        if let Some(data) = material.get("timestampVerificationData") {
            let data = Members::required(
                Some(data),
                "timestampVerificationData",
                &["rfc3161Timestamps"],
            )?;
            let list = data.array("rfc3161Timestamps")?;
            if list.len() > MAX_TIMESTAMPS {
                return Err(error(format!(
                    "bundle has {} timestamps, more than the {MAX_TIMESTAMPS} allowed",
                    list.len()
                )));
            }
            for timestamp in list {
                timestamps.push(
                    Members::required(Some(timestamp), "rfc3161Timestamps", &["signedTimestamp"])?
                        .required_bytes("signedTimestamp")?,
                );
            }
        }

        let envelope = Members::required(
            bundle.get("dsseEnvelope"),
            "dsseEnvelope",
            &["payload", "payloadType", "signatures"],
        )?;
        let [signature] = envelope.array("signatures")? else {
            return Err(error("DSSE envelope must have exactly one signature"));
        };
        let signature = Members::required(Some(signature), "signatures", &["sig", "keyid"])?;
        Ok(Self {
            media_type: media_type.to_string(),
            key_material,
            tlog_entries,
            timestamps,
            envelope: DsseEnvelope {
                payload: envelope.bytes("payload")?.unwrap_or_default(),
                payload_type: envelope
                    .string("payloadType")?
                    .unwrap_or_default()
                    .to_string(),
                signature: signature.required_bytes("sig")?,
                key_id: signature.string("keyid")?.unwrap_or_default().to_string(),
            },
        })
    }

    /// Decodes a bundle from JSON text: at most [`MAX_BUNDLE_SIZE`] bytes
    /// and not empty, strict JSON, and then as [`Bundle::from_value`].
    pub fn from_json(text: &[u8]) -> Result<Self, SigstoreError> {
        if text.is_empty() || text.len() > MAX_BUNDLE_SIZE {
            return Err(error("bundle size is outside allowed bounds"));
        }
        let value = json::parse(text).map_err(|cause| error(format!("parsing bundle: {cause}")))?;
        Self::from_value(&value)
    }

    /// The signing certificate's DER, when the bundle carries one.
    pub fn certificate_der(&self) -> Option<&[u8]> {
        match &self.key_material {
            KeyMaterial::Certificate(der) => Some(der),
            KeyMaterial::PublicKey { .. } => None,
        }
    }

    /// The signing key's hint, when the bundle names a key.
    pub fn key_hint(&self) -> Option<&str> {
        match &self.key_material {
            KeyMaterial::Certificate(_) => None,
            KeyMaterial::PublicKey { hint } => Some(hint),
        }
    }
}

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

fn hash(bytes: Vec<u8>, what: &str) -> Result<Hash, SigstoreError> {
    bytes
        .try_into()
        .map_err(|_| error(format!("{what} is not 32 bytes")))
}

fn tlog_entry(value: &Value) -> Result<TlogEntry, SigstoreError> {
    let entry = Members::required(
        Some(value),
        "tlogEntries",
        &[
            "logIndex",
            "logId",
            "kindVersion",
            "integratedTime",
            "inclusionPromise",
            "inclusionProof",
            "canonicalizedBody",
        ],
    )?;
    let kind_version = Members::required(
        entry.get("kindVersion"),
        "kindVersion",
        &["kind", "version"],
    )?;
    let inclusion_promise = match entry.get("inclusionPromise") {
        Some(promise) => {
            Members::required(Some(promise), "inclusionPromise", &["signedEntryTimestamp"])?
                .bytes("signedEntryTimestamp")?
                .or_else(|| Some(Vec::new()))
        }
        None => None,
    };
    let inclusion_proof = match entry.get("inclusionProof") {
        Some(proof) => {
            let proof = Members::required(
                Some(proof),
                "inclusionProof",
                &["logIndex", "rootHash", "treeSize", "hashes", "checkpoint"],
            )?;
            let encoded_hashes = proof.array("hashes")?;
            if encoded_hashes.len() > MAX_PROOF_HASHES {
                return Err(error("inclusion proof has too many hashes"));
            }
            let mut hashes = Vec::with_capacity(encoded_hashes.len());
            for encoded in encoded_hashes {
                let text = encoded
                    .as_str()
                    .ok_or_else(|| error("inclusion proof hash is not a string"))?;
                let bytes = crate::canonical::decode_base64("inclusionProof.hashes", text)?;
                hashes.push(hash(bytes, "inclusion proof hash")?);
            }
            let checkpoint =
                Members::required(proof.get("checkpoint"), "checkpoint", &["envelope"])?
                    .required_string("envelope")?;
            if checkpoint.len() > MAX_CHECKPOINT_SIZE {
                return Err(error("checkpoint size is outside allowed bounds"));
            }
            Some(InclusionProof {
                log_index: proof.required_index("logIndex")?,
                root_hash: hash(
                    proof.required_bytes("rootHash")?,
                    "inclusion proof root hash",
                )?,
                tree_size: proof.required_index("treeSize")?,
                hashes,
                checkpoint: checkpoint.to_string(),
            })
        }
        None => None,
    };
    if inclusion_promise.as_ref().is_none_or(Vec::is_empty) && inclusion_proof.is_none() {
        return Err(error(
            "log entry has neither an inclusion promise nor an inclusion proof",
        ));
    }
    Ok(TlogEntry {
        log_index: entry.required_index("logIndex")?,
        log_id: Members::required(entry.get("logId"), "logId", &["keyId"])?
            .required_bytes("keyId")?,
        kind: kind_version.string("kind")?.unwrap_or_default().to_string(),
        version: kind_version
            .string("version")?
            .unwrap_or_default()
            .to_string(),
        integrated_time: entry.int64("integratedTime")?,
        inclusion_promise,
        inclusion_proof,
        canonicalized_body: entry.required_bytes("canonicalizedBody")?,
    })
}
