//! The Sigstore bundle: a DSSE envelope with the material that verifies it.

use super::SigstoreError;
use super::merkle::Hash;
use crate::json::Value;
use crate::stub::pending;

/// The media type of the bundles that are read.
pub const BUNDLE_V03_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
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
    /// The log's signed entry timestamp, if the entry carries one.
    pub inclusion_promise: Option<Vec<u8>>,
    /// The inclusion proof, if the entry carries one.
    pub inclusion_proof: Option<InclusionProof>,
    /// The entry as the log stores it.
    pub canonicalized_body: Vec<u8>,
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
    /// - the value is an object whose compact JSON encoding is at most
    ///   [`MAX_BUNDLE_SIZE`] bytes;
    /// - `mediaType` is [`BUNDLE_V03_MEDIA_TYPE`];
    /// - `verificationMaterial` has exactly one of `certificate` (with
    ///   non-empty `rawBytes`) and `publicKey` (with a non-empty `hint`).
    ///   The certificate chain form of older bundles (`x509CertificateChain`)
    ///   is an error;
    /// - `tlogEntries` has 1 to [`MAX_TLOG_ENTRIES`] entries, and no two
    ///   share a log identifier and log index. Each has `logIndex`,
    ///   `logId.keyId`, `kindVersion` with `kind` and `version`, and
    ///   `canonicalizedBody`; `integratedTime`, `inclusionPromise` (with
    ///   `signedEntryTimestamp`) and `inclusionProof` are optional, but one
    ///   of the last two is present;
    /// - an inclusion proof has `logIndex`, `treeSize`, a 32-byte
    ///   `rootHash`, at most [`MAX_PROOF_HASHES`] 32-byte `hashes`, and a
    ///   `checkpoint.envelope` of at most [`MAX_CHECKPOINT_SIZE`] bytes;
    /// - `timestampVerificationData.rfc3161Timestamps`, when present, has at
    ///   most [`MAX_TIMESTAMPS`] entries, each with a non-empty
    ///   `signedTimestamp`;
    /// - `dsseEnvelope` is present (a `messageSignature` bundle is an
    ///   error) with `payload`, `payloadType` and exactly one entry in
    ///   `signatures`, whose `sig` is not empty and whose `keyid` is
    ///   optional;
    /// - `logIndex` and `treeSize` are unsigned: JSON strings of decimal
    ///   digits or JSON integer literals, without sign, fraction or
    ///   exponent, below 2^63;
    /// - `integratedTime` is a signed 64-bit integer in the same two forms,
    ///   where a leading `-` is allowed. An absent `integratedTime` and an
    ///   explicit zero are the same thing: both decode to zero, and "no
    ///   integrated time" means zero;
    /// - byte strings are canonical padded standard base64.
    pub fn from_value(value: &Value) -> Result<Self, SigstoreError> {
        pending("sigstore::bundle::Bundle::from_value")
    }

    /// Decodes a bundle from JSON text: at most [`MAX_BUNDLE_SIZE`] bytes
    /// and not empty, strict JSON, and then as [`Bundle::from_value`].
    pub fn from_json(text: &[u8]) -> Result<Self, SigstoreError> {
        pending("sigstore::bundle::Bundle::from_json")
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
