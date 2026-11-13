//! Approvals: config endorsements and artifact freshness statements.
//!
//! An approval is a DSSE bundle around a statement that carries its own
//! RFC 3161 timestamp. The signature says who approved (a pinned key, or a
//! registry certificate under a pinned root); the transparency log shows
//! that the approval was published; the inner timestamp says when, and is
//! what the age rule is applied to.

use std::sync::Arc;
use std::time::Duration;

use ::der::asn1::ObjectIdentifier;
use sha2::{Digest, Sha256};

use super::EndorsementError;
use super::provenance::ProvenanceClient;
use super::reference::is_sha256_hex;
use super::runtime::manifest_name;
use super::time::approval_window;
use super::wire;
use crate::canonical::{decode_base64, decode_hex, encode_lower_hex};
use crate::document::collateral::{RUNTIME_REPO, RuntimeReference};
use crate::instant::Instant;
use crate::json::{self, Value};
use crate::runtime::{MAX_CONFIG_SIZE, runtime_from_config};
use crate::semver;
use crate::sigstore::bundle::{Bundle, KeyMaterial};
use crate::sigstore::certificate::verify_certified_bundle;
use crate::sigstore::keyed::{check_approval_layout, verify_keyed_bundle};
use crate::sigstore::statement::{
    Canonical, DIGEST_ALGORITHM, MAX_STATEMENT_SIZE, STATEMENT_TYPE, endorsement_reference,
    key_hint, timestamp_input,
};
use crate::sigstore::timestamp::{
    AppraisalWindow, MAX_TIMESTAMP_SIZE, SIGSTORE_TIMESTAMP_POLICY, verify_signature_timestamps,
    verify_timestamp,
};
use crate::sigstore::trusted_root::TrustedRoot;
use crate::x509::extension::OID_SUBJECT_ALT_NAME;
use crate::x509::{
    Certificate, KeyPurpose, MAX_CERTIFICATE_SIZE, PublicKey, check_signed_by, verify_chain,
};

/// `ecdsa-with-SHA256`.
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `id-kp-codeSigning`.
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// The hex digits of the identifier of a private registry.
const REGISTRY_IDENTIFIER_HEX_LEN: usize = 32;
/// The longest part of a config identity, in bytes.
const MAX_SLUG_LENGTH: usize = 63;
/// The longest config revision, in bytes.
const MAX_REVISION_LENGTH: usize = 128;
/// The kind of a platform artifact in a statement.
const KIND_PLATFORM: &str = "platform";
/// The kind of a runtime artifact in a statement.
const KIND_RUNTIME: &str = "runtime";

fn error(message: impl Into<String>) -> EndorsementError {
    EndorsementError::new(message)
}

/// A pin that is set: an empty one pins nothing.
fn pinned(pin: &Option<String>) -> Option<&str> {
    pin.as_deref().filter(|pin| !pin.is_empty())
}

/// The predicate type of a config endorsement that names a config by
/// digest only.
pub const CONFIG_PREDICATE_TYPE_V1: &str = "https://tinfoil.sh/predicate/config-endorsement/v1";
/// The predicate type of a config endorsement that also names the registry
/// and the runtime.
pub const CONFIG_PREDICATE_TYPE_V2: &str = "https://tinfoil.sh/predicate/config-endorsement/v2";
/// The predicate type of an artifact freshness statement.
pub const ARTIFACT_FRESHNESS_PREDICATE_TYPE: &str =
    "https://tinfoil.sh/predicate/artifact-freshness/v1";

/// The prefix of every registry identifier.
pub const REGISTRY_ID_PREFIX: &str = "https://registry.tinfoil.sh/scopes/";
/// The identifier of the public registry.
pub const PUBLIC_REGISTRY_ID: &str = "https://registry.tinfoil.sh/scopes/public";

/// The longest validity of a registry signing certificate: ten minutes.
pub const CERTIFICATE_VALIDITY: Duration = Duration::from_secs(10 * 60);
/// How far an approval's inner timestamp may follow the timestamp of its
/// signature: one minute.
pub const CERTIFICATE_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// The domain that separates the timestamp input of a v1 config
/// endorsement.
pub const CONFIG_FRESHNESS_DOMAIN_V1: &str = "tinfoil-config-freshness/v1\0";
/// The domain that separates the timestamp input of a v2 config
/// endorsement.
pub const CONFIG_FRESHNESS_DOMAIN_V2: &str = "tinfoil-config-freshness/v2\0";
/// The domain that separates the timestamp input of an artifact freshness
/// statement.
pub const ARTIFACT_FRESHNESS_DOMAIN: &str = "tinfoil-artifact-freshness/v1\0";

/// The file name of the platform policy artifact.
pub const PLATFORM_ARTIFACT_NAME: &str = "platform-endorsements.json";
/// The prefix of a platform release tag.
pub const PLATFORM_TAG_PREFIX: &str = "platform-";

/// Checks that `registry_id` is the public registry identifier or
/// [`REGISTRY_ID_PREFIX`] followed by 32 lowercase hex digits.
pub fn validate_registry_id(registry_id: &str) -> Result<(), EndorsementError> {
    let private = registry_id
        .strip_prefix(REGISTRY_ID_PREFIX)
        .is_some_and(|identifier| {
            identifier.len() == REGISTRY_IDENTIFIER_HEX_LEN
                && crate::canonical::is_lower_hex(identifier)
        });
    if registry_id == PUBLIC_REGISTRY_ID || private {
        Ok(())
    } else {
        Err(error("registry ID must be a canonical registry URI"))
    }
}

/// Checks that `identity` is a config identity: `/org/project`, where each
/// part is at most 63 characters of lowercase letters and digits in groups
/// separated by single hyphens.
pub fn validate_identity(identity: &str) -> Result<(), EndorsementError> {
    let mut parts = identity.split('/');
    let (Some(""), Some(org), Some(project), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(error(format!("invalid config identity {identity:?}")));
    };
    for part in [org, project] {
        if !is_slug(part) {
            return Err(error(format!("invalid config identity component {part:?}")));
        }
    }
    Ok(())
}

/// Whether `part` is a part of a config identity: at most
/// [`MAX_SLUG_LENGTH`] bytes, lowercase letters and digits in non-empty
/// groups separated by single hyphens.
fn is_slug(part: &str) -> bool {
    part.len() <= MAX_SLUG_LENGTH
        && part.split('-').all(|group| {
            !group.is_empty()
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// Checks that `revision` is a config revision: at most 128 characters,
/// starting with an ASCII letter or digit and continuing with letters,
/// digits, `.`, `_` and `-`.
pub fn validate_revision(revision: &str) -> Result<(), EndorsementError> {
    let well_formed = revision.len() <= MAX_REVISION_LENGTH
        && revision
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if well_formed {
        Ok(())
    } else {
        Err(error(format!("invalid config revision {revision:?}")))
    }
}

/// Splits a versioned config name, `/org/project/revision`, at its last
/// `/` into the identity and the revision, and checks both. A name with a
/// NUL character is an error.
pub fn parse_name(name: &str) -> Result<(&str, &str), EndorsementError> {
    if name.contains('\0') {
        return Err(error("invalid config name"));
    }
    let Some((identity, revision)) = name.rsplit_once('/') else {
        return Err(error("config name has no revision"));
    };
    validate_identity(identity)?;
    validate_revision(revision)?;
    Ok((identity, revision))
}

/// Parses the payload of an approval statement, which has 1 to
/// [`MAX_STATEMENT_SIZE`] bytes.
fn parse_payload(payload: &[u8]) -> Result<Value, EndorsementError> {
    if payload.is_empty() || payload.len() > MAX_STATEMENT_SIZE {
        return Err(error("statement size is outside allowed bounds"));
    }
    json::parse(payload).map_err(|cause| error(format!("decoding statement: {cause}")))
}

/// The canonical form of a statement's one subject.
fn canonical_subject<'a>(name: &'a str, digest: &'a str) -> Canonical<'a> {
    Canonical::Array(vec![Canonical::Object(vec![
        (
            "digest",
            Canonical::Object(vec![(DIGEST_ALGORITHM, Canonical::String(digest))]),
        ),
        ("name", Canonical::String(name)),
    ])])
}

/// What a config endorsement says beyond the config's name and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigPredicate {
    /// A v1 endorsement: nothing more.
    V1,
    /// A v2 endorsement: the registry that holds the config and the runtime
    /// that the config pins.
    V2 {
        /// The registry identifier.
        registry_id: String,
        /// The runtime that the config pins.
        runtime: RuntimeReference,
    },
}

/// A decoded config endorsement statement. Nothing in it is authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigStatement {
    /// The versioned config name: the statement's one subject.
    pub name: String,
    /// The SHA-256 of the config, 64 lowercase hex digits.
    pub digest: String,
    /// What the predicate adds.
    pub predicate: ConfigPredicate,
    /// The inner RFC 3161 timestamp response, DER.
    pub timestamp: Vec<u8>,
}

impl ConfigStatement {
    /// Decodes a config endorsement from a DSSE payload.
    ///
    /// The payload has 1 to
    /// [`MAX_STATEMENT_SIZE`]
    /// bytes and is strict JSON with a closed set of members at every
    /// level: `_type`, `subject` (objects with `name` and `digest`),
    /// `predicateType`, and `predicate` with `scope`, `runtime` (`repo`,
    /// `tag`, `digest`) and `freshness` (`rfc3161Timestamp`, canonical
    /// base64). Rules, each an error when broken:
    ///
    /// - `_type` is the in-toto v1 statement type and `predicateType` is
    ///   one of the two config predicate types;
    /// - a v2 statement has a valid registry identifier in `scope`
    ///   ([`validate_registry_id`]) and a valid `runtime`
    ///   ([`RuntimeReference::validate`]); a v1 statement has neither;
    /// - there is exactly one subject; its name is a versioned config name
    ///   ([`parse_name`]); its digest map has exactly one entry, `sha256`,
    ///   of 64 lowercase hex digits;
    /// - the inner timestamp is present, not empty, and at most
    ///   [`MAX_TIMESTAMP_SIZE`]
    ///   bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, EndorsementError> {
        let value = parse_payload(payload)?;
        let parts = wire::statement(&value, &["scope", "runtime", "freshness"])
            .map_err(|cause| cause.within("decoding config endorsement"))?;
        let scope = wire::text(parts.predicate, "scope")?;
        let runtime = wire::object(
            parts
                .predicate
                .and_then(|predicate| predicate.get("runtime")),
            "runtime",
            &["repo", "tag", "digest"],
        )?;
        let runtime = match runtime {
            Some(_) => Some(RuntimeReference {
                repo: wire::text(runtime, "repo")?.to_string(),
                tag: wire::text(runtime, "tag")?.to_string(),
                digest: wire::text(runtime, "digest")?.to_string(),
            }),
            None => None,
        };
        let freshness = parts
            .predicate
            .and_then(|predicate| predicate.get("freshness"));
        // The member is decoded before the statement is judged, so that a
        // timestamp that is not base64 is an error of the decoding.
        let timestamp = match freshness {
            None | Some(Value::Null) => None,
            Some(_) => Some(decode_base64(
                "rfc3161Timestamp",
                wire::text(
                    wire::object(freshness, "freshness", &["rfc3161Timestamp"])?,
                    "rfc3161Timestamp",
                )?,
            )?),
        };

        if parts.statement_type != STATEMENT_TYPE {
            return Err(error("unsupported config endorsement statement type"));
        }
        let predicate = match parts.predicate_type {
            CONFIG_PREDICATE_TYPE_V2 => {
                let Some(runtime) = runtime else {
                    validate_registry_id(scope)?;
                    return Err(error("config endorsement requires a runtime reference"));
                };
                ConfigPredicate::V2 {
                    registry_id: scope.to_string(),
                    runtime,
                }
            }
            CONFIG_PREDICATE_TYPE_V1 => {
                if runtime.is_some() || !scope.is_empty() {
                    return Err(error(
                        "v1 config endorsement cannot contain a runtime reference",
                    ));
                }
                ConfigPredicate::V1
            }
            _ => return Err(error("unsupported config endorsement predicate type")),
        };
        let [subject] = parts.subjects.as_slice() else {
            predicate_is_valid(&predicate)?;
            return Err(error("config endorsement requires exactly one subject"));
        };
        let statement = Self {
            name: subject.name.to_string(),
            digest: subject
                .only_digest(DIGEST_ALGORITHM)
                .unwrap_or_default()
                .to_string(),
            predicate,
            timestamp: timestamp.unwrap_or_default(),
        };
        statement.validate()?;
        if statement.timestamp.is_empty() {
            return Err(error("config endorsement requires an inner timestamp"));
        }
        if statement.timestamp.len() > MAX_TIMESTAMP_SIZE {
            return Err(error("inner timestamp exceeds size limit"));
        }
        Ok(statement)
    }

    /// Checks everything but the inner timestamp: the registry identifier
    /// and the runtime of a v2 statement, the name, and the digest.
    fn validate(&self) -> Result<(), EndorsementError> {
        predicate_is_valid(&self.predicate)?;
        parse_name(&self.name)?;
        if !is_sha256_hex(&self.digest) {
            return Err(error("subject requires one lowercase SHA-256 digest"));
        }
        Ok(())
    }

    /// The bytes that the inner timestamp covers: the domain of the
    /// statement's version, then the canonical JSON of the statement
    /// without its `freshness` member
    /// ([`timestamp_input`]).
    ///
    /// The canonical statement has `_type`, `subject` (one object with
    /// `digest` and `name`), `predicateType` and `predicate`; the predicate
    /// of a v1 statement is an empty object, and that of a v2 statement
    /// has `runtime` and `scope`.
    pub fn timestamp_input(&self) -> Result<Vec<u8>, EndorsementError> {
        self.validate()?;
        let (domain, predicate_type, predicate) = match &self.predicate {
            ConfigPredicate::V1 => (
                CONFIG_FRESHNESS_DOMAIN_V1,
                CONFIG_PREDICATE_TYPE_V1,
                Canonical::Object(Vec::new()),
            ),
            ConfigPredicate::V2 {
                registry_id,
                runtime,
            } => (
                CONFIG_FRESHNESS_DOMAIN_V2,
                CONFIG_PREDICATE_TYPE_V2,
                Canonical::Object(vec![
                    (
                        "runtime",
                        Canonical::Object(vec![
                            ("digest", Canonical::String(&runtime.digest)),
                            ("repo", Canonical::String(&runtime.repo)),
                            ("tag", Canonical::String(&runtime.tag)),
                        ]),
                    ),
                    ("scope", Canonical::String(registry_id)),
                ]),
            ),
        };
        let core = Canonical::Object(vec![
            ("_type", Canonical::String(STATEMENT_TYPE)),
            ("predicate", predicate),
            ("predicateType", Canonical::String(predicate_type)),
            ("subject", canonical_subject(&self.name, &self.digest)),
        ]);
        Ok(timestamp_input(domain, &core)?)
    }
}

/// Checks the predicate of a config endorsement: a v2 statement has a
/// valid registry identifier and a valid runtime.
fn predicate_is_valid(predicate: &ConfigPredicate) -> Result<(), EndorsementError> {
    if let ConfigPredicate::V2 {
        registry_id,
        runtime,
    } = predicate
    {
        validate_registry_id(registry_id)?;
        runtime.validate()?;
    }
    Ok(())
}

/// The kind of a released artifact that Tinfoil approves as current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// The platform policy artifact; `platform` in a statement.
    Platform,
    /// A runtime manifest; `runtime` in a statement.
    Runtime,
}

impl ArtifactKind {
    /// The kind as a statement spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Platform => KIND_PLATFORM,
            ArtifactKind::Runtime => KIND_RUNTIME,
        }
    }

    fn from_statement(kind: &str) -> Result<Self, EndorsementError> {
        match kind {
            KIND_PLATFORM => Ok(ArtifactKind::Platform),
            KIND_RUNTIME => Ok(ArtifactKind::Runtime),
            other => Err(error(format!(
                "unsupported freshness artifact kind {other:?}"
            ))),
        }
    }
}

/// Whether `name` is the manifest name of the runtime release `tag`: the
/// name of the manifest of a version that is `tag`, or `tag` with build
/// metadata added.
fn is_runtime_name(tag: &str, name: &str) -> bool {
    let version = name.strip_prefix("tinfoil-inference-").unwrap_or(name);
    let version = version.strip_suffix("-manifest.json").unwrap_or(version);
    semver::parse(version).is_some_and(|parsed| version.strip_suffix(parsed.build) == Some(tag))
        && name == manifest_name(version)
}

/// The exact release bytes that an artifact freshness statement is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// The kind of artifact.
    pub kind: ArtifactKind,
    /// The repository that released it.
    pub repo: String,
    /// The release tag.
    pub tag: String,
    /// The artifact's file name.
    pub name: String,
    /// The SHA-256 of the artifact, 64 lowercase hex digits.
    pub digest: String,
}

impl Artifact {
    /// Checks the artifact's form.
    ///
    /// A platform artifact comes from the runtime repository, is named
    /// [`PLATFORM_ARTIFACT_NAME`], and has a tag of [`PLATFORM_TAG_PREFIX`]
    /// followed by a version. A runtime artifact comes from the runtime
    /// repository, has a version as its tag, and is named as the manifest
    /// of that version, where the name may add build metadata to the tag.
    /// The version is a full semantic version in canonical form, without
    /// build metadata. The digest is 64 lowercase hex digits.
    pub fn validate(&self) -> Result<(), EndorsementError> {
        let version = match self.kind {
            ArtifactKind::Platform => self
                .tag
                .strip_prefix(PLATFORM_TAG_PREFIX)
                .filter(|_| self.repo == RUNTIME_REPO && self.name == PLATFORM_ARTIFACT_NAME)
                .ok_or_else(|| {
                    error("platform freshness requires the cvmimage platform artifact")
                })?,
            ArtifactKind::Runtime => {
                if self.repo != RUNTIME_REPO || !is_runtime_name(&self.tag, &self.name) {
                    return Err(error(
                        "runtime freshness requires the versioned runtime manifest",
                    ));
                }
                self.tag.as_str()
            }
        };
        if !semver::parse(version).is_some_and(|parsed| parsed.full && parsed.build.is_empty()) {
            return Err(error("artifact tag must be a canonical semantic version"));
        }
        crate::canonical::decode_lower_hex("artifact digest", &self.digest, 32)?;
        Ok(())
    }
}

/// A decoded artifact freshness statement. Nothing in it is authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStatement {
    /// The artifact that the statement approves.
    pub artifact: Artifact,
    /// The inner RFC 3161 timestamp response, DER.
    pub timestamp: Vec<u8>,
}

impl ArtifactStatement {
    /// Decodes an artifact freshness statement from a DSSE payload.
    ///
    /// The payload has 1 to
    /// [`MAX_STATEMENT_SIZE`]
    /// bytes and is strict JSON with a closed set of members at every
    /// level: `_type`, `subject` (objects with `name` and `digest`),
    /// `predicateType`, and `predicate` with `kind`, `repo`, `tag` and
    /// `freshness` (`rfc3161Timestamp`, canonical base64). Rules, each an
    /// error when broken:
    ///
    /// - `_type` is the in-toto v1 statement type and `predicateType` is
    ///   [`ARTIFACT_FRESHNESS_PREDICATE_TYPE`];
    /// - there is exactly one subject, and its digest map has exactly one
    ///   entry;
    /// - the artifact made of the predicate's kind, repository and tag and
    ///   the subject's name and `sha256` digest is valid
    ///   ([`Artifact::validate`]);
    /// - the inner timestamp is present, not empty, and at most
    ///   [`MAX_TIMESTAMP_SIZE`]
    ///   bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, EndorsementError> {
        let value = parse_payload(payload)?;
        let parts = wire::statement(&value, &["kind", "repo", "tag", "freshness"])?;
        let kind = wire::text(parts.predicate, "kind")?;
        let repo = wire::text(parts.predicate, "repo")?;
        let tag = wire::text(parts.predicate, "tag")?;
        let freshness = parts
            .predicate
            .and_then(|predicate| predicate.get("freshness"));
        let timestamp = match freshness {
            None | Some(Value::Null) => None,
            Some(_) => Some(decode_base64(
                "rfc3161Timestamp",
                wire::text(
                    wire::object(freshness, "freshness", &["rfc3161Timestamp"])?,
                    "rfc3161Timestamp",
                )?,
            )?),
        };

        let unsupported = || error("unsupported artifact freshness statement");
        if parts.statement_type != STATEMENT_TYPE
            || parts.predicate_type != ARTIFACT_FRESHNESS_PREDICATE_TYPE
        {
            return Err(unsupported());
        }
        let [subject] = parts.subjects.as_slice() else {
            return Err(unsupported());
        };
        let [(algorithm, digest)] = subject.digests.as_slice() else {
            return Err(unsupported());
        };
        let artifact = Artifact {
            kind: ArtifactKind::from_statement(kind)?,
            repo: repo.to_string(),
            tag: tag.to_string(),
            name: subject.name.to_string(),
            // A digest under another algorithm leaves the SHA-256 empty.
            digest: if *algorithm == DIGEST_ALGORITHM {
                (*digest).to_string()
            } else {
                String::new()
            },
        };
        artifact.validate()?;
        let timestamp = timestamp.unwrap_or_default();
        if timestamp.is_empty() {
            return Err(error("artifact freshness requires an inner timestamp"));
        }
        if timestamp.len() > MAX_TIMESTAMP_SIZE {
            return Err(error("inner timestamp exceeds size limit"));
        }
        Ok(Self {
            artifact,
            timestamp,
        })
    }

    /// The bytes that the inner timestamp covers:
    /// [`ARTIFACT_FRESHNESS_DOMAIN`], then the canonical JSON of the
    /// statement without its `freshness` member.
    pub fn timestamp_input(&self) -> Result<Vec<u8>, EndorsementError> {
        let artifact = &self.artifact;
        artifact.validate()?;
        let core = Canonical::Object(vec![
            ("_type", Canonical::String(STATEMENT_TYPE)),
            (
                "predicate",
                Canonical::Object(vec![
                    ("kind", Canonical::String(artifact.kind.as_str())),
                    ("repo", Canonical::String(&artifact.repo)),
                    ("tag", Canonical::String(&artifact.tag)),
                ]),
            ),
            (
                "predicateType",
                Canonical::String(ARTIFACT_FRESHNESS_PREDICATE_TYPE),
            ),
            (
                "subject",
                canonical_subject(&artifact.name, &artifact.digest),
            ),
        ]);
        Ok(timestamp_input(ARTIFACT_FRESHNESS_DOMAIN, &core)?)
    }
}

/// Decodes an approval bundle from a document's collateral: the bundle
/// decodes ([`Bundle::from_value`]) and has the approval layout
/// ([`check_approval_layout`]).
pub fn parse_approval_bundle(bundle: &Value) -> Result<Bundle, EndorsementError> {
    let bundle = Bundle::from_value(bundle)?;
    check_approval_layout(&bundle)?;
    Ok(bundle)
}

/// Decodes an approval bundle from its JSON text: the text has 1 to
/// [`MAX_BUNDLE_SIZE`](crate::sigstore::bundle::MAX_BUNDLE_SIZE) bytes,
/// decodes ([`Bundle::from_json`]) and has the approval layout.
pub fn parse_approval_bundle_json(bundle: &[u8]) -> Result<Bundle, EndorsementError> {
    let bundle =
        Bundle::from_json(bundle).map_err(|cause| cause.within("parsing endorsement bundle"))?;
    check_approval_layout(&bundle)?;
    Ok(bundle)
}

/// Verifies approvals signed with pinned keys.
///
/// The keys are the whole source of signing authority: verification never
/// learns a key from the material that it verifies.
#[derive(Debug, Clone)]
pub struct ApprovalVerifier {
    root: Arc<TrustedRoot>,
    /// Each pinned key with its hint.
    keys: Vec<(String, PublicKey)>,
}

impl ApprovalVerifier {
    /// A verifier for the given pinned keys.
    ///
    /// Errors, in order: the trusted root lists no Rekor log; `keys` is
    /// empty; a key is not ECDSA P-256
    /// ([`key_hint`]); two keys have
    /// the same hint.
    pub fn new(root: Arc<TrustedRoot>, keys: &[PublicKey]) -> Result<Self, EndorsementError> {
        if root.rekor_logs().is_empty() {
            return Err(EndorsementError::new("Rekor trust is required"));
        }
        if keys.is_empty() {
            return Err(EndorsementError::new(
                "at least one independently trusted signing key is required",
            ));
        }
        let mut pinned: Vec<(String, PublicKey)> = Vec::with_capacity(keys.len());
        for key in keys {
            let hint = key_hint(key)?;
            if pinned.iter().any(|(earlier, _)| *earlier == hint) {
                return Err(EndorsementError::new(format!(
                    "duplicate signing key {hint}"
                )));
            }
            pinned.push((hint, key.clone()));
        }
        Ok(Self { root, keys: pinned })
    }

    /// Verifies an approval bundle and returns the hint of the pinned key
    /// that signed it.
    ///
    /// The bundle has passed [`parse_approval_bundle`]. In order: the
    /// bundle names a key by hint, and the hint is that of a pinned key;
    /// the bundle verifies under that key for `digest`
    /// ([`verify_keyed_bundle`]).
    pub fn verify(&self, bundle: &Bundle, digest: &[u8; 32]) -> Result<String, EndorsementError> {
        let (hint, key) = bundle
            .key_hint()
            .and_then(|hint| self.keys.iter().find(|(pinned, _)| pinned == hint))
            .ok_or_else(|| EndorsementError::new("untrusted approval signing key"))?;
        verify_keyed_bundle(&self.root, bundle, key, digest)
            .map_err(|cause| cause.within("verifying endorsement bundle"))?;
        Ok(hint.clone())
    }

    /// Authenticates an approval's inner timestamp.
    ///
    /// See [`verify_approval_timestamp`]; the trusted root is the
    /// verifier's.
    pub fn verify_timestamp(
        &self,
        response: &[u8],
        input: &[u8],
        window: &AppraisalWindow,
    ) -> Result<Instant, EndorsementError> {
        verify_approval_timestamp(&self.root, response, input, window)
    }
}

/// Authenticates an approval's inner timestamp over `input`, and returns
/// its time.
///
/// In order: `input` has 1 to
/// [`MAX_STATEMENT_SIZE`]
/// bytes; the response is authenticated by a timestamp authority of the
/// trusted root, covers `input`, and was issued under the Sigstore
/// timestamp policy
/// ([`verify_timestamp`] with
/// [`SIGSTORE_TIMESTAMP_POLICY`]);
/// the time is within `window`.
pub fn verify_approval_timestamp(
    root: &TrustedRoot,
    response: &[u8],
    input: &[u8],
    window: &AppraisalWindow,
) -> Result<Instant, EndorsementError> {
    if input.is_empty() || input.len() > MAX_STATEMENT_SIZE {
        return Err(EndorsementError::new(
            "timestamp input size is outside allowed bounds",
        ));
    }
    let at = verify_timestamp(root, response, input, Some(SIGSTORE_TIMESTAMP_POLICY))?;
    window.check(at)?;
    Ok(at)
}

/// What a config endorsement must match, and the clock that judges its
/// age.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPolicy {
    /// The config identity (`/org/project`) that the endorsement must
    /// name, when pinned. An empty identity, revision or digest pins
    /// nothing.
    pub identity: Option<String>,
    /// The config revision that the endorsement must name, when pinned.
    pub revision: Option<String>,
    /// The config digest that the endorsement must name, when pinned: 64
    /// lowercase hex digits.
    pub digest: Option<String>,
    /// The appraisal instant.
    pub now: Instant,
    /// The greatest age of the approval; `None` selects the default, and
    /// a given duration is used as it is.
    pub max_age: Option<Duration>,
    /// The allowed clock skew; `None` selects the default, and a given
    /// duration is used as it is.
    pub future_skew: Option<Duration>,
    /// The registries whose endorsements are accepted. `None` accepts any
    /// registry and endorsements outside a registry; a list accepts
    /// exactly its members.
    pub registry_ids: Option<Vec<String>>,
}

impl ConfigPolicy {
    /// Checks the pins, without the clock: a pinned identity
    /// ([`validate_identity`]), revision ([`validate_revision`]) and digest
    /// have their forms; a registry list is not empty, holds valid
    /// identifiers ([`validate_registry_id`]) and repeats none.
    pub fn validate_pins(&self) -> Result<(), EndorsementError> {
        if let Some(identity) = pinned(&self.identity) {
            validate_identity(identity)?;
        }
        if let Some(revision) = pinned(&self.revision) {
            validate_revision(revision)?;
        }
        if pinned(&self.digest).is_some_and(|digest| !is_sha256_hex(digest)) {
            return Err(error("digest pin must be lowercase SHA-256"));
        }
        let Some(registry_ids) = &self.registry_ids else {
            return Ok(());
        };
        if registry_ids.is_empty() {
            return Err(error("config registry IDs must not be empty"));
        }
        let mut seen: Vec<&str> = Vec::with_capacity(registry_ids.len());
        for registry_id in registry_ids {
            validate_registry_id(registry_id)?;
            if seen.contains(&registry_id.as_str()) {
                return Err(error("duplicate config registry ID"));
            }
            seen.push(registry_id);
        }
        Ok(())
    }
}

/// What a verified config endorsement establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigVerified {
    /// The versioned config name.
    pub name: String,
    /// The SHA-256 of the config, lowercase hex.
    pub digest: String,
    /// The reference of the signed statement
    /// ([`endorsement_reference`]).
    pub reference: String,
    /// The hint of the key that signed the endorsement.
    pub signing_key_hint: String,
    /// The authenticated time of the approval's inner timestamp.
    pub approval_time: Instant,
    /// The runtime that the config pins, for a v2 endorsement.
    pub runtime: Option<RuntimeReference>,
    /// The registry that the endorsement belongs to: the certificate's for
    /// a certified endorsement, the public registry for a key-signed one
    /// verified by a registry verifier, and `None` otherwise.
    pub registry_id: Option<String>,
    /// The authenticated time of the signature, for a certified
    /// endorsement.
    pub signature_time: Option<Instant>,
}

/// Verifies config endorsements.
#[derive(Debug, Clone)]
pub struct ConfigVerifier {
    approvals: ApprovalVerifier,
    /// The registry root keys; empty for a verifier of caller-pinned keys.
    root_keys: Vec<PublicKey>,
}

impl ConfigVerifier {
    /// A verifier whose `keys` sign config endorsements directly. It
    /// accepts no certified endorsement. Errors as
    /// [`ApprovalVerifier::new`].
    pub fn new(root: Arc<TrustedRoot>, keys: &[PublicKey]) -> Result<Self, EndorsementError> {
        Ok(Self {
            approvals: ApprovalVerifier::new(root, keys)?,
            root_keys: Vec::new(),
        })
    }

    /// A verifier for the registry: `root_keys` sign v1 endorsements of the
    /// public registry directly and are the roots that certify registry
    /// signing certificates. Errors as [`ApprovalVerifier::new`].
    pub fn for_registry(
        root: Arc<TrustedRoot>,
        root_keys: &[PublicKey],
    ) -> Result<Self, EndorsementError> {
        Ok(Self {
            approvals: ApprovalVerifier::new(root, root_keys)?,
            root_keys: root_keys.to_vec(),
        })
    }

    /// Verifies a key-signed config endorsement.
    ///
    /// `config` is the config's bytes when the document carries them. In
    /// order:
    ///
    /// 1. `config`, when given, has 1 to [`MAX_CONFIG_SIZE`] bytes;
    /// 2. the pins are valid ([`ConfigPolicy::validate_pins`]) and the
    ///    appraisal window exists ([`approval_window`]);
    /// 3. the bundle is an approval bundle ([`parse_approval_bundle`]);
    /// 4. the payload decodes ([`ConfigStatement::from_payload`]);
    /// 5. a pinned identity and a pinned revision equal those of the
    ///    statement's name; a pinned digest equals the statement's;
    /// 6. without `config`, the statement is v2. With `config`, its
    ///    SHA-256 is the statement's digest;
    /// 7. a registry verifier rejects a v2 statement here: a v2 registry
    ///    endorsement needs its issuer certificate
    ///    ([`ConfigVerifier::verify_certified`]);
    /// 8. the bundle verifies under a pinned key for the statement's
    ///    digest ([`ApprovalVerifier::verify`]). The registry is the public
    ///    one for a registry verifier and none otherwise;
    /// 9. for a v2 statement with `config`, the runtime that the config
    ///    pins ([`runtime_from_config`]) equals the statement's. The config
    ///    is read for its pin only here, once the signature binds the
    ///    statement and, through its digest, the config;
    /// 10. with a registry list in the policy, the registry is in it; an
    ///     endorsement outside a registry is in no list;
    /// 11. the inner timestamp is authenticated over the statement's
    ///     timestamp input and is within the window
    ///     ([`verify_approval_timestamp`]).
    pub fn verify(
        &self,
        config: Option<&[u8]>,
        bundle: &Value,
        policy: &ConfigPolicy,
    ) -> Result<ConfigVerified, EndorsementError> {
        self.verify_endorsement(config, bundle, None, policy)
    }

    /// Verifies a config endorsement signed with a registry certificate.
    ///
    /// Only a registry verifier accepts one, and `issuer_der` must not be
    /// empty. Steps 1 to 6 are those of [`ConfigVerifier::verify`]. Then,
    /// in order:
    ///
    /// 7. the statement is v2;
    /// 8. at least one RFC 3161 timestamp over the bundle's signature
    ///    verifies ([`verify_signature_timestamps`]); the first is the
    ///    signature time, and it is not beyond the future bound;
    /// 9. the signing certificate has the registry profile at the
    ///    signature time ([`verify_signing_certificate`]);
    /// 10. the certificate's URI is the statement's registry identifier;
    /// 11. the bundle verifies under the certificate for the statement's
    ///     digest ([`verify_certified_bundle`]), and the verified
    ///     identity's name is the registry identifier and its issuer claim
    ///     is empty;
    /// 12. with `config`, the runtime that the config pins equals the
    ///     statement's;
    /// 13. with a registry list in the policy, the registry is in it;
    /// 14. the inner timestamp is authenticated over the statement's
    ///     timestamp input and is within the window;
    /// 15. the inner timestamp is not more than
    ///     [`CERTIFICATE_CLOCK_SKEW`] after the signature time.
    pub fn verify_certified(
        &self,
        config: Option<&[u8]>,
        bundle: &Value,
        issuer_der: &[u8],
        policy: &ConfigPolicy,
    ) -> Result<ConfigVerified, EndorsementError> {
        if self.root_keys.is_empty() {
            return Err(error("registry root trust is not configured"));
        }
        if issuer_der.is_empty() {
            return Err(error(
                "certified registry verification requires an issuer certificate",
            ));
        }
        self.verify_endorsement(config, bundle, Some(issuer_der), policy)
    }

    fn verify_endorsement(
        &self,
        config: Option<&[u8]>,
        bundle: &Value,
        issuer_der: Option<&[u8]>,
        policy: &ConfigPolicy,
    ) -> Result<ConfigVerified, EndorsementError> {
        if config.is_some_and(|config| config.is_empty() || config.len() > MAX_CONFIG_SIZE) {
            return Err(error("config size is outside allowed bounds"));
        }
        policy.validate_pins()?;
        let window = approval_window(policy.now, policy.max_age, policy.future_skew)?;
        let bundle = parse_approval_bundle(bundle)?;
        let payload = bundle.envelope.payload.as_slice();
        let statement = ConfigStatement::from_payload(payload)?;
        let (identity, revision) = parse_name(&statement.name)?;
        if pinned(&policy.identity).is_some_and(|pin| pin != identity)
            || pinned(&policy.revision).is_some_and(|pin| pin != revision)
        {
            return Err(error(
                "config endorsement does not match the pinned identity or revision",
            ));
        }
        if pinned(&policy.digest).is_some_and(|pin| pin != statement.digest) {
            return Err(error("config endorsement does not match the pinned digest"));
        }
        let endorsed = match &statement.predicate {
            ConfigPredicate::V1 => None,
            ConfigPredicate::V2 {
                registry_id,
                runtime,
            } => Some((registry_id.as_str(), runtime)),
        };
        match config {
            None if endorsed.is_none() => {
                return Err(error(
                    "digest verification requires a v2 config endorsement",
                ));
            }
            Some(config) if encode_lower_hex(&Sha256::digest(config)) != statement.digest => {
                return Err(error("config bytes do not match the endorsed digest"));
            }
            _ => {}
        }
        let digest: [u8; 32] = decode_hex(&statement.digest)
            .and_then(|digest| digest.try_into().ok())
            .ok_or_else(|| error("config digest is not a SHA-256"))?;

        let root = &self.approvals.root;
        let (registry_id, hint, signed_at) = match issuer_der {
            Some(issuer_der) => {
                let Some((stated_registry, _)) = endorsed else {
                    return Err(error(
                        "certified registry endorsement requires a v2 statement",
                    ));
                };
                let signed_at = verify_signature_timestamps(root, &bundle)?
                    .first()
                    .copied()
                    .ok_or_else(|| error("threshold not met for verified signed timestamps"))?;
                if signed_at > window.latest {
                    return Err(error("signature timestamp is in the future"));
                }
                let certificate_der = match &bundle.key_material {
                    KeyMaterial::Certificate(der) => der.as_slice(),
                    KeyMaterial::PublicKey { .. } => &[],
                };
                let (certificate, issuer) = verify_signing_certificate(
                    certificate_der,
                    issuer_der,
                    &self.root_keys,
                    signed_at,
                )?;
                let (uris, _) = certificate.subject_alternative_uris()?;
                let [registry_id] = uris.as_slice() else {
                    return Err(error(
                        "registry identity requires exactly one critical URI SAN",
                    ));
                };
                if registry_id != stated_registry {
                    return Err(error(
                        "certificate registry ID does not match signed registry ID",
                    ));
                }
                let verified = verify_certified_bundle(root, &bundle, &issuer, &digest)?;
                if verified.identity.subject_alternative_name != *registry_id {
                    return Err(error("signing certificate does not name the registry"));
                }
                let hint = key_hint(&certificate.public_key()?)?;
                (Some(registry_id.clone()), hint, Some(signed_at))
            }
            None => {
                let for_registry = !self.root_keys.is_empty();
                if for_registry && endorsed.is_some() {
                    return Err(error(
                        "v2 registry endorsement requires an issuer certificate",
                    ));
                }
                let hint = self.approvals.verify(&bundle, &digest)?;
                (
                    for_registry.then(|| PUBLIC_REGISTRY_ID.to_string()),
                    hint,
                    None,
                )
            }
        };
        // The config is read for its runtime pin only now that the
        // signature binds the statement, and through its digest the config.
        if let (Some(config), Some((_, runtime))) = (config, endorsed)
            && runtime_from_config(config)? != *runtime
        {
            return Err(error("config runtime does not match the endorsed runtime"));
        }
        if policy.registry_ids.as_ref().is_some_and(|accepted| {
            !registry_id
                .as_ref()
                .is_some_and(|registry_id| accepted.contains(registry_id))
        }) {
            return Err(error("config registry ID is not accepted by the caller"));
        }
        let input = statement.timestamp_input()?;
        let approval_time = self
            .approvals
            .verify_timestamp(&statement.timestamp, &input, &window)
            .map_err(|cause| cause.within("inner timestamp"))?;
        // A signature time so late that the skew leaves the supported
        // years has no instant after it.
        if signed_at
            .and_then(|signed_at| signed_at.checked_add(CERTIFICATE_CLOCK_SKEW))
            .is_some_and(|latest| approval_time > latest)
        {
            return Err(error("approval timestamp follows signature timestamp"));
        }
        Ok(ConfigVerified {
            reference: endorsement_reference(payload),
            signing_key_hint: hint,
            approval_time,
            runtime: endorsed.map(|(_, runtime)| runtime.clone()),
            registry_id,
            signature_time: signed_at,
            name: statement.name,
            digest: statement.digest,
        })
    }
}

/// Authenticates a registry signing certificate at the instant `at`, and
/// returns it with its issuer. The caller authenticates `at` separately.
///
/// In order:
///
/// 1. `at` is not the unset clock
///    ([`is_unset_clock`](super::time::is_unset_clock)), and both
///    certificates have 1 to [`MAX_CERTIFICATE_SIZE`] bytes and parse;
/// 2. the issuer's key and every key of `roots` is an ECDSA P-256 key; the
///    issuer's key is one of `roots`, compared by key hint; the issuer may
///    sign certificates ([`check_signed_by`]) and its own signature
///    verifies under its key;
/// 3. the certificate has the profile: not a CA, with basic constraints
///    present; key usage exactly digital signature; extended key usage
///    exactly code signing; signed with ECDSA and SHA-256; valid for at
///    most [`CERTIFICATE_VALIDITY`], within the issuer's validity; an
///    empty subject; one subject alternative name, a URI, and no other
///    names;
/// 4. the URI is a registry identifier ([`validate_registry_id`]), and the
///    subject alternative name extension is critical and holds exactly
///    that one URI;
/// 5. the certificate's key is not one of `roots`;
/// 6. the certificate chains to the issuer at `at` with the code-signing
///    purpose ([`verify_chain`]).
pub fn verify_signing_certificate(
    certificate_der: &[u8],
    issuer_der: &[u8],
    roots: &[PublicKey],
    at: Instant,
) -> Result<(Certificate, Certificate), EndorsementError> {
    let bounded = |der: &[u8]| !der.is_empty() && der.len() <= MAX_CERTIFICATE_SIZE;
    if super::time::is_unset_clock(at) || !bounded(certificate_der) || !bounded(issuer_der) {
        return Err(error(
            "signing certificate requires a time and bounded certificate bytes",
        ));
    }
    let certificate = Certificate::from_der(certificate_der)?;
    let issuer = Certificate::from_der(issuer_der)?;
    let issuer_hint = key_hint(&issuer.public_key()?)?;
    let trusted = roots
        .iter()
        .map(key_hint)
        .collect::<Result<Vec<String>, _>>()?;
    if !trusted.contains(&issuer_hint) {
        return Err(error("untrusted registry root"));
    }
    check_signed_by(&issuer, &issuer)
        .map_err(|cause| error(format!("invalid registry root certificate: {cause}")))?;

    let invalid_profile = || error("invalid config signing certificate profile");
    let not_a_ca = certificate
        .basic_constraints()?
        .is_some_and(|constraints| !constraints.ca);
    let signs_only = certificate.key_usage()?.is_some_and(|usage| {
        usage.digital_signature
            && !usage.content_commitment
            && !usage.key_cert_sign
            && !usage.crl_sign
            && !usage.other
    });
    let code_signing_only = certificate
        .extended_key_usage()?
        .is_some_and(|purposes| purposes == [OID_CODE_SIGNING]);
    let short_lived = certificate
        .not_after()
        .duration_since(certificate.not_before())
        .is_none_or(|validity| validity <= CERTIFICATE_VALIDITY);
    let within_issuer = certificate.not_before() >= issuer.not_before()
        && certificate.not_after() <= issuer.not_after();
    // An empty name is a SEQUENCE without contents.
    let unnamed = certificate.subject_der() == [0x30, 0x00];
    let (uris, other_names) = certificate.subject_alternative_uris()?;
    let [registry_id] = uris.as_slice() else {
        return Err(invalid_profile());
    };
    if !(not_a_ca
        && signs_only
        && code_signing_only
        && certificate.signature_algorithm() == OID_ECDSA_WITH_SHA256
        && short_lived
        && within_issuer
        && unnamed
        && !other_names)
    {
        return Err(invalid_profile());
    }
    validate_registry_id(registry_id)?;
    if !certificate
        .extension(OID_SUBJECT_ALT_NAME)
        .is_some_and(|names| names.critical)
    {
        return Err(error(
            "registry identity requires exactly one critical URI SAN",
        ));
    }
    if trusted.contains(&key_hint(&certificate.public_key()?)?) {
        return Err(error("registry root cannot serve as a config signing key"));
    }
    verify_chain(
        &certificate,
        &[],
        std::slice::from_ref(&issuer),
        at,
        KeyPurpose::CodeSigning,
    )
    .map_err(|cause| error(format!("verifying config signing certificate: {cause}")))?;
    Ok((certificate, issuer))
}

/// The artifact that a freshness approval must be about, and the clock
/// that judges its age.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessPolicy {
    /// The expected artifact.
    pub artifact: Artifact,
    /// The appraisal instant.
    pub now: Instant,
    /// The greatest age of the approval; `None` selects the default.
    pub max_age: Option<Duration>,
    /// The allowed clock skew; `None` selects the default.
    pub future_skew: Option<Duration>,
}

/// What a verified artifact freshness approval establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessVerified {
    /// The approved artifact.
    pub artifact: Artifact,
    /// The reference of the signed statement.
    pub reference: String,
    /// The hint of the key that signed the approval.
    pub signing_key_hint: String,
    /// The authenticated time of the approval's inner timestamp.
    pub approval_time: Instant,
}

/// Verifies artifact freshness approvals under Tinfoil's approval keys,
/// which are separate from any organization's config signing authority.
#[derive(Debug, Clone)]
pub struct FreshnessVerifier {
    approvals: ApprovalVerifier,
}

impl FreshnessVerifier {
    /// A verifier for the given pinned keys. Errors as
    /// [`ApprovalVerifier::new`].
    pub fn new(root: Arc<TrustedRoot>, keys: &[PublicKey]) -> Result<Self, EndorsementError> {
        Ok(Self {
            approvals: ApprovalVerifier::new(root, keys)?,
        })
    }

    /// Verifies an artifact freshness approval.
    ///
    /// The artifact's build provenance is the caller's to verify. In
    /// order:
    ///
    /// 1. the expected artifact is valid ([`Artifact::validate`]) and the
    ///    appraisal window exists;
    /// 2. the bundle is an approval bundle ([`parse_approval_bundle`]);
    /// 3. the payload decodes ([`ArtifactStatement::from_payload`]);
    /// 4. the statement's artifact equals the expected one in every field;
    /// 5. the bundle verifies under a pinned key for the artifact's digest
    ///    ([`ApprovalVerifier::verify`]);
    /// 6. the inner timestamp is authenticated over the statement's
    ///    timestamp input and is within the window
    ///    ([`verify_approval_timestamp`]).
    pub fn verify(
        &self,
        bundle: &Value,
        policy: &FreshnessPolicy,
    ) -> Result<FreshnessVerified, EndorsementError> {
        policy.artifact.validate()?;
        let window = approval_window(policy.now, policy.max_age, policy.future_skew)?;
        let bundle = parse_approval_bundle(bundle)?;
        let payload = bundle.envelope.payload.as_slice();
        let statement = ArtifactStatement::from_payload(payload)?;
        if statement.artifact != policy.artifact {
            return Err(error(
                "freshness approval does not match the expected artifact",
            ));
        }
        let digest: [u8; 32] = decode_hex(&policy.artifact.digest)
            .and_then(|digest| digest.try_into().ok())
            .ok_or_else(|| error("artifact digest is not a SHA-256"))?;
        let signing_key_hint = self.approvals.verify(&bundle, &digest)?;
        let input = statement.timestamp_input()?;
        let approval_time = self
            .approvals
            .verify_timestamp(&statement.timestamp, &input, &window)
            .map_err(|cause| cause.within("inner timestamp"))?;
        Ok(FreshnessVerified {
            artifact: statement.artifact,
            reference: endorsement_reference(payload),
            signing_key_hint,
            approval_time,
        })
    }
}

impl ProvenanceClient {
    /// A config verifier of caller-pinned keys over this client's trusted
    /// root ([`ConfigVerifier::new`]).
    pub fn config_verifier(&self, keys: &[PublicKey]) -> Result<ConfigVerifier, EndorsementError> {
        ConfigVerifier::new(Arc::clone(self.trusted_root()), keys)
    }

    /// A registry config verifier over this client's trusted root
    /// ([`ConfigVerifier::for_registry`]).
    pub fn registry_verifier(
        &self,
        root_keys: &[PublicKey],
    ) -> Result<ConfigVerifier, EndorsementError> {
        ConfigVerifier::for_registry(Arc::clone(self.trusted_root()), root_keys)
    }

    /// An artifact freshness verifier over this client's trusted root
    /// ([`FreshnessVerifier::new`]).
    pub fn freshness_verifier(
        &self,
        keys: &[PublicKey],
    ) -> Result<FreshnessVerifier, EndorsementError> {
        FreshnessVerifier::new(Arc::clone(self.trusted_root()), keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "/tinfoil/model-router/v0.0.155";
    const STATEMENT_V1: &str = concat!(
        r#"{"_type":"https://in-toto.io/Statement/v1","#,
        r#""subject":[{"name":"/tinfoil/model-router/v0.0.155","digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],"#,
        r#""predicateType":"https://tinfoil.sh/predicate/config-endorsement/v1","#,
        r#""predicate":{"freshness":{"rfc3161Timestamp":"AQID"}}}"#
    );
    const ARTIFACT_STATEMENT: &str = concat!(
        r#"{"_type":"https://in-toto.io/Statement/v1","#,
        r#""subject":[{"name":"tinfoil-inference-v1.2.3-manifest.json","digest":{"sha256":"abababababababababababababababababababababababababababababababab"}}],"#,
        r#""predicateType":"https://tinfoil.sh/predicate/artifact-freshness/v1","#,
        r#""predicate":{"kind":"runtime","repo":"tinfoilsh/cvmimage","tag":"v1.2.3","freshness":{"rfc3161Timestamp":"AQID"}}}"#
    );

    #[test]
    fn config_names_are_canonical() {
        let long = |letter: &str, count: usize| letter.repeat(count);
        for invalid in [
            "/org/project".to_string(),
            "org/project/v1".to_string(),
            "//org/project/v1".to_string(),
            "/org//v1".to_string(),
            "/org/Project/v1".to_string(),
            "/Org/project/v1".to_string(),
            "/org/project/enclave/v1".to_string(),
            "/tinfoil/org/project/enclave/v1".to_string(),
            "/org/../v1".to_string(),
            "/org/project/../v1".to_string(),
            "/org/project/%2F".to_string(),
            "/org/project/v1/".to_string(),
            "/org/project/.hidden".to_string(),
            "/org/project/".to_string(),
            "/org/project/v1\0".to_string(),
            format!("/org/project/{}", long("a", MAX_REVISION_LENGTH + 1)),
            format!("/{}/project/v1", long("a", MAX_SLUG_LENGTH + 1)),
            format!("/org/{}/v1", long("a", MAX_SLUG_LENGTH + 1)),
        ] {
            assert!(parse_name(&invalid).is_err(), "{invalid:?}");
        }
        let longest = format!(
            "/{}/{}/{}",
            long("a", MAX_SLUG_LENGTH),
            long("b", MAX_SLUG_LENGTH),
            long("c", MAX_REVISION_LENGTH)
        );
        for (name, identity, revision) in [
            (NAME, "/tinfoil/model-router", "v0.0.155"),
            ("/org/project/v0.1.0", "/org/project", "v0.1.0"),
            (
                "/org-1/project-2/Release_1.2-rc",
                "/org-1/project-2",
                "Release_1.2-rc",
            ),
            (
                longest.as_str(),
                &longest[..2 * MAX_SLUG_LENGTH + 2],
                &longest[2 * MAX_SLUG_LENGTH + 3..],
            ),
        ] {
            assert_eq!(parse_name(name).unwrap(), (identity, revision));
        }
    }

    #[test]
    fn registry_identifiers_are_canonical() {
        const PRIVATE: &str = "https://registry.tinfoil.sh/scopes/9c4a7f21e0b836d56a13c8fe42d907ab";
        for valid in [
            PUBLIC_REGISTRY_ID,
            PRIVATE,
            "https://registry.tinfoil.sh/scopes/00000000000000000000000000000000",
            "https://registry.tinfoil.sh/scopes/ffffffffffffffffffffffffffffffff",
        ] {
            assert!(validate_registry_id(valid).is_ok(), "{valid}");
        }
        for invalid in [
            String::new(),
            format!("{PRIVATE}/"),
            format!("{PRIVATE}?x=1"),
            format!("{PRIVATE}#x"),
            format!("{PRIVATE}\n"),
            format!(" {PRIVATE}"),
            format!("{PUBLIC_REGISTRY_ID}\n"),
            PRIVATE[..PRIVATE.len() - 1].to_string(),
            format!("{PRIVATE}a"),
            PRIVATE.replacen("9c4a", "9C4A", 1),
            PRIVATE.replacen("9c4a", "9g4a", 1),
            PRIVATE.replacen("9c4a", "9 4a", 1),
            PRIVATE.replacen("9c4a", "%39c4a", 1),
            PRIVATE.replacen("https:", "http:", 1),
            PRIVATE.replacen("https:", "HTTPS:", 1),
            PRIVATE.replacen("registry.tinfoil.sh", "user@registry.tinfoil.sh", 1),
            PRIVATE.replacen("registry.tinfoil.sh", "registry.tinfoil.sh:443", 1),
            PRIVATE.replacen("scopes/", "scopes/v1/", 1),
            PRIVATE.replacen("9c4a", "9c-4a", 1),
        ] {
            assert!(validate_registry_id(&invalid).is_err(), "{invalid:?}");
        }
    }

    fn policy() -> ConfigPolicy {
        ConfigPolicy {
            identity: Some("/tinfoil/model-router".to_string()),
            revision: None,
            digest: None,
            now: Instant::UNIX_EPOCH,
            max_age: None,
            future_skew: None,
            registry_ids: None,
        }
    }

    #[test]
    fn pins_have_their_forms() {
        assert!(policy().validate_pins().is_ok());
        let pinned = ConfigPolicy {
            revision: Some("v0.0.155".to_string()),
            digest: Some("ab".repeat(32)),
            registry_ids: Some(vec![PUBLIC_REGISTRY_ID.to_string()]),
            ..policy()
        };
        assert!(pinned.validate_pins().is_ok());
        // An empty pin pins nothing.
        let unset = ConfigPolicy {
            identity: Some(String::new()),
            revision: Some(String::new()),
            digest: Some(String::new()),
            ..policy()
        };
        assert!(unset.validate_pins().is_ok());
        for (name, invalid) in [
            (
                "identity",
                ConfigPolicy {
                    identity: Some("/tinfoil".to_string()),
                    ..pinned.clone()
                },
            ),
            (
                "revision",
                ConfigPolicy {
                    revision: Some("../v1".to_string()),
                    ..pinned.clone()
                },
            ),
            (
                "digest",
                ConfigPolicy {
                    digest: Some("AB".repeat(32)),
                    ..pinned.clone()
                },
            ),
            (
                "no registries",
                ConfigPolicy {
                    registry_ids: Some(Vec::new()),
                    ..pinned.clone()
                },
            ),
            (
                "a registry that is not one",
                ConfigPolicy {
                    registry_ids: Some(vec!["https://example.com".to_string()]),
                    ..pinned.clone()
                },
            ),
            (
                "a repeated registry",
                ConfigPolicy {
                    registry_ids: Some(vec![PUBLIC_REGISTRY_ID.to_string(); 2]),
                    ..pinned.clone()
                },
            ),
        ] {
            assert!(invalid.validate_pins().is_err(), "{name}");
        }
    }

    #[test]
    fn a_config_timestamp_covers_the_canonical_statement_without_its_timestamp() {
        let statement = ConfigStatement::from_payload(STATEMENT_V1.as_bytes()).unwrap();
        assert_eq!(statement.timestamp, [1, 2, 3]);
        let core = concat!(
            r#"{"_type":"https://in-toto.io/Statement/v1","predicate":{},"#,
            r#""predicateType":"https://tinfoil.sh/predicate/config-endorsement/v1","#,
            r#""subject":[{"digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"name":"/tinfoil/model-router/v0.0.155"}]}"#
        );
        let expected = [b"tinfoil-config-freshness/v1\0".as_slice(), core.as_bytes()].concat();
        assert_eq!(statement.timestamp_input().unwrap(), expected);
        // The timestamp itself is not part of what it covers.
        let renewed = ConfigStatement {
            timestamp: b"another response".to_vec(),
            ..statement.clone()
        };
        assert_eq!(renewed.timestamp_input().unwrap(), expected);

        let deployment = ConfigStatement {
            predicate: ConfigPredicate::V2 {
                registry_id: PUBLIC_REGISTRY_ID.to_string(),
                runtime: RuntimeReference {
                    repo: RUNTIME_REPO.to_string(),
                    tag: "v0.15.0".to_string(),
                    digest: "ab".repeat(32),
                },
            },
            ..statement
        };
        let input = deployment.timestamp_input().unwrap();
        let text = String::from_utf8(input).unwrap();
        assert!(text.starts_with("tinfoil-config-freshness/v2\0{"));
        assert!(text.contains(concat!(
            r#""predicate":{"runtime":{"digest":"abababababababababababababababababababababababababababababababab","#,
            r#""repo":"tinfoilsh/cvmimage","tag":"v0.15.0"},"scope":"https://registry.tinfoil.sh/scopes/public"},"#,
            r#""predicateType":"https://tinfoil.sh/predicate/config-endorsement/v2""#
        )));
    }

    #[test]
    fn an_artifact_timestamp_covers_every_field_of_the_artifact() {
        let statement = ArtifactStatement::from_payload(ARTIFACT_STATEMENT.as_bytes()).unwrap();
        let core = concat!(
            r#"{"_type":"https://in-toto.io/Statement/v1","#,
            r#""predicate":{"kind":"runtime","repo":"tinfoilsh/cvmimage","tag":"v1.2.3"},"#,
            r#""predicateType":"https://tinfoil.sh/predicate/artifact-freshness/v1","#,
            r#""subject":[{"digest":{"sha256":"abababababababababababababababababababababababababababababababab"},"name":"tinfoil-inference-v1.2.3-manifest.json"}]}"#
        );
        let expected = [
            b"tinfoil-artifact-freshness/v1\0".as_slice(),
            core.as_bytes(),
        ]
        .concat();
        assert_eq!(statement.timestamp_input().unwrap(), expected);

        for tag in ["v1.2", "1.2.3", "v1.2.3/other", "v1.2.3+build"] {
            let artifact = Artifact {
                tag: tag.to_string(),
                name: manifest_name(tag),
                ..statement.artifact.clone()
            };
            assert!(artifact.validate().is_err(), "{tag}");
        }
    }

    #[test]
    fn an_approval_statement_is_an_in_toto_v1_statement() {
        const TYPE: &str = r#""_type":"https://in-toto.io/Statement/v1""#;
        for (payload, absent) in [
            (STATEMENT_V1, r#""predicateType""#),
            (ARTIFACT_STATEMENT, r#""predicateType""#),
        ] {
            let config = payload == STATEMENT_V1;
            let decodes = |payload: &str| {
                if config {
                    ConfigStatement::from_payload(payload.as_bytes()).is_ok()
                } else {
                    ArtifactStatement::from_payload(payload.as_bytes()).is_ok()
                }
            };
            assert!(decodes(payload));
            for other in [
                r#""_type":"https://in-toto.io/Statement/v0.1""#,
                r#""_type":"""#,
                r#""_type":null"#,
            ] {
                assert!(!decodes(&payload.replacen(TYPE, other, 1)), "{other}");
            }
            // Without the member at all.
            let without = payload.replacen(&format!("{TYPE},"), "", 1);
            assert!(without.contains(absent) && !without.contains("_type"));
            assert!(!decodes(&without));
        }
    }

    #[test]
    fn an_approval_statement_is_bounded_in_size() {
        for payload in [STATEMENT_V1, ARTIFACT_STATEMENT] {
            let padded = |size: usize| {
                let mut padded = payload.as_bytes().to_vec();
                padded.resize(size, b' ');
                padded
            };
            let decodes = |payload: &[u8]| {
                if payload.starts_with(STATEMENT_V1.as_bytes()) {
                    ConfigStatement::from_payload(payload).map(|_| ())
                } else {
                    ArtifactStatement::from_payload(payload).map(|_| ())
                }
            };
            assert!(decodes(&padded(MAX_STATEMENT_SIZE)).is_ok());
            let error = decodes(&padded(MAX_STATEMENT_SIZE + 1)).unwrap_err();
            assert!(error.to_string().contains("statement size"), "{error}");
        }
        assert!(ConfigStatement::from_payload(b"").is_err());
        assert!(ArtifactStatement::from_payload(b"").is_err());
    }

    #[test]
    fn an_approval_statement_is_decoded_strictly() {
        let rejected = |payload: String| {
            assert!(
                ConfigStatement::from_payload(payload.as_bytes()).is_err(),
                "{payload}"
            );
        };
        rejected(STATEMENT_V1.replacen(r#""predicate":"#, r#""predicate":{},"predicate":"#, 1));
        rejected(STATEMENT_V1.replacen(
            r#""predicate":{"#,
            r#""predicate":{"issuedAt":"2026-01-01","#,
            1,
        ));
        rejected(STATEMENT_V1.replacen(r#""freshness":"#, r#""Freshness":"#, 1));
        rejected(format!("{STATEMENT_V1}{{}}"));
        rejected(STATEMENT_V1.replacen(r#"{"freshness":{"rfc3161Timestamp":"AQID"}}"#, "{}", 1));
        rejected(STATEMENT_V1.replacen("AQID", "AQJ=", 1));
        let mut invalid_utf8 = STATEMENT_V1.as_bytes().to_vec();
        let at = STATEMENT_V1.find("model-router").unwrap();
        invalid_utf8[at] = 0xff;
        assert!(ConfigStatement::from_payload(&invalid_utf8).is_err());
    }
}
