//! Approvals: config endorsements and artifact freshness statements.
//!
//! An approval is a DSSE bundle around a statement that carries its own
//! RFC 3161 timestamp. The signature says who approved (a pinned key, or a
//! registry certificate under a pinned root); the transparency log shows
//! that the approval was published; the inner timestamp says when, and is
//! what the age rule is applied to.

use std::sync::Arc;
use std::time::Duration;

use super::EndorsementError;
use super::provenance::ProvenanceClient;
use crate::document::collateral::RuntimeReference;
use crate::instant::Instant;
use crate::json::Value;
use crate::sigstore::bundle::Bundle;
use crate::sigstore::timestamp::AppraisalWindow;
use crate::sigstore::trusted_root::TrustedRoot;
use crate::stub::pending;
use crate::x509::{Certificate, PublicKey};

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
    pending("endorsement::approval::validate_registry_id")
}

/// Checks that `identity` is a config identity: `/org/project`, where each
/// part is at most 63 characters of lowercase letters and digits in groups
/// separated by single hyphens.
pub fn validate_identity(identity: &str) -> Result<(), EndorsementError> {
    pending("endorsement::approval::validate_identity")
}

/// Checks that `revision` is a config revision: at most 128 characters,
/// starting with an ASCII letter or digit and continuing with letters,
/// digits, `.`, `_` and `-`.
pub fn validate_revision(revision: &str) -> Result<(), EndorsementError> {
    pending("endorsement::approval::validate_revision")
}

/// Splits a versioned config name, `/org/project/revision`, at its last
/// `/` into the identity and the revision, and checks both. A name with a
/// NUL character is an error.
pub fn parse_name(name: &str) -> Result<(&str, &str), EndorsementError> {
    pending("endorsement::approval::parse_name")
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
    /// [`MAX_STATEMENT_SIZE`](crate::sigstore::statement::MAX_STATEMENT_SIZE)
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
    ///   [`MAX_TIMESTAMP_SIZE`](crate::sigstore::timestamp::MAX_TIMESTAMP_SIZE)
    ///   bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, EndorsementError> {
        pending("endorsement::approval::ConfigStatement::from_payload")
    }

    /// The bytes that the inner timestamp covers: the domain of the
    /// statement's version, then the canonical JSON of the statement
    /// without its `freshness` member
    /// ([`timestamp_input`](crate::sigstore::statement::timestamp_input)).
    ///
    /// The canonical statement has `_type`, `subject` (one object with
    /// `digest` and `name`), `predicateType` and `predicate`; the predicate
    /// of a v1 statement is an empty object, and that of a v2 statement
    /// has `runtime` and `scope`.
    pub fn timestamp_input(&self) -> Result<Vec<u8>, EndorsementError> {
        pending("endorsement::approval::ConfigStatement::timestamp_input")
    }
}

/// The kind of a released artifact that Tinfoil approves as current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// The platform policy artifact; `platform` in a statement.
    Platform,
    /// A runtime manifest; `runtime` in a statement.
    Runtime,
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
        pending("endorsement::approval::Artifact::validate")
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
    /// [`MAX_STATEMENT_SIZE`](crate::sigstore::statement::MAX_STATEMENT_SIZE)
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
    ///   [`MAX_TIMESTAMP_SIZE`](crate::sigstore::timestamp::MAX_TIMESTAMP_SIZE)
    ///   bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, EndorsementError> {
        pending("endorsement::approval::ArtifactStatement::from_payload")
    }

    /// The bytes that the inner timestamp covers:
    /// [`ARTIFACT_FRESHNESS_DOMAIN`], then the canonical JSON of the
    /// statement without its `freshness` member.
    pub fn timestamp_input(&self) -> Result<Vec<u8>, EndorsementError> {
        pending("endorsement::approval::ArtifactStatement::timestamp_input")
    }
}

/// Decodes an approval bundle from a document's collateral: the bundle
/// decodes ([`Bundle::from_value`]) and has the approval layout
/// ([`check_approval_layout`](crate::sigstore::keyed::check_approval_layout)).
pub fn parse_approval_bundle(bundle: &Value) -> Result<Bundle, EndorsementError> {
    pending("endorsement::approval::parse_approval_bundle")
}

/// Decodes an approval bundle from its JSON text: the text has 1 to
/// [`MAX_BUNDLE_SIZE`](crate::sigstore::bundle::MAX_BUNDLE_SIZE) bytes,
/// decodes ([`Bundle::from_json`]) and has the approval layout.
pub fn parse_approval_bundle_json(bundle: &[u8]) -> Result<Bundle, EndorsementError> {
    pending("endorsement::approval::parse_approval_bundle_json")
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
    /// ([`key_hint`](crate::sigstore::statement::key_hint)); two keys have
    /// the same hint.
    pub fn new(root: Arc<TrustedRoot>, keys: &[PublicKey]) -> Result<Self, EndorsementError> {
        pending("endorsement::approval::ApprovalVerifier::new")
    }

    /// Verifies an approval bundle and returns the hint of the pinned key
    /// that signed it.
    ///
    /// The bundle has passed [`parse_approval_bundle`]. In order: the
    /// bundle names a key by hint, and the hint is that of a pinned key;
    /// the bundle verifies under that key for `digest`
    /// ([`verify_keyed_bundle`](crate::sigstore::keyed::verify_keyed_bundle)).
    pub fn verify(&self, bundle: &Bundle, digest: &[u8; 32]) -> Result<String, EndorsementError> {
        pending("endorsement::approval::ApprovalVerifier::verify")
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
/// [`MAX_STATEMENT_SIZE`](crate::sigstore::statement::MAX_STATEMENT_SIZE)
/// bytes; the response is authenticated by a timestamp authority of the
/// trusted root, covers `input`, and was issued under the Sigstore
/// timestamp policy
/// ([`verify_timestamp`](crate::sigstore::timestamp::verify_timestamp) with
/// [`SIGSTORE_TIMESTAMP_POLICY`](crate::sigstore::timestamp::SIGSTORE_TIMESTAMP_POLICY));
/// the time is within `window`.
pub fn verify_approval_timestamp(
    root: &TrustedRoot,
    response: &[u8],
    input: &[u8],
    window: &AppraisalWindow,
) -> Result<Instant, EndorsementError> {
    pending("endorsement::approval::verify_approval_timestamp")
}

/// What a config endorsement must match, and the clock that judges its
/// age.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPolicy {
    /// The config identity (`/org/project`) that the endorsement must
    /// name, when pinned.
    pub identity: Option<String>,
    /// The config revision that the endorsement must name, when pinned.
    pub revision: Option<String>,
    /// The config digest that the endorsement must name, when pinned: 64
    /// lowercase hex digits.
    pub digest: Option<String>,
    /// The appraisal instant.
    pub now: Instant,
    /// The greatest age of the approval; `None` selects the default.
    pub max_age: Option<Duration>,
    /// The allowed clock skew; `None` selects the default.
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
        pending("endorsement::approval::ConfigPolicy::validate_pins")
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
    /// ([`endorsement_reference`](crate::sigstore::statement::endorsement_reference)).
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
        pending("endorsement::approval::ConfigVerifier::new")
    }

    /// A verifier for the registry: `root_keys` sign v1 endorsements of the
    /// public registry directly and are the roots that certify registry
    /// signing certificates. Errors as [`ApprovalVerifier::new`].
    pub fn for_registry(
        root: Arc<TrustedRoot>,
        root_keys: &[PublicKey],
    ) -> Result<Self, EndorsementError> {
        pending("endorsement::approval::ConfigVerifier::for_registry")
    }

    /// Verifies a key-signed config endorsement.
    ///
    /// `config` is the config's bytes when the document carries them. In
    /// order:
    ///
    /// 1. `config`, when given, has 1 to
    ///    [`MAX_CONFIG_SIZE`](crate::runtime::MAX_CONFIG_SIZE) bytes;
    /// 2. the pins are valid ([`ConfigPolicy::validate_pins`]) and the
    ///    appraisal window exists
    ///    ([`approval_window`](super::time::approval_window));
    /// 3. the bundle is an approval bundle ([`parse_approval_bundle`]);
    /// 4. the payload decodes ([`ConfigStatement::from_payload`]);
    /// 5. a pinned identity and a pinned revision equal those of the
    ///    statement's name; a pinned digest equals the statement's;
    /// 6. without `config`, the statement is v2. With `config`, its
    ///    SHA-256 is the statement's digest, and for a v2 statement the
    ///    runtime that the config pins
    ///    ([`runtime_from_config`](crate::runtime::runtime_from_config))
    ///    equals the statement's;
    /// 7. a registry verifier rejects a v2 statement here: a v2 registry
    ///    endorsement needs its issuer certificate
    ///    ([`ConfigVerifier::verify_certified`]);
    /// 8. the bundle verifies under a pinned key for the statement's
    ///    digest ([`ApprovalVerifier::verify`]). The registry is the public
    ///    one for a registry verifier and none otherwise;
    /// 9. with a registry list in the policy, the registry is in it;
    /// 10. the inner timestamp is authenticated over the statement's
    ///     timestamp input and is within the window
    ///     ([`verify_approval_timestamp`]).
    pub fn verify(
        &self,
        config: Option<&[u8]>,
        bundle: &Value,
        policy: &ConfigPolicy,
    ) -> Result<ConfigVerified, EndorsementError> {
        pending("endorsement::approval::ConfigVerifier::verify")
    }

    /// Verifies a config endorsement signed with a registry certificate.
    ///
    /// Only a registry verifier accepts one, and `issuer_der` must not be
    /// empty. Steps 1 to 6 are those of [`ConfigVerifier::verify`]. Then,
    /// in order:
    ///
    /// 7. the statement is v2;
    /// 8. at least one RFC 3161 timestamp over the bundle's signature
    ///    verifies
    ///    ([`verify_signature_timestamps`](crate::sigstore::timestamp::verify_signature_timestamps));
    ///    the first is the signature time, and it is within the window;
    /// 9. the signing certificate has the registry profile at the
    ///    signature time ([`verify_signing_certificate`]);
    /// 10. the certificate's URI is the statement's registry identifier;
    /// 11. the bundle verifies under the certificate for the statement's
    ///     digest
    ///     ([`verify_certified_bundle`](crate::sigstore::certificate::verify_certified_bundle)),
    ///     and the verified identity's name is the registry identifier and
    ///     its issuer claim is empty;
    /// 12. with a registry list in the policy, the registry is in it;
    /// 13. the inner timestamp is authenticated over the statement's
    ///     timestamp input and is within the window;
    /// 14. the inner timestamp is not more than
    ///     [`CERTIFICATE_CLOCK_SKEW`] after the signature time.
    pub fn verify_certified(
        &self,
        config: Option<&[u8]>,
        bundle: &Value,
        issuer_der: &[u8],
        policy: &ConfigPolicy,
    ) -> Result<ConfigVerified, EndorsementError> {
        pending("endorsement::approval::ConfigVerifier::verify_certified")
    }
}

/// Authenticates a registry signing certificate at the instant `at`, and
/// returns it with its issuer. The caller authenticates `at` separately.
///
/// In order:
///
/// 1. both certificates have 1 to
///    [`MAX_CERTIFICATE_SIZE`](crate::x509::MAX_CERTIFICATE_SIZE) bytes and
///    parse;
/// 2. the issuer's key is one of `roots`, compared by key hint, and the
///    issuer's own signature verifies under its key;
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
///    purpose ([`verify_chain`](crate::x509::verify_chain)).
pub fn verify_signing_certificate(
    certificate_der: &[u8],
    issuer_der: &[u8],
    roots: &[PublicKey],
    at: Instant,
) -> Result<(Certificate, Certificate), EndorsementError> {
    pending("endorsement::approval::verify_signing_certificate")
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
        pending("endorsement::approval::FreshnessVerifier::new")
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
        pending("endorsement::approval::FreshnessVerifier::verify")
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
