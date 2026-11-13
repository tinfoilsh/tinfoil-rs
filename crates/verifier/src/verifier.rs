//! The verifier: one appraisal of an attestation document against a fixed
//! policy.

use std::error::Error as StdError;
use std::fmt;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::canonical;
use crate::document::collateral::{
    self, ARTIFACT_FRESHNESS_V1_FORMAT, FORMAT_V2, FORMAT_V3, FRESHNESS_ID_CODE,
    FRESHNESS_ID_PLATFORM, FRESHNESS_ID_RUNTIME, SIGSTORE_FRESHNESS_V1_FORMAT,
};
use crate::document::{self, Document};
use crate::embedded::Embedded;
use crate::endorsement::approval::{
    Artifact as ApprovedArtifact, ArtifactKind, ConfigPolicy, ConfigVerifier, FreshnessPolicy,
    FreshnessVerifier, PLATFORM_ARTIFACT_NAME, PUBLIC_REGISTRY_ID, parse_name,
};
use crate::endorsement::{
    self, AuthenticatedArtifact, EndorsementError, ProvenanceClient, Reference,
};
use crate::error::{BoxError, Error, Layer, UsageError, VerificationError};
use crate::instant::Instant;
use crate::measurement::{Expected, Register};
use crate::options::{ConfigAuthorizer, ConfigEndorsement, VerifierBuilder};
use crate::policy::{self, ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, Shape};
use crate::quote::{
    self, ConfigReferenceValues, LegacyReferenceValues, ReferenceValues, VendorRoots,
};
use crate::runtime::{
    MAX_CONFIG_SIZE, Measurements, RuntimeReference, parse_manifest, runtime_from_config,
};
use crate::verification::{
    ArtifactVerification, ConfigVerification, ReferenceSource, SoftwareIdentity, Verification,
    VerificationMetadata,
};

/// The name that a verification records for this SDK.
const VERIFIER_NAME: &str = "tinfoil-rs";
/// The version that a verification records for this SDK.
const VERIFIER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;

/// The verifiers of the configured trust.
#[derive(Debug, Clone)]
pub(crate) struct Trust {
    /// Authenticates reference values against the Sigstore trusted root.
    pub(crate) endorsements: ProvenanceClient,
    /// Verifies config endorsements.
    pub(crate) config_verifier: ConfigVerifier,
    /// Verifies artifact freshness approvals.
    pub(crate) freshness_verifier: FreshnessVerifier,
}

/// Appraises attestation documents against a fixed policy.
///
/// A verifier is immutable once built and can be shared between threads.
/// Verification performs no I/O: the document arrives as an argument, and
/// every trust anchor is embedded in the crate or carried by the document
/// itself. The verifier holds no cache, so it never decides that an earlier
/// answer is still good enough; that judgement belongs to whatever fetches
/// documents.
///
/// It does read the clock. [`verify_v3`](Self::verify_v3) samples it once
/// and judges everything that is bound to time against that instant: the
/// freshness witnesses and approvals, and the validity of the vendor
/// certificates and revocation lists of the CPU evidence.
/// [`verify_v3_at`](Self::verify_v3_at) takes the instant from the caller
/// instead. So the same document is accepted today and rejected once its
/// witnesses go stale.
pub struct Verifier {
    pub(crate) embedded: Embedded,
    pub(crate) pinned_registers: Option<Expected>,
    pub(crate) freshness_max_age: Duration,
    pub(crate) config_authorizer: Option<ConfigAuthorizer>,
    /// Whether the caller replaced the config signing keys.
    pub(crate) config_keys_pinned: bool,
    /// Whether the caller replaced the freshness signing keys.
    pub(crate) freshness_keys_pinned: bool,
    pub(crate) config_registry_ids: Option<Vec<String>>,
    /// The verifiers, or why the trust material embedded in the crate
    /// could not be loaded.
    pub(crate) trust: Result<Trust, String>,
    /// The vendor anchors of CPU evidence. Only a conformance build can
    /// hold anything but the embedded ones.
    pub(crate) vendor_roots: VendorRoots,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("pinned_registers", &self.pinned_registers)
            .field("freshness_max_age", &self.freshness_max_age)
            .field("config_authorizer", &self.config_authorizer.is_some())
            .field("config_keys_pinned", &self.config_keys_pinned)
            .field("freshness_keys_pinned", &self.freshness_keys_pinned)
            .field("config_registry_ids", &self.config_registry_ids)
            .field("embedded", &self.embedded)
            .finish_non_exhaustive()
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Why the reference values of a document were not accepted.
#[derive(Debug)]
enum Refused {
    /// The caller's mistake.
    Usage(UsageError),
    /// The caller's config authorizer refused the config.
    Authorizer(BoxError),
    /// The reference values do not authenticate.
    Rejected(EndorsementError),
}

impl<E: Into<EndorsementError>> From<E> for Refused {
    fn from(cause: E) -> Self {
        Refused::Rejected(cause.into())
    }
}

impl Refused {
    fn usage(cause: impl Into<BoxError>) -> Self {
        Refused::Usage(UsageError::new(cause))
    }

    fn rejected(message: impl Into<String>) -> Self {
        Refused::Rejected(EndorsementError::new(message))
    }
}

/// A config authorizer's refusal, as the cause of a verification error.
#[derive(Debug)]
struct AuthorizerRefusal(BoxError);

impl fmt::Display for AuthorizerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authorizing config: {}", self.0)
    }
}

impl StdError for AuthorizerRefusal {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}

/// The pins that a repository reference sets on a config endorsement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Pins {
    pub(crate) identity: Option<String>,
    pub(crate) revision: Option<String>,
    pub(crate) digest: Option<String>,
    pub(crate) registry_ids: Option<Vec<String>>,
}

/// Reference values in the form that policy assembly takes.
#[derive(Debug)]
enum References {
    /// A code release and the platform policy artifact.
    Legacy {
        endorsements: policy::Artifact,
        sev_snp_launch: Register,
        tdx_rtmr1: Register,
        tdx_rtmr2: Register,
        shape: Shape,
    },
    /// A config, its runtime and the platform policy artifact.
    Config {
        endorsements: policy::Artifact,
        runtime: Measurements,
        hash: [u8; SHA256_SIZE],
    },
}

impl References {
    fn values(&self) -> ReferenceValues<'_> {
        match self {
            References::Legacy {
                endorsements,
                sev_snp_launch,
                tdx_rtmr1,
                tdx_rtmr2,
                shape,
            } => ReferenceValues::Legacy(LegacyReferenceValues {
                endorsements,
                sev_snp_launch: *sev_snp_launch,
                tdx_rtmr1: *tdx_rtmr1,
                tdx_rtmr2: *tdx_rtmr2,
                shape,
            }),
            References::Config {
                endorsements,
                runtime,
                hash,
            } => ReferenceValues::Config(ConfigReferenceValues {
                endorsements,
                runtime,
                hash: *hash,
            }),
        }
    }
}

/// The identity of the code or runtime that a verification selected.
#[derive(Debug)]
struct Selected {
    repo: String,
    tag: String,
    digest: String,
}

/// What the provenance layer establishes.
#[derive(Debug)]
struct Endorsed {
    references: References,
    selected: Selected,
    config: Option<ConfigVerification>,
    runtime: Option<ArtifactVerification>,
    platform: Option<ArtifactVerification>,
    freshness_expires_at: Option<Instant>,
}

/// An accepted artifact with the time of its approval, when it has one.
#[derive(Debug)]
struct Accepted {
    record: ArtifactVerification,
    approved_at: Option<Instant>,
}

/// The system time of an authenticated instant.
fn system_time(instant: Instant) -> Result<SystemTime, EndorsementError> {
    instant
        .to_system_time()
        .ok_or_else(|| EndorsementError::new("authenticated time is out of range"))
}

/// The record of an artifact that an endorsement vouches for.
fn endorsed_artifact(
    artifact: AuthenticatedArtifact,
    approved_at: Option<Instant>,
) -> Result<Accepted, EndorsementError> {
    Ok(Accepted {
        record: ArtifactVerification {
            source: ReferenceSource::Endorsement,
            repo: Some(artifact.repo),
            tag: Some(artifact.tag),
            digest: artifact.digest,
            name: Some(artifact.subject_name),
            commit: Some(artifact.commit),
            approval_time: approved_at.map(system_time).transpose()?,
        },
        approved_at,
    })
}

/// When the freshness proofs stop vouching for a document: `max_age` after
/// the earliest of the authenticated times. `None` when there is no such
/// time. The deadline rests on authenticated times only, never on the
/// local appraisal time.
pub(crate) fn freshness_expiration(
    max_age: Duration,
    times: &[Option<Instant>],
) -> Result<Option<Instant>, EndorsementError> {
    let Some(earliest) = times.iter().flatten().min() else {
        return Ok(None);
    };
    earliest
        .checked_add(max_age)
        .map(Some)
        .ok_or_else(|| EndorsementError::new("freshness deadline is out of range"))
}

/// Validates `owner/name[@tag][@sha256:digest]` and returns its parts.
///
/// # Errors
///
/// [`Error::Usage`] when `reference` does not have that form.
pub fn parse_reference(reference: &str) -> Result<Reference, Error> {
    endorsement::parse_reference(reference).map_err(|cause| UsageError::new(cause).into())
}

/// The caller's repository pin as the reference text that verification
/// matches, where the empty text is the absence of a pin. A pin that is
/// itself empty is refused, so that only `None` sets no pin.
fn pin_reference(repo: Option<&str>) -> Result<&str, UsageError> {
    match repo {
        None => Ok(""),
        Some("") => Err(UsageError::new(
            "repository pin is empty; pass None to set no pin",
        )),
        Some(reference) => Ok(reference),
    }
}

impl Verifier {
    /// A verifier with the defaults: the trust anchors embedded in the
    /// crate, Tinfoil's public config and artifact signing keys, and a
    /// freshness bound of seven days.
    ///
    /// This cannot fail: the only thing that could is loading the trust
    /// material that is compiled into the crate, which the crate's tests
    /// prove to load. Were it ever not to, every verification would return
    /// a usage error that says so.
    pub fn new() -> Self {
        VerifierBuilder::build_default()
    }

    /// A builder that starts from the defaults.
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    /// The configured bound on the age of a freshness witness or approval.
    pub fn freshness_max_age(&self) -> Duration {
        self.freshness_max_age
    }

    /// Whether the caller supplies the config, with an embedded config, or
    /// authorizes it, with a config authorizer, in place of a repository
    /// pin that authenticates it.
    pub fn caller_authorizes_config(&self) -> bool {
        self.embedded.config.is_some() || self.config_authorizer.is_some()
    }

    /// The configured register pins, if any.
    pub fn pinned_registers(&self) -> Option<&Expected> {
        self.pinned_registers.as_ref()
    }

    /// Reports whether this verifier can verify an enclave against the
    /// repository pin `repo`, without a document or any I/O, so that a
    /// caller can refuse a pin before it fetches a document.
    ///
    /// Without a pin, `None`, the verifier accepts the configs that the
    /// configured registry trust authorizes, or the config that the caller
    /// embeds or authorizes. [`verify_v3`](Self::verify_v3) rejects every
    /// `repo` that this method rejects, whatever the document. It can
    /// still reject one that passes here: v3 collateral also requires the
    /// repository and the revision to be valid parts of a config identity,
    /// such as lowercase slugs, and v2 collateral does not, so that check
    /// waits for the document.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] when:
    ///
    /// - `repo` is a pin that is not an
    ///   `org/project[@revision][@sha256:digest]` reference; the empty
    ///   string is not one, and `None` is how a caller sets no pin;
    /// - `repo` is a pin and the verifier has a config authorizer, which
    ///   cannot authenticate a repository pin;
    /// - the verifier has an embedded config whose name or digest `repo`
    ///   does not match.
    pub fn check_repo_verifiability(&self, repo: Option<&str>) -> Result<(), Error> {
        let reference = pin_reference(repo)?;
        self.reference_pins(reference)
            .map(|_| ())
            .map_err(Error::Usage)
    }

    /// Appraises a nonce-bound v3 attestation document at the current
    /// time, which is read from the system clock once.
    ///
    /// `nonce` is the challenge that the caller generated, and `repo` pins
    /// the expected repository or registry project as
    /// `org/project[@revision][@sha256:digest]`. Without a pin, `None`,
    /// the verifier accepts what the configured registry trust authorizes;
    /// an embedded config authorizes its exact bytes instead; a config
    /// authorizer requires `None` and owns the authorization of the config.
    /// The empty string is not a pin: `Some("")` is an error.
    ///
    /// On success the caller must bind its traffic to the returned keys
    /// and enforce
    /// [`freshness_expires_at`](Verification::freshness_expires_at) when
    /// it is set. Hardware collateral bounds the result even when every
    /// reference is embedded.
    ///
    /// The verifier puts no bound on the size of `doc`, and parsing takes
    /// memory in proportion to it. The caller bounds the document where it
    /// reads it, before it calls the verifier.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] for a `repo` of `Some("")`, a nonce of the wrong length,
    /// a `repo` that this verifier cannot verify against, or a clock outside the years
    /// 0000 to 9999; [`Error::Verification`], with the layer that rejected
    /// it, for a document that must not be trusted.
    pub fn verify_v3(
        &self,
        doc: &[u8],
        nonce: &[u8],
        repo: Option<&str>,
    ) -> Result<Verification, Error> {
        // The only clock read.
        self.verify_v3_at(doc, nonce, repo, SystemTime::now())
    }

    /// [`verify_v3`](Self::verify_v3) for an archived document:
    /// `verification_time` replaces the current time in every check that is
    /// bound to time, and the verification's metadata reports it.
    ///
    /// The caller must authenticate `verification_time` independently, for
    /// example from a trusted timestamp recorded when the document was
    /// received. An earlier time accepts collateral that has since expired
    /// or been revoked, so live clients use [`verify_v3`](Self::verify_v3).
    ///
    /// # Errors
    ///
    /// As [`verify_v3`](Self::verify_v3).
    pub fn verify_v3_at(
        &self,
        doc: &[u8],
        nonce: &[u8],
        repo: Option<&str>,
        verification_time: SystemTime,
    ) -> Result<Verification, Error> {
        let reference = pin_reference(repo)?;
        let now = Instant::from_system_time(verification_time)
            .ok_or_else(|| UsageError::new("verification time is out of range"))?;
        self.verify_at(doc, nonce, reference, now)
    }

    /// Verifies a document at an instant of the verifier's own time type,
    /// which keeps nanoseconds on every platform. An empty `repo` is the
    /// absence of a pin.
    pub(crate) fn verify_at(
        &self,
        doc: &[u8],
        nonce: &[u8],
        repo: &str,
        now: Instant,
    ) -> Result<Verification, Error> {
        let trust = self.trust.as_ref().map_err(|cause| {
            UsageError::new(format!("embedded trust material is unusable: {cause}"))
        })?;
        let verified_at = now
            .to_system_time()
            .ok_or_else(|| UsageError::new("verification time is out of range"))?;
        let rejected_at =
            |layer: Layer| move |cause: BoxError| Error::from(VerificationError::new(layer, cause));

        let document = document::parse(doc, nonce).map_err(|cause| {
            if cause.is_invalid_input() {
                Error::from(UsageError::new(cause))
            } else {
                rejected_at(Layer::Envelope)(cause.into())
            }
        })?;

        // Reference values and CPU evidence are appraised at one instant.
        let format = document.collateral_format();
        let endorsed = if format == FORMAT_V3 {
            self.config_references(trust, &document, repo, now)
        } else if format == FORMAT_V2 {
            self.code_references(trust, &document, repo, now)
        } else {
            Err(Refused::rejected(format!(
                "unsupported collateral format {format:?}"
            )))
        };
        let endorsed = endorsed.map_err(|refused| match refused {
            Refused::Usage(usage) => Error::Usage(usage),
            Refused::Authorizer(cause) => {
                rejected_at(Layer::Provenance)(AuthorizerRefusal(cause).into())
            }
            Refused::Rejected(cause) => rejected_at(Layer::Provenance)(cause.into()),
        })?;

        let authenticated = quote::authenticate(
            document.cpu_evidence(),
            document.cpu_endorsements(),
            now,
            &self.vendor_roots,
        )
        .map_err(|cause| rejected_at(Layer::Quote)(cause.into()))?;
        let assembled = quote::assemble(
            &document,
            &endorsed.references.values(),
            self.pinned_registers.as_ref(),
            &authenticated,
        )
        .map_err(|cause| rejected_at(Layer::Policy)(cause.into()))?;
        assembled
            .validate()
            .map_err(|cause| rejected_at(Layer::Policy)(cause.into()))?;

        let expires_at = authenticated.expires_at();
        let freshness_expires_at = Some(
            system_time(
                endorsed
                    .freshness_expires_at
                    .map_or(expires_at, |at| at.min(expires_at)),
            )
            .map_err(|cause| rejected_at(Layer::Quote)(cause.into()))?,
        );
        Ok(Verification {
            config_repo: endorsed.selected.repo,
            code_digest: endorsed.selected.digest,
            code_tag: endorsed.selected.tag,
            code_measurement: assembled.code_measurement().clone(),
            config: endorsed.config,
            runtime: endorsed.runtime,
            platform: endorsed.platform,
            enclave_measurement: authenticated.measurement(),
            crypto_material: document.crypto_material_items().to_vec(),
            freshness_expires_at,
            metadata: VerificationMetadata {
                verifier: SoftwareIdentity {
                    name: VERIFIER_NAME.to_owned(),
                    version: VERIFIER_VERSION.to_owned(),
                },
                verified_at,
            },
        })
    }

    /// Whether the configured trust can only be applied to v3 collateral.
    fn requires_config_collateral(&self) -> bool {
        self.embedded.config.is_some()
            || self.embedded.runtime.is_some()
            || self.embedded.platform.is_some()
            || self.config_keys_pinned
            || self.freshness_keys_pinned
            || self.config_authorizer.is_some()
            || self.config_registry_ids.is_some()
    }

    /// The reference values of a document with v2 collateral: a code
    /// release and the platform policy artifact, each with its freshness
    /// witness.
    fn code_references(
        &self,
        trust: &Trust,
        document: &Document,
        repo: &str,
        now: Instant,
    ) -> Result<Endorsed, Refused> {
        if self.requires_config_collateral() {
            return Err(Refused::rejected(format!(
                "configured trust requires {FORMAT_V3}"
            )));
        }
        let code_ref = document.sigstore_code()?;
        let pin = endorsement::parse_reference(repo).map_err(Refused::usage)?;
        let code = trust.endorsements.authenticate_code(
            &code_ref.bundle,
            &pin,
            &code_ref.tag,
            &code_ref.digest,
        )?;
        let platform_ref = document.sigstore_platform()?;
        let platform = trust
            .endorsements
            .authenticate_platform_endorsements(
                &platform_ref.bundle,
                &platform_ref.repo,
                &platform_ref.tag,
                &platform_ref.digest,
                ARTIFACT_FORMAT,
            )
            .map_err(|cause| cause.within("verifying platform endorsements"))?;
        let code_witnessed_at = self
            .authenticate_freshness(trust, document, FRESHNESS_ID_CODE, &code.artifact, now)
            .map_err(|cause| cause.within("verifying code freshness"))?;
        let platform_witnessed_at = self
            .authenticate_freshness(
                trust,
                document,
                FRESHNESS_ID_PLATFORM,
                &platform.artifact,
                now,
            )
            .map_err(|cause| cause.within("verifying platform freshness"))?;
        let freshness_expires_at = freshness_expiration(
            self.freshness_max_age,
            &[Some(code_witnessed_at), Some(platform_witnessed_at)],
        )?;
        Ok(Endorsed {
            references: References::Legacy {
                endorsements: platform.policy,
                sev_snp_launch: code.sev_snp_launch,
                tdx_rtmr1: code.tdx_rtmr1,
                tdx_rtmr2: code.tdx_rtmr2,
                shape: code.shape,
            },
            selected: Selected {
                repo: code.artifact.repo,
                tag: code.artifact.tag,
                digest: code.artifact.digest,
            },
            config: None,
            runtime: None,
            platform: None,
            freshness_expires_at,
        })
    }

    /// Authenticates the freshness witness `id` of a document with v2
    /// collateral for `artifact`, and returns when it was witnessed.
    fn authenticate_freshness(
        &self,
        trust: &Trust,
        document: &Document,
        id: &str,
        artifact: &AuthenticatedArtifact,
        now: Instant,
    ) -> Result<Instant, EndorsementError> {
        let freshness = document.freshness(id)?;
        if freshness.format != SIGSTORE_FRESHNESS_V1_FORMAT {
            return Err(EndorsementError::new(format!(
                "legacy verification requires freshness collateral format {SIGSTORE_FRESHNESS_V1_FORMAT:?}"
            )));
        }
        trust.endorsements.authenticate_freshness(
            &freshness.bundle,
            artifact,
            now,
            Some(self.freshness_max_age),
        )
    }

    /// The pins that `reference` sets under this verifier's policy, where
    /// an empty `reference` is the absence of a pin, or a
    /// usage error if verification rejects `reference` whatever the
    /// document. Every check of that kind belongs here, so that
    /// [`check_repo_verifiability`](Self::check_repo_verifiability) makes
    /// it too.
    pub(crate) fn reference_pins(&self, reference: &str) -> Result<Pins, UsageError> {
        let mut pins = Pins {
            registry_ids: self.config_registry_ids.clone(),
            ..Pins::default()
        };
        if pins.registry_ids.is_none() && !self.config_keys_pinned {
            pins.registry_ids = Some(vec![PUBLIC_REGISTRY_ID.to_owned()]);
        }
        if self.config_authorizer.is_some() && !reference.is_empty() {
            return Err(UsageError::new(
                "config authorizer cannot authenticate repository or revision pins; enforce them in caller policy",
            ));
        }
        if !reference.is_empty() {
            let parsed = endorsement::parse_reference(reference).map_err(UsageError::new)?;
            pins.identity = Some(format!("/{}", parsed.repo));
            pins.revision = parsed.tag;
            pins.digest = parsed.digest;
        }
        if let Some(embedded) = &self.embedded.config {
            let (identity, revision) = match &embedded.name {
                Some(name) => parse_name(name).map_err(UsageError::new)?,
                None => ("", ""),
            };
            let differs =
                |pin: &Option<String>, value: &str| pin.as_deref().is_some_and(|pin| pin != value);
            if differs(&pins.identity, identity)
                || differs(&pins.revision, revision)
                || differs(&pins.digest, &embedded.digest)
            {
                return Err(UsageError::new(
                    "embedded config does not match the caller's pins",
                ));
            }
        }
        Ok(pins)
    }

    /// The reference values of a document with v3 collateral: a config,
    /// the runtime that it pins and the platform policy artifact, each
    /// endorsed and approved or supplied by the caller.
    fn config_references(
        &self,
        trust: &Trust,
        document: &Document,
        reference: &str,
        now: Instant,
    ) -> Result<Endorsed, Refused> {
        let pins = self.reference_pins(reference).map_err(Refused::Usage)?;
        let policy = ConfigPolicy {
            identity: pins.identity,
            revision: pins.revision,
            digest: pins.digest,
            now,
            max_age: Some(self.freshness_max_age),
            future_skew: None,
            registry_ids: pins.registry_ids,
        };
        // Config identities and revisions are stricter than the repository
        // references that v2 collateral accepts, so only v3 collateral
        // checks them.
        if policy.identity.is_some() {
            policy.validate_pins().map_err(Refused::usage)?;
        }
        let (expected_runtime, config, config_approved_at) =
            self.resolve_config(trust, document, &policy)?;
        let digest = canonical::decode_lower_hex("config digest", &config.digest, SHA256_SIZE)?;
        let hash: [u8; SHA256_SIZE] = digest
            .try_into()
            .map_err(|_| Refused::rejected("config digest is not a SHA-256"))?;
        let (measurements, runtime) =
            self.resolve_runtime(trust, document, &expected_runtime, now)?;
        let (endorsements, platform) = self.resolve_platform(trust, document, now)?;
        let freshness_expires_at = freshness_expiration(
            self.freshness_max_age,
            &[
                config_approved_at,
                platform.approved_at,
                runtime.approved_at,
            ],
        )?;
        let selected = Selected {
            repo: runtime.record.repo.clone().unwrap_or_default(),
            tag: runtime.record.tag.clone().unwrap_or_default(),
            digest: runtime.record.digest.clone(),
        };
        Ok(Endorsed {
            references: References::Config {
                endorsements,
                runtime: measurements,
                hash,
            },
            selected,
            config: Some(config),
            runtime: Some(runtime.record),
            platform: Some(platform.record),
            freshness_expires_at,
        })
    }

    /// Resolves the config of a document: the runtime that it pins, its
    /// record, and the time of its approval when an endorsement vouches
    /// for it.
    fn resolve_config(
        &self,
        trust: &Trust,
        document: &Document,
        policy: &ConfigPolicy,
    ) -> Result<(RuntimeReference, ConfigVerification, Option<Instant>), Refused> {
        if let Some(embedded) = &self.embedded.config {
            // The pins were matched against it when they were derived.
            let record = ConfigVerification {
                source: ReferenceSource::Embedded,
                name: embedded.name.clone(),
                digest: embedded.digest.clone(),
                reference: None,
                signing_key_hint: None,
                approval_time: None,
                registry_id: None,
                signature_time: None,
            };
            return Ok((embedded.runtime.clone(), record, None));
        }
        let config = document.config_endorsement()?;
        if let Some(authorize) = &self.config_authorizer {
            let material = ConfigEndorsement::from_collateral(config)
                .filter(|material| material.config().len() <= MAX_CONFIG_SIZE)
                .ok_or_else(|| Refused::rejected("config size is outside allowed bounds"))?;
            authorize(&material).map_err(Refused::Authorizer)?;
            let bytes = material.config();
            let expected = runtime_from_config(bytes)?;
            let record = ConfigVerification {
                source: ReferenceSource::Policy,
                name: None,
                digest: canonical::encode_lower_hex(&Sha256::digest(bytes)),
                reference: None,
                signing_key_hint: None,
                approval_time: None,
                registry_id: None,
                signature_time: None,
            };
            return Ok((expected, record, None));
        }
        let collateral::ConfigEndorsement::Signed {
            reference,
            bundle,
            config: bytes,
            issuer,
        } = config
        else {
            return Err(Refused::rejected(
                "unsigned config requires a config authorizer",
            ));
        };
        let bytes = bytes.as_deref();
        let approved = match issuer {
            Some(issuer) if !self.config_keys_pinned => trust
                .config_verifier
                .verify_certified(bytes, bundle, issuer, policy),
            _ => trust.config_verifier.verify(bytes, bundle, policy),
        }
        .map_err(|cause| cause.within("verifying config approval"))?;
        if *reference != approved.reference {
            return Err(Refused::rejected(
                "config endorsement reference does not match the verified approval",
            ));
        }
        let expected = match approved.runtime {
            Some(runtime) => runtime,
            None => runtime_from_config(bytes.unwrap_or_default())?,
        };
        let record = ConfigVerification {
            source: ReferenceSource::Endorsement,
            name: Some(approved.name),
            digest: approved.digest,
            reference: Some(approved.reference),
            signing_key_hint: Some(approved.signing_key_hint),
            approval_time: Some(system_time(approved.approval_time)?),
            registry_id: approved.registry_id,
            signature_time: approved.signature_time.map(system_time).transpose()?,
        };
        Ok((expected, record, Some(approved.approval_time)))
    }

    /// Resolves the runtime that a config pins: its launch measurements
    /// and its record.
    fn resolve_runtime(
        &self,
        trust: &Trust,
        document: &Document,
        expected: &RuntimeReference,
        now: Instant,
    ) -> Result<(Measurements, Accepted), Refused> {
        if let Some(embedded) = &self.embedded.runtime {
            let manifest = parse_manifest(embedded, expected)?;
            let record = ArtifactVerification {
                source: ReferenceSource::Embedded,
                repo: Some(expected.repo.clone()),
                tag: Some(crate::endorsement::runtime::release_tag(&expected.tag)),
                digest: expected.digest.clone(),
                name: None,
                commit: None,
                approval_time: None,
            };
            return Ok((
                manifest.measurements,
                Accepted {
                    record,
                    approved_at: None,
                },
            ));
        }
        let material = document.runtime()?;
        let authenticated = trust
            .endorsements
            .authenticate_runtime(material, expected)?;
        let approved_at = self
            .authenticate_artifact_freshness(
                trust,
                document,
                FRESHNESS_ID_RUNTIME,
                ArtifactKind::Runtime,
                &authenticated.artifact,
                now,
            )
            .map_err(|cause| cause.within("verifying runtime freshness"))?;
        Ok((
            authenticated.manifest.measurements,
            endorsed_artifact(authenticated.artifact, Some(approved_at))?,
        ))
    }

    /// Resolves the platform policy artifact and its record.
    fn resolve_platform(
        &self,
        trust: &Trust,
        document: &Document,
        now: Instant,
    ) -> Result<(policy::Artifact, Accepted), Refused> {
        if let Some(embedded) = &self.embedded.platform {
            let record = ArtifactVerification {
                source: ReferenceSource::Embedded,
                repo: None,
                tag: None,
                digest: embedded.digest.clone(),
                name: None,
                commit: None,
                approval_time: None,
            };
            return Ok((
                embedded.artifact.clone(),
                Accepted {
                    record,
                    approved_at: None,
                },
            ));
        }
        let material = document.config_platform()?;
        let platform = trust.endorsements.authenticate_platform_endorsements(
            &material.bundle,
            &material.repo,
            &material.tag,
            &material.digest,
            ARTIFACT_FORMAT_V2,
        )?;
        if platform.artifact.subject_name != PLATFORM_ARTIFACT_NAME {
            return Err(Refused::rejected(
                "config verification requires its dedicated platform endorsement artifact",
            ));
        }
        let approved_at = self
            .authenticate_artifact_freshness(
                trust,
                document,
                FRESHNESS_ID_PLATFORM,
                ArtifactKind::Platform,
                &platform.artifact,
                now,
            )
            .map_err(|cause| cause.within("verifying platform freshness"))?;
        Ok((
            platform.policy,
            endorsed_artifact(platform.artifact, Some(approved_at))?,
        ))
    }

    /// Verifies the freshness approval `id` of a document with v3
    /// collateral for `artifact`, and returns the time of the approval.
    fn authenticate_artifact_freshness(
        &self,
        trust: &Trust,
        document: &Document,
        id: &str,
        kind: ArtifactKind,
        artifact: &AuthenticatedArtifact,
        now: Instant,
    ) -> Result<Instant, EndorsementError> {
        let material = document.freshness(id)?;
        if material.format != ARTIFACT_FRESHNESS_V1_FORMAT {
            return Err(EndorsementError::new(
                "config verification requires Tinfoil artifact freshness approvals",
            ));
        }
        let approved = trust.freshness_verifier.verify(
            &material.bundle,
            &FreshnessPolicy {
                artifact: ApprovedArtifact {
                    kind,
                    repo: artifact.repo.clone(),
                    tag: artifact.tag.clone(),
                    name: artifact.subject_name.clone(),
                    digest: artifact.digest.clone(),
                },
                now,
                max_age: Some(self.freshness_max_age),
                future_skew: None,
            },
        )?;
        Ok(approved.approval_time)
    }
}
