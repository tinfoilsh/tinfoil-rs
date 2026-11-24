//! The options of a verifier and the types that they take.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::document::collateral;
use crate::embedded::{Embedded, EmbeddedConfig};
use crate::endorsement::approval::ConfigPolicy;
use crate::endorsement::freshness::MAX_FRESHNESS_AGE;
use crate::endorsement::{ProvenanceClient, public_signing_keys};
use crate::error::{BoxError, Error, UsageError};
use crate::instant::Instant;
use crate::json::Value;
use crate::measurement::Expected;
use crate::quote::VendorRoots;
use crate::verification::write_string;
use crate::verifier::{Trust, Verifier};
use crate::x509;

/// The longest freshness bound that a verifier accepts: the longest span
/// that a signed 64-bit count of nanoseconds holds, about 292 years.
const MAX_FRESHNESS_MAX_AGE: Duration = Duration::from_nanos(i64::MAX.unsigned_abs());

/// A public key that the caller trusts to sign config endorsements or
/// artifact freshness approvals.
///
/// Approvals are signed with ECDSA on the NIST P-256 curve; a key of any
/// other kind parses but is refused when the verifier is built.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) x509::PublicKey);

impl PublicKey {
    /// Parses a PEM file that holds exactly one `PUBLIC KEY` block, a
    /// SubjectPublicKeyInfo.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] when the text is not such a file or the key is not
    /// well formed.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        x509::PublicKey::from_pem(pem)
            .map(Self)
            .map_err(|cause| UsageError::new(format!("parsing public key: {cause}")).into())
    }

    /// Parses a DER SubjectPublicKeyInfo.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] when the bytes are not one canonical
    /// SubjectPublicKeyInfo of a supported key.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        x509::PublicKey::from_spki_der(der)
            .map(Self)
            .map_err(|cause| UsageError::new(format!("parsing public key: {cause}")).into())
    }

    /// The DER SubjectPublicKeyInfo of the key.
    pub fn to_spki_der(&self) -> Vec<u8> {
        self.0.spki_der().to_vec()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Config material from a document, handed to a caller's config
/// authorizer. Nothing in it is authenticated: the authorizer decides
/// whether the config bytes are acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEndorsement {
    config: Vec<u8>,
    reference: Option<String>,
    bundle_json: Option<Vec<u8>>,
    issuer_certificate_der: Option<Vec<u8>>,
}

impl ConfigEndorsement {
    /// The material of a document's config collateral; `None` when the
    /// document carries no config bytes.
    pub(crate) fn from_collateral(config: &collateral::ConfigEndorsement) -> Option<Self> {
        Some(Self {
            config: config.config()?.to_vec(),
            reference: config.reference().map(str::to_owned),
            bundle_json: config.bundle().map(to_json_text),
            issuer_certificate_der: config.issuer().map(<[u8]>::to_vec),
        })
    }

    /// The config bytes that the enclave claims to run; never empty.
    pub fn config(&self) -> &[u8] {
        &self.config
    }

    /// The reference of the endorsement that the document offers for the
    /// config, `sha256:` and 64 lowercase hex digits. `None` for a config
    /// without an endorsement.
    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    /// The endorsement bundle that the document offers, as JSON text.
    /// `None` for a config without an endorsement.
    ///
    /// The text is the bundle written compactly, with its members in the
    /// order of the document and every number as the document spells it:
    /// the same JSON value as in the document, not necessarily the same
    /// bytes.
    pub fn bundle_json(&self) -> Option<&[u8]> {
        self.bundle_json.as_deref()
    }

    /// The DER certificate of the registry issuer that the document
    /// offers, when it offers one.
    pub fn issuer_certificate_der(&self) -> Option<&[u8]> {
        self.issuer_certificate_der.as_deref()
    }
}

/// The compact JSON text of a parsed value, with object members in their
/// original order and numbers as they were spelled. It keeps its own stack
/// of work, so that a deeply nested value cannot exhaust the thread's.
fn to_json_text(value: &Value) -> Vec<u8> {
    enum Step<'a> {
        Value(&'a Value),
        Name(&'a str),
        Text(&'static str),
    }
    let mut out = String::new();
    let mut steps = vec![Step::Value(value)];
    while let Some(step) = steps.pop() {
        match step {
            Step::Text(text) => out.push_str(text),
            Step::Name(name) => {
                write_string(name, &mut out);
                out.push(':');
            }
            Step::Value(Value::Null) => out.push_str("null"),
            Step::Value(Value::Bool(true)) => out.push_str("true"),
            Step::Value(Value::Bool(false)) => out.push_str("false"),
            Step::Value(Value::Number(number)) => out.push_str(number.as_str()),
            Step::Value(Value::String(text)) => write_string(text, &mut out),
            Step::Value(Value::Array(items)) => {
                out.push('[');
                steps.push(Step::Text("]"));
                for (index, item) in items.iter().enumerate().rev() {
                    steps.push(Step::Value(item));
                    if index > 0 {
                        steps.push(Step::Text(","));
                    }
                }
            }
            Step::Value(Value::Object(object)) => {
                out.push('{');
                steps.push(Step::Text("}"));
                let members: Vec<(&str, &Value)> = object.iter().collect();
                for (index, (name, member)) in members.into_iter().enumerate().rev() {
                    steps.push(Step::Value(member));
                    steps.push(Step::Name(name));
                    if index > 0 {
                        steps.push(Step::Text(","));
                    }
                }
            }
        }
    }
    out.into_bytes()
}

/// A caller's policy that decides whether the config of a document is
/// authorized, in place of a config endorsement.
///
/// The function receives untrusted material from the document and must
/// return an error for config bytes that it does not authorize. It may be
/// called from several threads at once.
///
/// The runtime pin is read from the bytes that the function authorizes,
/// which must be a JSON config. Any other bytes are rejected, such as the
/// YAML config of a cvm-version before 0.15.5-rc.1.
#[derive(Clone)]
pub struct ConfigAuthorizer(pub(crate) Arc<AuthorizeFn>);

/// The function inside a [`ConfigAuthorizer`].
type AuthorizeFn = dyn Fn(&ConfigEndorsement) -> Result<(), BoxError> + Send + Sync + 'static;

impl ConfigAuthorizer {
    /// An authorizer that calls `authorize` with the config material of
    /// each document.
    pub fn new(
        authorize: impl Fn(&ConfigEndorsement) -> Result<(), BoxError> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(authorize))
    }
}

impl fmt::Debug for ConfigAuthorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigAuthorizer")
    }
}

/// Who vouches for the config that an enclave runs.
///
/// Each variant is one source of trust, so that two sources that would
/// conflict cannot be configured together. Every variant other than
/// [`PublicRegistry`](Self::PublicRegistry), the default, requires
/// documents with `attestation-collaterals/v3` collateral.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum ConfigTrust {
    /// Configs that Tinfoil's public registry endorses, under Tinfoil's
    /// registry root.
    #[default]
    PublicRegistry,
    /// Configs that exactly these registries endorse, under Tinfoil's
    /// registry root, in place of the public registry alone. To keep the
    /// public registry, list [`PUBLIC_REGISTRY_ID`](crate::PUBLIC_REGISTRY_ID)
    /// too.
    ///
    /// An empty list, an identifier that is not a canonical registry URI
    /// and a repeated identifier are usage errors.
    Registries(Vec<String>),
    /// Configs whose endorsements one of these keys signs, in place of
    /// Tinfoil's registry root. This trust path uses no registry and does
    /// not cover artifact freshness.
    ///
    /// An empty list, a repeated key and a key that is not ECDSA P-256 are
    /// usage errors.
    SigningKeys(Vec<PublicKey>),
    /// Configs that the caller's policy authorizes, in place of a config
    /// endorsement. Runtime, platform and hardware checks still apply. An
    /// authorized config has no authenticated registry name or approval
    /// time, so a verifier with this trust accepts no project pin.
    Authorizer(ConfigAuthorizer),
    /// A config that the caller supplies itself, in place of a registry
    /// endorsement. It must come from trusted client configuration.
    Embedded(EmbeddedConfig),
}

/// How a verifier trusts the runtime and platform artifacts that
/// `attestation-collaterals/v3` collateral references.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ArtifactTrust {
    /// Artifacts that the document's endorsements authenticate, with
    /// freshness approvals that `freshness_keys` sign. The default.
    Endorsed {
        /// The keys that sign freshness approvals. `None` selects
        /// Tinfoil's public keys. These keys approve platform and runtime
        /// artifacts only; they authorize no config. A set of keys
        /// requires `attestation-collaterals/v3` collateral, and an empty
        /// one is a usage error.
        freshness_keys: Option<Vec<PublicKey>>,
    },
    /// Artifacts that the caller supplies, in place of their endorsements;
    /// requires `attestation-collaterals/v3` collateral.
    ///
    /// No endorsement is consulted for a supplied artifact, even if the
    /// document carries one. An artifact that is not supplied is still
    /// endorsed, with its freshness approval signed by `freshness_keys`,
    /// as [`Endorsed`](Self::Endorsed) describes. Hardware
    /// authentication, the bindings between the components and register
    /// pins stay mandatory. The values must come from trusted client
    /// configuration.
    ///
    /// At least one artifact must be supplied, and `freshness_keys` must
    /// be `None` when both are, since nothing would be left for them to
    /// verify; either mistake is a usage error.
    Embedded {
        /// The exact runtime manifest that the config pins.
        runtime: Option<Vec<u8>>,
        /// A platform policy artifact in the `platform-endorsements/v2`
        /// format.
        platform: Option<Vec<u8>>,
        /// The keys that sign the freshness approval of an artifact that
        /// is not supplied, as in [`Endorsed`](Self::Endorsed).
        freshness_keys: Option<Vec<PublicKey>>,
    },
}

impl Default for ArtifactTrust {
    fn default() -> Self {
        ArtifactTrust::Endorsed {
            freshness_keys: None,
        }
    }
}

/// The checks that a verifier applies on top of its config trust.
///
/// The default policy keeps every default: no register pins, a freshness
/// bound of seven days, and runtime and platform artifacts that Tinfoil's
/// public keys approve.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Register checks. Each register that the pins set must match the
    /// enclave: it fills a register that the release leaves open, and must
    /// equal one that the release fixes. Pins for one platform reject
    /// every enclave on the other.
    pub pinned_registers: Option<Expected>,
    /// How old an authenticated freshness witness or approval may be.
    /// Zero selects the default of seven days, so that an unset value
    /// cannot disable the check. More than about 292 years is a usage
    /// error.
    pub freshness_max_age: Duration,
    /// How the runtime and platform artifacts are trusted.
    pub artifacts: ArtifactTrust,
}

/// Trust anchors that replace the ones embedded in the crate, so that the
/// conformance harness can authenticate synthetic collateral.
///
/// A supplied anchor destroys the guarantee that it protects, which is why
/// this type exists only in a conformance build. `None` keeps the embedded
/// anchor.
#[cfg(tinfoil_conformance)]
#[derive(Clone, Debug, Default)]
pub struct DangerousTestOnlyRoots {
    /// A Sigstore trusted root document, which otherwise guarantees that
    /// reference values come from Tinfoil's release workflows.
    pub sigstore_root_json: Option<Vec<u8>>,
    /// An AMD certificate chain, ASK then ARK, in PEM.
    pub amd_cert_chain_pem: Option<Vec<u8>>,
    /// An Intel SGX root certificate in PEM.
    pub intel_root_pem: Option<Vec<u8>>,
}

/// The trust anchors that a verifier is built on: the embedded ones, unless
/// a conformance build or a test replaces them.
#[derive(Default)]
pub(crate) struct Roots {
    /// A replacement for the embedded Sigstore trusted root.
    pub(crate) endorsements: Option<ProvenanceClient>,
    /// The vendor anchors of CPU evidence.
    pub(crate) vendor_roots: VendorRoots,
}

impl Roots {
    /// Anchors that replace the embedded ones: a Sigstore trusted root
    /// document, an AMD certificate chain and an Intel root certificate.
    /// `None` keeps the embedded anchor.
    #[cfg(any(test, tinfoil_conformance))]
    pub(crate) fn replaced(
        trusted_root_json: Option<&[u8]>,
        amd_cert_chain_pem: Option<Vec<u8>>,
        intel_root_pem: Option<Vec<u8>>,
    ) -> Result<Self, BoxError> {
        let endorsements = trusted_root_json
            .map(ProvenanceClient::from_trusted_root_json)
            .transpose()?;
        Ok(Self {
            endorsements,
            vendor_roots: VendorRoots::dangerous_test_only(amd_cert_chain_pem, intel_root_pem),
        })
    }
}

/// The parts of a verifier that its config trust and policy set, checked.
struct Parts {
    pinned_registers: Option<Expected>,
    freshness_max_age: Duration,
    config_keys: Option<Vec<x509::PublicKey>>,
    freshness_keys: Option<Vec<x509::PublicKey>>,
    config_registry_ids: Option<Vec<String>>,
    config_authorizer: Option<ConfigAuthorizer>,
    embedded: Embedded,
}

/// A set of keys, `None` when it is unset. An empty set is refused with
/// the message `empty`.
fn keys(
    keys: Option<Vec<PublicKey>>,
    empty: &'static str,
) -> Result<Option<Vec<x509::PublicKey>>, BoxError> {
    match keys {
        None => Ok(None),
        Some(keys) if keys.is_empty() => Err(empty.into()),
        Some(keys) => Ok(Some(keys.into_iter().map(|key| key.0).collect())),
    }
}

impl Parts {
    /// Checks `policy`, then `config`, each field in the order of its
    /// declaration. The first invalid value is the error.
    fn check(config: ConfigTrust, policy: Policy) -> Result<Self, BoxError> {
        let Policy {
            pinned_registers,
            freshness_max_age,
            artifacts,
        } = policy;
        if freshness_max_age > MAX_FRESHNESS_MAX_AGE {
            return Err("freshness maximum age is out of range".into());
        }
        let freshness_max_age = if freshness_max_age.is_zero() {
            MAX_FRESHNESS_AGE
        } else {
            freshness_max_age
        };
        const NO_FRESHNESS_KEYS: &str = "freshness signing keys must not be empty";
        let (runtime, platform, freshness_keys) = match artifacts {
            ArtifactTrust::Endorsed { freshness_keys } => {
                (None, None, keys(freshness_keys, NO_FRESHNESS_KEYS)?)
            }
            ArtifactTrust::Embedded {
                runtime,
                platform,
                freshness_keys,
            } => {
                if runtime.is_none() && platform.is_none() {
                    return Err("embedded artifacts must contain a runtime or a platform".into());
                }
                if runtime.is_some() && platform.is_some() && freshness_keys.is_some() {
                    return Err("freshness signing keys have no endorsed artifact to verify".into());
                }
                (runtime, platform, keys(freshness_keys, NO_FRESHNESS_KEYS)?)
            }
        };
        let mut parts = Parts {
            pinned_registers,
            freshness_max_age,
            config_keys: None,
            freshness_keys,
            config_registry_ids: None,
            config_authorizer: None,
            embedded: Embedded::default(),
        };
        let mut embedded_config = None;
        match config {
            ConfigTrust::PublicRegistry => {}
            ConfigTrust::Registries(registry_ids) => {
                let policy = ConfigPolicy {
                    identity: None,
                    revision: None,
                    digest: None,
                    now: Instant::UNIX_EPOCH,
                    max_age: None,
                    future_skew: None,
                    registry_ids: Some(registry_ids),
                };
                policy.validate_pins()?;
                parts.config_registry_ids = policy.registry_ids;
            }
            ConfigTrust::SigningKeys(signing_keys) => {
                parts.config_keys =
                    keys(Some(signing_keys), "config signing keys must not be empty")?;
            }
            ConfigTrust::Authorizer(authorizer) => parts.config_authorizer = Some(authorizer),
            ConfigTrust::Embedded(config) => embedded_config = Some(config),
        }
        parts.embedded = Embedded::check(embedded_config, runtime, platform)?;
        Ok(parts)
    }
}

/// Builds a verifier on `roots`.
pub(crate) fn build(config: ConfigTrust, policy: Policy, roots: Roots) -> Result<Verifier, Error> {
    let parts = Parts::check(config, policy).map_err(UsageError::new)?;
    let trust = trust(&parts, &roots).map_err(UsageError::new)?;
    Ok(into_verifier(parts, roots, Ok(trust)))
}

/// The verifier with the defaults. A failure can only come from the trust
/// material embedded in the crate; it is kept, and reported by every
/// verification.
pub(crate) fn build_default() -> Verifier {
    let roots = Roots::default();
    let parts = Parts {
        pinned_registers: None,
        freshness_max_age: MAX_FRESHNESS_AGE,
        config_keys: None,
        freshness_keys: None,
        config_registry_ids: None,
        config_authorizer: None,
        embedded: Embedded::default(),
    };
    let trust = trust(&parts, &roots).map_err(|cause| cause.to_string());
    into_verifier(parts, roots, trust)
}

/// The verifiers of the configured trust: the provenance client over the
/// trusted root, the config verifier over the caller's keys or the
/// registry roots, and the freshness verifier over the caller's keys or
/// Tinfoil's.
fn trust(parts: &Parts, roots: &Roots) -> Result<Trust, BoxError> {
    let endorsements = match &roots.endorsements {
        Some(client) => client.clone(),
        None => ProvenanceClient::embedded()?,
    };
    let public_keys = public_signing_keys()?;
    let config_verifier = match &parts.config_keys {
        None => endorsements.registry_verifier(&public_keys)?,
        Some(keys) => endorsements.config_verifier(keys)?,
    };
    let freshness_keys = parts.freshness_keys.as_deref().unwrap_or(&public_keys);
    let freshness_verifier = endorsements.freshness_verifier(freshness_keys)?;
    Ok(Trust {
        endorsements,
        config_verifier,
        freshness_verifier,
    })
}

fn into_verifier(parts: Parts, roots: Roots, trust: Result<Trust, String>) -> Verifier {
    Verifier {
        embedded: parts.embedded,
        pinned_registers: parts.pinned_registers,
        freshness_max_age: parts.freshness_max_age,
        config_authorizer: parts.config_authorizer,
        config_keys_pinned: parts.config_keys.is_some(),
        freshness_keys_pinned: parts.freshness_keys.is_some(),
        config_registry_ids: parts.config_registry_ids,
        trust,
        vendor_roots: roots.vendor_roots,
    }
}
