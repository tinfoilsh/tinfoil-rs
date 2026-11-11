//! The options of a verifier and the types that they take.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::document::collateral;
use crate::embedded::{Embedded, EmbeddedReferences};
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

/// A caller's config authorizer.
pub(crate) type ConfigAuthorizer =
    Arc<dyn Fn(&ConfigEndorsement) -> Result<(), BoxError> + Send + Sync + 'static>;

/// Builds a [`Verifier`]. Each method sets one option; the options are
/// checked in the order in which they are set, and [`build`](Self::build)
/// reports the first one that is invalid.
#[must_use = "a builder does nothing until `build` is called"]
pub struct VerifierBuilder {
    /// The first invalid option.
    error: Option<BoxError>,
    pinned_registers: Option<Expected>,
    freshness_max_age: Duration,
    config_keys: Option<Vec<x509::PublicKey>>,
    freshness_keys: Option<Vec<x509::PublicKey>>,
    config_registry_ids: Option<Vec<String>>,
    config_authorizer: Option<ConfigAuthorizer>,
    embedded: Embedded,
    /// A replacement for the embedded Sigstore trusted root. Only a
    /// conformance build can set one.
    endorsements: Option<ProvenanceClient>,
    vendor_roots: VendorRoots,
}

impl fmt::Debug for VerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierBuilder")
            .field("pinned_registers", &self.pinned_registers)
            .field("freshness_max_age", &self.freshness_max_age)
            .field("config_keys", &self.config_keys)
            .field("freshness_keys", &self.freshness_keys)
            .field("config_registry_ids", &self.config_registry_ids)
            .field("config_authorizer", &self.config_authorizer.is_some())
            .field("embedded", &self.embedded)
            .finish_non_exhaustive()
    }
}

impl Default for VerifierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierBuilder {
    /// A builder with every option at its default.
    pub(crate) fn new() -> Self {
        Self {
            error: None,
            pinned_registers: None,
            freshness_max_age: MAX_FRESHNESS_AGE,
            config_keys: None,
            freshness_keys: None,
            config_registry_ids: None,
            config_authorizer: None,
            embedded: Embedded::default(),
            endorsements: None,
            vendor_roots: VendorRoots::embedded(),
        }
    }

    /// Records an invalid option, unless an earlier one is already
    /// recorded.
    fn fail(&mut self, cause: impl Into<BoxError>) {
        if self.error.is_none() {
            self.error = Some(cause.into());
        }
    }

    /// Adds register checks. Each register that `pins` sets must match the
    /// enclave: it fills a register that the release leaves open, and must
    /// equal one that the release fixes. Pins for one platform reject
    /// every enclave on the other.
    pub fn pinned_registers(mut self, pins: Expected) -> Self {
        self.pinned_registers = Some(pins);
        self
    }

    /// Bounds how old an authenticated freshness witness or approval may
    /// be. The default is seven days. Zero keeps the bound as it is, so
    /// that an unset policy value cannot disable the check.
    ///
    /// An age of more than about 292 years is an invalid option.
    pub fn freshness_max_age(mut self, max_age: Duration) -> Self {
        if max_age > MAX_FRESHNESS_MAX_AGE {
            self.fail("freshness maximum age is out of range");
        } else if !max_age.is_zero() {
            self.freshness_max_age = max_age;
        }
        self
    }

    /// Replaces Tinfoil's public config trust with the given keys: only a
    /// config endorsement signed with one of them is accepted. This trust
    /// path uses no registry and does not cover artifact freshness. It
    /// requires documents with `attestation-collaterals/v3` collateral.
    ///
    /// An empty list is an invalid option.
    pub fn config_signing_keys(mut self, keys: Vec<PublicKey>) -> Self {
        if keys.is_empty() {
            self.fail("config signing keys must not be empty");
        } else {
            self.config_keys = Some(keys.into_iter().map(|key| key.0).collect());
        }
        self
    }

    /// Replaces Tinfoil's public approval keys for the platform policy
    /// artifact and the runtime. These keys authorize no config. The
    /// option requires documents with `attestation-collaterals/v3`
    /// collateral and at least one artifact that is not embedded.
    ///
    /// An empty list is an invalid option.
    pub fn freshness_signing_keys(mut self, keys: Vec<PublicKey>) -> Self {
        if keys.is_empty() {
            self.fail("freshness signing keys must not be empty");
        } else {
            self.freshness_keys = Some(keys.into_iter().map(|key| key.0).collect());
        }
        self
    }

    /// Accepts config endorsements of exactly these registries, in place of
    /// the public registry alone. To keep accepting the public registry,
    /// list [`PUBLIC_REGISTRY_ID`](crate::PUBLIC_REGISTRY_ID) too.
    ///
    /// An empty list, an identifier that is not a canonical registry URI, a
    /// repeated identifier and a second call are invalid options.
    pub fn config_registry_ids(mut self, registry_ids: Vec<String>) -> Self {
        let policy = ConfigPolicy {
            identity: None,
            revision: None,
            digest: None,
            now: Instant::UNIX_EPOCH,
            max_age: None,
            future_skew: None,
            registry_ids: Some(registry_ids),
        };
        if let Err(cause) = policy.validate_pins() {
            self.fail(cause);
        } else if self.config_registry_ids.is_some() {
            self.fail("config registry IDs must be supplied once");
        } else {
            self.config_registry_ids = policy.registry_ids;
        }
        self
    }

    /// Replaces config endorsement verification with the caller's policy.
    ///
    /// The function receives untrusted material from the document and must
    /// return an error for config bytes that it does not authorize. It may
    /// be called from several threads at once. Runtime, platform and
    /// hardware checks still apply; an authorized config has no
    /// authenticated registry name or approval time, and such a verifier
    /// accepts no repository pin.
    pub fn config_authorizer(
        mut self,
        authorize: impl Fn(&ConfigEndorsement) -> Result<(), BoxError> + Send + Sync + 'static,
    ) -> Self {
        self.config_authorizer = Some(Arc::new(authorize));
        self
    }

    /// Supplies reference values that the caller trusts by itself; see
    /// [`EmbeddedReferences`]. The values are checked and copied.
    ///
    /// References with no component, or with a component that is not well
    /// formed, are an invalid option.
    pub fn embedded_references(mut self, references: EmbeddedReferences) -> Self {
        match Embedded::check(references) {
            Ok(embedded) => self.embedded = embedded,
            Err(message) => self.fail(message),
        }
        self
    }

    /// Replaces the embedded Sigstore trusted root with the given trusted
    /// root document, so that the conformance harness can authenticate
    /// reference values signed by a synthetic authority.
    ///
    /// A supplied root destroys the guarantee that reference values come
    /// from Tinfoil's release workflows, which is why this method exists
    /// only in a conformance build. A document that is not a trusted root
    /// is an invalid option.
    #[cfg(tinfoil_conformance)]
    pub fn dangerous_test_only_sigstore_root(mut self, trusted_root_json: &[u8]) -> Self {
        match ProvenanceClient::from_trusted_root_json(trusted_root_json) {
            Ok(client) => self.endorsements = Some(client),
            Err(cause) => self.fail(cause),
        }
        self
    }

    /// Replaces the embedded AMD and Intel trust anchors, so that the
    /// conformance harness can authenticate synthetic CPU evidence: an AMD
    /// certificate chain (ASK then ARK, PEM) and an Intel SGX root
    /// certificate (PEM). `None` keeps the embedded anchor of that vendor.
    ///
    /// A supplied anchor destroys the guarantee that evidence chains to
    /// AMD or Intel, which is why this method exists only in a conformance
    /// build.
    #[cfg(tinfoil_conformance)]
    pub fn dangerous_test_only_vendor_roots(
        mut self,
        amd_cert_chain_pem: Option<Vec<u8>>,
        intel_root_pem: Option<Vec<u8>>,
    ) -> Self {
        self.vendor_roots = VendorRoots::dangerous_test_only(amd_cert_chain_pem, intel_root_pem);
        self
    }

    /// Replaces the provenance client, for tests that mint their own
    /// Sigstore material.
    #[cfg(test)]
    pub(crate) fn endorsements(mut self, client: ProvenanceClient) -> Self {
        self.endorsements = Some(client);
        self
    }

    /// Builds the verifier.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] for the first invalid option, and for options that
    /// select conflicting sources of trust: an embedded config with config
    /// signing keys; a config authorizer with an embedded config or config
    /// signing keys; registry identifiers with an embedded config, a
    /// config authorizer or config signing keys; freshness signing keys
    /// when both the runtime and the platform are embedded.
    pub fn build(self) -> Result<Verifier, Error> {
        self.build_parts().map_err(|cause| UsageError::new(cause).into())
    }

    /// Builds the verifier with the defaults. A failure can only come from
    /// the trust material embedded in the crate; it is kept, and reported
    /// by every verification.
    pub(crate) fn build_default() -> Verifier {
        let builder = Self::new();
        let trust = builder.trust().map_err(|cause| cause.to_string());
        builder.into_verifier(trust)
    }

    fn build_parts(mut self) -> Result<Verifier, BoxError> {
        if let Some(cause) = self.error.take() {
            return Err(cause);
        }
        let embedded_config = self.embedded.config.is_some();
        let config_keys = self.config_keys.is_some();
        let authorizer = self.config_authorizer.is_some();
        let registry_ids = self.config_registry_ids.is_some();
        if embedded_config && config_keys {
            return Err(
                "embedded config and config signing keys select conflicting trust sources".into(),
            );
        }
        if authorizer && (embedded_config || config_keys) {
            return Err(
                "config authorizer conflicts with embedded config or config signing keys".into(),
            );
        }
        if registry_ids && (embedded_config || authorizer) {
            return Err("config authority pins require endorsement verification".into());
        }
        if registry_ids && config_keys {
            return Err(
                "config registry ID policy requires Tinfoil registry root verification".into(),
            );
        }
        if self.embedded.runtime.is_some()
            && self.embedded.platform.is_some()
            && self.freshness_keys.is_some()
        {
            return Err("freshness signing keys have no endorsed artifact to verify".into());
        }
        let trust = self.trust()?;
        Ok(self.into_verifier(Ok(trust)))
    }

    /// The verifiers of the configured trust: the provenance client over
    /// the trusted root, the config verifier over the caller's keys or the
    /// registry roots, and the freshness verifier over the caller's keys
    /// or Tinfoil's.
    fn trust(&self) -> Result<Trust, BoxError> {
        let endorsements = match &self.endorsements {
            Some(client) => client.clone(),
            None => ProvenanceClient::embedded()?,
        };
        let public_keys = public_signing_keys()?;
        let config_verifier = match &self.config_keys {
            None => endorsements.registry_verifier(&public_keys)?,
            Some(keys) => endorsements.config_verifier(keys)?,
        };
        let freshness_keys = self.freshness_keys.as_deref().unwrap_or(&public_keys);
        let freshness_verifier = endorsements.freshness_verifier(freshness_keys)?;
        Ok(Trust {
            endorsements,
            config_verifier,
            freshness_verifier,
        })
    }

    fn into_verifier(self, trust: Result<Trust, String>) -> Verifier {
        Verifier {
            embedded: self.embedded,
            pinned_registers: self.pinned_registers,
            freshness_max_age: self.freshness_max_age,
            config_authorizer: self.config_authorizer,
            config_keys_pinned: self.config_keys.is_some(),
            freshness_keys_pinned: self.freshness_keys.is_some(),
            config_registry_ids: self.config_registry_ids,
            trust,
            vendor_roots: self.vendor_roots,
        }
    }
}
