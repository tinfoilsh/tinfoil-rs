//! Which models a gateway client serves, and what their replicas are
//! verified against.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Error;
use crate::gateway_client::{Catalog, ModelPin};
use crate::verifier::Verifier;

/// A replica to verify: its host, the reference to verify it against, and
/// the pinned model that the reference came from, if any.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Replica {
    pub(crate) host: String,
    pub(crate) reference: String,
    pub(crate) pinned_model: Option<String>,
}

/// The model pins and the verifier for everything else.
pub(crate) struct Policy {
    pins: HashMap<String, ModelPin>,
    pinned_only: bool,
    verifier: Arc<Verifier>,
}

impl Policy {
    /// Checks the pins and the verifiers, as
    /// `GatewayHttpClientBuilder::connect` lists, and gives each pin
    /// without a verifier the client's.
    pub(crate) fn new(
        pins: HashMap<String, ModelPin>,
        pinned_only: bool,
        verifier: Option<Arc<Verifier>>,
    ) -> Result<Self, Error> {
        Err(Error::not_implemented("the gateway policy"))
    }

    /// The hosts of `model` and the reference to verify them against.
    ///
    /// - With pinned-only set, a model without a pin is a configuration
    ///   error.
    /// - A model whose catalog entry is missing or untrusted is a
    ///   configuration error.
    /// - For a pinned model the catalog's repository must equal the pin's
    ///   repository without its tag and digest; a different repository is
    ///   an attestation error. The reference is the pin's.
    /// - For an unpinned model the reference is the catalog's repository.
    pub(crate) fn resolve(
        &self,
        model: &str,
        catalog: &Catalog,
    ) -> Result<(Vec<String>, Replica), Error> {
        Err(Error::not_implemented("the gateway policy"))
    }

    /// The verifier for a replica: the pin's for a pinned model, the
    /// client's otherwise.
    pub(crate) fn verifier_for(&self, replica: &Replica) -> Arc<Verifier> {
        replica
            .pinned_model
            .as_ref()
            .and_then(|model| self.pins.get(model))
            .and_then(|pin| pin.verifier.clone())
            .unwrap_or_else(|| Arc::clone(&self.verifier))
    }
}
