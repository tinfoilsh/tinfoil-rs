//! The gateway route: each request is sealed to a verified replica of the
//! model that it names.
//!
//! | module | what it does |
//! |---|---|
//! | [`catalog`] | fetches, bounds, filters and caches the catalog |
//! | [`policy`] | model pins, and which reference and verifier a model's replicas get |
//! | [`prepare`] | reads the model from a request and scopes its prompt cache |
//!
//! Not implemented: the bodies of this module and its submodules are
//! placeholders.

// Placeholder bodies leave their arguments and the items that they would
// use unused.
#![allow(dead_code, unused_variables)]

use std::sync::Arc;

use reqwest::{Method, Request, Url};

use crate::error::Error;
use crate::gateway_client::{Catalog, GatewayOptions, ReplicaVerification};
use crate::request::{Execute, ResponseFuture};
use crate::verifier::Verification;

pub(crate) mod catalog;
pub(crate) mod policy;
pub(crate) mod prepare;

pub(crate) use catalog::fetch_catalog;

/// Tinfoil's gateway.
pub(crate) const DEFAULT_URL: &str = "https://inference-gateway.tinfoil.sh/v1/";

/// The header that names the model of a request to the gateway.
pub(crate) const MODEL_HEADER: &str = "X-Tinfoil-Model";

/// The header that keeps the requests of one conversation on one replica.
pub(crate) const CACHE_PREFIX_HEADER: &str = "X-Tinfoil-Cache-Prefix";

/// The header that names the replica that a request is sealed to, and in a
/// `412` response the replica that the gateway routed to instead.
pub(crate) const SEAL_HEADER: &str = "X-Tinfoil-Seal";

/// How often a request follows the gateway to another replica.
pub(crate) const MAX_SEAL_REDIRECTS: usize = 3;

/// The state behind a `GatewayHttpClient`.
///
/// A request goes through, in order:
///
/// 1. the origin restriction on the gateway's base URL;
/// 2. the request checks of the EHBP mode, before the catalog is read or a
///    replica verified;
/// 3. [`prepare`]: the model, the cache salt and the cache prefix;
/// 4. the catalog and the [`policy`], which give the replicas' hosts and
///    the reference that they are verified against;
/// 5. replica choice: by rendezvous hash of the cache prefix, or at random
///    without one, with the replica that an earlier request of the same
///    prefix was rerouted to first. The first replica that verifies is
///    used; a replica that does not is skipped;
/// 6. the replica's own chain: one replay after a key rejection, the
///    enclave header, and an EHBP transport whose attestation document is
///    fetched through the gateway as a relay;
/// 7. seal negotiation: a `412` response that names another replica in
///    [`SEAL_HEADER`] is followed, when the body can be sent again, by
///    verifying that replica and sealing to it, at most
///    [`MAX_SEAL_REDIRECTS`] times; then a network error.
///
/// One transport per replica and reference is kept for the life of the
/// client, each with its own verification.
pub(crate) struct GatewayTransport {
    base_url: Url,
    /// Collects the parts of a request; it never sends.
    parts: reqwest::Client,
}

impl GatewayTransport {
    /// Checks `options` as `GatewayHttpClientBuilder::connect` lists and
    /// does no network I/O.
    pub(crate) fn new(options: GatewayOptions) -> Result<Self, Error> {
        Err(Error::not_implemented("the gateway transport"))
    }

    pub(crate) fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The catalog's models that the policy serves, sorted.
    pub(crate) async fn models(&self) -> Result<Vec<String>, Error> {
        Err(Error::not_implemented("the gateway's model list"))
    }

    /// A valid verification of a replica that serves `model`.
    pub(crate) async fn ensure_verified(&self, model: &str) -> Result<Arc<Verification>, Error> {
        Err(Error::not_implemented("gateway replica verification"))
    }

    /// The cached verification of every replica used so far, sorted by
    /// host, reference and pinned model.
    pub(crate) fn verifications(&self) -> Vec<ReplicaVerification> {
        Vec::new()
    }

    /// The current catalog: the caller's source, or the cached fetch.
    pub(crate) async fn catalog(&self) -> Result<Arc<Catalog>, Error> {
        Err(Error::not_implemented("the gateway catalog"))
    }
}

impl Execute for GatewayTransport {
    fn execute(&self, request: Request) -> ResponseFuture {
        ResponseFuture::new(async { Err(Error::not_implemented("the gateway transport")) })
    }

    fn start(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.parts.request(method, url)
    }
}
