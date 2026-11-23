//! The closed set of attested HTTP clients that an OpenAI client can send
//! through.

use std::sync::Arc;

use reqwest::Url;

use crate::enclave_client::EnclaveHttpClient;
use crate::error::Error;
use crate::internal::attested::AttestedClient;
use crate::request::http_request_methods;
use crate::router_client::RouterHttpClient;
use crate::verifier::Verification;

/// One of this crate's attested HTTP clients: what an `OpenAIClient`
/// sends through.
///
/// The set is closed: only a client that this crate built can be one, so
/// that no other HTTP client can stand in for an attested one. Match on the
/// variant for the methods of the concrete client; the methods here are
/// those that every variant has, the request methods among them.
///
/// Each client converts into it with `From`, so a constructor that takes
/// `impl Into<AttestedHttpClient>` takes the client itself.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AttestedHttpClient {
    /// A client for one enclave that the caller names.
    Enclave(EnclaveHttpClient),
    /// A client for the router that discovery chose.
    Router(RouterHttpClient),
}

impl From<EnclaveHttpClient> for AttestedHttpClient {
    fn from(client: EnclaveHttpClient) -> Self {
        AttestedHttpClient::Enclave(client)
    }
}

impl From<RouterHttpClient> for AttestedHttpClient {
    fn from(client: RouterHttpClient) -> Self {
        AttestedHttpClient::Router(client)
    }
}

impl AttestedHttpClient {
    /// Where requests are sent: the proxy URL of
    /// [`Transport::Ehbp`](crate::Transport::Ehbp), or else the enclave's
    /// own origin. The path ends in `/`.
    pub fn base_url(&self) -> &Url {
        self.attested().base_url()
    }

    /// The host of the enclave that the client verifies.
    pub fn enclave(&self) -> &str {
        self.attested().enclave()
    }

    /// The last successful verification, without checking it. See
    /// [`EnclaveHttpClient::current`].
    pub fn current(&self) -> Arc<Verification> {
        self.attested().current()
    }

    /// A verification that is valid now, verifying first only if the
    /// current one has expired or was discarded. The behaviour, the errors
    /// and the cancel safety are those of
    /// [`EnclaveHttpClient::ensure_verified`].
    pub async fn ensure_verified(&self) -> Result<Arc<Verification>, Error> {
        self.attested().ensure_verified().await
    }

    /// Verifies the enclave again even if the current verification is still
    /// valid. The behaviour, the errors and the cancel safety are those of
    /// [`EnclaveHttpClient::reverify`].
    pub async fn reverify(&self) -> Result<Arc<Verification>, Error> {
        self.attested().reverify().await
    }

    /// The attested client that requests go through.
    pub(crate) fn attested(&self) -> &Arc<AttestedClient> {
        match self {
            AttestedHttpClient::Enclave(client) => client.attested(),
            AttestedHttpClient::Router(client) => client.attested(),
        }
    }
}

http_request_methods!(AttestedHttpClient);
