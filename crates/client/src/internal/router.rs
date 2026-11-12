//! Discovers Tinfoil's router.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, Url};
use tokio::time::Instant;

use crate::error::Error;
use crate::internal::attested::{AttestedClient, Settings, within};
use crate::internal::enclave::{Enclave, Evidence};
use crate::internal::fetch;
use crate::internal::transport::base_url::authority_url;
use crate::internal::transport::{Mode, Transport};
use crate::options::Secret;

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;

/// The repository that every router is verified against. No option
/// changes it.
pub(crate) const ROUTER_REPO: &str = "tinfoilsh/confidential-model-router";

/// Where the list of routers is published.
pub(crate) const ROUTER_LIST_URL: &str = "https://atc.tinfoil.sh/routers";

/// The router that is used when no router from the list verifies.
pub(crate) const FALLBACK_ROUTER: &str = "inference.tinfoil.sh";

/// The bound on discovery as a whole: the list fetch and every probe.
pub(crate) const DISCOVERY_BUDGET: Duration = Duration::from_secs(30);

/// The bound on the list fetch by itself. It equals the budget, which
/// therefore ends the fetch first.
pub(crate) const LIST_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest router list that is read.
pub(crate) const MAX_ROUTER_LIST_BYTES: usize = 32 << 20;

/// Returns a verified transport for the first router of `list` that passes
/// verification, and otherwise for [`FALLBACK_ROUTER`].
///
/// 1. `list` yields the hosts to try: for a client, [`router_list`]. They
///    are tried one at a time, in the order of the list, as often as they
///    appear in it. Nothing is shuffled.
/// 2. `enclave_for` makes the enclave of a host, under the caller's policy
///    and the router repository. A host that it refuses is skipped.
/// 3. A probe is one verification without a retry, followed by binding
///    `mode` to its keys, so that a router whose keys the mode cannot use
///    is skipped as well. Whatever makes a probe fail (the network, the
///    document, the caller's veto, a configuration error), the next host
///    is tried, and the failure is not kept.
/// 4. The first router that passes wins and keeps its verification, so the
///    client does not verify it a second time.
/// 5. The list and all probes share [`DISCOVERY_BUDGET`]. When it runs
///    out, what is in progress is dropped, which closes its connection,
///    and no further router is tried.
/// 6. With no winner, [`FALLBACK_ROUTER`] is verified with the usual
///    retry, outside the budget. Its failure is the error of discovery; a
///    failed retry carries the first attempt.
///
/// The list is untrusted: it only proposes hosts, and each one must pass
/// the same verification as a host that the caller named.
///
/// Dropping the future drops the probe in progress and keeps nothing.
pub(crate) async fn discover<V: Evidence>(
    list: impl Future<Output = Vec<String>>,
    enclave_for: impl Fn(&str) -> Result<Enclave<V>, Error>,
    mode: Arc<dyn Mode<V>>,
) -> Result<Transport<V>, Error> {
    // A budget too long to add to the present cannot happen; if it did,
    // discovery would go straight to the fallback.
    if let Some(deadline) = Instant::now().checked_add(DISCOVERY_BUDGET) {
        let hosts = tokio::time::timeout_at(deadline, list)
            .await
            .unwrap_or_default();
        for host in hosts {
            if Instant::now() >= deadline {
                break;
            }
            let Ok(enclave) = enclave_for(&host) else {
                continue;
            };
            let probe = Transport::connect(enclave, Arc::clone(&mode), false);
            match tokio::time::timeout_at(deadline, probe).await {
                Ok(Ok(transport)) => return Ok(transport),
                Ok(Err(_)) => {}
                Err(_) => break,
            }
        }
    }
    Transport::connect(enclave_for(FALLBACK_ROUTER)?, mode, true).await
}

/// Discovers a router and returns the client for it, within the `timeout`
/// of `settings`, which bounds discovery, the fallback's verification and
/// the rest together.
///
/// `resolve` turns the `user_cache_secret` option into the client's
/// secret. It runs once and last: after discovery has chosen and verified
/// a router, and after everything else that can fail, so a client that
/// cannot be created stores no secret. It may read or create a small file,
/// and does so synchronously.
pub(crate) async fn connect<V: Evidence>(
    list: impl Future<Output = Vec<String>>,
    enclave_for: impl Fn(&str) -> Result<Enclave<V>, Error>,
    mode: Arc<dyn Mode<V>>,
    settings: Settings,
    resolve: impl FnOnce(Option<Secret>) -> Option<Secret>,
) -> Result<AttestedClient<V>, Error> {
    within(settings.timeout, async move {
        let transport = discover(list, enclave_for, mode).await?;
        AttestedClient::new_with(transport, settings, resolve)
    })
    .await
}

/// The hosts of Tinfoil's router list, fetched from [`ROUTER_LIST_URL`].
/// Any failure is an empty list.
///
/// The fetch is that of unattested material: standard certificate checks
/// against the compiled-in roots, redirects to `https://` URLs only and at
/// most ten requests in a chain, no connection kept, and a client that
/// never sends a loopback request to a proxy from the environment.
pub(crate) async fn router_list() -> Vec<String> {
    let Ok(url) = Url::parse(ROUTER_LIST_URL) else {
        return Vec::new();
    };
    let Ok(client) = fetch::plain_client_for(&url) else {
        return Vec::new();
    };
    list_through(&client, url, MAX_ROUTER_LIST_BYTES, LIST_FETCH_TIMEOUT).await
}

/// The hosts of the router list at `url`, fetched with `client`. A fetch
/// that fails, takes longer than `timeout`, ends in a status above 299 or
/// yields more than `limit` bytes, and a body that is not a router list
/// ([`parse_router_list`]), are all an empty list: discovery then falls
/// back.
async fn list_through(client: &Client, url: Url, limit: usize, timeout: Duration) -> Vec<String> {
    fetch::get_bounded(client, url, limit, timeout, "router list")
        .await
        .ok()
        .and_then(|body| parse_router_list(&body))
        .unwrap_or_default()
}

/// The hosts of a router list, in its order, repeated entries included.
///
/// `None` when `body` is not one JSON array whose entries are all strings
/// or `null`: one entry of another type refuses the whole list. Of the
/// entries, those that are not a host with an optional port
/// ([`authority_url`]) are left out, a `null` among them: an empty string,
/// a URL, a host with a path, or a host with whitespace around it. A host
/// is kept as it is written.
pub(crate) fn parse_router_list(body: &[u8]) -> Option<Vec<String>> {
    let entries: Vec<Option<String>> = serde_json::from_slice(body).ok()?;
    Some(
        entries
            .into_iter()
            .flatten()
            .filter(|host| authority_url(host).is_ok())
            .collect(),
    )
}
