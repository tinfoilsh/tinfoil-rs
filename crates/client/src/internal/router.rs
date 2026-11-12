//! Discovers Tinfoil's router.

use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::internal::Clock;
use crate::internal::transport::{Mode, Transport};
use crate::options::VerificationCheck;
use crate::verifier::{Verification, Verifier};

/// The repository that every router is verified against.
pub(crate) const ROUTER_REPO: &str = "tinfoilsh/confidential-model-router";

/// Where the list of routers is published.
pub(crate) const ROUTER_LIST_URL: &str = "https://atc.tinfoil.sh/routers";

/// The router that is used when no router from the list verifies.
pub(crate) const FALLBACK_ROUTER: &str = "inference.tinfoil.sh";

/// The bound on discovery as a whole: the list fetch and every probe.
pub(crate) const DISCOVERY_BUDGET: Duration = Duration::from_secs(30);

/// The largest router list that is read.
pub(crate) const MAX_ROUTER_LIST_BYTES: usize = 32 << 20;

/// Returns a verified transport for the first router of Tinfoil's router
/// list that passes verification, and otherwise for [`FALLBACK_ROUTER`].
///
/// 1. The list is fetched from [`ROUTER_LIST_URL`] with the rules of an
///    attestation fetch (no redirects, a size bound of
///    [`MAX_ROUTER_LIST_BYTES`]). It is a JSON array of hosts. A list that
///    cannot be fetched or parsed is an empty list, not an error, and an
///    entry that is not a host with an optional port is skipped.
/// 2. The routers are probed one at a time, in list order. A probe is one
///    verification without a retry, under `verifier`, the router
///    repository and `check`, followed by binding `mode` to its keys, so
///    that a router whose keys the mode cannot use is skipped as well. A
///    rejection by `check` moves on to the next router.
/// 3. The first router that passes wins and keeps its verification, so the
///    client does not verify it a second time.
/// 4. The list fetch and all probes share [`DISCOVERY_BUDGET`]. When it
///    runs out, the probe in progress is dropped, which closes its
///    connection, and no further router is tried.
/// 5. With no winner, [`FALLBACK_ROUTER`] is verified with the usual retry.
///    Its failure is the error of discovery.
///
/// The list is untrusted: it only proposes hosts, and each one must pass
/// the same verification as a host that the caller named.
///
/// Dropping the future drops the probe in progress and keeps nothing.
pub(crate) async fn discover(
    verifier: Option<Arc<Verifier>>,
    check: Option<VerificationCheck>,
    mode: Arc<dyn Mode<Verification>>,
    clock: Clock,
) -> Result<Transport, Error> {
    Err(Error::not_implemented("router discovery"))
}

/// The hosts of a router list, in order, without the entries that are not
/// a host with an optional port. `None` when `body` is not a JSON array.
pub(crate) fn parse_router_list(body: &[u8]) -> Option<Vec<String>> {
    None
}
