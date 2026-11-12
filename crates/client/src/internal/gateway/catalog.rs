//! The gateway's catalog: fetched, bounded, filtered and cached.

use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::gateway_client::{Catalog, CatalogEntry};

/// The path of a gateway's catalog.
pub(crate) const CATALOG_PATH: &str = "/catalog";

/// The bound on one catalog fetch.
pub(crate) const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a fetched catalog is used before it is refreshed. The gateway
/// lists only healthy replicas and reloads its own list as often.
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// The largest catalog that is read.
pub(crate) const MAX_CATALOG_BYTES: usize = 2 << 20;

/// The owner prefix of every repository that a catalog may name.
pub(crate) const TRUSTED_REPO_OWNER: &str = "tinfoilsh/";

/// Fetches `https://<host>/catalog` and returns its trusted entries. See
/// the public `fetch_catalog` for the contract.
pub(crate) async fn fetch_catalog(host: &str) -> Result<Catalog, Error> {
    Err(Error::not_implemented("the gateway catalog fetch"))
}

/// Whether a catalog entry can be used: its repository is a bare
/// `tinfoilsh/` reference, without a tag or a digest, and it lists at
/// least one host.
pub(crate) fn trusted(entry: &CatalogEntry) -> bool {
    false
}

/// A catalog that is fetched on first use and refreshed on use once
/// [`REFRESH_INTERVAL`] has passed.
///
/// Until a fetch succeeds, callers wait for one shared fetch, and a
/// failure is tried again on the next use. After that callers never wait:
/// they get the cached catalog while one refresh runs, and a failed
/// refresh keeps the cached catalog for another interval.
pub(crate) struct CatalogCache {
    host: String,
}

impl CatalogCache {
    pub(crate) fn new(host: String) -> Self {
        Self { host }
    }

    /// The catalog, as the type describes. Dropping the future leaves the
    /// cache as it was.
    pub(crate) async fn get(&self) -> Result<Arc<Catalog>, Error> {
        Err(Error::not_implemented("the gateway catalog cache"))
    }
}
