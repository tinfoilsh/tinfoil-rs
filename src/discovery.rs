//! Router discovery for finding available inference endpoints.

use crate::constants::ROUTER_URL;
use crate::error::{Error, Result};
use crate::verifier::util::fetch_with_retry;

/// Fetch the list of available SNP routers from the discovery endpoint.
pub async fn fetch_routers() -> Result<Vec<String>> {
    let response = fetch_with_retry(ROUTER_URL)
        .await
        .map_err(|e| Error::Network(format!("Failed to fetch routers: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Network(format!(
            "Router discovery failed: HTTP {}",
            response.status()
        )));
    }

    let routers: Vec<String> = response
        .json()
        .await
        .map_err(|e| Error::Network(format!("Failed to parse routers: {}", e)))?;

    Ok(routers)
}
