//! Router discovery for finding available inference endpoints.

use crate::error::{Error, Result};

const ROUTER_URL: &str = "https://atc.tinfoil.sh/routers?platform=snp";

/// Default router to use if discovery fails
pub const DEFAULT_ROUTER: &str = "inference.tinfoil.sh";

/// Default repository for the confidential model router
pub const DEFAULT_REPO: &str = "tinfoilsh/confidential-model-router";

/// Fetch the list of available SNP routers from the discovery endpoint.
pub async fn fetch_routers() -> Result<Vec<String>> {
    let response = reqwest::get(ROUTER_URL)
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
