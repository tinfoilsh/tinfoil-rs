//! GitHub API functions for fetching release information and attestation bundles.

use serde::Deserialize;

use crate::error::{Error, Result};

const GITHUB_PROXY: &str = "https://api-github-proxy.tinfoil.sh";

#[derive(Deserialize)]
struct ReleaseResponse {
    tag_name: String,
}

/// Fetch the latest release tag for a repository.
pub async fn fetch_latest_tag(repo: &str) -> Result<String> {
    let url = format!("{}/repos/{}/releases/latest", GITHUB_PROXY, repo);

    let response = reqwest::get(&url).await?;

    if !response.status().is_success() {
        return Err(Error::GitHub(format!(
            "failed to fetch latest release: HTTP {}",
            response.status()
        )));
    }

    let release: ReleaseResponse = response.json().await?;
    Ok(release.tag_name)
}
