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

/// Fetch the attestation digest (tinfoil.hash) for a given repo and tag.
pub async fn fetch_digest(repo: &str, tag: &str) -> Result<String> {
    let url = format!("{}/{}/releases/download/{}/tinfoil.hash", GITHUB_PROXY, repo, tag);

    let response = reqwest::get(&url).await?;

    if !response.status().is_success() {
        return Err(Error::GitHub(format!(
            "failed to fetch digest for {}@{}: HTTP {}",
            repo, tag, response.status()
        )));
    }

    let digest = response.text().await?;
    Ok(digest.trim().to_string())
}

/// Fetch the latest release digest for a repository.
pub async fn fetch_latest_digest(repo: &str) -> Result<String> {
    let tag = fetch_latest_tag(repo).await?;
    fetch_digest(repo, &tag).await
}
