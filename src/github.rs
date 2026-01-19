//! GitHub API functions for fetching release information and attestation bundles.

use serde::Deserialize;

use crate::error::{Error, Result};

const GITHUB_PROXY: &str = "https://api-github-proxy.tinfoil.sh";
const ATTESTATION_PROXY: &str = "https://gh-attestation-proxy.tinfoil.sh";

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

#[derive(Deserialize)]
struct Attestation {
    bundle: serde_json::Value,
}

#[derive(Deserialize)]
struct AttestationsResponse {
    attestations: Vec<Attestation>,
}

/// Fetch the Sigstore attestation bundle for a given repo and digest.
pub async fn fetch_attestation_bundle(repo: &str, digest: &str) -> Result<Vec<u8>> {
    let url = format!("{}/repos/{}/attestations/sha256:{}", ATTESTATION_PROXY, repo, digest);

    let response = reqwest::get(&url).await?;

    if !response.status().is_success() {
        return Err(Error::GitHub(format!(
            "failed to fetch attestation bundle for {}@{}: HTTP {}",
            repo, digest, response.status()
        )));
    }

    let attestations: AttestationsResponse = response.json().await?;

    if attestations.attestations.is_empty() {
        return Err(Error::GitHub(format!(
            "no attestations found for {}@{}",
            repo, digest
        )));
    }

    let bundle = serde_json::to_vec(&attestations.attestations[0].bundle)?;
    Ok(bundle)
}
