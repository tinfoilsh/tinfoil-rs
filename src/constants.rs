//! SDK-wide configuration constants.
//!
//! This module contains URLs and default values used throughout the SDK
//! for service discovery, GitHub API access, and attestation verification.

/// Proxy for GitHub API requests (releases, attestations)
pub const GITHUB_API_PROXY: &str = "https://api-github-proxy.tinfoil.sh";

/// Proxy for GitHub release asset downloads (tinfoil.hash, etc.)
pub const GITHUB_DOWNLOAD_PROXY: &str = "https://github-proxy.tinfoil.sh";

/// Proxy for GitHub attestation API requests
pub const ATTESTATION_PROXY: &str = "https://gh-attestation-proxy.tinfoil.sh";

/// Router discovery endpoint URL
pub const ROUTER_URL: &str = "https://atc.tinfoil.sh/routers?platform=snp";

/// Default router hostname for inference requests
pub const DEFAULT_ROUTER: &str = "inference.tinfoil.sh";

/// Default repository for the confidential model router
pub const DEFAULT_REPO: &str = "tinfoilsh/confidential-model-router";

/// AMD KDS proxy for VCEK certificate fetching
pub const KDS_PROXY: &str = "https://kds-proxy.tinfoil.sh";
