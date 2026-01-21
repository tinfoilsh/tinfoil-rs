//! SDK-wide configuration constants.
//!
//! This module contains URLs and default values used throughout the SDK
//! for service discovery, GitHub API access, and attestation verification.

/// Proxy for GitHub API requests (rate limit bypass and caching)
pub const GITHUB_PROXY: &str = "https://api-github-proxy.tinfoil.sh";

/// Proxy for GitHub attestation API requests
pub const ATTESTATION_PROXY: &str = "https://gh-attestation-proxy.tinfoil.sh";

/// Router discovery endpoint URL
pub const ROUTER_URL: &str = "https://atc.tinfoil.sh/routers?platform=snp";

/// Default router hostname for inference requests
pub const DEFAULT_ROUTER: &str = "inference.tinfoil.sh";

/// Default repository for the confidential model router
pub const DEFAULT_REPO: &str = "tinfoilsh/confidential-model-router";
