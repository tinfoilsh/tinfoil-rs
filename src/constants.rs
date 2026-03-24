//! SDK-wide configuration constants.
//!
//! This module contains URLs and default values used throughout the SDK
//! for service discovery, GitHub API access, and attestation verification.

/// Proxy for all GitHub requests (API, downloads, attestations)
pub const GITHUB_PROXY: &str = "https://github-proxy.tinfoil.sh";

/// Router discovery endpoint URL
pub const ROUTER_URL: &str = "https://atc.tinfoil.sh/routers?platform=snp";

/// Default router hostname for inference requests
pub const DEFAULT_ROUTER: &str = "inference.tinfoil.sh";

/// Default repository for the confidential model router
pub const DEFAULT_REPO: &str = "tinfoilsh/confidential-model-router";

/// AMD KDS proxy for VCEK certificate fetching
pub const KDS_PROXY: &str = "https://kds-proxy.tinfoil.sh";
