//! Negative integration tests for verification.
//!
//! These tests ensure that verification FAILS when it should — wrong repos,
//! wrong measurements, unreachable hosts, etc. A passing test suite that only
//! tests success paths gives no confidence that the security checks actually work.

use tinfoil::verifier::{attestation, sigstore};
use tinfoil::{Measurement, PredicateType, SecureClient};

const ROUTER_HOST: &str = "inference.tinfoil.sh";
const ROUTER_REPO: &str = "tinfoilsh/confidential-model-router";

// =========================================================================
// Wrong repo tests — Sigstore certificate identity must reject mismatches
// =========================================================================

/// Verification must fail when the repo doesn't exist.
#[tokio::test]
async fn test_wrong_repo_fails_verification() {
    let mut client = SecureClient::new(ROUTER_HOST, "wrong-org/wrong-repo", "test-key");
    assert!(client.verify().await.is_err());
}

/// Verification must fail when we use a real repo that exists but doesn't
/// match the enclave. This tests the Sigstore certificate identity check
/// or measurement comparison (not just a 404 from a nonexistent repo).
#[tokio::test]
async fn test_mismatched_real_repo_fails_verification() {
    let mut client =
        SecureClient::new(ROUTER_HOST, "tinfoilsh/confidential-llama3-3-70b", "test-key");
    assert!(client.verify().await.is_err());
}

/// Sigstore verify_repo must fail when called with the wrong repo.
#[tokio::test]
async fn test_sigstore_wrong_repo_fails() {
    assert!(sigstore::verify_repo("wrong-org/wrong-repo").await.is_err());
}

/// Verification must fail for a repo that doesn't exist on GitHub.
#[tokio::test]
async fn test_nonexistent_repo_fails() {
    let mut client = SecureClient::new(
        ROUTER_HOST,
        "tinfoilsh/this-repo-definitely-does-not-exist-xyz-12345",
        "test-key",
    );
    assert!(client.verify().await.is_err());
}

// =========================================================================
// Wrong measurement tests — pinned measurements must reject mismatches
// =========================================================================

/// Verification must fail when a pinned measurement doesn't match the enclave.
#[tokio::test]
async fn test_wrong_pinned_measurement_fails() {
    let wrong_measurement = Measurement {
        type_: PredicateType::SnpTdxMultiPlatformV1,
        registers: vec![
            "0".repeat(96),
            "0".repeat(96),
            "0".repeat(96),
        ],
    };

    let mut client = SecureClient::with_measurement(ROUTER_HOST, "test-key", wrong_measurement);
    assert!(client.verify().await.is_err());
}

// =========================================================================
// Unreachable host tests
// =========================================================================

/// Verification must fail when the enclave host is unreachable.
#[tokio::test]
async fn test_unreachable_host_fails() {
    let mut client = SecureClient::new(
        "nonexistent-host-that-does-not-resolve.tinfoil.sh",
        ROUTER_REPO,
        "test-key",
    );
    assert!(client.verify().await.is_err());
}

/// Hardware attestation fetch must fail for an unreachable host.
#[tokio::test]
async fn test_attestation_fetch_unreachable_host_fails() {
    assert!(
        attestation::fetch("nonexistent-host-that-does-not-resolve.tinfoil.sh")
            .await
            .is_err()
    );
}

// =========================================================================
// Pre-verification guard tests
// =========================================================================

/// http_client() must return an error before verify() is called.
#[tokio::test]
async fn test_not_verified_blocks_http_client() {
    let client = SecureClient::new(ROUTER_HOST, ROUTER_REPO, "test-key");
    assert!(!client.is_verified());
    assert!(client.http_client().is_err());
}

/// ground_truth() must return None before verify() is called.
#[tokio::test]
async fn test_not_verified_no_ground_truth() {
    let client = SecureClient::new(ROUTER_HOST, ROUTER_REPO, "test-key");
    assert!(client.ground_truth().is_none());
}
