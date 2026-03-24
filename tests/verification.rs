//! Integration tests for full attestation verification

use tinfoil::discovery;
use tinfoil::verifier::{attestation, github, sigstore};
use tinfoil::SecureClient;

const ROUTER_HOST: &str = "inference.tinfoil.sh";
const ROUTER_REPO: &str = "tinfoilsh/confidential-model-router";

/// Enclave/repo pairs for multi-enclave verification tests
const TEST_ENCLAVES: &[(&str, &str)] = &[
    ("inference.tinfoil.sh", "tinfoilsh/confidential-model-router"),
];

/// Test hardware attestation with full AMD certificate chain verification
#[tokio::test]
async fn test_full_hardware_attestation() {
    let doc = attestation::fetch(ROUTER_HOST)
        .await
        .expect("Failed to fetch attestation");

    let verification = attestation::verify_full(&doc)
        .await
        .expect("Full verification failed");

    assert!(
        !verification.measurement.registers[0].is_empty(),
        "Measurement should not be empty"
    );
}

/// Test Sigstore verification of code provenance
#[tokio::test]
async fn test_sigstore_verification() {
    let result = sigstore::verify_repo(ROUTER_REPO)
        .await
        .expect("Sigstore verification failed");

    assert!(
        !result.measurement.registers[0].is_empty(),
        "Source measurement should not be empty"
    );
    assert!(!result.digest.is_empty(), "Digest should not be empty");
}

/// Test GitHub release fetching
#[tokio::test]
async fn test_github_release() {
    let tag = github::fetch_latest_tag(ROUTER_REPO)
        .await
        .expect("Failed to fetch latest tag");

    assert!(tag.starts_with('v'), "Tag should start with 'v': {}", tag);

    let digest = github::fetch_digest(ROUTER_REPO, &tag)
        .await
        .expect("Failed to fetch digest");

    assert_eq!(digest.len(), 64, "Digest should be 64 hex chars");
}

/// Test full end-to-end verification (hardware + sigstore + measurement comparison).
/// This must FAIL if measurements don't match — swallowing mismatches would hide
/// a broken verification pipeline.
#[tokio::test]
async fn test_full_verification_measurements_match() {
    // Step 1: Hardware attestation
    let doc = attestation::fetch(ROUTER_HOST)
        .await
        .expect("Failed to fetch attestation");

    let enclave = attestation::verify_full(&doc)
        .await
        .expect("Hardware verification failed");

    // Step 2: Sigstore verification
    let sigstore_result = sigstore::verify_repo(ROUTER_REPO)
        .await
        .expect("Sigstore verification failed");

    // Step 3: Compare measurements — this MUST succeed
    enclave.measurement.equals(&sigstore_result.measurement).expect(
        &format!(
            "Measurement mismatch!\n  Enclave: {:?}\n  Code:    {:?}",
            enclave.measurement.registers, sigstore_result.measurement.registers
        ),
    );
}

/// Test verification against multiple enclaves
#[tokio::test]
async fn test_verify_multiple_enclaves() {
    for (enclave, repo) in TEST_ENCLAVES {
        let mut client = SecureClient::new(*enclave, *repo, "test-key");
        let result = client.verify().await;
        assert!(
            result.is_ok(),
            "Verification failed for {}: {:?}",
            enclave,
            result.err()
        );
    }
}

/// Test router discovery endpoint
#[tokio::test]
async fn test_fetch_routers() {
    let routers = discovery::fetch_routers()
        .await
        .expect("Failed to fetch routers");

    assert!(!routers.is_empty(), "Should have at least one router");
    assert!(
        routers[0].ends_with(".tinfoil.sh"),
        "Router should end with .tinfoil.sh: {}",
        routers[0]
    );
}

/// Test default client creation with router discovery
#[tokio::test]
async fn test_default_client() {
    let mut client = SecureClient::new_default_client("test-key")
        .await
        .expect("Failed to create default client");

    assert!(!client.host().is_empty(), "Should have a host");

    let result = client.verify().await;
    assert!(result.is_ok(), "Verification should succeed: {:?}", result.err());
}

/// Test fetching attestation bundle from GitHub
#[tokio::test]
async fn test_fetch_attestation_bundle() {
    let repo = "tinfoilsh/confidential-llama3-3-70b";
    let tag = "v0.0.1";

    let digest = github::fetch_digest(repo, tag)
        .await
        .expect("Failed to fetch digest");

    assert!(!digest.is_empty(), "Digest should not be empty");

    let bundle = github::fetch_attestation_bundle(repo, &digest)
        .await
        .expect("Failed to fetch attestation bundle");

    assert!(!bundle.is_empty(), "Bundle should not be empty");
}
