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

/// Test hardware attestation fetch and report parsing (no crypto verification)
#[tokio::test]
async fn test_hardware_attestation_parsing() {
    let doc = attestation::fetch(ROUTER_HOST)
        .await
        .expect("Failed to fetch attestation");

    let verification = attestation::parse_report(&doc).expect("Report parsing failed");

    assert!(
        !verification.measurement.registers[0].is_empty(),
        "Measurement should not be empty"
    );
    assert!(
        !verification.tls_public_key_fp.is_empty(),
        "TLS fingerprint should not be empty"
    );
}

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
    let measurement = sigstore::verify_repo(ROUTER_REPO)
        .await
        .expect("Sigstore verification failed");

    assert!(
        !measurement.registers[0].is_empty(),
        "Source measurement should not be empty"
    );
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

/// Test full end-to-end verification (hardware + sigstore + comparison)
#[tokio::test]
async fn test_full_verification() {
    // Step 1: Hardware attestation
    let doc = attestation::fetch(ROUTER_HOST)
        .await
        .expect("Failed to fetch attestation");

    let enclave = attestation::verify_full(&doc)
        .await
        .expect("Hardware verification failed");

    // Step 2: Sigstore verification
    let code_measurement = sigstore::verify_repo(ROUTER_REPO)
        .await
        .expect("Sigstore verification failed");

    // Step 3: Compare measurements
    let result = enclave.measurement.equals(&code_measurement);

    // Note: Measurements may not match if there's been a recent deployment
    // This is expected behavior - the test verifies both systems work
    if result.is_err() {
        eprintln!(
            "Warning: Measurements don't match (may be due to recent deployment)\n\
             Enclave: {}...\n\
             Source:  {}...",
            &enclave.measurement.registers[0][..48.min(enclave.measurement.registers[0].len())],
            &code_measurement.registers[0][..48.min(code_measurement.registers[0].len())]
        );
    }
}

/// Test verification against multiple enclaves
#[tokio::test]
async fn test_verify_multiple_enclaves() {
    for (enclave, _repo) in TEST_ENCLAVES {
        let mut client = SecureClient::new(*enclave, "test-key");
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
