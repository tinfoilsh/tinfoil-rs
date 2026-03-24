//! Integration tests for the Tinfoil secure client

use tinfoil::SecureClient;

/// Test client verification flow
#[tokio::test]
async fn test_client_verification() {
    let mut client = SecureClient::new("inference.tinfoil.sh", "tinfoilsh/confidential-model-router", "test-key");

    assert!(!client.is_verified(), "Client should not be verified initially");

    let result = client.verify().await;
    assert!(result.is_ok(), "Verification should succeed: {:?}", result.err());

    assert!(client.is_verified(), "Client should be verified after verify()");

    let gt = client.ground_truth().expect("Should have ground truth");
    assert!(gt.tls_public_key.is_some(), "Should have TLS public key");
    assert!(
        !gt.enclave_measurement.registers[0].is_empty(),
        "Should have measurement"
    );

    // After verification, http_client() should return a usable client
    assert!(client.http_client().is_ok(), "Should have HTTP client after verification");
    assert!(!client.base_url().is_empty(), "Should have base URL");
}
