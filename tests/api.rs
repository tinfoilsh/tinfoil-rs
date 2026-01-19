//! Integration tests for the Tinfoil API
//!
//! Tests that require TINFOIL_API_KEY will skip if the env var is not set.

use tinfoil::{ChatMessage, SecureClient};

/// Test client verification flow
#[tokio::test]
async fn test_client_verification() {
    let mut client = SecureClient::new("inference.tinfoil.sh", "test-key");

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
}

/// Test embedding API (requires valid API key)
#[tokio::test]
async fn test_embedding_api() {
    let api_key = match std::env::var("TINFOIL_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            eprintln!("Skipping test: TINFOIL_API_KEY not set");
            return;
        }
    };

    let mut client = SecureClient::new("inference.tinfoil.sh", &api_key);

    let embedding = client
        .embed("Hello, secure world!")
        .await
        .expect("Embedding should succeed");

    assert!(!embedding.is_empty(), "Embedding should not be empty");
    assert!(embedding.len() > 100, "Embedding should have many dimensions");
}

/// Test chat API (requires valid API key)
#[tokio::test]
async fn test_chat_api() {
    let api_key = match std::env::var("TINFOIL_API_KEY") {
        Ok(key) => key,
        Err(_) => {
            eprintln!("Skipping test: TINFOIL_API_KEY not set");
            return;
        }
    };

    let mut client = SecureClient::new("inference.tinfoil.sh", &api_key);

    let response = client
        .chat(vec![ChatMessage::user(
            "What is 2+2? Reply with just the number.",
        )])
        .await
        .expect("Chat should succeed");

    assert!(!response.choices.is_empty(), "Should have choices");
    let content = response.choices[0]
        .message
        .content
        .as_ref()
        .expect("Should have content");
    assert!(content.contains('4'), "Response should contain '4': {}", content);
}
