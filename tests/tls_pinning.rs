//! Integration tests for TLS certificate pinning

use tinfoil::verifier::tls::create_pinned_client;

/// Test that TLS pinning rejects connections with wrong fingerprint
#[tokio::test]
async fn test_wrong_fingerprint_rejected() {
    let wrong_fp = "0000000000000000000000000000000000000000000000000000000000000000";

    let client = create_pinned_client(wrong_fp).expect("Failed to create client");
    let result = client
        .get("https://inference.tinfoil.sh/.well-known/tinfoil-attestation")
        .send()
        .await;

    // Request should fail due to fingerprint mismatch
    assert!(result.is_err(), "Request should fail with wrong fingerprint");
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("fingerprint") || err_str.contains("certificate") || err_str.contains("TLS"),
        "Error should be related to certificate verification: {}",
        err_str
    );
}

/// Test that TLS pinning accepts connections with correct fingerprint
#[tokio::test]
async fn test_correct_fingerprint_accepted() {
    // First fetch the correct fingerprint from attestation
    let doc: serde_json::Value =
        reqwest::get("https://inference.tinfoil.sh/.well-known/tinfoil-attestation")
            .await
            .expect("Failed to fetch attestation")
            .json()
            .await
            .expect("Failed to parse attestation");

    // Decode and extract TLS fingerprint
    let body = doc.get("body").and_then(|b| b.as_str()).expect("No body");
    let compressed = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
        .expect("Base64 decode failed");

    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut report_bytes = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut report_bytes).expect("Decompress failed");

    assert!(
        report_bytes.len() >= 112,
        "Attestation report too short: expected at least 112 bytes, got {}",
        report_bytes.len()
    );

    // TLS fingerprint is at offset 80, first 32 bytes
    let tls_fp = hex::encode(&report_bytes[80..112]);

    let client = create_pinned_client(&tls_fp).expect("Failed to create client");
    let result = client
        .get("https://inference.tinfoil.sh/.well-known/tinfoil-attestation")
        .send()
        .await;

    assert!(
        result.is_ok(),
        "Request should succeed with correct fingerprint: {:?}",
        result.err()
    );
    assert!(result.unwrap().status().is_success());
}
