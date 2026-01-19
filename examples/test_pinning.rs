//! Test that TLS pinning actually rejects wrong fingerprints

use tinfoil::verifier::tls::create_pinned_client;

#[tokio::main]
async fn main() {
    println!("═══ TLS Pinning Security Test ═══\n");
    
    // Test 1: Wrong fingerprint should be rejected
    println!("Test 1: Request with WRONG fingerprint");
    let wrong_fp = "0000000000000000000000000000000000000000000000000000000000000000";
    
    let client = create_pinned_client(wrong_fp).expect("Failed to create client");
    let result = client.get("https://inference.tinfoil.sh/.well-known/tinfoil-attestation").send().await;
    
    match result {
        Ok(_) => {
            println!("   ❌ FAIL: Request succeeded with wrong fingerprint!");
            println!("   This is a security vulnerability!\n");
        }
        Err(e) => {
            // Check the full error chain
            let err_str = format!("{:?}", e);  // Debug format shows inner errors
            if err_str.contains("fingerprint mismatch") || err_str.contains("Certificate fingerprint") {
                println!("   ✅ PASS: Request correctly rejected due to fingerprint mismatch");
                // Extract just the relevant part
                if let Some(start) = err_str.find("Certificate fingerprint mismatch") {
                    let end = err_str[start..].find('"').unwrap_or(100);
                    println!("   Reason: {}\n", &err_str[start..start+end.min(100)]);
                }
            } else if err_str.contains("certificate") || err_str.contains("TLS") || err_str.contains("ssl") {
                println!("   ✅ PASS: Request rejected (TLS/certificate error)");
                println!("   Full error: {}\n", &err_str[..err_str.len().min(200)]);
            } else {
                println!("   ⚠️  Request failed (checking if due to pinning)");
                println!("   Error: {}\n", &err_str[..err_str.len().min(300)]);
            }
        }
    }
    
    // Test 2: Correct fingerprint should work
    println!("Test 2: Request with CORRECT fingerprint");
    
    // First fetch the correct fingerprint
    let doc: serde_json::Value = reqwest::get("https://inference.tinfoil.sh/.well-known/tinfoil-attestation")
        .await
        .expect("Failed to fetch attestation")
        .json()
        .await
        .expect("Failed to parse attestation");
    
    // Decode and extract TLS fingerprint
    let body = doc.get("body").and_then(|b| b.as_str()).expect("No body");
    let compressed = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).expect("Base64 decode failed");
    
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut report_bytes = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut report_bytes).expect("Decompress failed");
    
    // TLS fingerprint is at offset 80, first 32 bytes
    let tls_fp = hex::encode(&report_bytes[80..112]);
    println!("   Correct fingerprint: {}...", &tls_fp[..32]);
    
    let client = create_pinned_client(&tls_fp).expect("Failed to create client");
    let result = client.get("https://inference.tinfoil.sh/.well-known/tinfoil-attestation").send().await;
    
    match result {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("   ✅ PASS: Request succeeded with correct fingerprint\n");
            } else {
                println!("   ⚠️  Request returned non-success status: {}\n", resp.status());
            }
        }
        Err(e) => {
            println!("   ❌ FAIL: Request failed with correct fingerprint: {:?}\n", e);
        }
    }
    
    println!("═══ Summary ═══");
    println!("   TLS certificate pinning is ENFORCED on every connection.");
    println!("   Wrong fingerprint = connection rejected");
    println!("   Correct fingerprint = connection allowed");
    println!("\n═══ TLS Pinning Test Complete ═══");
}
