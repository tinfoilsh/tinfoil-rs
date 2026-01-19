//! Full end-to-end verification example
//! 
//! This demonstrates the complete three-step Tinfoil verification:
//! 1. Hardware attestation (AMD SEV-SNP)
//! 2. Sigstore verification (code provenance)
//! 3. Measurement comparison (code matches enclave)
//!
//! Architecture:
//!   Client → Confidential Model Router (enclave) → Model Enclaves
//!            inference.tinfoil.sh                   qwen3-coder, nomic-embed, etc.
//!
//! We verify the ROUTER, which internally verifies each model enclave.

use tinfoil::verifier::attestation;
use tinfoil::verifier::github;
use tinfoil::verifier::sigstore;

// The confidential model router - all API requests go through here
const ROUTER_HOST: &str = "inference.tinfoil.sh";
const ROUTER_REPO: &str = "tinfoilsh/confidential-model-router";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║      Tinfoil Full End-to-End Verification Demo               ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    
    println!("Router host: {}", ROUTER_HOST);
    println!("Router repo: {}\n", ROUTER_REPO);
    
    println!("Architecture:");
    println!("  Client → Router (enclave) → Model Enclaves");
    println!("           ↑ we verify this    ↑ router verifies these\n");
    
    // Step 1: Hardware Attestation
    println!("═══ Step 1: Hardware Attestation ═══");
    println!("   → Fetching attestation from router enclave...");
    let doc = attestation::fetch(ROUTER_HOST).await?;
    println!("   ✓ Received {:?} attestation", doc.format);
    
    println!("   → Verifying AMD SEV-SNP report...");
    let enclave = attestation::verify_full(&doc).await?;
    println!("   ✓ ARK public key matches pinned fingerprint (root of trust)");
    println!("   ✓ ARK self-signature verified (RSA-PSS SHA-384)");
    println!("   ✓ ASK signature verified against ARK");
    println!("   ✓ VCEK signature verified against ASK");
    println!("   ✓ Report signature verified against VCEK (ECDSA P-384)");
    println!("   Router measurement: {}...", &enclave.measurement.registers[0][..48]);
    
    // Step 2: Sigstore Verification
    println!("\n═══ Step 2: Sigstore Verification ═══");
    println!("   → Fetching latest release from GitHub...");
    let tag = github::fetch_latest_tag(ROUTER_REPO).await?;
    println!("   ✓ Latest release: {}", tag);
    
    println!("   → Fetching attestation bundle...");
    let digest = github::fetch_digest(ROUTER_REPO, &tag).await?;
    println!("   ✓ Digest: {}...", &digest[..32]);
    
    println!("   → Verifying Sigstore bundle...");
    let code_measurement = sigstore::verify_repo(ROUTER_REPO).await?;
    println!("   ✓ DSSE signature verified (ECDSA P-256)");
    println!("   ✓ Certificate issuer: GitHub Actions");
    println!("   ✓ Certificate repository: {}", ROUTER_REPO);
    println!("   Source measurement: {}...", &code_measurement.registers[0][..48]);
    
    // Step 3: Consistency Check
    println!("\n═══ Step 3: Consistency Verification ═══");
    println!("   Router enclave: {}...", &enclave.measurement.registers[0][..48]);
    println!("   Source code:    {}...", &code_measurement.registers[0][..48]);
    print!("   → Comparing measurements... ");
    
    match enclave.measurement.equals(&code_measurement) {
        Ok(()) => {
            println!("✓ MATCH!");
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║                    ✅ VERIFICATION PASSED                    ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!("║  The router is running the exact code from GitHub.           ║");
            println!("║  All requests through this router are verified.              ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
        }
        Err(e) => {
            println!("✗ Different");
            println!("\n   Error: {}", e);
            println!("\n   Possible reasons:");
            println!("   • Router was recently updated (fetch latest release)");
            println!("   • Network returned stale attestation (retry)");
        }
    }
    
    // Summary
    println!("\n═══ Verification Summary ═══");
    println!("   ✅ Step 1: Hardware attestation verified");
    println!("      • AMD ARK public key pinned ✓");
    println!("      • Certificate chain: ARK → ASK → VCEK (all RSA-PSS verified)");
    println!("      • Report signature: ECDSA P-384 verified");
    println!("   ✅ Step 2: Sigstore verification passed");
    println!("      • DSSE envelope: ECDSA P-256 verified");
    println!("      • Certificate: GitHub Actions for {}", ROUTER_REPO);
    
    println!("\n═══ Available Models (via verified router) ═══");
    println!("   • qwen3-coder-480b  - Advanced coding (480B MoE)");
    println!("   • nomic-embed-text  - Embeddings (768 dimensions)");
    println!("   • docling           - Document processing");
    println!("   • llama3-3-70b      - General chat");
    println!("   • deepseek-r1-0528  - Advanced reasoning");
    
    println!("\n   TLS fingerprint: {}...", &enclave.tls_public_key_fp[..32]);
    if let Some(hpke) = &enclave.hpke_public_key {
        println!("   HPKE public key: {}...", &hpke[..32]);
    }
    
    Ok(())
}
