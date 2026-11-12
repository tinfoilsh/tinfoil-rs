//! A router client with a verification policy of its own: a shorter
//! freshness window than the default, and a check that records every
//! verification that the client relies on.
//!
//! ```sh
//! TINFOIL_API_KEY=... cargo run -p tinfoil --example router_custom_verifier
//! ```

use std::sync::Arc;
use std::time::Duration;

use tinfoil::RouterHttpClient;
use tinfoil::verifier::Verifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One verifier can serve any number of clients.
    let verifier = Arc::new(
        Verifier::builder()
            .freshness_max_age(Duration::from_secs(3 * 24 * 60 * 60))
            .build()?,
    );

    let client = RouterHttpClient::builder()
        .verifier(Arc::clone(&verifier))
        // Called for each router that discovery tries, and again whenever
        // the client verifies its router. An error rejects the router.
        .verification_check(|verified| {
            println!(
                "verified {} at {} (tag {})",
                verified.config_repo(),
                verified.code_digest(),
                verified.code_tag(),
            );
            if verified.hpke_public_key().is_none() {
                return Err("this deployment requires an HPKE key".into());
            }
            Ok(())
        })
        .timeout(Duration::from_secs(120))
        .connect()
        .await?;

    println!("router: {}", client.enclave());

    let api_key = std::env::var("TINFOIL_API_KEY")?;

    let response = client
        .post(client.base_url().join("v1/chat/completions")?)
        .bearer_auth(api_key)
        .json(&serde_json::json!({
            "model": "gpt-oss-120b",
            "messages": [{"role": "user", "content": "Hello!"}],
        }))
        .send()
        .await?;
    println!("{}", response.text().await?);

    // The verification is renewed by the client when it expires. To renew
    // it now, for example after a deployment:
    let renewed = client.reverify().await?;
    println!("valid until {:?}", renewed.freshness_expires_at());

    Ok(())
}
