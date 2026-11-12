//! An HTTP client for one enclave: first with the defaults, then
//! configured to send sealed bodies through a proxy.
//!
//! ```sh
//! TINFOIL_API_KEY=... cargo run -p tinfoil --example enclave_http
//! ```
//!
//! The second part runs only when `TINFOIL_PROXY_URL` names a proxy that
//! forwards to the enclave, for example `https://proxy.example.com/tinfoil/`.

use std::time::Duration;

use tinfoil::{EnclaveHttpClient, ErrorKind, TransportMode};

const ENCLAVE: &str = "inference.tinfoil.sh";
const REPO: &str = "tinfoilsh/confidential-model-router";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = api_key()?;

    // The enclave is verified before `connect` returns.
    let client = EnclaveHttpClient::connect(ENCLAVE, Some(REPO)).await?;

    let verified = client.current();
    println!("enclave:     {}", client.enclave());
    println!("code digest: {}", verified.code_digest());
    println!("TLS key:     {:?}", verified.tls_public_key_fp());

    // Requests use reqwest's types and go only to the verified enclave.
    let models = client
        .get(client.base_url().join("v1/models")?)
        .bearer_auth(&api_key)
        .send()
        .await?;
    println!("{}", models.text().await?);

    // A request to any other origin is refused before anything is sent.
    match client.get("https://example.com/").send().await {
        Err(error) if error.kind() == ErrorKind::Configuration => println!("refused: {error}"),
        other => println!("unexpected: {other:?}"),
    }

    // Configured: bodies are sealed to the enclave's HPKE key and travel
    // through a proxy, which sees only the method, the URL and the headers.
    let Ok(proxy_url) = std::env::var("TINFOIL_PROXY_URL") else {
        println!("set TINFOIL_PROXY_URL to send a sealed request through a proxy");
        return Ok(());
    };
    let proxied = EnclaveHttpClient::builder(ENCLAVE, Some(REPO))
        .transport_mode(TransportMode::Ehbp)
        .base_url(proxy_url)
        .timeout(Duration::from_secs(60))
        .connect()
        .await?;

    let response = proxied
        .post(proxied.base_url().join("v1/chat/completions")?)
        // Headers are not sealed: the proxy sees this one.
        .bearer_auth(&api_key)
        .json(&serde_json::json!({
            "model": "gpt-oss-120b",
            "messages": [{"role": "user", "content": "Hello!"}],
        }))
        .send()
        .await?;
    println!("{}", response.status());

    Ok(())
}

/// The API key from the environment, or an error that says what to set.
fn api_key() -> Result<String, Box<dyn std::error::Error>> {
    match std::env::var("TINFOIL_API_KEY") {
        Ok(key) if !key.is_empty() => Ok(key),
        _ => Err("set the TINFOIL_API_KEY environment variable to a Tinfoil API key".into()),
    }
}
