# Tinfoil Rust Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-rs/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-rs/actions)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/rust-sdk)

For complete documentation, see the [Rust SDK documentation](https://docs.tinfoil.sh/sdk/rust-sdk).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs" }
```

## Quick Start

The Tinfoil Rust client provides secure communication with Tinfoil enclaves. It has an OpenAI-compatible API with additional security features:

- Automatic attestation validation to ensure enclave integrity verification
- TLS certificate pinning using attested certificates to provide direct-to-enclave encrypted communication

```rust
use tinfoil::{SecureClient, ChatMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client
    let mut client = SecureClient::new_default_client("<YOUR_API_KEY>").await?;

    // Make requests using the OpenAI-compatible API
    // Note: enclave verification and TLS pinning happens automatically
    let response = client.chat(vec![
        ChatMessage::user("Say this is a test"),
    ]).await?;

    println!("{}", response.choices[0].message.content);

    Ok(())
}
```

## Usage

```rust
// 1. Create a client (automatically verifies and sets up TLS pinning)
let mut client = SecureClient::new_default_client(
    std::env::var("TINFOIL_API_KEY")?
).await?;

// 2. Use client with OpenAI-compatible API
let response = client.chat(vec![
    ChatMessage::user("Hello!"),
]).await?;
```

## Advanced Functionality

```rust
use tinfoil::{SecureClient, verifier::attestation, verifier::sigstore};

// For manual verification, create a client for a specific host
let mut client = SecureClient::new("inference.tinfoil.sh", "your-api-key");

// Manual verification
let ground_truth = client.verify().await?;
println!("Verified enclave: {:?}", ground_truth.enclave_fingerprint);

// Or perform step-by-step verification
let doc = attestation::fetch("inference.tinfoil.sh").await?;
let enclave = attestation::verify_full(&doc).await?;
println!("Hardware attestation verified");

let source = sigstore::verify_repo("tinfoilsh/confidential-model-router").await?;
enclave.measurement.equals(&source)?;
println!("Code provenance verified");
```

## API Documentation

This library provides an OpenAI-compatible API for use with Tinfoil enclaves. See the [Rust SDK documentation](https://docs.tinfoil.sh/sdk/rust-sdk) for complete API usage.

### Chat Completions

```rust
// Simple chat
let response = client.chat(vec![
    ChatMessage::user("What is 2+2?"),
]).await?;

// Chat with specific model
let response = client.chat_with_model("qwen3-coder-480b", vec![
    ChatMessage::system("You are a helpful assistant"),
    ChatMessage::user("Write a function to sort a vector"),
], None).await?;

// Chat with tools
let response = client.chat_with_tools(messages, tools).await?;
```

### Embeddings

```rust
let embedding = client.embed("text to embed").await?;
// Returns Vec<f32> with 768 dimensions
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
