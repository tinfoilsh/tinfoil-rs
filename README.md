# Tinfoil Rust Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-rs/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-rs/actions)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/rust-sdk)

For complete documentation, see the [Rust SDK documentation](https://docs.tinfoil.sh/sdk/rust-sdk).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs" }
tokio = { version = "1", features = ["full"] }
```

## Quick Start

The Tinfoil Rust client is a wrapper around [async-openai](https://github.com/64bit/async-openai) and provides secure communication with Tinfoil enclaves. It has the same API as the async-openai client, with additional security features:

- Automatic attestation validation to ensure enclave integrity verification
- Supports [Encrypted HTTP Body Protocol](https://docs.tinfoil.sh/resources/ehbp) to provide direct-to-enclave encrypted communication with attested public keys
- Supports a fallback mode with TLS certificate pinning using attested certificates to provide direct-to-enclave encrypted communication over TLS

```rust
use tinfoil::Client;
use tinfoil::async_openai::types::{
    ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client
    let client = Client::new_default("<YOUR_API_KEY>").await?;

    // Make requests using the OpenAI client API
    // Note: enclave verification and direct-to-enclave encryption happens automatically
    let request = CreateChatCompletionRequestArgs::default()
        .model("llama3-3-70b")
        .messages(vec![
            ChatCompletionRequestUserMessageArgs::default()
                .content("Say this is a test")
                .build()?
                .into(),
        ])
        .build()?;

    let response = client.chat().create(request).await?;

    println!("{}", response.choices[0].message.content.as_ref().unwrap());

    Ok(())
}
```

## Usage

```rust
// 1. Create a client
let client = Client::new_default(
    std::env::var("TINFOIL_API_KEY")?
).await?;

// 2. Use client as you would async_openai::Client
// see https://docs.rs/async-openai for API documentation
```

## Advanced Functionality

```rust
use tinfoil::{Client, SecureClient};

// Create a client with explicit enclave and repo parameters
let client = Client::new(
    "enclave.example.com",
    "org/repo",
    "<YOUR_API_KEY>",
).await?;

// For direct HTTP access, use the underlying http_client
let http = client.http_client()?;
let resp = http
    .get(format!("https://{}/health", client.enclave()))
    .send()
    .await?;
```

## API Documentation

This library is a drop-in replacement for [async-openai](https://github.com/64bit/async-openai) that can be used with Tinfoil. All methods and types are identical. See the [async-openai documentation](https://docs.rs/async-openai) for complete API usage and documentation.

## Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.
