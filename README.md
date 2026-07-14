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
- Supports a fallback mode with TLS certificate pinning using attested certificates to provide direct-to-enclave encrypted communication over TLS

```rust
use tinfoil::Client;
use tinfoil::chat::{
    ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client (reads TINFOIL_API_KEY from env)
    let client = Client::new_default().await?;

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

The common request/response types live under `tinfoil::chat`, `tinfoil::audio`,
and `tinfoil::embeddings` — all of which are re-exports of the corresponding
`async_openai::types::*` modules.

## Usage

```rust
// 1. Create a client (reads TINFOIL_API_KEY from env)
let client = Client::new_default().await?;

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

## Prompt Cache Scoping

The inference router partitions its prompt cache per API identity, so your cached prompts are never observable by other tenants. Within your tenant, the SDK scopes caching further with a `user_cache_secret`: requests carrying the same secret share cached prompt prefixes, requests carrying different secrets cannot observe each other's cache timing. The secret never reaches the model — the router consumes it to derive the cache namespace and strips it from the request.

By default the SDK generates a random secret and persists it at `~/.tinfoil/user_cache_secret` (mode `0600`, shared with the other Tinfoil SDKs on the same machine), so caching just works with per-machine scoping. You can control it explicitly:

```rust
// Pin the secret for this client (e.g. one stable value per end user)
let client = Client::new_default().await?.with_user_cache_secret(secret);

// Or provision it via the environment
//   TINFOIL_USER_CACHE_SECRET=<secret>   use this value

// Servers that hold many end users' conversations should scope per request;
// a non-empty field set on the body wins over the client-level secret:
let body = client.chat_relaxed().request()
    .model("model-name")
    .push_message(serde_json::json!({"role": "user", "content": "Hello!"}))
    .set("user_cache_secret", per_user_secret)
    .build();
let response = client.chat_relaxed().create(body).await?;
```

Empty client or environment values are treated as unset. If the secret cannot be persisted (no home directory, read-only filesystem), the SDK falls back to an in-memory secret and warns once: cache continuity then resets on every process restart. Requests hand-rolled through `http_client()` must provide `user_cache_secret` in eligible request bodies themselves. Containerized deployments should set `TINFOIL_USER_CACHE_SECRET` to a stable non-empty value wherever cache sharing is intended.

## API Documentation

This library is a drop-in replacement for [async-openai](https://github.com/64bit/async-openai) that can be used with Tinfoil. All methods and types are identical. See the [async-openai documentation](https://docs.rs/async-openai) for complete API usage and documentation.

## Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.
