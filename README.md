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

The inference router partitions prompt-prefix caches using both the authenticated API identity and `user_cache_secret`. Cache reuse requires the same identity, secret, model, and matching prompt prefix. Changing the identity or secret selects a different cache namespace, so those requests do not share cache entries or cache-hit timing.

`user_cache_secret` is sensitive application data used only for cache partitioning. It is not an API credential or encryption key. Do not log or expose it unnecessarily: a caller who can send requests with the same API identity and secret joins that cache namespace and can observe its cache-hit timing. The SDK adds it to eligible request bodies before transport over the pinned connection to the verified enclave.

By default, the SDK generates a random secret and persists it at `~/.tinfoil/user_cache_secret`, requesting mode `0600` where supported. Tinfoil SDKs using the same home directory reuse this value. This default is suitable for a single-user application, but it does not separate end users who share one application process or home directory. You can control the scope explicitly:

```rust
// Pin a stable, non-empty, opaque secret for this client.
let client = Client::new_default().await?.with_user_cache_secret(secret);

// Or provision it via the environment
//   TINFOIL_USER_CACHE_SECRET=<secret>   use this value

// Multi-user services should scope every request to its end user;
// a non-empty string field set on the body wins over the client-level secret:
let body = client.chat_relaxed().request()
    .model("model-name")
    .push_message(serde_json::json!({"role": "user", "content": "Hello!"}))
    .set("user_cache_secret", per_user_secret)
    .build();
let response = client.chat_relaxed().create(body).await?;
```

Resolution order is a non-empty per-request string, a non-empty client value, a non-empty `TINFOIL_USER_CACHE_SECRET`, then the generated default. Empty client or environment values are treated as unset, and an empty per-request string is replaced with the resolved client value. The SDK leaves non-string values unchanged, and applications should not use them for cache scoping.

Multi-user services must provide a stable, non-empty, opaque value for each user (or group whose members may share cache-hit timing) on every eligible request. Do not use a raw user identifier, API key, or encryption key. A single client, environment, or generated value groups all requests using it under the same API identity. Requests hand-rolled through `http_client()` bypass automatic injection and must provide the field themselves. If persistence is unavailable, the SDK uses an in-memory value and cache continuity ends when the process exits.

## API Documentation

This library is a drop-in replacement for [async-openai](https://github.com/64bit/async-openai) that can be used with Tinfoil. All methods and types are identical. See the [async-openai documentation](https://docs.rs/async-openai) for complete API usage and documentation.

## Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.
