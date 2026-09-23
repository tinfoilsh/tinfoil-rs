# Tinfoil Rust Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-rs/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-rs/actions)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/rust-sdk)

A Rust client for verifiably private AI inference with Tinfoil. It wraps [async-openai](https://github.com/64bit/async-openai) with the same API, and before sending any request it verifies the enclave's attestation and pins the TLS connection to the attested certificate, so requests reach only the verified enclave. An [EHBP](https://docs.tinfoil.sh/resources/ehbp) proxy mode encrypts request bodies to the attested key for routing through your own backend.

For complete documentation, see the [Rust SDK documentation](https://docs.tinfoil.sh/sdk/rust-sdk).

## Installation

```toml
[dependencies]
tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs" }
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use tinfoil::Client;
use tinfoil::chat::{
    ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Reads TINFOIL_API_KEY from the environment
    let client = Client::new_default().await?;

    // Enclave verification and pinning happen automatically.
    let request = CreateChatCompletionRequestArgs::default()
        .model("llama3-3-70b") // see https://docs.tinfoil.sh/models/catalog
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

Request and response types live under `tinfoil::chat`, `tinfoil::audio`, and `tinfoil::embeddings`, re-exported from `async_openai::types`.

## Verification document

After verification, the client exposes the accepted repository, release, measurements, and verifier version:

```rust
let document = client.secure_client().verification_document().unwrap();
println!("{} {:?} {}", document.config_repo, document.release_tag, document.release_digest);
println!("{}", document.verified_at);
```

`verified_at` is recorded from the local clock after successful verification. It is not an attested timestamp or a freshness guarantee.

## Prompt Cache Scoping

The router partitions prompt caches by API identity and a `user_cache_secret` that the SDK adds to eligible requests. By default it generates one and persists it at `~/.tinfoil/user_cache_secret`, which is suitable for single-user applications. Multi-user services should scope each request to its end user:

```rust
// Pin a stable, opaque secret for this client (or set TINFOIL_USER_CACHE_SECRET).
let client = Client::new_default().await?.with_user_cache_secret(secret);

// A per-request value wins over the client-level secret.
let body = client.chat_relaxed().request()
    .model("llama3-3-70b")
    .push_message(serde_json::json!({"role": "user", "content": "Hello!"}))
    .set("user_cache_secret", per_user_secret)
    .build();
let response = client.chat_relaxed().create(body).await?;
```

Requests hand-rolled through `http_client()` bypass automatic injection and must set the field themselves. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching) for resolution order and guidance on choosing a scope.

## Advanced Functionality

```rust
// Target a specific enclave and repository
let client = Client::new("enclave.example.com", "org/repo", "<YOUR_API_KEY>").await?;

// Route through an EHBP proxy; bodies stay encrypted to the enclave
let client = Client::new_with_proxy("enclave.example.com", "org/repo", "<YOUR_API_KEY>", "https://your-proxy.example.com").await?;

// Make verified HTTP requests to the enclave directly (TLS mode only)
let http = client.http_client()?;
let resp = http.get(format!("https://{}/health", client.enclave())).send().await?;
```

`http_client()` returns an error in proxy mode so request bodies always remain sealed to the attested key.

## API Documentation

This library is a drop-in replacement for [async-openai](https://github.com/64bit/async-openai). All methods and types are identical; see the [async-openai documentation](https://docs.rs/async-openai) for API usage.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
