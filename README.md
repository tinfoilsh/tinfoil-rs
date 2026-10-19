# Tinfoil Rust Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-rs/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-rs/actions)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/rust-sdk)

A Rust client for verifiably private AI inference with Tinfoil. It wraps [async-openai](https://github.com/64bit/async-openai) with the same API, and before sending any request it verifies the enclave's attestation and pins the TLS connection to the attested certificate, so requests reach only the verified enclave. An [EHBP](https://docs.tinfoil.sh/resources/ehbp) proxy mode encrypts request bodies to the attested key for routing through your own backend.

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
        .model("gpt-oss-120b") // see https://docs.tinfoil.sh/models/chat
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

## Documentation

- [Rust SDK documentation](https://docs.tinfoil.sh/sdk/rust-sdk) and [error handling](https://docs.tinfoil.sh/sdk/error-handling).
- Multi-user services must scope prompt caches to each end user with `with_user_cache_secret` or a per-request `user_cache_secret`. Requests sent through `http_client()` do not get the field added automatically. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).
- `Client::new_with_proxy` routes through your own backend with request bodies sealed to the enclave; see the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server). `http_client()` is unavailable in that mode.
- All OpenAI methods and types are unchanged; see the [async-openai documentation](https://docs.rs/async-openai).

## Development

```bash
cargo test --lib
cargo test --test '*'
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
