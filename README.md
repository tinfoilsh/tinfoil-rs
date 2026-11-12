# Tinfoil Rust SDK

[![Build Status](https://github.com/tinfoilsh/tinfoil-rs/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-rs/actions)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/rust-sdk)

A Rust client for verifiably private AI inference with Tinfoil. Before a client sends anything, it fetches the enclave's attestation document, verifies it, and binds its traffic to the keys that the verified document endorses, so that requests reach that enclave and nothing else.

The repository holds two crates:

| crate | what it is |
|---|---|
| `tinfoil` (`crates/client`) | The attested HTTP clients, and OpenAI clients that wrap [async-openai](https://github.com/64bit/async-openai) with the same API. It re-exports the verifier as `tinfoil::verifier`. |
| `tinfoil-verifier` (`crates/verifier`) | Offline verification of attestation documents. It opens no connections, reads no files and needs no async runtime, and it can be used alone. |

Coming from 0.2? See [MIGRATION.md](MIGRATION.md).

## Installation

Releases are git tags of this repository. Depend on a tag:

```toml
[dependencies]
tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs", tag = "v0.3.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

For the verifier alone:

```toml
[dependencies]
tinfoil-verifier = { git = "https://github.com/tinfoilsh/tinfoil-rs", tag = "v0.3.0" }
```

The clients need a Tokio runtime. There is no blocking API.

## Quick start

```rust,no_run
use tinfoil::Client;
use tinfoil::async_openai::config::OpenAIConfig;
use tinfoil::chat::{ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("TINFOIL_API_KEY")?;

    // Discovers Tinfoil's router and verifies it before returning.
    let client = Client::connect(OpenAIConfig::new().with_api_key(api_key)).await?;

    let request = CreateChatCompletionRequestArgs::default()
        .model("gpt-oss-120b") // see https://docs.tinfoil.sh/models/chat
        .messages([ChatCompletionRequestUserMessageArgs::default()
            .content("Say this is a test")
            .build()?
            .into()])
        .build()?;

    let response = client.chat().create(request).await?;
    for choice in response.choices {
        println!("{}", choice.message.content.unwrap_or_default());
    }
    Ok(())
}
```

`Client` dereferences to `async_openai::Client`, so the whole async-openai API is available on it, streaming included. Request and response types are re-exported as `tinfoil::chat`, `tinfoil::audio` and `tinfoil::embeddings`, and the crates themselves as `tinfoil::async_openai` and `tinfoil::reqwest`, so that the types in the API are the ones that the SDK was built with.

The API key travels only in the `OpenAIConfig` that you pass. The SDK reads no API key from the environment. (`OpenAIConfig::new()` itself reads `OPENAI_API_KEY`; `with_api_key` replaces what it read.)

## Clients

| route | HTTP client | OpenAI client |
|---|---|---|
| Tinfoil's router, discovered (recommended) | `RouterHttpClient` | `Client`, or `RouterOpenAIClient` to configure it |
| an enclave that you name | `EnclaveHttpClient` | `EnclaveOpenAIClient` |

Every client:

- is created by `connect(..)`, with the defaults, or by `builder(..)` followed by setters and `connect()`. Options are checked before any network I/O, and the enclave is verified before `connect` returns;
- verifies the enclave again by itself when the verification expires or the enclave's key changes;
- refuses a request to any origin other than the one that it is bound to;
- is a cheap-to-clone handle, `Send` and `Sync`, with methods on `&self`. There is nothing to close, and no background task runs.

### HTTP clients

The HTTP clients send requests with `reqwest`'s types: `get`, `post`, `put`, `patch`, `delete`, `head` and `request` return a request builder, and `execute` takes a `reqwest::Request`. URLs are absolute.

```rust,no_run
use tinfoil::EnclaveHttpClient;

async fn list_models(api_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    // A host (not a URL), and the repository that its code must come from.
    let client = EnclaveHttpClient::connect(
        "inference.tinfoil.sh",
        Some("tinfoilsh/confidential-model-router"),
    )
    .await?;

    let verified = client.current();
    println!("code digest: {}", verified.code_digest());
    println!("TLS key:     {:?}", verified.tls_public_key_fp());

    let response = client
        .get(client.base_url().join("v1/models")?)
        .bearer_auth(api_key)
        .send()
        .await?;
    Ok(response.text().await?)
}
```

`RouterHttpClient::connect()` takes no host: it tries the routers of Tinfoil's published list in order and keeps the first that passes verification, or else `inference.tinfoil.sh`.

On every client, `current()` returns the last successful verification without checking it, `ensure_verified()` returns one that is valid now (verifying first if needed), and `reverify()` verifies again unconditionally. On the OpenAI clients, `http_client()` returns the HTTP client underneath, for these methods and for raw requests.

Redirects are not followed on attested requests: a `3xx` response is returned to the caller.

## Transport modes

| mode | what is protected | when to use it |
|---|---|---|
| `TransportMode::Tls` (default) | The whole request and response. Every connection is pinned to the attested TLS key: the standard certificate checks run, then the server's public key is compared with the attested fingerprint, on every handshake. | A direct connection to the enclave. |
| `TransportMode::Ehbp` | Request and response bodies, which are sealed to the attested HPKE key ([EHBP](https://docs.tinfoil.sh/resources/ehbp)). The method, the URL and the headers are **not** sealed, and neither is a request without a body or the response to it. | Routing through your own backend or another proxy. |

A `base_url` on another origin than the enclave is a proxy, and requires `TransportMode::Ehbp`. Requests to it carry the header `X-Tinfoil-Enclave-Url`, so that the proxy knows where to forward them. The proxy sees the headers of every request, an API key among them. See the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).

```rust,no_run
use std::time::Duration;

use tinfoil::async_openai::config::OpenAIConfig;
use tinfoil::{RouterOpenAIClient, TransportMode};

async fn through_a_proxy(api_key: &str) -> Result<RouterOpenAIClient, tinfoil::Error> {
    // The key is sent in a header, which the proxy can read and replace.
    let config = OpenAIConfig::new().with_api_key(api_key);
    RouterOpenAIClient::builder(config)
        .transport_mode(TransportMode::Ehbp)
        .base_url("https://api.example.com/tinfoil/v1/")
        .timeout(Duration::from_secs(120))
        .connect()
        .await
}
```

The base URL must be absolute and use HTTPS (`http://` is accepted for `localhost` and loopback addresses only), without credentials, a query string or a fragment. The mode is the option and nothing else: a client never falls back from one mode to the other.

## What verification covers

A verification passes only if all of the following hold. They are checked offline, against trust anchors that are compiled into the verifier.

- **The hardware evidence is authentic.** The AMD SEV-SNP report or Intel TDX quote is signed by a key that chains to the vendor's root, and it satisfies the platform policy.
- **The evidence answers this request.** The document is bound to a fresh random nonce that the client sent.
- **The enclave runs what the pin names.** The enclave's measurement matches reference values that are themselves authenticated, through signed endorsements and the Sigstore trusted root, for the repository that the client pins. Without a pin (`None` on an enclave client), the enclave must run a config that Tinfoil's public registry authorizes.
- **The evidence is fresh.** The signed freshness proofs are no older than the freshness window (seven days by default), and the verification expires when they stop vouching for the document.
- **The keys belong to the enclave.** The TLS key fingerprint and the HPKE key that the client binds its traffic to are part of what the hardware signed.

The result is a `tinfoil::verifier::Verification`: the code digest and tag, the measurements, the endorsed keys, and when the verification expires. `to_json()` serializes it. A rejected document is an error that names the layer that rejected it: `envelope`, `provenance`, `quote` or `policy`.

## Custom verification policy

A `Verifier` holds the policy. Build one to pin measurement registers or to change the freshness window, and add a `verification_check` to veto a verification that the verifier accepted. One verifier can serve any number of clients.

```rust,no_run
use std::sync::Arc;
use std::time::Duration;

use tinfoil::RouterHttpClient;
use tinfoil::verifier::{Expected, Verifier};

async fn connect_pinned(launch_digest: &str) -> Result<RouterHttpClient, Box<dyn std::error::Error>> {
    let verifier = Arc::new(
        Verifier::builder()
            // Only an SEV-SNP enclave with this launch measurement passes.
            .pinned_registers(Expected::parse_sev_snp(launch_digest)?)
            // Accept freshness evidence up to three days old.
            .freshness_max_age(Duration::from_secs(3 * 24 * 60 * 60))
            .build()?,
    );

    let client = RouterHttpClient::builder()
        .verifier(verifier)
        // Called for every verification that the client is about to rely
        // on. An error rejects the enclave.
        .verification_check(|verified| {
            println!("verified {} at {}", verified.config_repo(), verified.code_digest());
            if verified.hpke_public_key().is_none() {
                return Err("this deployment requires an HPKE key".into());
            }
            Ok(())
        })
        .connect()
        .await?;
    Ok(client)
}
```

The verifier has further options, among them your own config signing keys, a config authorizer, and embedded references for a config that you pin yourself; see the documentation of `tinfoil::verifier::VerifierBuilder`. To verify a document that you fetched yourself, call `Verifier::verify_v3`.

## Error handling

Errors of the SDK are `tinfoil::Error` values. `kind()` says what to do about one:

| `ErrorKind` | meaning | what to do |
|---|---|---|
| `Configuration` | Invalid options, or a request that the client cannot protect (another origin, a reserved header). | Fix the caller; retrying will not help. |
| `Network` | The client could not reach what it needed, or a deadline passed (`is_timeout()`). | Retry later with the same client. |
| `Attestation` | The enclave could not be trusted. Nothing was sent to it. | The client verifies again on the next request. A failure that persists deserves an investigation. |

The message starts with the kind, as in `attestation error: ...`, and `source()` returns the underlying error.

Calls of the async-openai API return async-openai's `OpenAIError`, and a response body is read with `reqwest`'s methods, which return `reqwest::Error`. `Error::from_openai` and `Error::from_reqwest` return the SDK's error inside either, if there is one:

```rust,no_run
use tinfoil::async_openai::error::OpenAIError;
use tinfoil::{Error, ErrorKind};

fn report(error: &OpenAIError) {
    match Error::from_openai(error) {
        Some(cause) if cause.kind() == ErrorKind::Attestation => {
            eprintln!("the enclave could not be verified: {cause}");
        }
        Some(cause) if cause.is_timeout() => eprintln!("timed out: {cause}"),
        // The message starts with the kind: "network error: ...".
        Some(cause) => eprintln!("{cause}"),
        // The API answered with an error, or async-openai failed.
        None => eprintln!("API error: {error}"),
    }
}

async fn read(response: tinfoil::reqwest::Response) -> Option<String> {
    match response.text().await {
        Ok(text) => Some(text),
        Err(error) => {
            // In EHBP mode, a body that stops authenticating is an
            // attestation error; a broken connection is a network error.
            match Error::from_reqwest(&error) {
                Some(cause) => eprintln!("{cause}"),
                None => eprintln!("{error}"),
            }
            None
        }
    }
}
```

See also the [error handling guide](https://docs.tinfoil.sh/sdk/error-handling).

## Timeouts and retries

**Deadlines.** By default a client sets no overall deadline. The builders' `timeout(duration)` bounds each operation of the client: `connect`, each `ensure_verified` and `reverify`, and each request from the call until the response body has been read, including the wait for a verification that the request needs. A request's own `timeout` replaces it for that request. On the OpenAI clients it bounds each attempt of a call, not the backoff between attempts. Dropping a future cancels its operation.

These bounds are fixed:

| operation | bound |
|---|---|
| fetching an attestation document | 30 seconds, 32 MiB |
| router discovery (the list and every router that is tried) | 30 seconds in all; then `inference.tinfoil.sh` is verified |
| an event of a relaxed chat stream | 16 MiB per line and per event |

**Retries.**

- A verification that fails with a network or attestation error is tried once more after one second. A configuration error and a rejection by `verification_check` are not tried again. During discovery, each listed router gets a single verification.
- A request that the enclave rejects because its keys changed is sent once more after a new verification, if its body can be sent again. A streamed body cannot; the OpenAI clients rebuild an upload once.
- The OpenAI clients send a call again at most twice (three attempts) when the response has status `429` or `5xx`, after a backoff or the response's `Retry-After`. An error of the SDK itself (a refused verification, a refused request, a failed connection, a deadline) is reported once. Nothing is tried again once a stream has started.
- The HTTP clients do not retry on a status code.

## More on the OpenAI clients

- `chat_relaxed()` sends and returns raw JSON, for request fields and response events that async-openai's types do not model (web search, vendor events). Its stream ends at `[DONE]`, and fails if the response ends inside an event.
- `transcribe(request)` and `embed_batch(model, inputs)` are shortcuts; `embed_batch` returns one vector for each input, in input order.
- `tinfoil::multimodal` builds image and audio content parts from files and bytes.
- `tinfoil::sse::parse_event_stream` is the bounded server-sent-event parser, for streaming endpoints that you call through an HTTP client.

**Prompt caching.** Multi-user services must scope prompt caches to each end user: set `user_cache_secret(..)` on the builder, or a `user_cache_secret` member in a request's JSON body, which wins. When the option is unset, the router clients take the secret from `TINFOIL_USER_CACHE_SECRET` or from `~/.tinfoil/user_cache_secret`, which they create on first use; the enclave clients add nothing. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).

## Cargo features

| feature | default | what it adds |
|---|---|---|
| `openai` | yes | The OpenAI clients over async-openai, with its chat completion, embedding, audio and responses APIs; `chat_relaxed`; the `sse` and `multimodal` modules. Without it the crate is the HTTP clients and the verifier. |
| `openai-<family>` | no | One further API family of async-openai on the OpenAI clients; each implies `openai`. The families: `administration`, `batches`, `byot`, `chatkit`, `completions`, `containers`, `content-provenance-checks`, `evals`, `files`, `fine-tuning`, `images`, `models`, `moderations`, `safety`, `skills`, `uploads`, `vector-stores`. |
| `unstable-gateway` | no | **Experimental and not implemented.** The types of a gateway route, whose calls fail with an error that says so. Do not enable it; it may change or be removed in any release. |

Every call of an enabled family goes through the attested client. async-openai's realtime API is not offered, because it opens WebSocket connections of its own that the attested client cannot protect. One helper of async-openai makes a request of its own: `ImagesResponse::save` (`openai-images`) downloads with a plain HTTP client, and that download is not attested.

`tinfoil-verifier` has one feature, `serde`, which implements `serde::Serialize` for `Verification` and the measurement types.

## Platform support

- Linux, macOS and Windows (MSVC), each tested in CI.
- The minimum supported Rust version is **1.88**.
- TLS is [rustls](https://github.com/rustls/rustls) with the `ring` provider. The SDK needs no OpenSSL and no C toolchain beyond what `ring` needs, and it links on Windows MSVC.
- Root certificates are compiled in. The operating system's trust store is not read.
- HTTP/2 is negotiated when the server offers it.
- WebAssembly targets are not supported.

## Examples

The examples are in [`crates/client/examples`](crates/client/examples):

```sh
TINFOIL_API_KEY=... cargo run -p tinfoil --example openai_drop_in
TINFOIL_API_KEY=... cargo run -p tinfoil --example enclave_http
TINFOIL_API_KEY=... cargo run -p tinfoil --example router_custom_verifier
```

## Development

```sh
cargo test --workspace
cargo test -p tinfoil --no-default-features
cargo test -p tinfoil --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

The code examples of this README are compiled as documentation tests of the `tinfoil` crate.

`conformance/` is a test tool that runs the verifier over shared test vectors; it is not part of a release. `scripts/sync_trust.py` regenerates the trust anchors that are embedded in the verifier.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
