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

Releases are git tags of this repository. Depend on a tag, with the latest release tag from the repository's [releases page](https://github.com/tinfoilsh/tinfoil-rs/releases) in place of `<release tag>`:

```toml
[dependencies]
tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs", tag = "<release tag>" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

For the verifier alone:

```toml
[dependencies]
tinfoil-verifier = { git = "https://github.com/tinfoilsh/tinfoil-rs", tag = "<release tag>" }
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

The base URL must be absolute and use HTTPS, without credentials, a query string or a fragment. `http://` is accepted only for the name `localhost` and for a loopback IP address: `127.0.0.0/8` or `[::1]`. An IPv4 address must be written as four decimal numbers. The mode is the option and nothing else: a client never falls back from one mode to the other.

## Limits of the protection

- **EHBP mode does not authenticate the end of a response.** Each part of a sealed response body is authenticated, and so is the order of the parts, so the content cannot be forged, altered or reordered. Nothing marks the last part, though: whoever controls the connection (a proxy, for example) can end a sealed response early between two parts, or return one with no parts at all, and the read ends without an error. A response that is cut inside a part is an error. If you need to know that a response is complete, check its own terminator: that the JSON document is whole, or that the final event of a stream arrived. The SSE parser (`chat_relaxed().create_stream`, `sse::parse_event_stream`) reports a stream that is cut inside an event, and a stream that ends after a complete event without `[DONE]` ends without an error.
- **In EHBP mode a request without a body is sent as it is**, and its response is returned as it arrives: neither is encrypted or authenticated. An error response (a status outside `2xx`) to a sealed request that is not sealed itself is passed through as received, because a proxy may refuse a request before it reaches the enclave; its status, headers and body are not authenticated either. There are exceptions, none of which returns a response. A `2xx` response to a sealed request that is not sealed is refused. The enclave's key rejection (a `422` with the protocol's key-configuration problem) is not returned either: it is an attestation error, and after a new verification the client sends the request once more if its body can be sent again. A request whose streamed body turns out to be empty goes out unsealed but is held to the rules of a sealed one: a `2xx` response and any response that claims to be sealed are attestation errors. So is the key-configuration problem in answer to such a request, but it is not a key rejection, since nothing was sealed to a key: the current verification stays in place, the client does not verify again, and the request is not sent again.
- **Requests without a cache secret share one prompt-cache namespace** with every other request that carries none. No secret is added by an enclave client whose `user_cache_secret` option is unset; to a request that is not a `POST` with a body to a path ending in `/chat/completions`, `/completions` or `/responses`; to a body that is not a single JSON object; to a body in which `user_cache_secret` appears more than once or with a value that is not a string, which is sent as it is; or, on a router client without the option, when the operating system supplies no random bytes for the secret of the process. A non-empty `user_cache_secret` string in the body is kept.
- **The OpenAI clients bound the responses that are read into memory for you.** async-openai reads a response whole, and in EHBP mode an error response, or the response to a request without a body, can come from a proxy. A body beyond its limit is not cut short: the read fails with a network error (`Error::from_openai` finds it, except in a typed stream, whose errors hold a message only).

  | response | read into memory up to |
  |---|---|
  | an error response (any status outside `2xx`) of a typed or relaxed call | 1 MiB |
  | a successful response of a typed call, streamed or not, and of `chat_relaxed().create` | 64 MiB |
  | a stream of `chat_relaxed().create_stream` or `sse::parse_event_stream` | 16 MiB per line and per event; no limit on the whole stream |
  | a response of the HTTP clients | no limit: the caller reads the body |

  Within the 64 MiB of a typed stream, async-openai holds each event until it ends and reads ahead of the caller, without a limit of its own; `chat_relaxed().create_stream` bounds each event. To download something larger than 64 MiB (a file's content, for example), send the request through `http_client()` and read the body as a stream.
- **The router list is not trusted.** The list that `RouterHttpClient` discovers routers from is fetched over ordinary HTTPS and is only a list of candidates: every router is verified like any other enclave before it is used. A wrong list can cause failed attempts within the 30 seconds that discovery may take, after which `inference.tinfoil.sh` is verified; it cannot make the client use an enclave that does not pass verification.

## What verification covers

A verification passes only if all of the following hold. They are checked offline. The roots of trust are compiled into the verifier and cannot be replaced: the Sigstore trusted root, and the AMD and Intel roots for the hardware evidence. The rest of the policy has defaults that a `Verifier` of your own can replace: Tinfoil's public keys for config endorsements and for freshness approvals, the public registry as the only accepted config registry, the freshness window, and how a config is authorized (see [Custom verification policy](#custom-verification-policy)).

- **The hardware evidence is authentic.** The AMD SEV-SNP report or Intel TDX quote is signed by a key that chains to the vendor's root, and it satisfies the platform policy.
- **The evidence answers this request.** The document is bound to a fresh random nonce that the client sent.
- **The enclave runs what the pin names.** The enclave's measurement matches reference values that are themselves authenticated, through signed endorsements and the Sigstore trusted root, for the repository that the client pins. Without a pin (`None` on an enclave client), the enclave must run a config that the verifier's policy authorizes, which by default is one that Tinfoil signed into the public registry.
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

The other options replace a default of the policy: `config_signing_keys` (the keys that config endorsements must be signed with, in place of Tinfoil's), `freshness_signing_keys` (the keys that approve the runtime and the platform policy), `config_registry_ids` (the registries whose config endorsements are accepted, in place of the public one), `config_authorizer` (your own function decides which config is authorized, in place of endorsement verification), and `embedded_references` (reference values that you supply and trust yourself). None of them replaces the Sigstore, AMD or Intel roots. See the documentation of `tinfoil::verifier::VerifierBuilder`. To verify a document that you fetched yourself, call `Verifier::verify_v3`.

## Error handling

Errors of the SDK are `tinfoil::Error` values. `kind()` says what to do about one:

| `ErrorKind` | meaning | what to do |
|---|---|---|
| `Configuration` | Invalid options, or a request that the client cannot protect (another origin, a reserved header). | Fix the caller; retrying will not help. |
| `Network` | The client could not reach what it needed, or a deadline passed (`is_timeout()`). | Retry later with the same client. |
| `Attestation` | The enclave could not be trusted, or its answer could not be authenticated. | The client verifies again on the next request. A failure that persists deserves an investigation. |

An attestation error from a verification (`connect`, `ensure_verified`, `reverify`, or the verification before a request: rejected evidence, a refusal by `verification_check`, no key for the transport mode) means that nothing was sent. In TLS mode the only other attestation error is a server certificate that fails the standard checks or lacks the attested key, which fails the handshake before the request is written; so in TLS mode no attestation error leaves a request delivered. In EHBP mode an attestation error can also arise after the sealed request has left: the answer says that the enclave does not hold the key, a success response carries no valid proof that the enclave sent it, or a part of the response body does not authenticate while it is read. Nobody else could read the request, but the enclave may have received it and acted on it. Send requests that must not take effect twice with an idempotency key, or check what became of them before sending them again.

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

`Error::from_openai` finds the SDK's error in every call that fails before its response arrives, in calls whose response is read whole, and at any point in `chat_relaxed()` calls and streams. It does not find it in a stream of a typed call (`chat().create_stream(..)` and the like) that fails after it started: such a stream still ends with an error and delivers nothing after it, but async-openai keeps only a message (`OpenAIError::StreamError`), so an attestation failure, a broken connection and a deadline cannot be told apart there. Use `chat_relaxed().create_stream(..)` where that matters.

See also the [error handling guide](https://docs.tinfoil.sh/sdk/error-handling).

## Timeouts and retries

**Deadlines.** By default a client sets no overall deadline. The builders' `timeout(duration)` bounds each operation of the client: `connect`, each `ensure_verified` and `reverify`, and each request from the call until the response body has been read, including the wait for a verification that the request needs. A request's own `timeout` replaces it for that request. On the OpenAI clients it bounds each request that a call sends and each wait between two attempts, not the call as a whole: a call has up to three attempts and two waits, so it can take several times the timeout. Dropping a future cancels its operation.

These bounds are fixed:

| operation | bound |
|---|---|
| fetching an attestation document | 30 seconds, 32 MiB |
| router discovery (the list and every router that is tried) | 30 seconds in all; then `inference.tinfoil.sh` is verified |
| an event of a relaxed chat stream | 16 MiB per line and per event |
| a response body on the OpenAI clients | 1 MiB for an error response, 64 MiB for a successful one (see [Limits of the protection](#limits-of-the-protection)) |

**Retries.**

- A verification that fails with a network or attestation error is tried once more after one second. A configuration error and a rejection by `verification_check` are not tried again. During discovery, each listed router gets a single verification.
- A request that the enclave rejects because its keys changed is sent once more after a new verification, if its body can be sent again. A streamed body cannot; the OpenAI clients rebuild an upload once.
- The OpenAI clients send a call again at most twice (three attempts) when the response has status `429` or `5xx`. The wait is half a second before the first retry and one second before the second, each shortened at random by up to a quarter. A response can name the wait itself, in `Retry-After-Ms` (milliseconds) or `Retry-After` (seconds, or a date in the form `Sun, 06 Nov 1994 08:49:37 GMT`; a date in another form is ignored, and the backoff applies); it is obeyed up to two minutes, or up to the `timeout` option if that is shorter. A response that asks for a longer wait is not tried again, and the call returns its error at once. A `429` whose error is `insufficient_quota` is not tried again; any other `429` is, also one whose body is not the API's error object, is larger than 1 MiB or cannot be read. An error of the SDK itself (a refused verification, a refused request, a failed connection, a deadline) is reported once. Nothing is tried again once a stream has started.
- The HTTP clients do not retry on a status code.

## More on the OpenAI clients

- `chat_relaxed()` sends and returns raw JSON, for request fields and response events that async-openai's types do not model (web search, vendor events). Its stream ends at `[DONE]`, and fails if the response ends inside an event.
- `transcribe(request)` and `embed_batch(model, inputs)` are shortcuts; `embed_batch` returns one vector for each input, in input order.
- `tinfoil::multimodal` builds image and audio content parts from files and bytes.
- `tinfoil::sse::parse_event_stream` is the bounded server-sent-event parser, for streaming endpoints that you call through an HTTP client.

**Prompt caching.** Multi-user services must scope prompt caches to each end user: set `user_cache_secret(..)` on the builder, or a `user_cache_secret` member in a request's JSON body, which wins. When the option is unset, the router clients use a random secret that is generated in memory once per process and that every router client in the process shares, so prompt-cache hits are not shared across processes; the enclave clients add nothing. The SDK never reads the secret from the environment or from a file: an application that wants a secret that stays the same across processes or machines stores it itself and passes it as the option. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).

## Cargo features

| feature | default | what it adds |
|---|---|---|
| `openai` | yes | The OpenAI clients over async-openai, with its chat completion, embedding, audio and responses APIs; `chat_relaxed`; the `sse` and `multimodal` modules. Without it the crate is the HTTP clients and the verifier. |
| `openai-<family>` | no | One further API family of async-openai on the OpenAI clients; each implies `openai`. The families: `administration`, `batches`, `byot`, `chatkit`, `completions`, `containers`, `content-provenance-checks`, `evals`, `files`, `fine-tuning`, `images`, `models`, `moderations`, `safety`, `skills`, `uploads`, `vector-stores`. |

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

`conformance/` is a test tool that runs the verifier over shared test vectors; it is not part of a release. `scripts/sync_trust.py` regenerates the trust material that is embedded in the verifier: the Sigstore, AMD and Intel roots, and Tinfoil's default signing key.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
