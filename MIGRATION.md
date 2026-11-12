# Migrating from 0.2 to 0.3

Version 0.3 is a rewrite of the SDK around a new attestation format and a new
client design. The 0.2 names are removed, without aliases. This guide maps each
of them to its replacement and lists the behaviour that changed under names that
stayed.

The README describes the new API in full; the code below shows only the
differences.

## What changed, in short

- **Two crates.** `tinfoil` holds the clients; `tinfoil-verifier` holds the
  verifier, which does no I/O. `tinfoil::verifier` is now a re-export of
  `tinfoil-verifier`, with a new API.
- **Constructors are `connect`, and they verify.** A client that exists has
  been verified. There is no unverified client to call `verify()` on.
- **Configuration is a builder.** `Type::builder(..)`, setters, `connect()`.
  An option is unset until its setter is called; an empty string is an error,
  not "unset".
- **Clients re-verify by themselves**, in both transport modes, when the
  verification expires or the enclave's key changes. All methods take `&self`,
  and clients are cheap to clone.
- **The API key is yours to pass.** The SDK no longer reads `TINFOIL_API_KEY`.
- **Errors have a kind** instead of seventeen variants.
- **The verification document is gone.** A `Verification` carries the verified
  facts, and a failure names the layer that rejected the document.

## Dependency

```toml
# 0.2
tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs", tag = "v0.2.3" }

# 0.3
tinfoil = { git = "https://github.com/tinfoilsh/tinfoil-rs", tag = "v0.3.0" }
```

The minimum supported Rust version is still 1.88. The package is still named
`tinfoil`; it now lives in `crates/client`, which Cargo finds by name.

async-openai moves from 0.41 to 0.42. Use the re-exports (`tinfoil::async_openai`,
`tinfoil::chat`, `tinfoil::audio`, `tinfoil::embeddings`) rather than a
dependency of your own, so that the versions cannot differ.

The OpenAI clients are behind the cargo feature `openai`, which is on by
default. With `default-features = false` the crate is the HTTP clients and the
verifier only.

## The drop-in client

### `Client::new_default()`, `Client::new_default_with_api_key(key)`

The environment is no longer read. Pass the key in an `OpenAIConfig`:

```rust,ignore
// 0.2
let client = tinfoil::Client::new_default().await?;

// 0.3
use tinfoil::async_openai::config::OpenAIConfig;

let api_key = std::env::var("TINFOIL_API_KEY")?;
let client = tinfoil::Client::connect(OpenAIConfig::new().with_api_key(api_key)).await?;
```

`Client::connect` discovers and verifies Tinfoil's router, as `new_default`
did. It takes no other options; use `RouterOpenAIClient::builder(config)` to
set a transport mode, a verifier, a timeout or a cache secret on the same
route.

The `OpenAIConfig` also carries the organization, the project and extra
headers. Its API base is always replaced with the attested route.

### `Client::new(enclave, repo, api_key)`

```rust,ignore
// 0.2
let client = tinfoil::Client::new(
    "inference.tinfoil.sh",
    "tinfoilsh/confidential-model-router",
    api_key,
)
.await?;

// 0.3
use tinfoil::EnclaveOpenAIClient;
use tinfoil::async_openai::config::OpenAIConfig;

let client = EnclaveOpenAIClient::connect(
    "inference.tinfoil.sh",
    Some("tinfoilsh/confidential-model-router"),
    OpenAIConfig::new().with_api_key(api_key),
)
.await?;
```

The repository is an `Option<&str>`: `None` sets no pin, and `Some("")` is an
error.

### `Client::new_with_proxy(enclave, repo, api_key, proxy_url)`

Proxy mode is a transport mode plus a base URL, on any client:

```rust,ignore
// 0.2
let client = tinfoil::Client::new_with_proxy(enclave, repo, api_key, proxy_url).await?;

// 0.3
use tinfoil::{EnclaveOpenAIClient, TransportMode};

let client = EnclaveOpenAIClient::builder(enclave, Some(repo), config)
    .transport_mode(TransportMode::Ehbp)
    .base_url(proxy_url)
    .connect()
    .await?;
```

The OpenAI client uses the base URL verbatim as its API base, so include the
path that your proxy serves the API under (for example `…/v1/`). The base URL
must be HTTPS (or `http://` on localhost), without credentials, a query string
or a fragment. With the router, `RouterOpenAIClient::builder(config)` takes
the same two setters, and the router that discovery chooses is named to the
proxy in the `X-Tinfoil-Enclave-Url` header.

### `Client::verify(&mut self)`

Not needed after construction. To check or renew a verification:

```rust,ignore
// 0.2
let ground_truth = client.verify().await?;

// 0.3
let verified = client.http_client().ensure_verified().await?; // valid now
let renewed = client.http_client().reverify().await?;         // verify again regardless
```

### Other methods of `Client`

| 0.2 | 0.3 |
|---|---|
| `client.chat()`, `client.embeddings()`, … (through `Deref`) | unchanged |
| `client.chat_relaxed()` | unchanged in shape; see [behaviour changes](#behaviour-changes-in-names-that-stayed) |
| `client.transcribe(request)` | unchanged |
| `client.embed_batch(model, inputs)` | unchanged in shape; now checks the response |
| `client.with_user_cache_secret(secret)` | `.user_cache_secret(secret)` on a builder, before `connect()`. An empty string is an error; leave the option unset for the default |
| `client.secure_client()` | `client.http_client()`, which returns the attested HTTP client (`RouterHttpClient` or `EnclaveHttpClient`) |
| `client.http_client()` → `Result<&OriginBoundClient>` | `client.http_client()`, infallible, and it works in EHBP mode too |
| `client.enclave()`, `client.repo()` | `client.http_client().enclave()`, `.repo()` |

## `SecureClient`

`SecureClient` is removed. It was created unverified and became usable after
`verify()`. Its replacements verify before they return:

| 0.2 | 0.3 |
|---|---|
| `SecureClient::new(host, repo, api_key)` + `verify()` | `EnclaveHttpClient::connect(host, Some(repo))` |
| `SecureClient::new_with_proxy(host, repo, api_key, proxy_url)` + `verify()` | `EnclaveHttpClient::builder(host, Some(repo)).transport_mode(TransportMode::Ehbp).base_url(proxy_url).connect()` |
| `SecureClient::new_default_client(api_key)` | `RouterHttpClient::connect()` |
| `SecureClient::with_measurement(host, api_key, measurement)` | a `Verifier` with `pinned_registers(..)`; see below |
| `is_verified()` | removed: a client is always verified. `current()` returns the last verification |
| `verify(&mut self)` | `ensure_verified()` / `reverify()` on `&self` |
| `ground_truth()`, `ground_truth_json()` | `current()`, `current().to_json()` |
| `verification_document()`, `verification_document_json()` | removed; see [Verification results](#verification-results) |
| `http_client()` | the request methods are on the client itself: `client.get(url)`, `client.post(url)`, `client.execute(request)` |
| `host()` | `enclave()` |
| `base_url()` → `String`, `request_base_url()` | `base_url()` → `&Url`: where requests are sent (the proxy, when one is set). Its path ends in `/` |
| `api_key()` | removed. The HTTP clients hold no API key: set the `Authorization` header on each request (`.bearer_auth(key)`) |

```rust,ignore
// 0.2
let mut secure = tinfoil::SecureClient::new(host, repo, api_key);
secure.verify().await?;
let response = secure
    .http_client()?
    .get(format!("{}/v1/models", secure.base_url()))
    .bearer_auth(secure.api_key())
    .send()
    .await?;

// 0.3
let client = tinfoil::EnclaveHttpClient::connect(host, Some(repo)).await?;
let response = client
    .get(client.base_url().join("v1/models")?)
    .bearer_auth(api_key)
    .send()
    .await?;
```

The request builder has `header`, `headers`, `bearer_auth`, `body`, `json`,
`query`, `timeout`, `build` and `send`. Requests take absolute URLs, a request
to another origin is refused, and redirects are not followed: a `3xx` response
is returned.

In 0.2, `http_client()` failed in proxy mode. In 0.3 the same request methods
work in both modes; in `TransportMode::Ehbp` they seal the body.

### A pinned measurement

`with_measurement` skipped the provenance checks and compared one measurement.
In 0.3 a pin is an additional check on top of the full verification:

```rust,ignore
// 0.2
let secure = tinfoil::SecureClient::with_measurement(host, api_key, measurement);

// 0.3
use tinfoil::verifier::{Expected, Verifier};

let verifier = Verifier::builder()
    .pinned_registers(Expected::parse_sev_snp(launch_digest_hex)?)
    .build()?;
let client = tinfoil::EnclaveHttpClient::builder(host, Some(repo))
    .verifier(verifier)
    .connect()
    .await?;
```

To verify against a config that you supply yourself rather than a repository,
see `VerifierBuilder::embedded_references` and
`VerifierBuilder::config_authorizer`.

## Verification results

| 0.2 | 0.3 |
|---|---|
| `GroundTruth` | `tinfoil::verifier::Verification`, from `current()`, `ensure_verified()` or `reverify()` |
| its TLS fingerprint and HPKE key fields | `tls_public_key_fp()`, `hpke_public_key()` |
| its digest and measurement fields | `code_digest()`, `code_tag()`, `code_measurement()`, `enclave_measurement()` |
| `ground_truth_json()` | `to_json()` (a new shape), or `serde::Serialize` with the verifier's `serde` feature |
| `Measurement` with string registers | `Measurement::SevSnp { launch }` / `Measurement::Tdx { mrtd, rtmr0, .. }` with `Register` values; `Expected` for pins |
| `PredicateType` | removed; the platform is the variant of `Measurement` |
| `SoftwareIdentity` | `verification.metadata().verifier` |
| `VerificationDocument`, `VerificationSteps`, `VerificationStepState`, `VerificationStepStatus`, `DocumentEnclaveMeasurement`, `VERIFICATION_DOCUMENT_SCHEMA_VERSION` | **removed, without a replacement type.** On success, every fact is on `Verification`. On failure, the error's source is a `tinfoil::verifier::Error` whose `VerificationError::layer()` is `envelope`, `provenance`, `quote` or `policy`. An application that showed step states derives them from those two |

A `Verification` also has `freshness_expires_at()`, which is when the client
will verify again, and `config()`, `runtime()` and `platform()`, which describe
what vouched for the enclave.

## Errors

`tinfoil::Error` is now a struct with a kind, not an enum:

| 0.2 | 0.3 |
|---|---|
| `Error::Configuration`, `is_configuration()` | `error.kind() == ErrorKind::Configuration` |
| `Error::AttestationFetch`, `Network`, `Http`, `GitHub`, `Io`; `is_fetch()` | `ErrorKind::Network` |
| `Error::AttestationVerification`, `CertificateMismatch`, `SigstoreVerification`, `MeasurementMismatch`, `Tls`, `Ehbp`, `UnsupportedFormat`, `Json`, `Base64`; `is_attestation()` | `ErrorKind::Attestation`. The source is the verifier's error, with the layer that rejected the document |
| `Error::EhbpKeyMismatch`, `is_ehbp_key_mismatch()` | handled inside the client, which verifies again and sends the request once more. If that fails too, the error has `earlier_attempt()` |
| `Error::Api(OpenAIError)`, `is_api()` | API errors are not wrapped: OpenAI calls return `OpenAIError` itself |
| `is_retryable()` | `ErrorKind::Network` means "retry later"; `is_timeout()` tells a deadline apart |
| `tinfoil::error::Result` | write `Result<T, tinfoil::Error>` |

Typed OpenAI calls returned `OpenAIError` in 0.2 as well. What is new is that
a failure of the attested client under such a call can be recovered:

```rust,ignore
// 0.3
match client.chat().create(request).await {
    Ok(response) => { /* … */ }
    Err(error) => match tinfoil::Error::from_openai(&error) {
        Some(cause) if cause.kind() == tinfoil::ErrorKind::Attestation => { /* not trusted */ }
        Some(cause) => { /* configuration or network */ }
        None => { /* the API's own error */ }
    },
}
```

`Error::from_reqwest` does the same for the `reqwest::Error` of a failed read
of a response body. Messages now start with the kind (`network error: …`).

## The old `tinfoil::verifier` module tree

`tinfoil::verifier` used to hold the SDK's verification code and its fetchers:
`fetch`, `verify_full`, `verify_complete` and the modules `attestation`,
`github`, `sigstore`, `tls`, `util` and `embedded`. All of it is replaced by
the `tinfoil-verifier` crate:

| 0.2 | 0.3 |
|---|---|
| fetch a document and verify it (`verifier::fetch`, `verify_full`, `verify_complete`) | connect a client, or fetch the document yourself and call `Verifier::verify_v3(&document, &nonce, repo)` |
| `verifier::github`, `verifier::sigstore`, the VCEK disk cache, the KDS and GitHub proxies | removed. The document carries its own collateral, and the verifier makes no request and writes no file |
| `verifier::tls` (`OriginBoundClient`, certificate pinning helpers) | removed from the public API; the clients pin connections themselves |
| `tinfoil::constants` (`ROUTER_URL`, `DEFAULT_ROUTER`, `DEFAULT_REPO`, `GITHUB_PROXY`, `KDS_PROXY`) | removed. `RouterHttpClient::repo()` returns the router repository |
| `tinfoil::discovery::fetch_routers` | removed; `RouterHttpClient::connect()` discovers |

## Removed without replacement

- **The `conformance` binary** (`src/bin/conformance.rs`, a command-line
  wrapper around the old Sigstore bundle verifier for the upstream Sigstore
  conformance suite). The new verifier implements the subset of Sigstore that
  Tinfoil's attestation uses and has no general-purpose bundle verification
  command.
- **Reading `TINFOIL_API_KEY`.** Nothing in the SDK reads an API key from the
  environment.
- **`Client::api_key()` / `SecureClient::api_key()`.** The caller owns the
  key.

## Behaviour changes in names that stayed

### Verification

- **Clients verify again by themselves** when the verification expires, or
  when the enclave stops holding the attested key, in TLS mode as well as in
  EHBP mode. In 0.2 only the EHBP path refreshed, and a TLS client kept its pin
  until it was rebuilt.
- **Freshness is enforced.** A verification is valid for a bounded time (by
  default, evidence may be up to seven days old).
- **A failed verification is tried once more** after one second, unless the
  failure is a configuration error.
- **Router discovery** tries the published routers in list order, within 30
  seconds in all, and then falls back to `inference.tinfoil.sh`. The router
  list is bounded in size, and the request no longer filters by platform.
- **TLS roots are compiled in**; the operating system's store is not read.

### Requests

- **Only the bound origin.** A request to another origin is a configuration
  error and nothing is sent. Redirects are not followed.
- **Reserved headers.** A request that sets `Host`, or in EHBP mode
  `Content-Length`, `Transfer-Encoding` or an `Ehbp-*` header, is refused.
- **In EHBP mode a request without a body is not sealed**, and neither is the
  response to it. Requests with a body, and their responses, are.
- **Timeouts.** There is one `timeout` option, which bounds `connect`, each
  verification and each request until its body has been read. Unset, there is
  no overall deadline.

### Prompt cache secret

- The client-level secret is an option of the builder
  (`user_cache_secret(..)`), not a method on a built client.
- When the option is unset, **router clients** resolve the secret as before:
  `TINFOIL_USER_CACHE_SECRET`, then `~/.tinfoil/user_cache_secret`, created on
  first use. **Enclave clients add no secret** unless the option is set.
- The secret is added to the JSON body of `POST` requests to
  `…/chat/completions`, `…/completions` and `…/responses`, also for requests
  that you send through the HTTP clients. A non-empty `user_cache_secret` in
  the body still wins.

### `chat_relaxed` and the SSE parser

- **A stream that ends inside an event is an error.** 0.2 delivered the
  incomplete tail as if it were a whole event, so a truncated value could
  arrive as a shorter one.
- **`[DONE]` ends the stream.** Nothing after it is read.
- **The data lines of one event are joined** with a newline before the event
  is parsed as JSON.
- **Limits:** a line or an event of more than 16 MiB is an error.
- **Relaxed calls are tried again** on `429` and `5xx`, at most twice, as
  typed calls are; a `429` whose error is `insufficient_quota` is not.
  Nothing is tried again once a stream has started.
- **Error types:** `create` and `create_stream` return `OpenAIError` (0.2:
  `tinfoil::Error`); a `4xx` response whose body is not an API error object is
  `OpenAIError::JSONDeserialize`. `RelaxedToolCall::arguments` returns
  `serde_json::Error`. The items of `sse::EventStream` are
  `Result<Value, OpenAIError>`.
- The relaxed types are exported from the crate root (`tinfoil::RelaxedChat`,
  …); the module path `tinfoil::relaxed` is gone.

### `embed_batch`

- A response that does not hold exactly one embedding for each input, with the
  indexes `0..n`, is an `OpenAIError::InvalidArgument`. 0.2 returned whatever
  vectors came back, which could silently misalign them with the inputs.

### OpenAI retries

- A `429` or `5xx` response is tried again at most twice, except a `429` whose
  error is `insufficient_quota`, which is reported at once. A failure of the
  attested client (verification, connection, deadline) is reported once.

## New in 0.3

- `RouterHttpClient` and `EnclaveHttpClient` as first-class HTTP clients, with
  `TransportMode::Tls` and `TransportMode::Ehbp` on both.
- Intel TDX enclaves, in addition to AMD SEV-SNP.
- `verification_check`, a veto over every verification that a client relies
  on.
- `tinfoil-verifier` as a crate of its own, usable without an async runtime.
- Cargo features `openai-<family>` for the other API families of
  async-openai.
- HTTP/2.
