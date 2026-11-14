//! Tests against Tinfoil's production router. They use the network, so
//! they are ignored unless asked for:
//!
//! ```sh
//! TINFOIL_API_KEY=... cargo test -p tinfoil --test live -- --ignored
//! ```
//!
//! The tests that call the inference API need `TINFOIL_API_KEY`; the one
//! that only verifies the router does not.

use std::time::Duration;

use tinfoil::RouterHttpClient;

const TIMEOUT: Duration = Duration::from_secs(120);
/// Keeps the router clients from creating a secret file on the machine.
const CACHE_SECRET: &str = "tinfoil-rs-live-test";

#[tokio::test]
#[ignore = "uses the network"]
async fn the_router_is_discovered_verified_and_reached_over_a_pinned_connection() {
    let client = RouterHttpClient::builder()
        .user_cache_secret(CACHE_SECRET)
        .timeout(TIMEOUT)
        .connect()
        .await
        .unwrap();

    let verified = client.current();
    assert_eq!(Some(verified.config_repo()), client.pin().repo.as_deref());
    assert!(verified.tls_public_key_fp().is_some());
    assert!(verified.freshness_expires_at().is_some());

    let models = client
        .get(client.base_url().join("v1/models").unwrap())
        .send()
        .await
        .unwrap();
    assert!(models.status().is_success(), "{}", models.status());

    // Another origin is refused before anything is sent.
    let refused = client.get("https://example.com/").send().await.unwrap_err();
    assert_eq!(refused.kind(), tinfoil::ErrorKind::Configuration);
}

/// The tests of the OpenAI clients.
#[cfg(feature = "openai")]
mod openai {
    use tinfoil::async_openai::config::OpenAIConfig;
    use tinfoil::chat::{
        ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequest,
        CreateChatCompletionRequestArgs,
    };
    use tinfoil::{Client, RouterOpenAIClient, TransportMode};

    use super::{CACHE_SECRET, TIMEOUT};

    const MODEL: &str = "gpt-oss-120b";

    // A helper outside a test function fails its test by panicking.
    #[allow(clippy::expect_used)]
    fn openai_config() -> OpenAIConfig {
        let key = std::env::var("TINFOIL_API_KEY")
            .ok()
            .filter(|key| !key.is_empty())
            .expect("TINFOIL_API_KEY must be set for the tests that call the inference API");
        OpenAIConfig::new().with_api_key(key)
    }

    #[allow(clippy::expect_used)]
    fn chat_request() -> CreateChatCompletionRequest {
        CreateChatCompletionRequestArgs::default()
            .model(MODEL)
            .messages([ChatCompletionRequestUserMessageArgs::default()
                .content("Reply with the single word: ok")
                .build()
                .expect("a user message")
                .into()])
            .build()
            .expect("a chat request")
    }

    #[tokio::test]
    #[ignore = "uses the network and needs TINFOIL_API_KEY"]
    async fn the_drop_in_client_completes_a_chat() {
        let client = Client::connect(openai_config()).await.unwrap();
        let response = client.chat().create(chat_request()).await.unwrap();
        assert!(!response.choices.is_empty());
    }

    #[tokio::test]
    #[ignore = "uses the network and needs TINFOIL_API_KEY"]
    async fn a_chat_with_sealed_bodies_completes() {
        let client = RouterOpenAIClient::builder(openai_config())
            .transport_mode(TransportMode::Ehbp)
            .user_cache_secret(CACHE_SECRET)
            .timeout(TIMEOUT)
            .connect()
            .await
            .unwrap();
        assert!(client.http_client().current().hpke_public_key().is_some());
        let response = client.chat().create(chat_request()).await.unwrap();
        assert!(!response.choices.is_empty());
    }
}
