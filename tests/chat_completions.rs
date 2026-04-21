//! Live chat completion tests against the Tinfoil router.
//!
//! These tests require a valid `TINFOIL_API_KEY` environment variable and hit
//! the real inference endpoint, so they are gated behind `#[ignore]` and only
//! run in CI when the key secret is present (`cargo test -- --ignored`).

use futures_util::StreamExt;
use tinfoil::async_openai::types::chat::{
    ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
};
use tinfoil::Client;

const TEST_MODEL: &str = "llama3-3-70b";
const TEST_PROMPT: &str = "Say this is a test";
const MAX_TOKENS: u32 = 32;

fn api_key() -> String {
    std::env::var("TINFOIL_API_KEY")
        .expect("TINFOIL_API_KEY must be set to run live chat completion tests")
}

fn build_request() -> CreateChatCompletionRequestArgs {
    let mut args = CreateChatCompletionRequestArgs::default();
    args.model(TEST_MODEL)
        .max_tokens(MAX_TOKENS)
        .messages(vec![ChatCompletionRequestUserMessageArgs::default()
            .content(TEST_PROMPT)
            .build()
            .expect("Failed to build user message")
            .into()]);
    args
}

/// Non-streaming chat completion against the verified enclave.
#[tokio::test]
#[ignore]
async fn test_chat_completion_non_streaming() {
    let client = Client::new_default(api_key())
        .await
        .expect("Failed to create verified Tinfoil client");

    let request = build_request()
        .build()
        .expect("Failed to build chat completion request");

    let response = client
        .chat()
        .create(request)
        .await
        .expect("Chat completion request failed");

    assert!(
        !response.choices.is_empty(),
        "Response should contain at least one choice"
    );

    let content = response.choices[0]
        .message
        .content
        .as_ref()
        .expect("Response message should have content");

    assert!(
        !content.trim().is_empty(),
        "Response content should not be empty"
    );
}

/// Streaming chat completion against the verified enclave.
#[tokio::test]
#[ignore]
async fn test_chat_completion_streaming() {
    let client = Client::new_default(api_key())
        .await
        .expect("Failed to create verified Tinfoil client");

    let request = build_request()
        .stream(true)
        .build()
        .expect("Failed to build streaming chat completion request");

    let mut stream = client
        .chat()
        .create_stream(request)
        .await
        .expect("Failed to open chat completion stream");

    let mut chunk_count = 0usize;
    let mut aggregated = String::new();

    while let Some(item) = stream.next().await {
        let chunk = item.expect("Stream chunk returned an error");
        chunk_count += 1;

        for choice in &chunk.choices {
            if let Some(delta) = choice.delta.content.as_deref() {
                aggregated.push_str(delta);
            }
        }
    }

    assert!(chunk_count > 0, "Stream should yield at least one chunk");
    assert!(
        !aggregated.trim().is_empty(),
        "Aggregated streamed content should not be empty"
    );
}
