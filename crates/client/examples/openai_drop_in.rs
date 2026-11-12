//! The drop-in OpenAI client: an `async_openai` client whose requests go
//! to Tinfoil's router, verified before the first request.
//!
//! ```sh
//! TINFOIL_API_KEY=... cargo run -p tinfoil --example openai_drop_in
//! ```

use tinfoil::async_openai::config::OpenAIConfig;
use tinfoil::chat::{ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs};
use tinfoil::{Client, Error, ErrorKind};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("TINFOIL_API_KEY")?;
    let client = Client::connect(OpenAIConfig::new().with_api_key(api_key)).await?;

    // What the client verified, and where it sends.
    let router = client.http_client();
    println!(
        "router {} runs {}",
        router.enclave(),
        router.current().code_digest()
    );
    println!("API base: {}", client.base_url());

    // The whole async_openai API is available on the client.
    let request = CreateChatCompletionRequestArgs::default()
        .model("gpt-oss-120b")
        .messages([ChatCompletionRequestUserMessageArgs::default()
            .content("Why is the sky blue?")
            .build()?
            .into()])
        .build()?;

    match client.chat().create(request).await {
        Ok(response) => {
            for choice in response.choices {
                println!("{}", choice.message.content.unwrap_or_default());
            }
        }
        // A failed call is an `OpenAIError`. When the attested client
        // caused it, the cause is one of this crate's errors.
        Err(error) => match Error::from_openai(&error) {
            Some(cause) if cause.kind() == ErrorKind::Attestation => {
                eprintln!("the router could not be verified: {cause}");
            }
            Some(cause) => eprintln!("{cause}"),
            None => eprintln!("API error: {error}"),
        },
    }

    Ok(())
}
