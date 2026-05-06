//! Permissive chat-completion helper.
//!
//! Use this when `async-openai` rejects router fields such as custom
//! `finish_reason` values, or when you need vendor extensions like
//! `structured_outputs`, `web_search_options`, or `pii_check_options`.

use serde_json::{json, Map, Value};

use crate::client::Client;
use crate::error::{Error, Result};

/// Handle returned by [`Client::chat_relaxed`].
pub struct RelaxedChat<'a> {
    client: &'a Client,
}

impl<'a> RelaxedChat<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Start a request builder.
    pub fn request(&self) -> RelaxedChatRequestBuilder {
        RelaxedChatRequestBuilder::new()
    }

    /// Send a chat-completion request expressed as raw JSON.
    ///
    /// The body is forwarded to `/v1/chat/completions` on the verified enclave
    /// using the pinned TLS client.
    pub async fn create(&self, body: impl Into<Value>) -> Result<RelaxedResponse> {
        let secure = self.client.secure_client();
        let url = format!("{}/v1/chat/completions", secure.base_url());

        let response = secure
            .http_client()?
            .post(&url)
            .bearer_auth(secure.api_key())
            .json(&body.into())
            .send()
            .await?;

        let status = response.status();
        let body: Value = response.json().await?;

        if !status.is_success() {
            let message = body
                .pointer("/error/message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| body.to_string());
            return Err(Error::Network(format!(
                "Chat completion request failed ({}): {}",
                status, message
            )));
        }

        Ok(RelaxedResponse { body })
    }
}

/// Permissive view of a chat-completion response.
#[derive(Debug, Clone)]
pub struct RelaxedResponse {
    body: Value,
}

impl RelaxedResponse {
    /// Construct from a pre-parsed JSON value (mostly useful in tests).
    pub fn from_value(body: Value) -> Self {
        Self { body }
    }

    /// Underlying JSON, unmodified.
    pub fn raw(&self) -> &Value {
        &self.body
    }

    /// Take ownership of the underlying JSON.
    pub fn into_raw(self) -> Value {
        self.body
    }

    /// Plain-text content of the first choice's message, if any.
    pub fn content(&self) -> Option<&str> {
        self.body
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
    }

    /// Raw `finish_reason` string of the first choice. Free-form to allow
    /// vendor-specific values like `"repetition"` or `"stop_reason"`.
    pub fn finish_reason(&self) -> Option<&str> {
        self.body
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
    }

    /// Tool calls from the first choice's message. Empty slice if there are
    /// none. Each entry is the verbatim JSON object returned by the server.
    pub fn tool_calls(&self) -> &[Value] {
        self.body
            .pointer("/choices/0/message/tool_calls")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Annotations attached to the first choice's message (citations etc.).
    pub fn annotations(&self) -> &[Value] {
        self.body
            .pointer("/choices/0/message/annotations")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Model name reported by the server.
    pub fn model(&self) -> Option<&str> {
        self.body.get("model").and_then(Value::as_str)
    }

    /// Server-assigned response id, when present.
    pub fn id(&self) -> Option<&str> {
        self.body.get("id").and_then(Value::as_str)
    }

    /// Number of choices returned.
    pub fn choices_len(&self) -> usize {
        self.body
            .get("choices")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    }
}

/// Builder that produces a JSON body for [`RelaxedChat::create`].
#[derive(Debug, Clone, Default)]
pub struct RelaxedChatRequestBuilder {
    body: Map<String, Value>,
}

impl RelaxedChatRequestBuilder {
    /// Empty builder with no fields set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `model` field.
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.body
            .insert("model".to_string(), Value::String(model.into()));
        self
    }

    /// Replace the `messages` array with the supplied JSON values.
    pub fn messages<I, V>(mut self, messages: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        let arr: Vec<Value> = messages.into_iter().map(Into::into).collect();
        self.body.insert("messages".to_string(), Value::Array(arr));
        self
    }

    /// Append a single message to the `messages` array.
    pub fn push_message(mut self, message: impl Into<Value>) -> Self {
        let entry = self
            .body
            .entry("messages".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(arr) = entry.as_array_mut() {
            arr.push(message.into());
        }
        self
    }

    /// Enable Tinfoil-side web search by sending an empty
    /// `web_search_options` object. Pass [`web_search_with_options`] for
    /// a non-empty payload.
    ///
    /// [`web_search_with_options`]: Self::web_search_with_options
    pub fn web_search(self) -> Self {
        self.web_search_with_options(json!({}))
    }

    /// Send a populated `web_search_options` object.
    pub fn web_search_with_options(mut self, options: impl Into<Value>) -> Self {
        self.body
            .insert("web_search_options".to_string(), options.into());
        self
    }

    /// Enable Tinfoil-side PII checking with default options.
    pub fn pii_check(self) -> Self {
        self.pii_check_with_options(json!({}))
    }

    /// Send a populated `pii_check_options` object.
    pub fn pii_check_with_options(mut self, options: impl Into<Value>) -> Self {
        self.body
            .insert("pii_check_options".to_string(), options.into());
        self
    }

    /// Constrain the model output to one of the supplied choices using
    /// vLLM's `structured_outputs.choice` extension.
    pub fn structured_outputs_choice<I, S>(self, choices: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let arr: Vec<Value> = choices
            .into_iter()
            .map(|s| Value::String(s.into()))
            .collect();
        self.set("structured_outputs", json!({ "choice": Value::Array(arr) }))
    }

    /// Constrain the model output to match a regular expression using
    /// vLLM's `structured_outputs.regex` extension.
    pub fn structured_outputs_regex(self, pattern: impl Into<String>) -> Self {
        self.set("structured_outputs", json!({ "regex": pattern.into() }))
    }

    /// Constrain the model output to a JSON Schema (OpenAI-compatible
    /// `response_format.json_schema`).
    pub fn response_format_json_schema(
        self,
        name: impl Into<String>,
        schema: impl Into<Value>,
    ) -> Self {
        self.set(
            "response_format",
            json!({
                "type": "json_schema",
                "json_schema": {
                    "name": name.into(),
                    "schema": schema.into(),
                }
            }),
        )
    }

    /// Set an arbitrary top-level field. Use this for parameters that
    /// don't have dedicated builder methods yet.
    pub fn set(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.body.insert(key.into(), value.into());
        self
    }

    /// Finalise the builder into the JSON body that
    /// [`RelaxedChat::create`] expects.
    pub fn build(self) -> Value {
        Value::Object(self.body)
    }
}

impl From<RelaxedChatRequestBuilder> for Value {
    fn from(builder: RelaxedChatRequestBuilder) -> Self {
        builder.build()
    }
}

impl Client {
    /// Permissive chat-completion handle for raw JSON requests and responses.
    pub fn chat_relaxed(&self) -> RelaxedChat<'_> {
        RelaxedChat::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn relaxed_response_extracts_content() {
        let body = json!({
            "id": "chatcmpl-1",
            "model": "gpt-oss-120b",
            "choices": [{
                "finish_reason": "repetition",
                "message": {
                    "role": "assistant",
                    "content": "hello",
                    "tool_calls": [{"id": "call_1"}],
                    "annotations": []
                }
            }]
        });

        let resp = RelaxedResponse::from_value(body);
        assert_eq!(resp.content(), Some("hello"));
        assert_eq!(resp.finish_reason(), Some("repetition"));
        assert_eq!(resp.tool_calls().len(), 1);
        assert_eq!(resp.annotations().len(), 0);
        assert_eq!(resp.model(), Some("gpt-oss-120b"));
        assert_eq!(resp.id(), Some("chatcmpl-1"));
        assert_eq!(resp.choices_len(), 1);
    }

    #[test]
    fn relaxed_response_handles_missing_fields() {
        let resp = RelaxedResponse::from_value(json!({}));
        assert_eq!(resp.content(), None);
        assert_eq!(resp.finish_reason(), None);
        assert!(resp.tool_calls().is_empty());
        assert!(resp.annotations().is_empty());
        assert_eq!(resp.choices_len(), 0);
    }

    #[test]
    fn builder_serialises_chat_fields_and_extensions() {
        let body: Value = RelaxedChatRequestBuilder::new()
            .model("gpt-oss-120b")
            .messages([json!({"role": "user", "content": "hi"})])
            .web_search()
            .pii_check_with_options(json!({"redact": true}))
            .into();

        assert_eq!(body["model"], "gpt-oss-120b");
        assert_eq!(body["messages"][0]["content"], "hi");
        assert_eq!(body["web_search_options"], json!({}));
        assert_eq!(body["pii_check_options"]["redact"], true);
    }

    #[test]
    fn builder_supports_structured_outputs_helpers() {
        let choice = RelaxedChatRequestBuilder::new()
            .structured_outputs_choice(["positive", "negative"])
            .build();
        assert_eq!(
            choice["structured_outputs"]["choice"],
            json!(["positive", "negative"])
        );

        let regex = RelaxedChatRequestBuilder::new()
            .structured_outputs_regex(r"\w+@\w+\.com")
            .build();
        assert_eq!(regex["structured_outputs"]["regex"], r"\w+@\w+\.com");

        let schema = RelaxedChatRequestBuilder::new()
            .response_format_json_schema("person", json!({"type": "object"}))
            .build();
        assert_eq!(schema["response_format"]["type"], "json_schema");
        assert_eq!(schema["response_format"]["json_schema"]["name"], "person");
    }

    #[test]
    fn builder_push_message_appends_to_existing_array() {
        let body: Value = RelaxedChatRequestBuilder::new()
            .messages([json!({"role": "user", "content": "first"})])
            .push_message(json!({"role": "assistant", "content": "second"}))
            .build();
        let arr = body["messages"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[1]["content"], "second");
    }
}
