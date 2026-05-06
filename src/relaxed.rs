//! Permissive chat-completion helper.
//!
//! Use this when `async-openai` rejects router fields such as custom
//! `finish_reason` values, or when you need vendor extensions like
//! `structured_outputs`, `web_search_options`, or `pii_check_options`.

use async_openai::error::{ApiError, OpenAIError};
use futures_util::Stream;
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};

use crate::client::Client;
use crate::error::{Error, Result};
use crate::sse;

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
    ///
    /// Sets `stream: false` defensively so callers who accidentally include
    /// `stream: true` in the body don't end up parsing SSE as JSON. Use
    /// [`create_stream`](Self::create_stream) for streaming.
    pub async fn create(&self, body: impl Into<Value>) -> Result<RelaxedResponse> {
        let mut body = body.into();
        force_stream(&mut body, false);

        let secure = self.client.secure_client();
        let url = format!("{}/v1/chat/completions", secure.base_url());

        let response = secure
            .http_client()?
            .post(&url)
            .bearer_auth(secure.api_key())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        let bytes = response.bytes().await?;

        if !status.is_success() {
            return Err(http_error(status, &bytes));
        }

        let body: Value = serde_json::from_slice(&bytes)?;
        Ok(RelaxedResponse { body })
    }

    /// Streaming counterpart of [`create`](Self::create).
    ///
    /// Returns a stream of [`RelaxedStreamChunk`]s decoded from the
    /// router's Server-Sent Events response. Vendor-specific events
    /// (for example `web_search_call`) are surfaced verbatim through
    /// [`RelaxedStreamChunk::raw`] and the typed accessors on the chunk.
    pub async fn create_stream(
        &self,
        body: impl Into<Value>,
    ) -> Result<RelaxedStream> {
        let mut body = body.into();
        force_stream(&mut body, true);

        let secure = self.client.secure_client();
        let url = format!("{}/v1/chat/completions", secure.base_url());

        let response = secure
            .http_client()?
            .post(&url)
            .bearer_auth(secure.api_key())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(http_error(status, &bytes));
        }

        Ok(into_chunk_stream(response.bytes_stream()))
    }
}

/// Box-pinned stream type returned by [`RelaxedChat::create_stream`].
pub type RelaxedStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<RelaxedStreamChunk>> + Send>>;

fn into_chunk_stream<S, E>(byte_stream: S) -> RelaxedStream
where
    S: Stream<Item = std::result::Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    use futures_util::StreamExt;
    let mapped = sse::parse_event_stream(byte_stream)
        .map(|event| event.map(|body| RelaxedStreamChunk { body }));
    Box::pin(mapped)
}

fn force_stream(body: &mut Value, value: bool) {
    if let Some(map) = body.as_object_mut() {
        map.insert("stream".to_string(), Value::Bool(value));
    }
}

fn http_error(status: reqwest::StatusCode, bytes: &[u8]) -> Error {
    let parsed: Option<Value> = serde_json::from_slice(bytes).ok();
    let message = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/message").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| {
            let text = String::from_utf8_lossy(bytes);
            if text.is_empty() {
                format!("HTTP {}", status)
            } else {
                text.into_owned()
            }
        });

    let r#type = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/type").and_then(Value::as_str))
        .map(str::to_string);
    let param = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/param").and_then(Value::as_str))
        .map(str::to_string);
    let parsed_code = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/code").and_then(Value::as_str))
        .map(str::to_string);

    // Synthesise the canonical OpenAI error code so `is_retryable()` can
    // tell server faults / rate limits apart from client mistakes when
    // the upstream body didn't include one.
    let code = parsed_code.or_else(|| {
        if status.is_server_error() {
            Some("server_error".to_string())
        } else if status == 429 {
            Some("rate_limit_exceeded".to_string())
        } else if status == 408 {
            Some("server_error".to_string())
        } else {
            None
        }
    });

    Error::Api(OpenAIError::ApiError(ApiError {
        message,
        r#type,
        param,
        code,
    }))
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

    /// Tool calls from the first choice, decoded into a typed view that
    /// preserves access to the raw arguments string.
    pub fn typed_tool_calls(&self) -> Vec<RelaxedToolCall> {
        self.tool_calls()
            .iter()
            .map(RelaxedToolCall::from_value)
            .collect()
    }
}

/// One chunk of a streamed chat-completion response.
///
/// The router emits two flavours of event over the same stream:
///   - standard chat-completion deltas (text content, tool-call deltas,
///     finish reasons),
///   - Tinfoil-specific vendor events such as `web_search_call`.
///
/// Both shapes are exposed through the same struct; use the typed
/// accessors for the common cases and fall back to [`raw`](Self::raw)
/// for anything the SDK doesn't model yet.
#[derive(Debug, Clone)]
pub struct RelaxedStreamChunk {
    body: Value,
}

impl RelaxedStreamChunk {
    /// Construct from a pre-parsed JSON value (test helper).
    pub fn from_value(body: Value) -> Self {
        Self { body }
    }

    /// Underlying JSON event, exactly as emitted by the server.
    pub fn raw(&self) -> &Value {
        &self.body
    }

    /// Take ownership of the underlying JSON.
    pub fn into_raw(self) -> Value {
        self.body
    }

    /// Vendor event type (`"web_search_call"`, `"image_generation_call"`,
    /// ...) when the chunk is a vendor event rather than a delta.
    pub fn event_type(&self) -> Option<&str> {
        self.body.get("type").and_then(Value::as_str)
    }

    /// `true` if this chunk is a Tinfoil/vLLM vendor event rather than a
    /// chat-completion delta.
    pub fn is_vendor_event(&self) -> bool {
        self.event_type().is_some()
    }

    /// Convenience for the most common delta: the assistant's content
    /// fragment.
    pub fn delta_content(&self) -> Option<&str> {
        self.body
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
    }

    /// Tool-call delta entries from the first choice. Empty when this
    /// chunk doesn't carry tool deltas.
    pub fn tool_call_deltas(&self) -> &[Value] {
        self.body
            .pointer("/choices/0/delta/tool_calls")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Annotation deltas from the first choice (URL citations etc.).
    pub fn annotation_deltas(&self) -> &[Value] {
        self.body
            .pointer("/choices/0/delta/annotations")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Raw `finish_reason` for the first choice, when this chunk
    /// terminates a generation.
    pub fn finish_reason(&self) -> Option<&str> {
        self.body
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
    }
}

/// Tool call extracted from a [`RelaxedResponse`].
///
/// Holds the verbatim arguments string so callers can deserialise into
/// their own type via [`arguments`](Self::arguments) without going back
/// through `serde_json::Value`.
#[derive(Debug, Clone)]
pub struct RelaxedToolCall {
    pub id: Option<String>,
    pub function_name: Option<String>,
    pub arguments_raw: String,
}

impl RelaxedToolCall {
    fn from_value(value: &Value) -> Self {
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let function_name = value
            .pointer("/function/name")
            .and_then(Value::as_str)
            .map(str::to_string);
        let arguments_raw = value
            .pointer("/function/arguments")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        Self {
            id,
            function_name,
            arguments_raw,
        }
    }

    /// Deserialise the arguments string into the caller's type.
    pub fn arguments<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_str(&self.arguments_raw)?)
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

    #[test]
    fn http_error_classifies_status_codes() {
        let bad_request = http_error(
            reqwest::StatusCode::BAD_REQUEST,
            br#"{"error": {"message": "bad", "type": "invalid_request_error"}}"#,
        );
        assert!(bad_request.is_api(), "4xx should be API error");
        assert!(!bad_request.is_retryable(), "4xx should not retry");

        let server_error = http_error(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error": {"message": "boom"}}"#,
        );
        assert!(server_error.is_api(), "5xx is still an API error");
        assert!(server_error.is_retryable(), "5xx should retry");

        let rate_limit = http_error(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            b"rate-limited",
        );
        assert!(rate_limit.is_api());
        assert!(rate_limit.is_retryable());
    }

    #[test]
    fn http_error_falls_back_to_text_when_body_is_not_json() {
        let err = http_error(reqwest::StatusCode::UNAUTHORIZED, b"Unauthorized");
        assert!(err.is_api());
        assert!(format!("{}", err).contains("Unauthorized"));
    }

    #[test]
    fn force_stream_overrides_caller_provided_value() {
        let mut body = json!({"stream": true});
        force_stream(&mut body, false);
        assert_eq!(body["stream"], false);

        let mut body = json!({});
        force_stream(&mut body, true);
        assert_eq!(body["stream"], true);
    }

    #[test]
    fn relaxed_stream_chunk_distinguishes_deltas_from_vendor_events() {
        let delta = RelaxedStreamChunk::from_value(json!({
            "choices": [{"delta": {"content": "hel"}}]
        }));
        assert_eq!(delta.delta_content(), Some("hel"));
        assert!(!delta.is_vendor_event());

        let vendor = RelaxedStreamChunk::from_value(json!({
            "type": "web_search_call",
            "status": "in_progress",
            "action": {"query": "rust"}
        }));
        assert_eq!(vendor.event_type(), Some("web_search_call"));
        assert!(vendor.is_vendor_event());
        assert!(vendor.delta_content().is_none());
    }

    #[test]
    fn relaxed_tool_call_deserialises_typed_arguments() {
        #[derive(serde::Deserialize)]
        struct Args {
            city: String,
            unit: String,
        }

        let body = json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "id": "call_1",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\",\"unit\":\"celsius\"}"
                        }
                    }]
                }
            }]
        });
        let resp = RelaxedResponse::from_value(body);
        let calls = resp.typed_tool_calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.id.as_deref(), Some("call_1"));
        assert_eq!(call.function_name.as_deref(), Some("get_weather"));
        let args: Args = call.arguments().unwrap();
        assert_eq!(args.city, "Paris");
        assert_eq!(args.unit, "celsius");
    }
}
