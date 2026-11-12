//! A permissive chat-completion helper.
//!
//! Use it when the typed `async_openai` chat API rejects what a Tinfoil
//! model sends or accepts: a `finish_reason` outside OpenAI's set, or
//! vendor extensions such as `structured_outputs`, `web_search_options`
//! and `pii_check_options`. Requests and responses are raw JSON, with
//! accessors for the common fields.

use std::pin::Pin;
use std::sync::Arc;

use async_openai::config::{Config, OpenAIConfig};
use async_openai::error::{ApiError, ApiErrorResponse, OpenAIError, WrappedError};
use async_openai::middleware::HttpRequestFactory;
use futures_core::Stream;
use reqwest::header::CONTENT_TYPE;
use reqwest::{Method, Response, Url};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use crate::openai::service::Sender;
use crate::request::Execute;

/// The path of the chat-completion endpoint under an OpenAI base URL.
pub(crate) const CHAT_COMPLETIONS_PATH: &str = "chat/completions";

/// The handle that an OpenAI client's `chat_relaxed` returns.
///
/// Its requests go through the same attested HTTP client as the typed
/// calls, with the same credentials and headers from the client's
/// `OpenAIConfig` and the same retries, to `chat/completions` under the
/// client's API base.
pub struct RelaxedChat<'a> {
    pub(crate) sender: Sender,
    pub(crate) http: Arc<dyn Execute>,
    pub(crate) api_base: &'a Url,
    pub(crate) config: &'a OpenAIConfig,
}

impl RelaxedChat<'_> {
    /// Starts a request body.
    pub fn request(&self) -> RelaxedChatRequestBuilder {
        RelaxedChatRequestBuilder::new()
    }

    /// Sends a chat-completion request given as raw JSON and returns the
    /// response as raw JSON.
    ///
    /// `stream` is set to `false` in the body, so a body that asks for a
    /// stream by mistake is not answered with events; use
    /// [`create_stream`](Self::create_stream) for those. A body that is
    /// not a JSON object is sent as it is. The user cache secret is added
    /// by the HTTP client underneath, as for every chat request.
    ///
    /// # Errors
    ///
    /// The errors are those of a typed call. An error status from the API
    /// is `OpenAIError::ApiError`, with the fields of the API's error
    /// object; the body of a `5xx` response is its message as it is, and a
    /// `4xx` body without an error object is
    /// `OpenAIError::JSONDeserialize`, as is a successful response that is
    /// not JSON. A failure of the attested HTTP client travels inside the
    /// `OpenAIError`, where
    /// [`Error::from_openai`](crate::Error::from_openai) finds it. A `429`
    /// or `5xx` response is tried again as for a typed call.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future cancels the request, as
    /// [`EnclaveHttpClient::execute`](crate::EnclaveHttpClient::execute)
    /// describes.
    pub async fn create(&self, body: impl Into<Value>) -> Result<RelaxedResponse, OpenAIError> {
        let response = self.send(body.into(), false).await?;
        let bytes = response.bytes().await.map_err(OpenAIError::Reqwest)?;
        let body = serde_json::from_slice(&bytes).map_err(|error| not_json(error, &bytes))?;
        Ok(RelaxedResponse { body })
    }

    /// As [`create`](Self::create), for a streamed response: `stream` is
    /// set to `true`, and the events of the response are returned as they
    /// arrive. Vendor events, such as `web_search_call`, are passed on
    /// as they were sent.
    ///
    /// The future resolves when the response headers have arrived; an
    /// error status is reported then, after the retries of a typed call.
    /// Nothing is tried again once the stream has started. The stream is
    /// that of [`parse_event_stream`](crate::sse::parse_event_stream): it
    /// ends at `[DONE]`, or when the response ends after a complete event,
    /// and it fails when the response ends inside an event or cannot be
    /// read further.
    ///
    /// Dropping the future cancels the request, and dropping the stream
    /// closes the connection.
    pub async fn create_stream(
        &self,
        body: impl Into<Value>,
    ) -> Result<RelaxedStream, OpenAIError> {
        let response = self.send(body.into(), true).await?;
        let mut events = crate::sse::parse_event_stream(response.bytes_stream());
        Ok(Box::pin(async_stream::stream! {
            while let Some(event) =
                std::future::poll_fn(|cx| events.as_mut().poll_next(cx)).await
            {
                yield event.map(|body| RelaxedStreamChunk { body });
            }
        }))
    }

    /// Sends `body` with its `stream` member set to `stream` and returns
    /// the response if its status is a success; otherwise the API's error.
    async fn send(&self, mut body: Value, stream: bool) -> Result<Response, OpenAIError> {
        force_stream(&mut body, stream);
        let url = self
            .api_base
            .join(CHAT_COMPLETIONS_PATH)
            .map_err(|error| OpenAIError::InvalidArgument(error.to_string()))?;
        let body = serde_json::to_vec(&body)
            .map_err(|error| OpenAIError::InvalidArgument(error.to_string()))?;
        let (http, headers) = (Arc::clone(&self.http), self.config.headers());
        let query: Vec<(String, String)> = self
            .config
            .query()
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        // Built anew for each attempt, as every call of the client is.
        let factory = HttpRequestFactory::new(move || {
            let request = http
                .start(Method::POST, url.clone())
                .headers(headers.clone())
                .query(&query)
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .build()
                .map_err(OpenAIError::Reqwest);
            std::future::ready(request)
        });
        let response = self.sender.send(factory).await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(api_error(response).await)
        }
    }
}

/// Sets the `stream` member of a body that is a JSON object.
fn force_stream(body: &mut Value, stream: bool) {
    if let Some(members) = body.as_object_mut() {
        members.insert("stream".to_owned(), Value::Bool(stream));
    }
}

/// The error for a response body that is not the JSON that was expected.
fn not_json(error: serde_json::Error, body: &[u8]) -> OpenAIError {
    OpenAIError::JSONDeserialize(error, String::from_utf8_lossy(body).into_owned())
}

/// The error for a response with an error status, read as a typed call
/// reads it: the body of a `5xx` response is the message as it is, since
/// such a body need not be JSON; any other body must hold the API's
/// error object.
async fn api_error(response: Response) -> OpenAIError {
    let status_code = response.status();
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => return OpenAIError::Reqwest(error),
    };
    let parsed = if status_code.is_server_error() {
        let message = String::from_utf8_lossy(&bytes).into_owned();
        serde_json::from_value::<ApiError>(json!({ "message": message }))
    } else {
        serde_json::from_slice::<WrappedError>(&bytes).map(|wrapped| wrapped.error)
    };
    match parsed {
        Ok(api_error) => OpenAIError::ApiError(ApiErrorResponse {
            status_code,
            api_error,
        }),
        Err(error) => not_json(error, &bytes),
    }
}

impl std::fmt::Debug for RelaxedChat<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaxedChat")
            .field("api_base", &self.api_base.as_str())
            .finish_non_exhaustive()
    }
}

/// The events of a streamed chat completion, from
/// [`RelaxedChat::create_stream`].
pub type RelaxedStream =
    Pin<Box<dyn Stream<Item = Result<RelaxedStreamChunk, OpenAIError>> + Send + 'static>>;

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
    /// The call's id, when the server sent one.
    pub id: Option<String>,
    /// The name of the function to call.
    pub function_name: Option<String>,
    /// The arguments exactly as the server sent them: a JSON text.
    pub arguments_raw: String,
}

impl RelaxedToolCall {
    fn from_value(value: &Value) -> Self {
        let id = value.get("id").and_then(Value::as_str).map(str::to_string);
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
    pub fn arguments<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.arguments_raw)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_exposes_the_first_choice() {
        let response = RelaxedResponse::from_value(json!({
            "id": "r1",
            "model": "m",
            "choices": [{
                "finish_reason": "repetition",
                "message": {
                    "content": "hello",
                    "tool_calls": [{"id": "c1", "function": {"name": "f", "arguments": "{\"x\":1}"}}],
                },
            }],
        }));
        assert_eq!(response.content(), Some("hello"));
        assert_eq!(response.finish_reason(), Some("repetition"));
        assert_eq!(response.choices_len(), 1);
        let calls = response.typed_tool_calls();
        assert_eq!(calls.len(), 1);
        let arguments: Value = calls
            .first()
            .map(|call| call.arguments().expect("the arguments are JSON"))
            .expect("one call");
        assert_eq!(arguments, json!({"x": 1}));
    }

    #[test]
    fn a_chunk_is_a_delta_or_a_vendor_event() {
        let delta =
            RelaxedStreamChunk::from_value(json!({"choices": [{"delta": {"content": "hi"}}]}));
        assert_eq!(delta.delta_content(), Some("hi"));
        assert!(!delta.is_vendor_event());
        let event = RelaxedStreamChunk::from_value(json!({"type": "web_search_call"}));
        assert_eq!(event.event_type(), Some("web_search_call"));
    }

    #[test]
    fn the_request_builder_produces_the_body() {
        let body = RelaxedChatRequestBuilder::new()
            .model("m")
            .push_message(json!({"role": "user", "content": "hi"}))
            .web_search()
            .set("seed", 7)
            .build();
        assert_eq!(
            body,
            json!({
                "model": "m",
                "messages": [{"role": "user", "content": "hi"}],
                "web_search_options": {},
                "seed": 7,
            })
        );
    }
}
