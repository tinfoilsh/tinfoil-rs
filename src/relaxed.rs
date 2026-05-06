//! Permissive chat-completion helper.
//!
//! `async-openai`'s response types are exhaustive: a single unrecognised value
//! (for example `"finish_reason": "repetition"` from a vLLM-backed router)
//! fails deserialisation of the entire payload, even when the message content
//! itself is fine. The server-side response shape also changes faster than
//! the typed bindings can keep up.
//!
//! [`RelaxedChat`] sends the request through the enclave's pinned HTTP client
//! and parses the response as raw JSON. Typed accessors cover the common
//! fields, and [`RelaxedResponse::raw`] is available for anything else.
//!
//! Use this when you need to read fields the typed API rejects, or when you
//! want to send vendor extensions (vLLM `structured_outputs`,
//! Tinfoil-specific `web_search_options` / `pii_check_options`, ...).

use serde_json::Value;

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
///
/// Wraps the raw [`serde_json::Value`]. Each accessor returns `Option`/empty-
/// slice rather than panicking on missing fields, so partial / experimental
/// router responses degrade gracefully.
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

    /// Number of choices returned. Most callers only need the first.
    pub fn choices_len(&self) -> usize {
        self.body
            .get("choices")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    }
}

impl Client {
    /// Permissive chat-completion handle that bypasses async-openai's
    /// strict response types.
    ///
    /// Use this when you need fields the typed API doesn't model, when the
    /// router emits values async-openai's enums don't recognise, or when you
    /// want to forward vendor extensions like `web_search_options` or
    /// `structured_outputs` without composing typed builders.
    ///
    /// All requests still flow through the enclave's verified, TLS-pinned
    /// transport.
    ///
    /// # Example
    /// ```rust,ignore
    /// use serde_json::json;
    /// use tinfoil::Client;
    ///
    /// # async fn run() -> tinfoil::error::Result<()> {
    /// let client = Client::new_default("api-key").await?;
    /// let response = client.chat_relaxed().create(json!({
    ///     "model": "gpt-oss-120b",
    ///     "messages": [{"role": "user", "content": "Hi"}],
    /// })).await?;
    ///
    /// if let Some(text) = response.content() {
    ///     println!("{}", text);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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
}
