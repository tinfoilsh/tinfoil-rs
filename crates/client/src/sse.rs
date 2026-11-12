//! A minimal parser for server-sent events that carry JSON.
//!
//! [`RelaxedChat::create_stream`](crate::RelaxedChat::create_stream) uses
//! it; it is public for callers that read a streaming endpoint of their
//! own through an attested HTTP client.

use std::pin::Pin;

use async_openai::error::OpenAIError;
use bytes::Bytes;
use futures_core::Stream;
use serde_json::Value;

use crate::verifier::BoxError;

/// The largest single event that is buffered.
pub(crate) const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// A stream of the JSON payloads of server-sent events.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<Value, OpenAIError>> + Send + 'static>>;

/// Turns a stream of bytes, such as `reqwest::Response::bytes_stream()`,
/// into a stream of the JSON payloads of its events.
///
/// It yields one value for each `data:` line and skips `data: [DONE]`.
/// The stream ends with an error, and yields nothing after it, when:
///
/// - the byte stream fails: the error is passed on inside the
///   `OpenAIError`, so that a failure of the attested HTTP client can be
///   found with [`Error::from_openai`](crate::Error::from_openai);
/// - the bytes are not valid UTF-8;
/// - an event is larger than 1 MiB;
/// - a payload is not JSON: the error carries the payload.
///
/// Dropping the returned stream drops the byte stream.
pub fn parse_event_stream<S, E>(byte_stream: S) -> EventStream
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + Send + 'static,
{
    Box::pin(async_stream::stream! {
        drop(byte_stream);
        yield Err(crate::openai::relaxed::not_implemented("parse_event_stream"));
    })
}
