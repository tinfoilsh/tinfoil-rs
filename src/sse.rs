//! Minimal Server-Sent Events parser.
//!
//! `chat_relaxed().create_stream()` uses this internally; it's also exposed
//! publicly for users who want to roll their own streaming endpoints.
//!
//! The parser yields one `serde_json::Value` per `data:` line, skipping
//! `data: [DONE]`. Any line that doesn't deserialise as JSON is surfaced
//! as an error with the offending payload included for debugging.

use std::pin::Pin;

use bytes::Bytes;
use futures_util::Stream;
use serde_json::Value;

use crate::error::{Error, Result};

const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;
const MAX_PENDING_UTF8_BYTES: usize = 3;

/// Box-pinned stream of JSON event payloads, the canonical return type
/// of [`parse_event_stream`].
pub type EventStream = Pin<Box<dyn Stream<Item = Result<Value>> + Send>>;

/// Convert a raw byte stream (typically `reqwest::Response::bytes_stream()`)
/// into a stream of decoded JSON event payloads.
///
/// The input stream's error type is erased to a `String` so any
/// transport-level failure becomes [`Error::Network`]. The returned
/// stream is already box-pinned so callers can `.next().await` without
/// pinning manually.
pub fn parse_event_stream<S, E>(byte_stream: S) -> EventStream
where
    S: Stream<Item = std::result::Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    use async_stream::try_stream;
    use futures_util::StreamExt;

    let mut byte_stream: Pin<Box<dyn Stream<Item = std::result::Result<Bytes, E>> + Send>> =
        Box::pin(byte_stream);

    let stream = try_stream! {
        let mut buffer = String::new();
        let mut pending: Vec<u8> = Vec::new();

        while let Some(chunk) = byte_stream.next().await {
            let chunk = chunk.map_err(|e| Error::Network(e.to_string()))?;
            pending.extend_from_slice(&chunk);

            let error_len = match std::str::from_utf8(&pending) {
                Ok(valid) => {
                    buffer.push_str(valid);
                    pending.clear();
                    None
                }
                Err(e) => {
                    let valid_up_to = e.valid_up_to();
                    if valid_up_to > 0 {
                        let valid = std::str::from_utf8(&pending[..valid_up_to])
                            .expect("validated prefix is UTF-8");
                        buffer.push_str(valid);
                        pending.drain(..valid_up_to);
                    }
                    e.error_len()
                }
            };

            if error_len.is_some() || pending.len() > MAX_PENDING_UTF8_BYTES {
                Err(Error::Network("SSE stream contained invalid UTF-8".to_string()))?;
            }

            while let Some((idx, separator_len)) = find_event_boundary(&buffer) {
                if idx > MAX_SSE_EVENT_BYTES {
                    Err(Error::Network(format!(
                        "SSE event exceeded {} bytes",
                        MAX_SSE_EVENT_BYTES
                    )))?;
                }

                let event = buffer[..idx].to_string();
                buffer.drain(..idx + separator_len);

                for value in parse_event_block(&event)? {
                    yield value;
                }
            }

            if buffer.len() > MAX_SSE_EVENT_BYTES {
                Err(Error::Network(format!(
                    "SSE event exceeded {} bytes",
                    MAX_SSE_EVENT_BYTES
                )))?;
            }
        }

        if !pending.is_empty() {
            Err(Error::Network(
                "SSE stream ended with incomplete UTF-8".to_string(),
            ))?;
        }

        // Drain whatever is left after the stream closes (servers don't always
        // emit a trailing `\n\n`).
        if !buffer.is_empty() {
            for value in parse_event_block(&buffer)? {
                yield value;
            }
        }
    };

    Box::pin(stream)
}

fn find_event_boundary(buffer: &str) -> Option<(usize, usize)> {
    let lf = buffer.find("\n\n").map(|idx| (idx, 2));
    let crlf = buffer.find("\r\n\r\n").map(|idx| (idx, 4));
    match (lf, crlf) {
        (Some(lf), Some(crlf)) => Some(if lf.0 < crlf.0 { lf } else { crlf }),
        (Some(boundary), None) | (None, Some(boundary)) => Some(boundary),
        (None, None) => None,
    }
}

fn parse_event_block(event: &str) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for line in event.lines() {
        let line = line.trim_start();
        let payload = match line.strip_prefix("data:") {
            Some(rest) => rest.trim(),
            None => continue,
        };
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let value = serde_json::from_str(payload).map_err(|e| {
            Error::Network(format!(
                "failed to decode SSE payload as JSON: {} (payload: {})",
                e, payload
            ))
        })?;
        out.push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream::{self, StreamExt};

    fn make_stream(
        chunks: Vec<&'static str>,
    ) -> impl Stream<Item = std::result::Result<Bytes, std::io::Error>> {
        stream::iter(
            chunks
                .into_iter()
                .map(|s| Ok::<Bytes, std::io::Error>(Bytes::from(s.as_bytes()))),
        )
    }

    fn make_byte_stream(
        chunks: Vec<Vec<u8>>,
    ) -> impl Stream<Item = std::result::Result<Bytes, std::io::Error>> {
        stream::iter(
            chunks
                .into_iter()
                .map(|bytes| Ok::<Bytes, std::io::Error>(Bytes::from(bytes))),
        )
    }

    #[tokio::test]
    async fn parses_complete_events() {
        let stream = make_stream(vec!["data: {\"a\":1}\n\n", "data: {\"b\":2}\n\n"]);
        let mut out = parse_event_stream(stream);
        let first = out.next().await.unwrap().unwrap();
        let second = out.next().await.unwrap().unwrap();
        assert_eq!(first["a"], 1);
        assert_eq!(second["b"], 2);
        assert!(out.next().await.is_none());
    }

    #[tokio::test]
    async fn parses_crlf_delimited_events() {
        let stream = make_stream(vec!["data: {\"a\":1}\r\n\r\n", "data: {\"b\":2}\r\n\r\n"]);
        let mut out = parse_event_stream(stream);
        let first = out.next().await.unwrap().unwrap();
        let second = out.next().await.unwrap().unwrap();
        assert_eq!(first["a"], 1);
        assert_eq!(second["b"], 2);
        assert!(out.next().await.is_none());
    }

    #[tokio::test]
    async fn handles_split_chunks() {
        let stream = make_stream(vec!["data: {\"a\"", ":42}\n\n"]);
        let mut out = parse_event_stream(stream);
        let first = out.next().await.unwrap().unwrap();
        assert_eq!(first["a"], 42);
    }

    #[tokio::test]
    async fn handles_utf8_split_across_chunks() {
        let stream = make_byte_stream(vec![
            b"data: {\"text\":\"".to_vec(),
            vec![0xc3],
            vec![0xa9],
            b"\"}\n\n".to_vec(),
        ]);
        let mut out = parse_event_stream(stream);
        let first = out.next().await.unwrap().unwrap();
        assert_eq!(first["text"], "é");
    }

    #[tokio::test]
    async fn rejects_event_past_size_limit() {
        let stream = make_byte_stream(vec![vec![b'x'; MAX_SSE_EVENT_BYTES + 1]]);
        let mut out = parse_event_stream(stream);
        let err = out.next().await.unwrap();
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_utf8() {
        let stream = make_byte_stream(vec![vec![0xff]]);
        let mut out = parse_event_stream(stream);
        let err = out.next().await.unwrap();
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn skips_done_marker() {
        let stream = make_stream(vec!["data: {\"k\":\"v\"}\n\ndata: [DONE]\n\n"]);
        let mut out = parse_event_stream(stream);
        let first = out.next().await.unwrap().unwrap();
        assert_eq!(first["k"], "v");
        assert!(out.next().await.is_none());
    }

    #[tokio::test]
    async fn flushes_trailing_event_without_blank_line() {
        let stream = make_stream(vec!["data: {\"x\":1}"]);
        let mut out = parse_event_stream(stream);
        let first = out.next().await.unwrap().unwrap();
        assert_eq!(first["x"], 1);
    }

    #[tokio::test]
    async fn surfaces_invalid_json_as_error() {
        let stream = make_stream(vec!["data: not-json\n\n"]);
        let mut out = parse_event_stream(stream);
        let err = out.next().await.unwrap();
        assert!(err.is_err());
    }
}
