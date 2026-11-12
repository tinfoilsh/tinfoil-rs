//! A parser for server-sent events that carry JSON.
//!
//! [`RelaxedChat::create_stream`](crate::RelaxedChat::create_stream) uses
//! it; it is public for callers that read a streaming endpoint of their
//! own through an attested HTTP client.

use std::fmt;
use std::pin::Pin;

use async_openai::error::{OpenAIError, StreamError};
use bytes::Bytes;
use futures_core::Stream;
use serde_json::Value;

use crate::verifier::BoxError;

/// The longest line that is buffered: 16 MiB.
pub(crate) const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// The largest data of one event that is buffered: 16 MiB.
pub(crate) const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

/// The data that ends a stream.
const DONE: &str = "[DONE]";

/// A stream of the JSON payloads of server-sent events.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<Value, OpenAIError>> + Send + 'static>>;

/// Turns a stream of bytes, such as `reqwest::Response::bytes_stream()`,
/// into a stream of the JSON payloads of its events.
///
/// The bytes are read as an event stream is defined: lines end with a
/// line feed, a carriage return, or both; a byte order mark at the very
/// start is skipped; a line that starts with `:` is a comment; the `data`
/// lines of an event are joined with line feeds; and a blank line ends
/// the event. The `event`, `id` and `retry` fields and unknown fields are
/// read and not used, except that an event of the type `keepalive` is
/// skipped. Chunks may split the bytes anywhere.
///
/// Each event's data is parsed as one JSON value, which the stream
/// yields. An event without data, or whose data is only whitespace, is
/// skipped. The stream ends, without reading further, at an event whose
/// data is `[DONE]`; it also ends when the bytes end after a complete
/// event.
///
/// The stream ends with an error, and yields nothing after it, when:
///
/// - the byte stream fails: the error is passed on inside the
///   `OpenAIError`, so that a failure of the attested HTTP client can be
///   found with [`Error::from_openai`](crate::Error::from_openai);
/// - a line is not valid UTF-8;
/// - a line, or the data of one event, is longer than 16 MiB: nothing is
///   cut short to fit;
/// - the data of an event is not JSON: the error carries the data;
/// - the bytes end inside an event (after some of its lines and before
///   the blank line that ends it, or inside a line), unless what is
///   pending is `[DONE]`: a stream that was cut off is not passed off as
///   a complete one.
///
/// Dropping the returned stream drops the byte stream.
pub fn parse_event_stream<S, E>(byte_stream: S) -> EventStream
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + Send + 'static,
{
    Box::pin(async_stream::stream! {
        let mut byte_stream = std::pin::pin!(byte_stream);
        let mut decoder = Decoder::default();
        let mut events = Vec::new();
        loop {
            let next = std::future::poll_fn(|cx| byte_stream.as_mut().poll_next(cx)).await;
            let outcome = match next {
                Some(Ok(chunk)) => decoder.feed(&chunk, &mut events),
                Some(Err(error)) => {
                    yield Err(OpenAIError::from(error.into()));
                    return;
                }
                None => decoder.finish().map(|()| true),
            };
            for data in events.drain(..) {
                match serde_json::from_str(&data) {
                    Ok(value) => yield Ok(value),
                    Err(error) => {
                        yield Err(OpenAIError::JSONDeserialize(error, data));
                        return;
                    }
                }
            }
            match outcome {
                Ok(true) => return,
                Ok(false) => {}
                Err(fault) => {
                    yield Err(fault.into());
                    return;
                }
            }
        }
    })
}

/// Why an event stream could not be read further.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// A line is not valid UTF-8.
    InvalidUtf8,
    /// A line is longer than [`MAX_LINE_BYTES`].
    LineTooLong,
    /// The data of an event is longer than [`MAX_EVENT_BYTES`].
    EventTooLarge,
    /// The bytes ended inside an event.
    Truncated,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::InvalidUtf8 => f.write_str("a line of the event stream is not valid UTF-8"),
            Fault::LineTooLong => write!(
                f,
                "a line of the event stream is longer than {MAX_LINE_BYTES} bytes"
            ),
            Fault::EventTooLarge => write!(
                f,
                "the data of an event is longer than {MAX_EVENT_BYTES} bytes"
            ),
            Fault::Truncated => f.write_str("the event stream ended inside an event"),
        }
    }
}

impl From<Fault> for OpenAIError {
    fn from(fault: Fault) -> Self {
        OpenAIError::StreamError(Box::new(StreamError::EventStream(fault.to_string())))
    }
}

/// The state of reading an event stream: the line and the event that are
/// being collected.
#[derive(Default)]
pub(crate) struct Decoder {
    /// The bytes of the current line, without its end.
    line: Vec<u8>,
    /// Whether the last byte was a carriage return, whose line feed, if
    /// one follows, belongs to the same line end.
    after_cr: bool,
    /// Whether a first line has been read: a byte order mark is skipped
    /// only in front of it.
    started: bool,
    /// The data of the current event, each `data` line followed by a line
    /// feed.
    data: String,
    /// The type of the current event.
    event_type: String,
    /// Whether the stream's last event has been read.
    done: bool,
}

impl Decoder {
    /// Reads `chunk` and appends the data of each event that it completes
    /// to `events`. Returns whether the stream is over: the event that
    /// ends it was read. Nothing is read after that event or after a
    /// fault.
    pub(crate) fn feed(&mut self, chunk: &[u8], events: &mut Vec<String>) -> Result<bool, Fault> {
        for &byte in chunk {
            if self.done {
                break;
            }
            let after_cr = std::mem::take(&mut self.after_cr);
            match byte {
                b'\n' if after_cr => {}
                b'\n' => self.end_line(events)?,
                b'\r' => {
                    self.end_line(events)?;
                    self.after_cr = true;
                }
                byte => {
                    if self.line.len() >= MAX_LINE_BYTES {
                        return Err(Fault::LineTooLong);
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(self.done)
    }

    /// The end of the bytes. A fault unless they ended between events, or
    /// what is pending is the event that ends a stream.
    pub(crate) fn finish(&mut self) -> Result<(), Fault> {
        if self.done {
            return Ok(());
        }
        if !self.line.is_empty() {
            // An unfinished line counts only towards recognizing the end.
            let mut ignored = Vec::new();
            self.end_line(&mut ignored)?;
        }
        if self.data.is_empty() || self.data.trim() == DONE {
            Ok(())
        } else {
            Err(Fault::Truncated)
        }
    }

    /// Takes the current line as complete.
    fn end_line(&mut self, events: &mut Vec<String>) -> Result<(), Fault> {
        let line = std::mem::take(&mut self.line);
        let mut line = std::str::from_utf8(&line).map_err(|_| Fault::InvalidUtf8)?;
        if !std::mem::replace(&mut self.started, true) {
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
        }
        if line.is_empty() {
            self.dispatch(events);
            return Ok(());
        }
        // A line without a colon is a field with an empty value; one
        // space after the colon is not part of the value.
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            // A comment.
            "" => {}
            "data" => {
                // The data, with the line feed after each of its lines.
                let size = self
                    .data
                    .len()
                    .saturating_add(value.len())
                    .saturating_add(1);
                if size > MAX_EVENT_BYTES {
                    return Err(Fault::EventTooLarge);
                }
                self.data.push_str(value);
                self.data.push('\n');
            }
            "event" => value.clone_into(&mut self.event_type),
            // `id`, `retry` and unknown fields are not used.
            _ => {}
        }
        Ok(())
    }

    /// Ends the current event: its data, without the last line feed, is
    /// appended to `events`, unless there is none, it is only whitespace,
    /// or the event is a keep-alive. Data of `[DONE]` ends the stream.
    fn dispatch(&mut self, events: &mut Vec<String>) {
        let mut data = std::mem::take(&mut self.data);
        let event_type = std::mem::take(&mut self.event_type);
        if data.ends_with('\n') {
            data.pop();
        }
        if data.trim() == DONE {
            self.done = true;
        } else if !data.trim().is_empty() && event_type != "keepalive" {
            events.push(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::task::{Context, Poll};

    use super::*;
    use crate::error::{Error, ErrorKind};

    /// Reads `chunks` to the end: the events, and how the stream ended.
    fn decode(chunks: &[&[u8]]) -> (Vec<String>, Result<bool, Fault>) {
        let mut decoder = Decoder::default();
        let mut events = Vec::new();
        for chunk in chunks {
            match decoder.feed(chunk, &mut events) {
                Ok(false) => {}
                ended => return (events, ended),
            }
        }
        let ended = decoder.finish().map(|()| false);
        (events, ended)
    }

    /// The events of `text` read in one chunk, which must end cleanly.
    fn events(text: &str) -> Vec<String> {
        let (events, ended) = decode(&[text.as_bytes()]);
        assert!(ended.is_ok(), "{text:?}: {ended:?}");
        events
    }

    #[test]
    fn a_blank_line_ends_an_event_whatever_the_line_ends_are() {
        for end in ["\n", "\r", "\r\n"] {
            let text = format!("data: one{end}{end}data: two{end}{end}");
            assert_eq!(events(&text), ["one", "two"], "{end:?}");
        }
        // Mixed in one stream.
        assert_eq!(
            events("data: a\r\n\ndata: b\r\rdata: c\n\r\n"),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn the_data_lines_of_one_event_are_joined_with_line_feeds() {
        assert_eq!(
            events("data: {\ndata:  \"a\": 1\ndata: }\n\n"),
            ["{\n \"a\": 1\n}"]
        );
        assert_eq!(events("data: a\ndata:\ndata: b\n\n"), ["a\n\nb"]);
        // A carriage return and the line feed after it are one line end,
        // also when two chunks part them.
        assert_eq!(events("data: a\r\ndata: b\r\n\r\n"), ["a\nb"]);
        let (split, ended) = decode(&[b"data: a\r", b"\ndata: b\r", b"\n\r", b"\n"]);
        assert_eq!((split, ended), (vec!["a\nb".to_owned()], Ok(false)));
    }

    #[test]
    fn fields_are_read_as_the_format_defines_them() {
        // One space after the colon is dropped, and only one.
        assert_eq!(events("data:x\n\n"), ["x"]);
        assert_eq!(events("data: x\n\n"), ["x"]);
        assert_eq!(events("data:  x\n\n"), [" x"]);
        // The value may hold colons.
        assert_eq!(events("data: {\"a\":\"b:c\"}\n\n"), ["{\"a\":\"b:c\"}"]);
        // Comments, other fields and unknown fields carry no data.
        assert_eq!(
            events(": comment\nevent: message\nid: 7\nretry: 100\nfoo: bar\ndata: x\n\n"),
            ["x"]
        );
        assert_eq!(events(":\n: keep-alive\n\ndata: x\n\n"), ["x"]);
        // A field name is the whole text before the colon.
        assert!(events(" data: x\n\n").is_empty());
        assert!(events("DATA: x\n\n").is_empty());
        assert!(events("datax: x\n\n").is_empty());
        // A line without a colon is a field without a value.
        assert!(events("data\n\n").is_empty());
        assert!(events("event\nid\n\n").is_empty());
    }

    #[test]
    fn an_event_without_data_is_not_an_event() {
        assert!(events("").is_empty());
        assert!(events("\n\n\n").is_empty());
        assert!(events("event: ping\n\n").is_empty());
        assert!(events("data:\n\n").is_empty());
        assert!(events("data:   \n\n").is_empty());
        assert!(events("event: keepalive\ndata: {}\n\n").is_empty());
        // The type of one event does not carry over to the next.
        assert_eq!(events("event: keepalive\ndata: 1\n\ndata: 2\n\n"), ["2"]);
    }

    #[test]
    fn a_byte_order_mark_is_skipped_only_at_the_very_start() {
        assert_eq!(events("\u{feff}data: x\n\n"), ["x"]);
        assert!(events("\n\u{feff}data: x\n\n").is_empty());
        assert!(events("data: x\n\n\u{feff}data: y\n\n") == ["x"]);
    }

    #[test]
    fn done_ends_the_stream_and_nothing_after_it_is_read() {
        let (events, ended) = decode(&[b"data: 1\n\ndata: [DONE]\n\ndata: 2\n\n\xff"]);
        assert_eq!(events, ["1"]);
        assert_eq!(ended, Ok(true));
        let (events, ended) = decode(&[b"data: [DONE]\n\n", b"data: 2\n\n"]);
        assert!(events.is_empty());
        assert_eq!(ended, Ok(true));
        // With spaces around it.
        assert_eq!(decode(&[b"data:  [DONE] \n\n"]).1, Ok(true));
    }

    #[test]
    fn bytes_that_end_between_events_end_the_stream_cleanly() {
        for text in [
            "",
            "data: 1\n\n",
            "data: 1\r\n\r\n",
            "data: 1\n\n: comment\n",
            "data: 1\n\n: comment",
            "data: 1\n\nevent: x\n",
            // The last event of a stream, however much of its end arrived.
            "data: 1\n\ndata: [DONE]\n\n",
            "data: 1\n\ndata: [DONE]\n",
            "data: 1\n\ndata: [DONE]",
            "data: 1\n\ndata: [DONE]\r",
        ] {
            let (events, ended) = decode(&[text.as_bytes()]);
            assert!(ended.is_ok(), "{text:?}: {ended:?}");
            assert_eq!(events.len(), usize::from(!text.is_empty()), "{text:?}");
        }
    }

    #[test]
    fn bytes_that_end_inside_an_event_are_a_fault_and_the_event_is_not_delivered() {
        for text in [
            "data: {\"a\":1}",
            "data: {\"a\":1}\n",
            "data: {\"a\":1}\r",
            "data: 12",
            "data: 1\n\ndata: 2\n",
            "data: 1\n\ndata: 2",
            "data: [DONE]\ndata: more",
        ] {
            let (events, ended) = decode(&[text.as_bytes()]);
            assert_eq!(ended, Err(Fault::Truncated), "{text:?}");
            assert!(events.len() <= 1, "{text:?}");
            assert!(!events.iter().any(|event| event.contains('2')), "{text:?}");
        }
    }

    #[test]
    fn a_line_that_is_not_utf8_is_a_fault() {
        assert_eq!(decode(&[b"data: \xff\n\n"]).1, Err(Fault::InvalidUtf8));
        assert_eq!(decode(&[b"data: \xc3\n\n"]).1, Err(Fault::InvalidUtf8));
        assert_eq!(decode(&[b": \xed\xa0\x80\n"]).1, Err(Fault::InvalidUtf8));
        // The event before it was delivered.
        let (events, ended) = decode(&[b"data: 1\n\ndata: \xff\n\n"]);
        assert_eq!((events.len(), ended), (1, Err(Fault::InvalidUtf8)));
    }

    const TRANSCRIPT: &str = "\u{feff}: start\r\n\
        data: {\"n\":1,\"text\":\"h\u{e9}llo \u{1f600}\"}\r\n\r\n\
        event: message\nid: 2\ndata: {\"n\":2}\n\n\
        data: {\rdata:  \"n\": 3\rdata: }\r\r\
        : keep-alive\n\n\
        event: keepalive\ndata: {}\n\n\
        data: {\"n\":4,\"type\":\"web_search_call\"}\r\n\n\
        data: [DONE]\n\n";

    #[test]
    fn the_same_events_come_out_wherever_the_bytes_are_split() {
        let whole = TRANSCRIPT.as_bytes();
        let (expected, ended) = decode(&[whole]);
        assert_eq!(ended, Ok(true));
        assert_eq!(
            expected,
            [
                "{\"n\":1,\"text\":\"h\u{e9}llo \u{1f600}\"}",
                "{\"n\":2}",
                "{\n \"n\": 3\n}",
                "{\"n\":4,\"type\":\"web_search_call\"}"
            ]
        );
        // Every split into two chunks: inside a line end, inside a
        // multi-byte character, inside the byte order mark.
        for at in 0..=whole.len() {
            let (head, tail) = whole.split_at(at);
            let (events, ended) = decode(&[head, tail]);
            assert_eq!(ended, Ok(true), "split at {at}");
            assert_eq!(events, expected, "split at {at}");
        }
        // And one byte at a time.
        let bytes: Vec<&[u8]> = whole.chunks(1).collect();
        let (events, ended) = decode(&bytes);
        assert_eq!((events, ended), (expected, Ok(true)));
    }

    #[test]
    fn a_line_or_an_event_over_the_limit_is_a_fault_and_one_at_the_limit_is_not() {
        assert_eq!(MAX_LINE_BYTES, 16 << 20);
        assert_eq!(MAX_EVENT_BYTES, 16 << 20);

        // A line that never ends, in chunks.
        let mut decoder = Decoder::default();
        let mut events = Vec::new();
        let chunk = vec![b'x'; 1 << 20];
        for _ in 0..16 {
            assert_eq!(decoder.feed(&chunk, &mut events), Ok(false));
        }
        assert_eq!(decoder.feed(b"x", &mut events), Err(Fault::LineTooLong));
        assert!(events.is_empty());

        // A comment is a line like any other.
        let mut long = vec![b':'; MAX_LINE_BYTES + 1];
        assert_eq!(decode(&[&long]).1, Err(Fault::LineTooLong));
        long.truncate(MAX_LINE_BYTES);
        long.push(b'\n');
        assert_eq!(decode(&[&long]).1, Ok(false));

        // An event of many short lines.
        let line = format!("data: {}\n", "y".repeat((1 << 20) - 1));
        let mut decoder = Decoder::default();
        for _ in 0..16 {
            assert_eq!(decoder.feed(line.as_bytes(), &mut events), Ok(false));
        }
        assert_eq!(
            decoder.feed(line.as_bytes(), &mut events),
            Err(Fault::EventTooLarge)
        );
        assert!(events.is_empty());

        // Events that are each within the limit are not added up.
        let event = format!("data: \"{}\"\n\n", "z".repeat(1 << 20));
        let mut decoder = Decoder::default();
        for _ in 0..20 {
            assert_eq!(decoder.feed(event.as_bytes(), &mut events), Ok(false));
        }
        assert_eq!(events.len(), 20);
    }

    // The stream.

    /// Polls a future that needs no waiting.
    fn now<T>(future: impl Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the future is not ready"),
        }
    }

    type Chunk = Result<Bytes, BoxError>;

    /// The items of the stream over `chunks`.
    fn parse(chunks: Vec<Chunk>) -> Vec<Result<Value, OpenAIError>> {
        let mut stream = parse_event_stream(futures_util::stream::iter(chunks));
        let mut items = Vec::new();
        while let Some(item) = now(std::future::poll_fn(|cx| stream.as_mut().poll_next(cx))) {
            items.push(item);
            assert!(items.len() < 1_000, "the stream does not end");
        }
        items
    }

    fn bytes(text: &'static str) -> Chunk {
        Ok(Bytes::from_static(text.as_bytes()))
    }

    #[test]
    fn each_event_is_one_json_value_and_done_ends_the_stream() {
        let items = parse(vec![
            bytes("data: {\"a\":1}\n\nda"),
            bytes("ta: {\"b\":\n"),
            bytes("data: 2}\n\ndata: [DONE]\n\ndata: {\"c\":3}\n\n"),
        ]);
        let values: Vec<Value> = items.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            values,
            [serde_json::json!({"a":1}), serde_json::json!({"b":2})]
        );
    }

    #[test]
    fn data_that_is_not_json_is_an_error_that_carries_it_and_ends_the_stream() {
        let items = parse(vec![bytes("data: 1\n\ndata: not json\n\ndata: 2\n\n")]);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_ref().unwrap(), &serde_json::json!(1));
        match &items[1] {
            Err(OpenAIError::JSONDeserialize(_, data)) => assert_eq!(data, "not json"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_fault_is_a_stream_error_after_the_events_before_it() {
        let items = parse(vec![bytes("data: 1\n\ndata: 2")]);
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        match &items[1] {
            Err(OpenAIError::StreamError(error)) => {
                assert!(
                    error.to_string().contains("ended inside an event"),
                    "{error}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_failure_of_the_bytes_is_passed_on_with_the_client_error_inside() {
        let failure: BoxError = Box::new(Error::deadline("too slow"));
        let items = parse(vec![
            bytes("data: 1\n\ndata: 2\n"),
            Err(failure),
            bytes("\n"),
        ]);
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        let error = items[1].as_ref().unwrap_err();
        let found = Error::from_openai(error).expect("the client's error");
        assert_eq!(found.kind(), ErrorKind::Network);
        assert!(found.is_timeout());
    }
}
