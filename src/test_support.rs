//! Unit-test helpers shared across in-crate test modules (compiled only
//! under `cfg(test)`, see `lib.rs`).

use std::sync::{Arc, Mutex};

use serde_json::Value;

/// Minimal one-request-per-connection HTTP/1.1 server; the crate carries
/// no mock-server dev-dependency. Every request body received is parsed as
/// JSON and pushed onto `received`, then answered with a fixed
/// chat-completion response.
pub(crate) async fn serve_chat_completions(
    listener: tokio::net::TcpListener,
    received: Arc<Mutex<Vec<Value>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let received = Arc::clone(&received);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (headers_end, content_length) = loop {
                let Ok(n) = stream.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let content_length = headers
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::to_string)
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (pos + 4, content_length);
                }
            };
            while buf.len() < headers_end + content_length {
                let Ok(n) = stream.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            if buf.len() < headers_end + content_length {
                // Connection closed before the full body arrived.
                return;
            }
            let body = &buf[headers_end..headers_end + content_length];
            received
                .lock()
                .unwrap()
                .push(serde_json::from_slice(body).unwrap_or(Value::Null));

            let response_body = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop","logprobs":null}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
