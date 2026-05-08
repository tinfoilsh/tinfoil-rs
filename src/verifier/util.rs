//! Utility functions for verification modules.

use base64::Engine;
use std::time::Duration;

/// Maximum number of retry attempts for network requests.
const MAX_RETRIES: u32 = 2;

/// Initial backoff delay in milliseconds.
const INITIAL_BACKOFF_MS: u64 = 500;

/// Upper bound on any single retry wait, including waits derived from a
/// server-supplied Retry-After header. Prevents a hostile or misconfigured
/// server from stalling verification for minutes.
const MAX_RETRY_AFTER_MS: u64 = 10_000;

/// Decode a base64-encoded string to bytes.
///
/// Uses the standard base64 alphabet with padding.
pub fn decode_b64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}

/// Parse a Retry-After header value into a bounded delay.
///
/// Supports the delta-seconds form (the HTTP-date form is uncommon for APIs
/// we talk to and is ignored). The result is clamped to `MAX_RETRY_AFTER_MS`.
fn parse_retry_after(response: &reqwest::Response) -> Option<Duration> {
    let header = response.headers().get(reqwest::header::RETRY_AFTER)?;
    let value = header.to_str().ok()?.trim();
    let seconds: u64 = value.parse().ok()?;
    let millis = seconds.saturating_mul(1000).min(MAX_RETRY_AFTER_MS);
    Some(Duration::from_millis(millis))
}

/// Fetch a URL with retry and exponential backoff (500ms, 1s, 2s).
///
/// Retries up to MAX_RETRIES times on network errors, server errors (5xx),
/// and rate-limit responses (429). When the server returns a Retry-After
/// header we honor it (clamped to `MAX_RETRY_AFTER_MS`); otherwise we fall
/// back to exponential backoff. Matches the JS SDK's withRetry() behavior
/// of retrying both network failures and HTTP error responses.
pub async fn fetch_with_retry(url: &str) -> reqwest::Result<reqwest::Response> {
    // Single chokepoint for every unpinned reqwest call in the crate.
    // Guarantees the rustls crypto provider is installed before
    // reqwest's internal ClientConfig::builder() runs, no matter which
    // public entry point the caller used to get here.
    crate::ensure_crypto_provider();

    let mut last_response = None;
    let mut last_err = None;

    for attempt in 0..=MAX_RETRIES {
        let mut retry_after: Option<Duration> = None;

        match reqwest::get(url).await {
            Ok(response)
                if response.status().is_server_error()
                    || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                retry_after = parse_retry_after(&response);
                last_response = Some(response);
                last_err = None;
            }
            Ok(response) => return Ok(response),
            Err(e) => {
                last_response = None;
                last_err = Some(e);
            }
        }

        if attempt < MAX_RETRIES {
            let backoff = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt));
            let delay = retry_after.unwrap_or(backoff);
            tokio::time::sleep(delay).await;
        }
    }

    match last_response {
        Some(response) => Ok(response),
        None => Err(last_err.unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_b64() {
        let encoded = "SGVsbG8gV29ybGQ="; // "Hello World"
        let decoded = decode_b64(encoded).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_decode_b64_invalid() {
        let invalid = "not valid base64!!!";
        assert!(decode_b64(invalid).is_err());
    }
}
