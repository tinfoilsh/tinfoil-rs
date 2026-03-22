//! Utility functions for verification modules.

use base64::Engine;

/// Maximum number of retry attempts for network requests.
const MAX_RETRIES: u32 = 2;

/// Initial backoff delay in milliseconds.
const INITIAL_BACKOFF_MS: u64 = 500;

/// Decode a base64-encoded string to bytes.
///
/// Uses the standard base64 alphabet with padding.
pub fn decode_b64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}

/// Fetch a URL with retry and exponential backoff (500ms, 1s, 2s).
///
/// Retries up to MAX_RETRIES times on network errors or server errors (5xx).
/// Matches the JS SDK's withRetry() behavior where both network failures
/// and HTTP error responses are retried.
pub async fn fetch_with_retry(url: &str) -> reqwest::Result<reqwest::Response> {
    let mut last_response = None;
    let mut last_err = None;

    for attempt in 0..=MAX_RETRIES {
        match reqwest::get(url).await {
            Ok(response) if response.status().is_server_error() => {
                // Server error (5xx) -- retry
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
            let delay = INITIAL_BACKOFF_MS * 2u64.pow(attempt);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
    }

    // Return the last server error response or network error
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
