//! Utility functions for verification modules.

use base64::Engine;

/// Decode a base64-encoded string to bytes.
///
/// Uses the standard base64 alphabet with padding.
pub fn decode_b64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
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
