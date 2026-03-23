//! Decoder for dcode-encoded values in DNS SAN entries.
//!
//! Tinfoil enclaves encode HPKE keys and attestation hashes into TLS
//! certificate SANs using a chunked base32 format:
//!
//!   `NN<base32-chunk>.<prefix>.<domain>`
//!
//! Where `NN` is a 2-digit zero-padded chunk index, and `<prefix>` is
//! `hpke` for HPKE keys or `hatt` for attestation hashes.
//!
//! This is necessary because DNS labels have a 63-character limit.

use data_encoding::BASE32_NOPAD;

/// Decode a dcode-encoded value from DNS SAN entries.
///
/// Filters SANs containing `.<prefix>.`, extracts the indexed base32 chunks
/// from the leftmost label, sorts by index, concatenates, and base32-decodes.
///
/// Returns `None` if no matching SANs are found or decoding fails.
pub fn decode_from_sans(sans: &[&str], prefix: &str) -> Option<Vec<u8>> {
    let pattern = format!(".{}.", prefix);

    // Collect (index, base32_chunk) pairs from matching SANs
    let mut chunks: Vec<(u32, String)> = Vec::new();

    for san in sans {
        if !san.contains(&pattern) {
            continue;
        }

        // The leftmost DNS label contains: NN<base32-chunk>
        let first_label = san.split('.').next()?;
        if first_label.len() < 3 {
            // Need at least 2 chars for index + 1 char of data
            continue;
        }

        let index: u32 = first_label[..2].parse().ok()?;
        let chunk = &first_label[2..];
        chunks.push((index, chunk.to_uppercase()));
    }

    if chunks.is_empty() {
        return None;
    }

    // Sort by index and concatenate
    chunks.sort_by_key(|(idx, _)| *idx);
    let combined: String = chunks.into_iter().map(|(_, chunk)| chunk).collect();

    // Base32 decode (RFC 4648, no padding)
    BASE32_NOPAD.decode(combined.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hpke_single_chunk() {
        // "hello" in base32 is "NBSWY3DP"
        let sans = vec!["00NBSWY3DP.hpke.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_decode_hpke_multiple_chunks() {
        // "helloworld" split into two base32 chunks at 5-byte boundary:
        // "hello" -> NBSWY3DP, "world" -> O5XXE3DE
        let sans = vec!["01O5XXE3DE.hpke.example.com", "00NBSWY3DP.hpke.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, Some(b"helloworld".to_vec()));
    }

    #[test]
    fn test_decode_no_matching_sans() {
        let sans = vec!["example.com", "www.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_case_insensitive() {
        // base32 should be case-insensitive
        let sans = vec!["00nbswy3dp.hpke.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_decode_hatt_prefix() {
        let sans = vec!["00NBSWY3DP.hatt.example.com"];
        let result = decode_from_sans(&sans, "hatt");
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_decode_ignores_other_prefixes() {
        let sans = vec!["00NBSWY3DP.hpke.example.com", "00JBSWY3DP.hatt.example.com"];
        // Only decode hpke entries
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, Some(b"hello".to_vec()));
    }
}
