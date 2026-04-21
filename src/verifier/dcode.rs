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
/// Only SANs whose **second** DNS label is exactly `<prefix>` are considered a
/// match (e.g. `00ABCD.hpke.example.com` matches prefix `hpke`, but
/// `ok.hpkex.example.com` or `foo.a.hpke.bar.example.com` do not). The leftmost
/// label must be `NN<base32-chunk>` where `NN` is a two-digit zero-padded index
/// and the chunk is non-empty base32.
///
/// Malformed SANs that look like they were meant to match (right prefix label
/// but wrong chunk shape) are skipped silently so that a single stray entry
/// does not poison decoding of valid entries.
///
/// Returns `None` if no matching SANs are found or the concatenated chunks
/// fail base32 decoding.
pub fn decode_from_sans(sans: &[&str], prefix: &str) -> Option<Vec<u8>> {
    let mut chunks: Vec<(u32, String)> = Vec::new();

    for san in sans {
        let mut labels = san.split('.');
        let first_label = match labels.next() {
            Some(l) => l,
            None => continue,
        };
        let second_label = match labels.next() {
            Some(l) => l,
            None => continue,
        };

        if second_label != prefix {
            continue;
        }

        // Leftmost label must be NN<base32-chunk> with non-empty chunk.
        if first_label.len() < 3 {
            continue;
        }
        let (index_str, chunk) = first_label.split_at(2);
        if !index_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let index: u32 = match index_str.parse() {
            Ok(i) => i,
            Err(_) => continue,
        };
        if chunk.is_empty() {
            continue;
        }

        chunks.push((index, chunk.to_uppercase()));
    }

    if chunks.is_empty() {
        return None;
    }

    // Reject duplicate indices to catch malformed/ambiguous SAN sets.
    chunks.sort_by_key(|(idx, _)| *idx);
    if chunks.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }

    let combined: String = chunks.into_iter().map(|(_, chunk)| chunk).collect();
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

    #[test]
    fn test_decode_rejects_prefix_substring() {
        // "hpkex" is not an exact label match for "hpke".
        let sans = vec!["00NBSWY3DP.hpkex.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_requires_prefix_in_second_label() {
        // Prefix label must be the SAN's second DNS label, not buried later.
        let sans = vec!["00NBSWY3DP.foo.hpke.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_rejects_duplicate_indices() {
        let sans = vec!["00NBSWY3DP.hpke.example.com", "00O5XXE3DE.hpke.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_skips_malformed_and_keeps_valid() {
        // Malformed first label "xxABCD" should be skipped, not poison decode.
        let sans = vec!["xxNBSWY3DP.hpke.example.com", "00NBSWY3DP.hpke.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    #[test]
    fn test_decode_rejects_empty_chunk() {
        let sans = vec!["00.hpke.example.com"];
        let result = decode_from_sans(&sans, "hpke");
        assert_eq!(result, None);
    }
}
