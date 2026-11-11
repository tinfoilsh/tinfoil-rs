//! The machine identifier of an SEV-SNP report.

use super::lib::abi::CHIP_ID_SIZE;
use crate::canonical::encode_lower_hex;
use crate::quote::QuoteError;

/// The key under which a machine is listed in a policy artifact: the
/// report's CHIP_ID field in lowercase hex.
///
/// The field is always 64 bytes. Hardware that identifies itself with a
/// shorter value delivers it padded with zeros, which is the listed form, so
/// no product needs its own handling.
pub fn identity(chip_id: &[u8]) -> Result<String, QuoteError> {
    if chip_id.len() != CHIP_ID_SIZE {
        return Err(QuoteError::new(format!(
            "SEV CHIP_ID must be {CHIP_ID_SIZE} bytes, got {}",
            chip_id.len()
        )));
    }
    Ok(encode_lower_hex(chip_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_is_the_whole_field_in_lowercase_hex() {
        let mut chip_id = [0u8; CHIP_ID_SIZE];
        chip_id[0] = 0xAB;
        chip_id[7] = 0x01;
        let text = identity(&chip_id).unwrap();
        assert_eq!(text.len(), 128);
        assert!(text.starts_with("ab00000000000001"));
        assert!(text.ends_with(&"0".repeat(112)));
    }

    #[test]
    fn a_field_of_another_length_is_rejected() {
        assert!(identity(&[0; 63]).is_err());
        assert!(identity(&[0; 65]).is_err());
        assert!(identity(&[]).is_err());
    }
}
