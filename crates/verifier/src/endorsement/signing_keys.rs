//! Tinfoil's public signing keys.

use super::EndorsementError;
use crate::trust::TINFOIL_SIGNING_KEY_PEM;
use crate::x509::PublicKey;

/// The keys that authenticate registry issuers, public configs and
/// artifact freshness approvals when the caller pins none: the keys
/// embedded in the crate. An error only if an embedded key does not parse.
pub fn public_signing_keys() -> Result<Vec<PublicKey>, EndorsementError> {
    let pem = std::str::from_utf8(TINFOIL_SIGNING_KEY_PEM)
        .map_err(|_| EndorsementError::new("embedded signing key is not text"))?;
    Ok(vec![PublicKey::from_pem(pem)?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::statement::key_hint;

    #[test]
    fn the_embedded_keys_are_usable_approval_keys() {
        let keys = public_signing_keys().unwrap();
        assert_eq!(keys.len(), 1);
        for key in &keys {
            key_hint(key).unwrap();
        }
    }
}
