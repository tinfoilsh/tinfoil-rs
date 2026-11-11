//! Tinfoil's public signing keys.

use super::EndorsementError;
use crate::stub::pending;
use crate::x509::PublicKey;

/// The keys that authenticate registry issuers, public configs and
/// artifact freshness approvals when the caller pins none: the keys
/// embedded in the crate. An error only if an embedded key does not parse.
pub fn public_signing_keys() -> Result<Vec<PublicKey>, EndorsementError> {
    pending("endorsement::signing_keys::public_signing_keys")
}
