//! X.509 for the verifier: strict DER, certificates, public keys, chains at
//! a supplied time, and revocation lists.
//!
//! Every chain in the verifier is short and comes with its own trust anchor
//! (the Sigstore trusted root, the AMD and Intel roots, a registry root), so
//! this module verifies a path against explicit anchors at an explicit
//! [`Instant`](crate::instant::Instant). It never consults a system trust
//! store or a clock.
//!
//! Parsing is strict: input is canonical DER with nothing after it, and a
//! certificate re-encodes to the bytes it was parsed from, so that a
//! signature is always checked over the bytes that were signed.

pub mod certificate;
pub mod chain;
pub mod crl;
pub mod der;
pub mod key;

use crate::stub::message_error;

pub use certificate::{Certificate, Extension, NameField};
pub use chain::{KeyPurpose, verify_chain};
pub use crl::Crl;
pub use der::{PemBlock, pem_blocks};
pub use key::{EcdsaHash, KeyAlgorithm, PublicKey, SignatureScheme};

message_error! {
    /// Certificate material that does not parse, does not verify, or is not
    /// acceptable for its use.
    pub struct X509Error;
}

impl From<::der::Error> for X509Error {
    fn from(error: ::der::Error) -> Self {
        Self::new(format!("DER: {error}"))
    }
}

/// The largest certificate that is parsed, in bytes.
pub const MAX_CERTIFICATE_SIZE: usize = 16 << 10;
