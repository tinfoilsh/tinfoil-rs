//! The machine identifier of a TDX quote.

use super::lib::abi::QuoteV4;
use crate::quote::QuoteError;
use crate::stub::pending;

/// The size of a platform provisioning identifier in bytes.
pub const PPID_SIZE: usize = 16;

/// The key under which a machine is listed in a policy artifact: the
/// platform provisioning identifier (PPID) of the PCK certificate embedded
/// in the quote, as 32 lowercase hex digits.
///
/// The PPID is authentic only once the quote's PCK chain has been verified
/// up to the Intel SGX root, so this is called after verification. In
/// order: the quote carries a PCK certificate chain; its first PEM block is
/// a certificate that parses; the certificate's SGX extensions decode
/// ([`pck_extensions`](super::lib::pcs::pck_extensions)); the PPID is
/// [`PPID_SIZE`] bytes.
pub fn identity(quote: &QuoteV4) -> Result<String, QuoteError> {
    pending("quote::tdx::identity")
}
