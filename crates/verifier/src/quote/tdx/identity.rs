//! The machine identifier of a TDX quote.

use super::lib::abi::QuoteV4;
use super::lib::pcs::pck_extensions;
use super::lib::verify::pck_certificate_chain;
use crate::quote::QuoteError;

pub use super::lib::pcs::PPID_SIZE;

/// The key under which a machine is listed in a policy artifact: the
/// platform provisioning identifier (PPID) of the PCK certificate embedded
/// in the quote, as 32 lowercase hex digits.
///
/// The PPID is authentic only once the quote's PCK chain has been verified
/// up to the Intel SGX root, so this is called after verification. In
/// order: the quote carries a PCK certificate chain
/// ([`pck_certificate_chain`]); its first certificate's SGX extensions
/// decode ([`pck_extensions`]), which establishes a PPID of [`PPID_SIZE`]
/// bytes.
pub fn identity(quote: &QuoteV4) -> Result<String, QuoteError> {
    let chain = pck_certificate_chain(&quote.signed_data.pck_cert_chain)?;
    let extensions = pck_extensions(&chain.pck)
        .map_err(|error| error.within("parsing PCK certificate extensions"))?;
    if extensions.ppid.len() != PPID_SIZE.saturating_mul(2) {
        return Err(QuoteError::new(format!(
            "PCK certificate carries malformed PPID {:?}",
            extensions.ppid
        )));
    }
    Ok(extensions.ppid)
}
