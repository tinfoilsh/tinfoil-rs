//! AMD SEV-SNP: authentication of attestation reports against the pinned
//! AMD roots, and the translation of an endorsed policy into complete
//! expectations.

pub mod authenticate;
pub mod expectations;
pub mod identity;
pub mod lib;

pub use authenticate::{Evidence, Quote, authenticate};
pub use expectations::{Expectations, assemble};
pub use identity::identity;
pub use lib::abi::ProductLine;
