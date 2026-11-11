//! Intel TDX: authentication of quotes against the pinned Intel SGX root,
//! replaying the Intel collateral that the document recorded, and the
//! translation of an endorsed policy into complete expectations.

pub mod authenticate;
#[cfg(test)]
mod differential_tests;
pub mod expectations;
pub mod identity;
pub mod lib;
#[cfg(test)]
mod tests;

pub use authenticate::{Evidence, PcsReplay, Quote, authenticate};
pub use expectations::{Expectations, assemble};
pub use identity::identity;
