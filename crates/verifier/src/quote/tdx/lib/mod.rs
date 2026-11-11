//! The TDX mechanics underneath the policy code: the quote format, Intel's
//! collateral, quote verification, and field validation.
//!
//! - [`abi`]: the version 4 quote;
//! - [`pcs`]: the collateral of Intel's Provisioning Certification Service
//!   and the SGX extensions of a PCK certificate;
//! - [`verify`]: the PCK chain, the collateral signatures and the quote
//!   signatures;
//! - [`validate`]: the quote's fields against exact values and floors.

pub mod abi;
pub mod pcs;
pub mod validate;
pub mod verify;
