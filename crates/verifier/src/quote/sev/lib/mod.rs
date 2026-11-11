//! The SEV-SNP mechanics underneath the policy code: the report format, the
//! AMD certificate profile, chain and signature verification, and field
//! validation.
//!
//! - [`abi`]: the attestation report and its bit fields;
//! - [`kds`]: TCB versions, product lines and the AMD certificate
//!   extensions, as the AMD Key Distribution Service defines them;
//! - [`verify`]: the VCEK chain, revocation and the report signature;
//! - [`validate`]: the report's fields against bounds and exact values.

pub mod abi;
pub mod kds;
pub mod validate;
pub mod verify;
