//! Offline verification of Tinfoil enclave attestation documents.
//!
//! This crate is the functional core of the SDK. It opens no connections,
//! reads no files and keeps no state between calls: a caller hands it an
//! attestation document and gets back either the verified facts or the reason
//! the document must not be trusted. Fetching documents and binding
//! connections to a verified enclave belong to the `tinfoil` client crate.
//!
//! The crate is under construction and exports nothing yet.
