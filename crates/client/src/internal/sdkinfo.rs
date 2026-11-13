//! The SDK's name and version, as sent with attestation fetches.

/// The value of the [`SDK_NAME_HEADER`] header.
pub(crate) const NAME: &str = "tinfoil-rs";

/// The version of this crate.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The request header that names the SDK.
pub(crate) const SDK_NAME_HEADER: &str = "Tinfoil-SDK";

/// The request header that carries the SDK's version.
pub(crate) const SDK_VERSION_HEADER: &str = "Tinfoil-SDK-Version";
