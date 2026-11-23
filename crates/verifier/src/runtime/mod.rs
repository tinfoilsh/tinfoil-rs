//! The runtime release that a config pins: the manifest of its launch
//! measurements, and the pin itself as a config states it. The container
//! build requirements of a config are read here too.

mod config;
mod manifest;
mod provenance;

pub use crate::document::collateral::RuntimeReference;
pub use config::{MAX_CONFIG_SIZE, RuntimeConfigError, runtime_from_config};
pub use manifest::{
    FORMAT_VERSION, MAX_MANIFEST_SIZE, MEASUREMENT_SIZE, Manifest, ManifestError, Measurements,
    SnpLaunch, TdxLaunch, decode_manifest, parse_manifest,
};
pub use provenance::{
    ContainerProvenance, ContainerProvenanceError, REF_WILDCARD, container_provenance_from_config,
};

#[cfg(test)]
mod provenance_tests;
#[cfg(test)]
mod tests;
