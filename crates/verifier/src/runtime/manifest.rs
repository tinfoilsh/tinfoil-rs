//! The runtime manifest: the launch measurements of one runtime release.

use std::fmt;

use sha2::{Digest, Sha256};

use super::RuntimeReference;
use crate::canonical::{self, CanonicalError};
use crate::json::decode::{self, DecodeError};
use crate::json::{self, JsonError, Value};
use crate::semver;

/// The manifest format that this module reads.
pub const FORMAT_VERSION: i64 = 1;
/// The size of a launch measurement in bytes.
pub const MEASUREMENT_SIZE: usize = 48;
/// The largest manifest that is read, in bytes.
pub const MAX_MANIFEST_SIZE: usize = 1 << 20;

/// A TDX runtime measurement register that the launch leaves untouched.
const ZERO_REGISTER: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// A runtime manifest that is not the pinned one, or is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    message: String,
}

impl ManifestError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ManifestError {}

impl From<JsonError> for ManifestError {
    fn from(error: JsonError) -> Self {
        Self::new(format!("parsing runtime manifest: {error}"))
    }
}

impl From<DecodeError> for ManifestError {
    fn from(error: DecodeError) -> Self {
        Self::new(format!("parsing runtime manifest: {error}"))
    }
}

impl From<CanonicalError> for ManifestError {
    fn from(error: CanonicalError) -> Self {
        Self::new(error.to_string())
    }
}

/// A validated runtime manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The release: a full semantic version with a leading `v`.
    pub version: String,
    /// The launch measurements of the release.
    pub measurements: Measurements,
}

/// The launch measurements of a runtime release, for every platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurements {
    /// The format of the measurements; always [`FORMAT_VERSION`].
    pub format_version: i64,
    /// The SEV-SNP launch.
    pub snp_launch: SnpLaunch,
    /// The TDX launch.
    pub tdx_launch: TdxLaunch,
}

/// The SEV-SNP launch measurement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnpLaunch {
    /// The launch digest: 48 bytes, lowercase hex.
    pub measurement: String,
}

/// The TDX launch measurements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TdxLaunch {
    /// MRTD: 48 bytes, lowercase hex.
    pub mrtd: String,
    /// RTMR0; zero in a valid manifest.
    pub rtmr0: String,
    /// RTMR1; zero in a valid manifest.
    pub rtmr1: String,
    /// RTMR2; zero in a valid manifest.
    pub rtmr2: String,
    /// RTMR3; zero in a valid manifest.
    pub rtmr3: String,
}

impl TdxLaunch {
    /// MRTD followed by RTMR0 to RTMR3.
    pub fn registers(&self) -> [&str; 5] {
        [
            &self.mrtd,
            &self.rtmr0,
            &self.rtmr1,
            &self.rtmr2,
            &self.rtmr3,
        ]
    }
}

/// Checks that `data` is the manifest that `expected` pins, then decodes it.
///
/// The digest is compared before anything is parsed, and the manifest's own
/// version must equal the pinned tag.
pub fn parse_manifest(data: &[u8], expected: &RuntimeReference) -> Result<Manifest, ManifestError> {
    if canonical::encode_lower_hex(&Sha256::digest(data)) != expected.digest {
        return Err(ManifestError::new(
            "runtime manifest does not match the config's digest pin",
        ));
    }
    let manifest = decode_manifest(data)?;
    if manifest.version != expected.tag {
        return Err(ManifestError::new(format!(
            "runtime manifest version {:?} does not match the config's pin {:?}",
            manifest.version, expected.tag
        )));
    }
    Ok(manifest)
}

/// The members of a manifest as the document spells them, before the
/// required ones are known to be present.
#[derive(Default)]
struct Decoded {
    version: String,
    measurements: Option<DecodedMeasurements>,
}

#[derive(Default)]
struct DecodedMeasurements {
    format_version: i64,
    snp_launch: Option<SnpLaunch>,
    tdx_launch: Option<TdxLaunch>,
}

/// Checks the size and the structure of a manifest, with no pin to match it
/// against.
///
/// Members that the manifest format does not define are ignored, but a
/// repeated member name is rejected wherever it occurs. A `null` member is
/// read as an absent one.
pub fn decode_manifest(data: &[u8]) -> Result<Manifest, ManifestError> {
    if data.is_empty() || data.len() > MAX_MANIFEST_SIZE {
        return Err(ManifestError::new(
            "runtime manifest size is outside allowed bounds",
        ));
    }
    let decoded = decode(json::parse(data)?)?;
    if !semver::is_full(&decoded.version) {
        return Err(ManifestError::new(
            "runtime manifest version must be a full semantic version",
        ));
    }
    let Some(measurements) = decoded
        .measurements
        .filter(|measurements| measurements.format_version == FORMAT_VERSION)
    else {
        return Err(ManifestError::new("runtime manifest format is unsupported"));
    };
    let (Some(snp_launch), Some(tdx_launch)) = (measurements.snp_launch, measurements.tdx_launch)
    else {
        return Err(ManifestError::new(
            "runtime manifest requires complete launch measurements",
        ));
    };
    canonical::decode_lower_hex("SNP measurement", &snp_launch.measurement, MEASUREMENT_SIZE)?;
    canonical::decode_lower_hex("MRTD", &tdx_launch.mrtd, MEASUREMENT_SIZE)?;
    if tdx_launch
        .registers()
        .iter()
        .skip(1)
        .any(|register| *register != ZERO_REGISTER)
    {
        return Err(ManifestError::new(
            "runtime format v1 requires zero TDX RTMRs",
        ));
    }
    Ok(Manifest {
        version: decoded.version,
        measurements: Measurements {
            format_version: measurements.format_version,
            snp_launch,
            tdx_launch,
        },
    })
}

/// Reads the members that the manifest format defines and checks their
/// types. `null` at the top level is a manifest with nothing set.
fn decode(value: Value) -> Result<Decoded, DecodeError> {
    let mut decoded = Decoded::default();
    let Some(object) = decode::object(value, "runtime manifest")? else {
        return Ok(decoded);
    };
    for (name, value) in object.into_members() {
        match name.as_str() {
            "version" => decoded.version = decode::string(value, &name)?,
            "igvm" => decoded.measurements = decode_measurements(value, &name)?,
            _ => {}
        }
    }
    Ok(decoded)
}

fn decode_measurements(
    value: Value,
    path: &str,
) -> Result<Option<DecodedMeasurements>, DecodeError> {
    let Some(object) = decode::object(value, path)? else {
        return Ok(None);
    };
    let mut measurements = DecodedMeasurements::default();
    for (name, value) in object.into_members() {
        match name.as_str() {
            "format_version" => measurements.format_version = decode::i64(&value, &name)?,
            "snp_launch" => measurements.snp_launch = decode_snp_launch(value, &name)?,
            "tdx_launch" => measurements.tdx_launch = decode_tdx_launch(value, &name)?,
            _ => {}
        }
    }
    Ok(Some(measurements))
}

fn decode_snp_launch(value: Value, path: &str) -> Result<Option<SnpLaunch>, DecodeError> {
    let Some(object) = decode::object(value, path)? else {
        return Ok(None);
    };
    let mut launch = SnpLaunch::default();
    for (name, value) in object.into_members() {
        if name == "measurement" {
            launch.measurement = decode::string(value, &name)?;
        }
    }
    Ok(Some(launch))
}

fn decode_tdx_launch(value: Value, path: &str) -> Result<Option<TdxLaunch>, DecodeError> {
    let Some(object) = decode::object(value, path)? else {
        return Ok(None);
    };
    let mut launch = TdxLaunch::default();
    for (name, value) in object.into_members() {
        let register = match name.as_str() {
            "mrtd" => &mut launch.mrtd,
            "rtmr0" => &mut launch.rtmr0,
            "rtmr1" => &mut launch.rtmr1,
            "rtmr2" => &mut launch.rtmr2,
            "rtmr3" => &mut launch.rtmr3,
            _ => continue,
        };
        *register = decode::string(value, &name)?;
    }
    Ok(Some(launch))
}
