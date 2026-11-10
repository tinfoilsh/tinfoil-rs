//! The VM shape that a platform measurement was taken for.

use std::fmt;

use super::optional;
use crate::json::Value;
use crate::json::decode::{self, DecodeError};

/// The launch dimensions that determine a platform measurement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Shape {
    /// The number of virtual CPUs.
    pub cpus: i64,
    /// The memory size in mebibytes.
    pub memory_mb: i64,
    /// The number of GPUs. `None` when the dimension is unknown for a
    /// measured configuration; a code artifact always declares it.
    pub gpus: Option<i64>,
    /// Every attached disk: root, config, external config and one per model.
    pub disks: i64,
}

impl Shape {
    /// Whether this measured shape satisfies the shape that a code artifact
    /// requires. The GPU count is compared only when both declare it.
    pub fn satisfies(&self, required: &Shape) -> bool {
        if self.cpus != required.cpus
            || self.memory_mb != required.memory_mb
            || self.disks != required.disks
        {
            return false;
        }
        match (self.gpus, required.gpus) {
            (Some(measured), Some(wanted)) => measured == wanted,
            _ => true,
        }
    }

    /// Decodes a `shape` member; `null` is no shape.
    pub(super) fn from_value(value: Value, path: &str) -> Result<Option<Self>, DecodeError> {
        let Some(object) = decode::object(value, path)? else {
            return Ok(None);
        };
        let mut shape = Shape::default();
        for (name, value) in object.into_members() {
            match name.as_str() {
                "cpus" => shape.cpus = decode::i64(&value, &name)?,
                "memory_mb" => shape.memory_mb = decode::i64(&value, &name)?,
                "gpus" => shape.gpus = optional(&value, &name, decode::i64)?,
                "disks" => shape.disks = decode::i64(&value, &name)?,
                _ => return Err(decode::unknown_member(path, &name)),
            }
        }
        Ok(Some(shape))
    }
}

/// Shows the shape in error messages.
impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{CPUs:{} MemoryMB:{} GPUs:", self.cpus, self.memory_mb)?;
        match self.gpus {
            Some(gpus) => write!(f, "{gpus}")?,
            None => f.write_str("<nil>")?,
        }
        write!(f, " Disks:{}}}", self.disks)
    }
}

/// Whether a measured shape satisfies a required one. A missing shape on
/// either side satisfies nothing.
pub fn satisfies(shape: Option<&Shape>, required: Option<&Shape>) -> bool {
    match (shape, required) {
        (Some(shape), Some(required)) => shape.satisfies(required),
        _ => false,
    }
}

/// The host software that produced a measurement. Informational; never
/// checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stack {
    /// The QEMU version.
    pub qemu: String,
    /// The OVMF version.
    pub ovmf: String,
}

impl Stack {
    /// Decodes a `stack` member; `null` is no stack.
    pub(super) fn from_value(value: Value, path: &str) -> Result<Option<Self>, DecodeError> {
        let Some(object) = decode::object(value, path)? else {
            return Ok(None);
        };
        let mut stack = Stack::default();
        for (name, value) in object.into_members() {
            match name.as_str() {
                "qemu" => stack.qemu = decode::string(value, &name)?,
                "ovmf" => stack.ovmf = decode::string(value, &name)?,
                _ => return Err(decode::unknown_member(path, &name)),
            }
        }
        Ok(Some(stack))
    }
}
