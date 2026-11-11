//! `v3-authenticate-provenance`: the code bundle's identity, digest and
//! predicate.

use crate::{Input, Output, STAGE_AUTHENTICATE_PROVENANCE, unsupported};

/// Whether this stage is implemented.
pub(crate) const SUPPORTED: bool = false;

/// Runs the stage, which is not implemented yet.
pub(crate) fn run(_input: &Input) -> (Output, i32) {
    unsupported(STAGE_AUTHENTICATE_PROVENANCE)
}
