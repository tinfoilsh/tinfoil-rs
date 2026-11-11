//! `verify-attestation-v3`: full verification of a document.

use crate::{Input, Output, STAGE_VERIFY, unsupported};

/// Whether this stage is implemented.
pub(crate) const SUPPORTED: bool = false;

/// Runs the stage, which is not implemented yet.
pub(crate) fn run(_input: &Input) -> (Output, i32) {
    unsupported(STAGE_VERIFY)
}
