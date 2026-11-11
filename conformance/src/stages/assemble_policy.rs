//! `v3-assemble-policy`: the platform bundle and the endorsements artifact
//! that it carries.

use crate::{Input, Output, STAGE_ASSEMBLE_POLICY, unsupported};

/// Whether this stage is implemented.
pub(crate) const SUPPORTED: bool = false;

/// Runs the stage, which is not implemented yet.
pub(crate) fn run(_input: &Input) -> (Output, i32) {
    unsupported(STAGE_ASSEMBLE_POLICY)
}
