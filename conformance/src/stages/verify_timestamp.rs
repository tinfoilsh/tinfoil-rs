//! `v3-verify-timestamp`: an RFC 3161 timestamp response over given bytes,
//! at the appraisal time of the input.

use tinfoil_verifier::conformance::endorsement::approval::verify_approval_timestamp;
use tinfoil_verifier::conformance::endorsement::approval_window;

use super::{accepted, appraisal_time, is_unset_clock, rejected, trusted_root};
use crate::{
    AcceptOutputs, CODE_PROVENANCE_REJECTED, Input, Output, STAGE_VERIFY_TIMESTAMP, decode_base64,
    malformed,
};

/// Runs the stage.
///
/// An input without an appraisal time or with that of an unset clock,
/// fields that do not decode and a trusted root that is not one are
/// malformed input; everything about the response is a rejection.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_VERIFY_TIMESTAMP;
    let Some(now) = appraisal_time(input).filter(|_| !is_unset_clock(input)) else {
        return malformed(stage);
    };
    let Some(response) = decode_base64(&input.timestamp_response_b64) else {
        return malformed(stage);
    };
    let Some(covered) = decode_base64(&input.timestamp_input_b64) else {
        return malformed(stage);
    };
    let Some(root) = trusted_root(input) else {
        return malformed(stage);
    };
    // No timestamp falls in a window that has no representable ends.
    let Ok(window) = approval_window(now, None, None) else {
        return rejected(stage, CODE_PROVENANCE_REJECTED);
    };
    match verify_approval_timestamp(&root, &response, &covered, &window) {
        Ok(at) => accepted(
            stage,
            Some(AcceptOutputs {
                timestamp: at.to_rfc3339_seconds(),
                ..AcceptOutputs::default()
            }),
        ),
        Err(_) => rejected(stage, CODE_PROVENANCE_REJECTED),
    }
}
