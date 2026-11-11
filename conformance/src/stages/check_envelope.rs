//! `v3-check-envelope`: strict parse, nonce equality, endorsed-section
//! hashes and report data.

use tinfoil_verifier::conformance::document;

use super::{accepted, rejected, trusted_root};
use crate::{
    CODE_ENVELOPE_REJECTED, Input, Output, STAGE_CHECK_ENVELOPE, decode_base64, decode_hex,
    malformed,
};

/// Whether this stage is implemented.
pub(crate) const SUPPORTED: bool = true;

/// Runs the stage. The nonce is the one in the input, never the
/// document's own.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_CHECK_ENVELOPE;
    let Some(doc) = decode_base64(&input.document_b64) else {
        return malformed(stage);
    };
    let Some(nonce) = decode_hex(&input.nonce_hex) else {
        return malformed(stage);
    };
    // Every document stage is set up with the trusted root of its input,
    // so a root that is not one is malformed input here too.
    if trusted_root(input).is_none() {
        return malformed(stage);
    }
    match document::parse(&doc, &nonce) {
        Ok(_) => accepted(stage, None),
        Err(_) => rejected(stage, CODE_ENVELOPE_REJECTED),
    }
}
