//! `verify-attestation-v3`: full verification of a document, through the
//! verifier's public entry point.

use std::time::SystemTime;

use tinfoil_verifier::conformance::instant::Instant;

use tinfoil_verifier::{Error, Verifier};

use super::{accepted, appraisal_time, is_unset_clock, rejected};
use crate::{
    CODE_ENVELOPE_REJECTED, CODE_MALFORMED_INPUT, EXIT_INTERNAL, EXIT_MALFORMED, Input, Output,
    Rejection, STAGE_VERIFY, decode_base64, decode_hex, facts, malformed,
};

/// The output and exit code for an error of the verifier: a usage error is
/// malformed input, and a rejection carries the code of its layer. An
/// error or a layer that the wire contract does not know gives no verdict.
fn rejection(error: &Error) -> (Output, i32) {
    let stage = STAGE_VERIFY;
    let code = match error {
        Error::Usage(_) => {
            let output = Output {
                stage: stage.to_owned(),
                accepted: false,
                outputs: None,
                rejection: Some(Rejection {
                    code: CODE_MALFORMED_INPUT.to_owned(),
                }),
            };
            return (output, EXIT_MALFORMED);
        }
        Error::Verification(rejected) => facts::layer_code(rejected.layer()),
        _ => None,
    };
    match code {
        Some(code) => rejected(stage, code),
        None => {
            let output = Output {
                stage: stage.to_owned(),
                accepted: false,
                outputs: None,
                rejection: None,
            };
            (output, EXIT_INTERNAL)
        }
    }
}

/// Runs the stage with the verifier that was built for the input.
///
/// Fields that do not decode and the time of an unset clock are malformed
/// input. The document is verified at the input's appraisal time, or now
/// when it states none. A document
/// that verifies but endorses no usable TLS or HPKE key is of no use to a
/// client, which binds its traffic to those keys, so the stage rejects it
/// at the envelope layer.
pub(crate) fn run(input: &Input, verifier: &Verifier) -> (Output, i32) {
    let stage = STAGE_VERIFY;
    let Some(doc) = decode_base64(&input.document_b64) else {
        return malformed(stage);
    };
    let Some(nonce) = decode_hex(&input.nonce_hex) else {
        return malformed(stage);
    };
    let appraisal = if input.verification_time_unix == 0 {
        Some(SystemTime::now())
    } else if is_unset_clock(input) {
        None
    } else {
        appraisal_time(input).and_then(Instant::to_system_time)
    };
    let Some(appraisal) = appraisal else {
        return malformed(stage);
    };
    let verified = match verifier.verify_v3_at(&doc, &nonce, &input.pin(), appraisal) {
        Ok(verified) => verified,
        Err(error) => return rejection(&error),
    };
    match facts::verified(&verified) {
        Some(outputs) => accepted(stage, Some(outputs)),
        None => rejected(stage, CODE_ENVELOPE_REJECTED),
    }
}
