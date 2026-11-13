//! `v3-authenticate-quote`: the CPU quote's signature chain to the vendor
//! root, without any comparison against a policy.

use std::time::SystemTime;

use tinfoil_verifier::conformance::document;
use tinfoil_verifier::conformance::instant::Instant;
use tinfoil_verifier::conformance::quote::{self, VendorRoots};

use super::{accepted, appraisal_time, rejected, trusted_root, vendor_roots};
use crate::facts::measurement;
use crate::{
    AcceptOutputs, CODE_QUOTE_REJECTED, Input, Output, STAGE_AUTHENTICATE_QUOTE, decode_base64,
    malformed,
};

/// Runs the stage.
///
/// A document that does not decode and a trusted root that is not one are
/// malformed input; a quote that does not authenticate is a rejection.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_AUTHENTICATE_QUOTE;
    let Some(doc) = decode_base64(&input.document_b64) else {
        return malformed(stage);
    };
    if trusted_root(input).is_none() {
        return malformed(stage);
    }
    // Only an input that states no time is appraised now.
    let now = if input.verification_time_unix == 0 {
        Instant::from_system_time(SystemTime::now())
    } else {
        appraisal_time(input)
    };
    let Some(now) = now else {
        return malformed(stage);
    };
    let Ok(document) = document::decode(&doc) else {
        return malformed(stage);
    };
    let (amd, intel) = vendor_roots(input);
    let roots = VendorRoots::dangerous_test_only(amd, intel);
    match quote::authenticate(
        document.cpu_evidence(),
        document.cpu_endorsements(),
        now,
        &roots,
    ) {
        Ok(authenticated) => accepted(
            stage,
            Some(AcceptOutputs {
                enclave_measurement: measurement(&authenticated.measurement()),
                ..AcceptOutputs::default()
            }),
        ),
        Err(_) => rejected(stage, CODE_QUOTE_REJECTED),
    }
}
