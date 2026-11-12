//! `v3-authenticate-quote`: the CPU quote's signature chain to the vendor
//! root, without any comparison against a policy.

use std::time::SystemTime;

use tinfoil_verifier::Measurement as Registers;
use tinfoil_verifier::conformance::document;
use tinfoil_verifier::conformance::instant::Instant;
use tinfoil_verifier::conformance::quote::{self, VendorRoots};

use super::{accepted, appraisal_time, rejected, trusted_root, vendor_roots};
use crate::{
    AcceptOutputs, CODE_QUOTE_REJECTED, Input, Measurement, Output, STAGE_AUTHENTICATE_QUOTE,
    decode_base64, malformed,
};

/// The measurement type of an SEV-SNP quote on the wire.
pub(crate) const SEV_SNP_MEASUREMENT_TYPE: &str = "https://tinfoil.sh/predicate/sev-snp-guest/v2";
/// The measurement type of a TDX quote on the wire.
pub(crate) const TDX_MEASUREMENT_TYPE: &str = "https://tinfoil.sh/predicate/tdx-guest/v2";

/// Lays out authenticated registers for the wire, in platform order.
/// `None` for a measurement of a platform that the wire contract does not
/// know.
pub(crate) fn measurement(registers: &Registers) -> Option<Measurement> {
    Some(match registers {
        Registers::SevSnp { launch } => Measurement {
            kind: SEV_SNP_MEASUREMENT_TYPE.to_owned(),
            registers: vec![launch.to_string()],
        },
        Registers::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => Measurement {
            kind: TDX_MEASUREMENT_TYPE.to_owned(),
            registers: [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
                .into_iter()
                .map(ToString::to_string)
                .collect(),
        },
        _ => return None,
    })
}

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
    let now = appraisal_time(input).or_else(|| Instant::from_system_time(SystemTime::now()));
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
