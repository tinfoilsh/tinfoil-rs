//! `verify-attestation-v3`: full verification of a document, through the
//! verifier's public entry point.

use std::time::SystemTime;

use tinfoil_verifier::conformance::instant::Instant;

use tinfoil_verifier::{Error, Expected, Layer, Verifier};

use super::authenticate_quote::{SEV_SNP_MEASUREMENT_TYPE, TDX_MEASUREMENT_TYPE, measurement};
use super::{accepted, appraisal_time, is_unset_clock, rejected};
use crate::{
    AcceptOutputs, CODE_ENVELOPE_REJECTED, CODE_MALFORMED_INPUT, CODE_POLICY_REJECTED,
    CODE_PROVENANCE_REJECTED, CODE_QUOTE_REJECTED, EXIT_INTERNAL, EXIT_MALFORMED, Input,
    Measurement, Output, Rejection, STAGE_VERIFY, decode_base64, decode_hex, malformed,
};

/// Lays out expected registers for the wire, in platform order, with an
/// empty string for a register that is left unconstrained. `None` for a
/// platform that the wire contract does not know.
fn expected(registers: &Expected) -> Option<Measurement> {
    let hex = |register: &Option<tinfoil_verifier::Register>| {
        register
            .map(|register| register.to_string())
            .unwrap_or_default()
    };
    Some(match registers {
        Expected::SevSnp { launch } => Measurement {
            kind: SEV_SNP_MEASUREMENT_TYPE.to_owned(),
            registers: vec![hex(launch)],
        },
        Expected::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => Measurement {
            kind: TDX_MEASUREMENT_TYPE.to_owned(),
            registers: [mrtd, rtmr0, rtmr1, rtmr2, rtmr3]
                .into_iter()
                .map(hex)
                .collect(),
        },
        _ => return None,
    })
}

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
        Error::Verification(rejected) => match rejected.layer() {
            Layer::Envelope => Some(CODE_ENVELOPE_REJECTED),
            Layer::Provenance => Some(CODE_PROVENANCE_REJECTED),
            Layer::Quote => Some(CODE_QUOTE_REJECTED),
            Layer::Policy => Some(CODE_POLICY_REJECTED),
            _ => None,
        },
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
    // An empty repository in the input is the absence of a pin.
    let repo = Some(input.repo.as_str()).filter(|repo| !repo.is_empty());
    let verified = match verifier.verify_v3_at(&doc, &nonce, repo, appraisal) {
        Ok(verified) => verified,
        Err(error) => return rejection(&error),
    };
    let (Some(tls_public_key_fp), Some(hpke_public_key)) =
        (verified.tls_public_key_fp(), verified.hpke_public_key())
    else {
        return rejected(stage, CODE_ENVELOPE_REJECTED);
    };
    accepted(
        stage,
        Some(AcceptOutputs {
            code_digest: verified.code_digest().to_owned(),
            code_measurement: expected(verified.code_measurement()),
            enclave_measurement: measurement(verified.enclave_measurement()),
            tls_public_key_fp: tls_public_key_fp.to_owned(),
            hpke_public_key: hpke_public_key.to_owned(),
            ..AcceptOutputs::default()
        }),
    )
}
