//! The stages, over the verifier's internal modules. Each stage lives in
//! its own file and answers for whether it is implemented.

pub(crate) mod assemble_policy;
pub(crate) mod authenticate_approval;
pub(crate) mod authenticate_provenance;
pub(crate) mod authenticate_quote;
pub(crate) mod check_envelope;
pub(crate) mod verify_attestation;
pub(crate) mod verify_timestamp;

use std::sync::Arc;

use tinfoil_verifier::conformance::endorsement::ProvenanceClient;
use tinfoil_verifier::conformance::instant::Instant;
use tinfoil_verifier::conformance::sigstore::trusted_root::TrustedRoot;

use super::{
    AcceptOutputs, EXIT_ACCEPTED, EXIT_REJECTED, Input, Output, Rejection, STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_APPROVAL, STAGE_AUTHENTICATE_PROVENANCE, STAGE_AUTHENTICATE_QUOTE,
    STAGE_CHECK_ENVELOPE, STAGE_VERIFY, STAGE_VERIFY_TIMESTAMP, decode_base64, unsupported,
};

/// Whether this build implements `stage`.
pub(crate) fn is_supported(stage: &str) -> bool {
    match stage {
        STAGE_VERIFY => verify_attestation::SUPPORTED,
        STAGE_CHECK_ENVELOPE => check_envelope::SUPPORTED,
        STAGE_AUTHENTICATE_PROVENANCE => authenticate_provenance::SUPPORTED,
        STAGE_ASSEMBLE_POLICY => assemble_policy::SUPPORTED,
        STAGE_AUTHENTICATE_QUOTE => {
            authenticate_quote::sev_snp_is_built() || authenticate_quote::tdx_is_built()
        }
        STAGE_AUTHENTICATE_APPROVAL => authenticate_approval::SUPPORTED,
        STAGE_VERIFY_TIMESTAMP => verify_timestamp::SUPPORTED,
        _ => false,
    }
}

/// Runs `stage` over a decoded input.
pub(crate) fn run(stage: &str, input: &Input) -> (Output, i32) {
    match stage {
        STAGE_VERIFY => verify_attestation::run(input),
        STAGE_CHECK_ENVELOPE => check_envelope::run(input),
        STAGE_AUTHENTICATE_PROVENANCE => authenticate_provenance::run(input),
        STAGE_ASSEMBLE_POLICY => assemble_policy::run(input),
        STAGE_AUTHENTICATE_QUOTE => authenticate_quote::run(input),
        STAGE_AUTHENTICATE_APPROVAL => authenticate_approval::run(input),
        STAGE_VERIFY_TIMESTAMP => verify_timestamp::run(input),
        _ => unsupported(stage),
    }
}

/// The output and exit code of a stage that accepted its input.
pub(crate) fn accepted(stage: &str, outputs: Option<AcceptOutputs>) -> (Output, i32) {
    let output = Output {
        stage: stage.to_owned(),
        accepted: true,
        outputs,
        rejection: None,
    };
    (output, EXIT_ACCEPTED)
}

/// The output and exit code of a stage that rejected its input at the
/// layer named by `code`.
pub(crate) fn rejected(stage: &str, code: &str) -> (Output, i32) {
    let output = Output {
        stage: stage.to_owned(),
        accepted: false,
        outputs: None,
        rejection: Some(Rejection {
            code: code.to_owned(),
        }),
    };
    (output, EXIT_REJECTED)
}

/// The Sigstore trusted root of an input: the document that the input
/// carries, or the root embedded in the verifier when it carries none.
/// `None` when the document is not a trusted root.
pub(crate) fn trusted_root(input: &Input) -> Option<Arc<TrustedRoot>> {
    let supplied = decode_base64(&input.sigstore_trusted_root_json_b64)?;
    if supplied.is_empty() {
        let client = ProvenanceClient::embedded().ok()?;
        return Some(Arc::clone(client.trusted_root()));
    }
    TrustedRoot::from_json(&supplied).ok().map(Arc::new)
}

/// The appraisal time of an input; `None` when the input states none.
pub(crate) fn appraisal_time(input: &Input) -> Option<Instant> {
    if input.verification_time_unix == 0 {
        return None;
    }
    let seconds = i64::try_from(input.verification_time_unix).ok()?;
    Instant::from_unix(seconds, 0)
}
