//! The stages. Each lives in its own file. Full verification goes through
//! the verifier's public entry point; the other stages isolate one layer
//! and reach the verifier's internal modules for it.

pub(crate) mod assemble_policy;
pub(crate) mod authenticate_approval;
pub(crate) mod authenticate_provenance;
pub(crate) mod authenticate_quote;
pub(crate) mod check_envelope;
pub(crate) mod verify_attestation;
pub(crate) mod verify_timestamp;

use std::sync::Arc;

use tinfoil_verifier::Verifier;
use tinfoil_verifier::conformance::endorsement::ProvenanceClient;
use tinfoil_verifier::conformance::instant::Instant;
use tinfoil_verifier::conformance::sigstore::trusted_root::TrustedRoot;

use super::{
    AcceptOutputs, EXIT_ACCEPTED, EXIT_REJECTED, Input, Output, Rejection, STAGE_ASSEMBLE_POLICY,
    STAGE_AUTHENTICATE_APPROVAL, STAGE_AUTHENTICATE_PROVENANCE, STAGE_AUTHENTICATE_QUOTE,
    STAGE_CHECK_ENVELOPE, STAGE_VERIFY, STAGE_VERIFY_TIMESTAMP, decode_base64, malformed,
    unsupported,
};

/// The vendor anchors of an input: the AMD chain, intermediate and then
/// root, and the Intel root. `None` selects the embedded anchor.
pub(crate) fn vendor_roots(input: &Input) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let amd = (!input.ask_pem.is_empty()).then(|| {
        format!(
            "{}\n{}\n",
            input.ask_pem.trim(),
            input.amd_root_ca_pem.trim()
        )
        .into_bytes()
    });
    let intel = (!input.intel_sgx_root_pem.is_empty())
        .then(|| input.intel_sgx_root_pem.clone().into_bytes());
    (amd, intel)
}

/// The verifier for an input, with the input's trust anchors in place of
/// the embedded ones. `None` when the input's Sigstore trusted root cannot
/// back a verifier.
fn verifier(input: &Input) -> Option<Verifier> {
    let supplied = decode_base64(&input.sigstore_trusted_root_json_b64)?;
    let (amd, intel) = vendor_roots(input);
    let mut builder = Verifier::builder().dangerous_test_only_vendor_roots(amd, intel);
    if !supplied.is_empty() {
        builder = builder.dangerous_test_only_sigstore_root(&supplied);
    }
    builder.build().ok()
}

/// Runs `stage` over a decoded input.
///
/// The approval and timestamp stages verify their own inputs against the
/// Sigstore trusted root alone. Every other stage works on a document, and
/// is set up with the verifier of the input first: an input whose trust
/// anchors cannot back a verifier is malformed for all of them.
pub(crate) fn run(stage: &str, input: &Input) -> (Output, i32) {
    match stage {
        STAGE_AUTHENTICATE_APPROVAL => return authenticate_approval::run(input),
        STAGE_VERIFY_TIMESTAMP => return verify_timestamp::run(input),
        STAGE_VERIFY
        | STAGE_CHECK_ENVELOPE
        | STAGE_AUTHENTICATE_PROVENANCE
        | STAGE_ASSEMBLE_POLICY
        | STAGE_AUTHENTICATE_QUOTE => {}
        _ => return unsupported(stage),
    }
    let Some(verifier) = verifier(input) else {
        return malformed(stage);
    };
    match stage {
        STAGE_VERIFY => verify_attestation::run(input, &verifier),
        STAGE_CHECK_ENVELOPE => check_envelope::run(input),
        STAGE_AUTHENTICATE_PROVENANCE => authenticate_provenance::run(input),
        STAGE_ASSEMBLE_POLICY => assemble_policy::run(input),
        STAGE_AUTHENTICATE_QUOTE => authenticate_quote::run(input),
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
