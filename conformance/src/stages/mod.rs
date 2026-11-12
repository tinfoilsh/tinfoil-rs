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

/// The first second of the year 0000 and the last second of the year 9999,
/// in seconds since the epoch: the instants that the verifier can hold.
const FIRST_APPRAISAL_SECOND: i64 = -62_167_219_200;
const LAST_APPRAISAL_SECOND: i64 = 253_402_300_799;

/// The first second of year 1, which stands for a clock that was never set.
const UNSET_CLOCK_SECOND: i64 = -62_135_596_800;

/// Whether the input's time is that of a clock that was never set. Full
/// verification and the timestamp stage take such a time as malformed
/// input: it is a mistake of the caller, not something to appraise at.
pub(crate) fn is_unset_clock(input: &Input) -> bool {
    input.verification_time_unix == UNSET_CLOCK_SECOND
}

/// The appraisal time of an input; `None` when the input states none, which
/// a time of zero does.
///
/// Any other time is the appraisal time, never the current time. One
/// outside the years 0000 to 9999 is taken as the nearest instant inside
/// them: what is valid at such a time is decided in the same way there,
/// since no certificate, revocation list or timestamp is valid beyond
/// those years.
pub(crate) fn appraisal_time(input: &Input) -> Option<Instant> {
    if input.verification_time_unix == 0 {
        return None;
    }
    let seconds = input
        .verification_time_unix
        .clamp(FIRST_APPRAISAL_SECOND, LAST_APPRAISAL_SECOND);
    Instant::from_unix(seconds, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EXIT_MALFORMED, run};

    fn input_at(seconds: i64) -> Input {
        let text = format!(r#"{{"schema_version":"1","verification_time_unix":{seconds}}}"#);
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn only_a_time_of_zero_states_no_appraisal_time() {
        assert_eq!(appraisal_time(&input_at(0)), None);
        for (seconds, want) in [
            (1, 1),
            (-1, -1),
            (LAST_APPRAISAL_SECOND, LAST_APPRAISAL_SECOND),
            (LAST_APPRAISAL_SECOND + 1, LAST_APPRAISAL_SECOND),
            (i64::MAX, LAST_APPRAISAL_SECOND),
            (FIRST_APPRAISAL_SECOND, FIRST_APPRAISAL_SECOND),
            (FIRST_APPRAISAL_SECOND - 1, FIRST_APPRAISAL_SECOND),
            (i64::MIN, FIRST_APPRAISAL_SECOND),
        ] {
            let at = appraisal_time(&input_at(seconds)).unwrap();
            assert_eq!(
                (at.unix_seconds(), at.subsec_nanos()),
                (want, 0),
                "{seconds}"
            );
        }
    }

    #[test]
    fn a_time_outside_the_representable_years_is_appraised_not_malformed() {
        // An empty response is no timestamp, so the stage has a verdict:
        // a rejection, at the far ends of the range too.
        for seconds in [1, -1, i64::MAX, i64::MIN, LAST_APPRAISAL_SECOND + 1] {
            let stdin = format!(r#"{{"schema_version":"1","verification_time_unix":{seconds}}}"#);
            let (output, exit) = run(STAGE_VERIFY_TIMESTAMP, stdin.as_bytes());
            assert_eq!(exit, EXIT_REJECTED, "{seconds}");
            assert!(output.rejection.is_some(), "{seconds}");
        }
    }

    #[test]
    fn the_time_of_an_unset_clock_is_malformed_for_the_timestamp_stage() {
        assert!(is_unset_clock(&input_at(UNSET_CLOCK_SECOND)));
        assert!(!is_unset_clock(&input_at(0)));
        let stdin =
            format!(r#"{{"schema_version":"1","verification_time_unix":{UNSET_CLOCK_SECOND}}}"#);
        let (_, exit) = run(STAGE_VERIFY_TIMESTAMP, stdin.as_bytes());
        assert_eq!(exit, EXIT_MALFORMED);
    }
}
