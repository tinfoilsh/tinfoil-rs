//! `v3-authenticate-provenance`: the code bundle's identity, digest and
//! predicate.

use tinfoil_verifier::conformance::document;
use tinfoil_verifier::conformance::endorsement::provenance::MULTI_PLATFORM_PREDICATE_TYPE;
use tinfoil_verifier::conformance::endorsement::{ProvenanceClient, parse_reference};

use super::{accepted, rejected, trusted_root};
use crate::{
    AcceptOutputs, CODE_PROVENANCE_REJECTED, Input, Measurement, Output,
    STAGE_AUTHENTICATE_PROVENANCE, decode_base64, decode_hex, malformed,
};

/// Whether this stage is implemented.
pub(crate) const SUPPORTED: bool = true;

/// Runs the stage.
///
/// Fields that do not decode, a trusted root that is not one and a
/// document that does not decode are malformed input. A document without a
/// code bundle, a repository pin that is not a release reference, and
/// everything about the bundle are rejections. The accepted facts are the
/// digest of the release and the registers that its predicate fixes: the
/// SEV-SNP launch measurement, then the TDX RTMR1 and RTMR2.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_AUTHENTICATE_PROVENANCE;
    let Some(doc) = decode_base64(&input.document_b64) else {
        return malformed(stage);
    };
    if decode_hex(&input.nonce_hex).is_none() {
        return malformed(stage);
    }
    let Some(root) = trusted_root(input) else {
        return malformed(stage);
    };
    let client = ProvenanceClient::with_trusted_root(root);
    let Ok(document) = document::decode(&doc) else {
        return malformed(stage);
    };
    let reject = || rejected(stage, CODE_PROVENANCE_REJECTED);
    let Ok(code_ref) = document.sigstore_code() else {
        return reject();
    };
    let Ok(pin) = parse_reference(&input.repo) else {
        return reject();
    };
    let Ok(code) =
        client.authenticate_code(&code_ref.bundle, &pin, &code_ref.tag, &code_ref.digest)
    else {
        return reject();
    };
    accepted(
        stage,
        Some(AcceptOutputs {
            code_digest: code.artifact.digest,
            code_measurement: Some(Measurement {
                kind: MULTI_PLATFORM_PREDICATE_TYPE.to_owned(),
                registers: [code.sev_snp_launch, code.tdx_rtmr1, code.tdx_rtmr2]
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            }),
            ..AcceptOutputs::default()
        }),
    )
}
