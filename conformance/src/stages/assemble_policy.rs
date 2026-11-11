//! `v3-assemble-policy`: the platform bundle and the endorsements artifact
//! that it carries.

use tinfoil_verifier::conformance::document;
use tinfoil_verifier::conformance::endorsement::ProvenanceClient;
use tinfoil_verifier::conformance::policy::ARTIFACT_FORMAT;

use super::{accepted, rejected, trusted_root};
use crate::{
    CODE_PROVENANCE_REJECTED, Input, Output, STAGE_ASSEMBLE_POLICY, decode_base64, decode_hex,
    malformed,
};

/// Whether this stage is implemented.
pub(crate) const SUPPORTED: bool = true;

/// Runs the stage.
///
/// The stage authenticates the platform policy artifact and goes no
/// further: nothing is compared against a quote. Fields that do not
/// decode, a trusted root that is not one and a document that does not
/// decode are malformed input. A document without a platform bundle and
/// everything about the bundle and its artifact are rejections, reported
/// at the provenance layer.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_ASSEMBLE_POLICY;
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
    let Ok(platform_ref) = document.sigstore_platform() else {
        return reject();
    };
    match client.authenticate_platform_endorsements(
        &platform_ref.bundle,
        &platform_ref.repo,
        &platform_ref.tag,
        &platform_ref.digest,
        ARTIFACT_FORMAT,
    ) {
        Ok(_) => accepted(stage, None),
        Err(_) => reject(),
    }
}
