//! `v3-authenticate-containers`: the container builds that the document's
//! config requires, each against the build attestation of its image.

use tinfoil_verifier::Verifier;
use tinfoil_verifier::conformance::document;

use super::{accepted, rejected};
use crate::{
    AcceptOutputs, CODE_PROVENANCE_REJECTED, Container, Input, Output,
    STAGE_AUTHENTICATE_CONTAINERS, decode_base64, decode_hex, malformed,
};

/// Runs the stage.
///
/// The stage runs the verifier's own container step on the config that the
/// document carries, which it takes as given: neither the config nor the
/// quote is authenticated. Fields that do not decode and a document that
/// does not decode are malformed input. A document without a config entry,
/// a config whose requirements cannot be read and everything about the
/// build attestations are rejections. The accepted facts are the
/// authenticated containers in config order, an empty list when the config
/// requires none.
pub(crate) fn run(input: &Input, verifier: &Verifier) -> (Output, i32) {
    let stage = STAGE_AUTHENTICATE_CONTAINERS;
    let Some(doc) = decode_base64(&input.document_b64) else {
        return malformed(stage);
    };
    if decode_hex(&input.nonce_hex).is_none() {
        return malformed(stage);
    }
    let Ok(document) = document::decode(&doc) else {
        return malformed(stage);
    };
    let reject = || rejected(stage, CODE_PROVENANCE_REJECTED);
    let Ok(config) = document.config_endorsement() else {
        return reject();
    };
    let Ok(verified) = verifier.dangerous_test_only_resolve_containers(&document, config.config())
    else {
        return reject();
    };
    let containers = verified
        .into_iter()
        .map(|verified| Container {
            container: verified.container,
            digest: verified.digest,
            repository: verified.repository,
            workflow: verified.workflow,
            git_ref: verified.git_ref,
            commit: verified.commit,
        })
        .collect();
    accepted(
        stage,
        Some(AcceptOutputs {
            containers: Some(containers),
            ..AcceptOutputs::default()
        }),
    )
}
