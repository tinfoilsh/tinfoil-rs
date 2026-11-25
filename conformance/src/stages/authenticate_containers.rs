//! `v3-authenticate-containers`: the container builds that the document's
//! config requires.

use tinfoil_verifier::conformance::document;
use tinfoil_verifier::conformance::endorsement::ProvenanceClient;

use super::{accepted, rejected, trusted_root};
use crate::{
    CODE_PROVENANCE_REJECTED, Input, Output, STAGE_AUTHENTICATE_CONTAINERS, decode_base64,
    decode_hex, malformed,
};

/// Runs the stage.
///
/// Fields that do not decode, a trusted root that is not one and a
/// document that does not decode are malformed input. The stage takes the
/// config as given: it authenticates the builds that the config requires,
/// not the config. A document without config bytes, requirements that
/// cannot be read and everything about the build attestations are
/// rejections.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_AUTHENTICATE_CONTAINERS;
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
    let config = document
        .config_endorsement()
        .ok()
        .and_then(|config| config.config());
    match config.map(|config| client.authenticate_containers(config, &document)) {
        Some(Ok(())) => accepted(stage, None),
        _ => rejected(stage, CODE_PROVENANCE_REJECTED),
    }
}
