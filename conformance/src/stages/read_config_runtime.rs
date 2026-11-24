//! `v3-read-config-runtime`: the runtime pin that the config of a document
//! states.

use tinfoil_verifier::conformance::document;
use tinfoil_verifier::conformance::runtime::runtime_from_config;

use super::{accepted, rejected, trusted_root};
use crate::{
    AcceptOutputs, CODE_PROVENANCE_REJECTED, Input, Output, Runtime, STAGE_READ_CONFIG_RUNTIME,
    decode_base64, decode_hex, malformed,
};

/// Runs the stage.
///
/// The stage reads the config and does not authenticate it. Fields that do
/// not decode, a trusted root that is not one and a document that does not
/// decode are malformed input. A document without a config entry, an entry
/// without the config's bytes and a config that states no usable pin are
/// rejections, reported at the provenance layer.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_READ_CONFIG_RUNTIME;
    let Some(doc) = decode_base64(&input.document_b64) else {
        return malformed(stage);
    };
    if decode_hex(&input.nonce_hex).is_none() {
        return malformed(stage);
    }
    if trusted_root(input).is_none() {
        return malformed(stage);
    }
    let Ok(document) = document::decode(&doc) else {
        return malformed(stage);
    };
    let reject = || rejected(stage, CODE_PROVENANCE_REJECTED);
    let Ok(entry) = document.config_endorsement() else {
        return reject();
    };
    let Some(config) = entry.config() else {
        return reject();
    };
    match runtime_from_config(config) {
        Ok(runtime) => accepted(
            stage,
            Some(AcceptOutputs {
                runtime: Some(Runtime {
                    repo: runtime.repo,
                    tag: runtime.tag,
                    digest: runtime.digest,
                }),
                ..AcceptOutputs::default()
            }),
        ),
        Err(_) => reject(),
    }
}
