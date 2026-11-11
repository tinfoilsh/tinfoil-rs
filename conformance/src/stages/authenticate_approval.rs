//! `v3-authenticate-approval`: a key-signed approval bundle under the keys
//! that the input pins.

use tinfoil_verifier::conformance::endorsement::ApprovalVerifier;
use tinfoil_verifier::conformance::endorsement::approval::parse_approval_bundle_json;
use tinfoil_verifier::conformance::x509::PublicKey;

use super::{accepted, rejected, trusted_root};
use crate::{
    AcceptOutputs, CODE_PROVENANCE_REJECTED, Input, Output, STAGE_AUTHENTICATE_APPROVAL,
    decode_base64, decode_hex, malformed,
};

/// Whether this stage is implemented.
pub(crate) const SUPPORTED: bool = true;

/// Runs the stage.
///
/// Fields that do not decode, a trusted root that is not one, and a key
/// set that cannot be used (empty, a key that does not parse, a repeated
/// or unsupported key) are malformed input. Everything about the bundle is
/// a rejection, as is a trusted root without transparency logs.
pub(crate) fn run(input: &Input) -> (Output, i32) {
    let stage = STAGE_AUTHENTICATE_APPROVAL;
    let Some(bundle_json) = decode_base64(&input.bundle_json_b64) else {
        return malformed(stage);
    };
    let Some(digest) = decode_hex(&input.artifact_digest_hex) else {
        return malformed(stage);
    };
    let Some(root) = trusted_root(input) else {
        return malformed(stage);
    };
    if input.signing_keys_pem.is_empty() {
        return malformed(stage);
    }
    let mut keys = Vec::with_capacity(input.signing_keys_pem.len());
    for pem in &input.signing_keys_pem {
        let Ok(key) = PublicKey::from_pem(pem) else {
            return malformed(stage);
        };
        keys.push(key);
    }
    if root.rekor_logs().is_empty() {
        return rejected(stage, CODE_PROVENANCE_REJECTED);
    }
    let Ok(verifier) = ApprovalVerifier::new(root, &keys) else {
        return malformed(stage);
    };
    // The statement names a SHA-256 digest, so a digest of another length
    // names nothing.
    let Ok(digest) = <[u8; 32]>::try_from(digest) else {
        return rejected(stage, CODE_PROVENANCE_REJECTED);
    };
    let verified = parse_approval_bundle_json(&bundle_json)
        .and_then(|bundle| verifier.verify(&bundle, &digest));
    match verified {
        Ok(signing_key_hint) => accepted(
            stage,
            Some(AcceptOutputs {
                signing_key_hint,
                ..AcceptOutputs::default()
            }),
        ),
        Err(_) => rejected(stage, CODE_PROVENANCE_REJECTED),
    }
}
