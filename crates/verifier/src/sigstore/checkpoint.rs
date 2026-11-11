// Adapted from sigstore-rs (Apache 2.0 License)
// https://github.com/sigstore/sigstore-rs/blob/34f232af72ba6108f001f1612fdb03c87af8ca62/src/rekor/models/checkpoint.rs
//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Modifications: signatures verify through this crate's key type, no serde
// implementations, a bound on the number of signature lines.

//! Transparency-log checkpoints: the signed note in which a log commits to
//! its size and root hash.
//!
//! The format is the signed note of
//! <https://github.com/transparency-dev/formats/blob/main/log/README.md>:
//! a body of origin, size and root hash lines, a blank line, and one
//! signature line per signer.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::SigstoreError;
use crate::canonical::encode_lower_hex;
use crate::x509::{EcdsaHash, KeyAlgorithm, PublicKey, SignatureScheme};

/// The most signature lines that a checkpoint may carry.
pub const MAX_NOTE_SIGNATURES: usize = 100;

/// A checkpoint and the signatures over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// The signed body.
    pub checkpoint: Checkpoint,
    /// The signature lines, in order.
    pub signatures: Vec<NoteSignature>,
}

/// The body of a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The log's identity string.
    pub origin: String,
    /// The number of leaves in the tree.
    pub size: u64,
    /// The root hash of the tree.
    pub root_hash: [u8; 32],
    /// Further non-empty lines of the body, in order.
    pub other_content: Vec<String>,
}

/// One signature line of a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    /// The signer's name.
    pub name: String,
    /// The four-byte hint that identifies the signer's key.
    pub key_hint: [u8; 4],
    /// The signature bytes.
    pub signature: Vec<u8>,
}

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

impl SignedCheckpoint {
    /// Decodes a checkpoint envelope: the body, a blank line, and at least
    /// one and at most [`MAX_NOTE_SIGNATURES`] signature lines.
    pub fn decode(envelope: &str) -> Result<Self, SigstoreError> {
        let (body, signature_lines) = envelope
            .split_once("\n\n")
            .ok_or_else(|| error("checkpoint has no signature section"))?;
        let signatures = signature_lines
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(NoteSignature::decode)
            .collect::<Result<Vec<_>, _>>()?;
        if signatures.is_empty() {
            return Err(error("checkpoint has no signatures"));
        }
        if signatures.len() > MAX_NOTE_SIGNATURES {
            return Err(error("checkpoint has too many signatures"));
        }
        Ok(Self {
            checkpoint: Checkpoint::decode(body)?,
            signatures,
        })
    }

    /// Verifies the checkpoint under a log's key.
    ///
    /// A signature line counts when its name is `name` and its key hint is
    /// the first four bytes of `key_id`; lines of other signers, such as
    /// witnesses, are ignored. The checkpoint verifies when one such line
    /// carries a valid signature over the body: ECDSA P-256 with SHA-256 in
    /// DER, or Ed25519.
    pub fn verify_signature(
        &self,
        key: &PublicKey,
        name: &str,
        key_id: &[u8],
    ) -> Result<(), SigstoreError> {
        let hint = key_id.first_chunk::<4>();
        let message = self.checkpoint.encode();
        for line in &self.signatures {
            if line.name != name || hint != Some(&line.key_hint) {
                continue;
            }
            if verify_log_signature(key, message.as_bytes(), &line.signature).is_ok() {
                return Ok(());
            }
        }
        Err(error(format!(
            "no valid checkpoint signature by {name} (key hint {})",
            encode_lower_hex(hint.map(|hint| hint.as_slice()).unwrap_or_default())
        )))
    }
}

impl Checkpoint {
    /// The signed text of the body: origin, size and base64 root hash, each
    /// on its own line, followed by the other content lines.
    pub fn encode(&self) -> String {
        let mut text = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            STANDARD.encode(self.root_hash)
        );
        for line in &self.other_content {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    /// Decodes a body: a non-empty origin line, a decimal size, a base64
    /// 32-byte root hash, and any further lines.
    fn decode(body: &str) -> Result<Self, SigstoreError> {
        let mut lines = body.split('\n');
        let (Some(origin), Some(size), Some(root_hash)) =
            (lines.next(), lines.next(), lines.next())
        else {
            return Err(error("checkpoint body is not in the expected form"));
        };
        if origin.trim().is_empty() {
            return Err(error("checkpoint origin must not be empty"));
        }
        let size = size
            .parse::<u64>()
            .map_err(|_| error("checkpoint size is not a decimal number"))?;
        let root_hash: [u8; 32] = STANDARD
            .decode(root_hash)
            .map_err(|_| error("checkpoint root hash is not base64"))?
            .try_into()
            .map_err(|_| error("checkpoint root hash is not 32 bytes"))?;
        let other_content = lines
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        Ok(Self {
            origin: origin.to_string(),
            size,
            root_hash,
            other_content,
        })
    }
}

impl NoteSignature {
    /// Decodes a signature line: an em dash, the signer's non-empty name,
    /// and the base64 of the key hint followed by the signature, separated
    /// by single spaces.
    fn decode(line: &str) -> Result<Self, SigstoreError> {
        let mut parts = line.split(' ');
        let (Some("\u{2014}"), Some(name), Some(encoded), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(error("checkpoint signature line is malformed"));
        };
        if name.is_empty() {
            return Err(error("checkpoint signature line names no signer"));
        }
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| error("checkpoint signature is not base64"))?;
        let (key_hint, signature) = decoded
            .split_first_chunk::<4>()
            .ok_or_else(|| error("checkpoint signature is too short for a key hint"))?;
        Ok(Self {
            name: name.to_string(),
            key_hint: *key_hint,
            signature: signature.to_vec(),
        })
    }

    #[cfg(test)]
    fn encode(&self) -> String {
        let mut bytes = self.key_hint.to_vec();
        bytes.extend_from_slice(&self.signature);
        format!("\u{2014} {} {}\n", self.name, STANDARD.encode(bytes))
    }
}

/// Verifies a signature made by a transparency log's key: ECDSA P-256 with
/// SHA-256 and a DER signature, or Ed25519 with a 64-byte signature. Used
/// for checkpoints and signed entry timestamps.
pub(super) fn verify_log_signature(
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SigstoreError> {
    let scheme = match key.algorithm() {
        KeyAlgorithm::EcdsaP256 => SignatureScheme::EcdsaDer(EcdsaHash::Sha256),
        KeyAlgorithm::Ed25519 => SignatureScheme::Ed25519,
        other => {
            return Err(error(format!("unsupported log key type {other:?}")));
        }
    };
    key.verify(scheme, message, signature)
        .map_err(|cause| error(format!("log signature: {cause}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::testutil;

    fn body(origin: &str, size: u64, fill: u8, other: &[&str]) -> Checkpoint {
        Checkpoint {
            origin: origin.to_string(),
            size,
            root_hash: [fill; 32],
            other_content: other.iter().map(|line| line.to_string()).collect(),
        }
    }

    #[test]
    fn a_body_encodes_to_its_signed_text() {
        let cases = [
            (
                body("Log Checkpoint v0", 123, 0, &[]),
                "Log Checkpoint v0\n123\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            ),
            (
                body("Banana Checkpoint v5", 9944, 1, &[]),
                "Banana Checkpoint v5\n9944\nAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n",
            ),
            (
                body("Banana Checkpoint v7", 9943, 2, &["foo", "bar"]),
                "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nfoo\nbar\n",
            ),
        ];
        for (checkpoint, text) in cases {
            assert_eq!(checkpoint.encode(), text);
        }
    }

    #[test]
    fn a_valid_body_decodes() {
        let cases = [
            (
                body("Log Checkpoint v0", 123, 0, &[]),
                "Log Checkpoint v0\n123\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            ),
            (
                body("Banana Checkpoint v7", 9943, 2, &["foo", "bar"]),
                "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nfoo\nbar\n",
            ),
            (
                body(
                    "Banana Checkpoint v7",
                    9943,
                    2,
                    &["Timestamp: 1689748607742585419"],
                ),
                "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nTimestamp: 1689748607742585419\n",
            ),
            (
                body("Banana Checkpoint v7", 9943, 2, &[]),
                "Banana Checkpoint v7\n9943\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\n\n\n",
            ),
        ];
        for (checkpoint, text) in cases {
            assert_eq!(Checkpoint::decode(text).unwrap(), checkpoint, "{text:?}");
        }
    }

    #[test]
    fn an_invalid_body_is_rejected() {
        let cases = [
            ("too few lines", "Head\n9944\n"),
            (
                "empty origin",
                "\n9944\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            ),
            (
                "missing origin",
                "123\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nother data\n",
            ),
            (
                "root hash of the wrong size",
                "Log Checkpoint v0\n123\nYmFuYW5hcw==",
            ),
            (
                "size is not a number",
                "Log Checkpoint v0\nbananas\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            ),
            (
                "negative size",
                "Log Checkpoint v0\n-34\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            ),
            (
                "size out of range",
                "Log Checkpoint v0\n3438945738945739845734895735\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            ),
            (
                "root hash is not base64",
                "Log Checkpoint v0\n123\nThisIsn'tBase64\n",
            ),
        ];
        for (what, text) in cases {
            assert!(Checkpoint::decode(text).is_err(), "accepted: {what}");
        }
    }

    fn line(name: &str) -> NoteSignature {
        NoteSignature {
            name: name.to_string(),
            key_hint: [0; 4],
            signature: vec![1; 32],
        }
    }

    #[test]
    fn a_signature_line_encodes_and_decodes() {
        for name in ["log.example.org", "815f6c60aab9"] {
            let text =
                format!("\u{2014} {name} AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n");
            assert_eq!(line(name).encode(), text);
            assert_eq!(
                NoteSignature::decode(text.trim_end_matches('\n')).unwrap(),
                line(name)
            );
        }
    }

    #[test]
    fn a_malformed_signature_line_is_rejected() {
        for text in [
            "\u{2014} Foo Bar AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
            "- log.example.org AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
            "\u{2014} log.example.org",
            "\u{2014} log.example.org AAAA",
            "\u{2014} log.example.org not-base64",
            "\u{2014}  AAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
        ] {
            assert!(NoteSignature::decode(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn an_envelope_with_several_signers_round_trips() {
        let first = NoteSignature {
            name: "log1.example.org".to_string(),
            key_hint: [1, 2, 3, 4],
            signature: vec![5; 32],
        };
        let second = NoteSignature {
            name: "log2.example.org".to_string(),
            key_hint: [9, 8, 7, 6],
            signature: vec![6; 32],
        };
        let checkpoint = body("Test Log", 42, 7, &[]);
        let envelope = format!(
            "{}\n{}{}",
            checkpoint.encode(),
            first.encode(),
            second.encode()
        );
        let decoded = SignedCheckpoint::decode(&envelope).unwrap();
        assert_eq!(decoded.checkpoint, checkpoint);
        assert_eq!(decoded.signatures, [first, second]);
    }

    #[test]
    fn an_envelope_needs_signatures_within_the_bound() {
        let checkpoint = body("Test Log", 42, 7, &[]);
        assert!(SignedCheckpoint::decode(&checkpoint.encode()).is_err());
        assert!(SignedCheckpoint::decode(&format!("{}\n", checkpoint.encode())).is_err());
        let lines = line("log.example.org").encode().repeat(MAX_NOTE_SIGNATURES);
        assert!(SignedCheckpoint::decode(&format!("{}\n{lines}", checkpoint.encode())).is_ok());
        let lines = line("log.example.org")
            .encode()
            .repeat(MAX_NOTE_SIGNATURES + 1);
        assert!(SignedCheckpoint::decode(&format!("{}\n{lines}", checkpoint.encode())).is_err());
    }

    /// The checkpoint of a production Rekor entry, with its log's key, name
    /// and identifier.
    fn production_checkpoint() -> (SignedCheckpoint, PublicKey, String, Vec<u8>) {
        let bundle = testutil::bundle(testutil::REKOR_V1_BUNDLE);
        let entry = &bundle.tlog_entries[0];
        let proof = entry.inclusion_proof.as_ref().unwrap();
        let checkpoint = SignedCheckpoint::decode(&proof.checkpoint).unwrap();
        let log = testutil::log(testutil::PRODUCTION_TRUSTED_ROOT, &entry.log_id);
        (checkpoint, log.key, log.name, entry.log_id.clone())
    }

    #[test]
    fn a_production_checkpoint_verifies_under_its_log_key() {
        let (checkpoint, key, name, log_id) = production_checkpoint();
        checkpoint.verify_signature(&key, &name, &log_id).unwrap();
    }

    #[test]
    fn a_checkpoint_with_another_key_hint_is_rejected() {
        let (checkpoint, key, name, mut log_id) = production_checkpoint();
        log_id[0] ^= 1;
        assert!(checkpoint.verify_signature(&key, &name, &log_id).is_err());
        assert!(checkpoint.verify_signature(&key, &name, &[]).is_err());
    }

    #[test]
    fn a_checkpoint_with_another_signer_name_is_rejected() {
        let (checkpoint, key, _, log_id) = production_checkpoint();
        assert!(
            checkpoint
                .verify_signature(&key, "rekor.example.org", &log_id)
                .is_err()
        );
    }

    #[test]
    fn a_changed_checkpoint_body_is_rejected() {
        let (mut checkpoint, key, name, log_id) = production_checkpoint();
        checkpoint.checkpoint.size += 1;
        assert!(checkpoint.verify_signature(&key, &name, &log_id).is_err());
    }

    #[test]
    fn an_ed25519_checkpoint_verifies_among_witness_signatures() {
        let bundle = testutil::bundle(testutil::REKOR_V2_BUNDLE);
        let entry = &bundle.tlog_entries[0];
        let proof = entry.inclusion_proof.as_ref().unwrap();
        let checkpoint = SignedCheckpoint::decode(&proof.checkpoint).unwrap();
        assert!(checkpoint.signatures.len() > 1);
        let log = testutil::log(testutil::STAGING_TRUSTED_ROOT, &entry.log_id);
        assert_eq!(log.key.algorithm(), KeyAlgorithm::Ed25519);
        checkpoint
            .verify_signature(&log.key, &log.name, &entry.log_id)
            .unwrap();
        assert!(
            checkpoint
                .verify_signature(&log.key, "witness.stagemole.eu", &entry.log_id)
                .is_err()
        );
    }
}
