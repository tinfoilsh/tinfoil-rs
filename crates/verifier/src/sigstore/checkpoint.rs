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
use sha2::{Digest, Sha256};

use crate::x509::{EcdsaHash, KeyAlgorithm, PublicKey, SignatureScheme};

/// The most signature lines that a checkpoint may carry.
pub const MAX_NOTE_SIGNATURES: usize = 100;

/// A checkpoint and the signatures over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// The signed body, decoded from `signed_text`.
    checkpoint: Checkpoint,
    /// The signature lines, in order.
    signatures: Vec<NoteSignature>,
    /// The body exactly as it was received, with its final line end: the
    /// text that the signatures cover.
    signed_text: String,
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
    /// The signed body. It cannot be changed after decoding, so it always
    /// is what the signatures cover.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// The signature lines, in order.
    pub fn signatures(&self) -> &[NoteSignature] {
        &self.signatures
    }

    /// Decodes a checkpoint envelope: the body, a blank line, and at least
    /// one and at most [`MAX_NOTE_SIGNATURES`] signature lines, each ended
    /// by a line feed. The signature lines are what follows the last blank
    /// line.
    ///
    /// The body is kept as received, and signatures are verified over that
    /// text, never over a re-encoding of the decoded fields.
    pub fn decode(envelope: &str) -> Result<Self, SigstoreError> {
        let (body, signature_lines) = envelope
            .rsplit_once("\n\n")
            .ok_or_else(|| error("checkpoint has no signature section"))?;
        let signature_lines = signature_lines
            .strip_suffix('\n')
            .filter(|lines| !lines.is_empty())
            .ok_or_else(|| error("checkpoint has no signatures"))?;
        let mut signatures = Vec::new();
        for line in signature_lines.split('\n') {
            if signatures.len() >= MAX_NOTE_SIGNATURES {
                return Err(error("checkpoint has too many signatures"));
            }
            signatures.push(NoteSignature::decode(line)?);
        }
        Ok(Self {
            checkpoint: Checkpoint::decode(body)?,
            signatures,
            signed_text: format!("{body}\n"),
        })
    }

    /// Verifies a checkpoint that its log alone signs: every signature
    /// line must be by `key`.
    ///
    /// Each line's key hint is the first four bytes of the SHA-256 of the
    /// key's SubjectPublicKeyInfo, and each line carries a valid signature
    /// over the body as it was received: ECDSA with SHA-256 in DER (for a
    /// key on either curve), or Ed25519. The names on the lines are not
    /// compared. One line of another signer, or one line that does not
    /// verify, fails the whole checkpoint.
    pub fn verify_every_signature(&self, key: &PublicKey) -> Result<(), SigstoreError> {
        let hint = spki_key_hint(key);
        let scheme = match key.algorithm() {
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => {
                SignatureScheme::EcdsaDer(EcdsaHash::Sha256)
            }
            KeyAlgorithm::Ed25519 => SignatureScheme::Ed25519,
            other => return Err(error(format!("unsupported log key type {other:?}"))),
        };
        for line in &self.signatures {
            if line.key_hint != hint {
                return Err(error("checkpoint carries a signature line of another key"));
            }
            key.verify(scheme, self.signed_text.as_bytes(), &line.signature)
                .map_err(|cause| error(format!("checkpoint signature: {cause}")))?;
        }
        Ok(())
    }

    /// Verifies a checkpoint as a signed note that `name` signed with
    /// `key`, possibly among other signers such as witnesses.
    ///
    /// The envelope holds no control character other than the line feed,
    /// and every signer name is free of whitespace and `+`. A line counts
    /// when its name is `name` and its key hint is the hint of `key` under
    /// that name ([`note_key_hint`]); lines of other signers are ignored,
    /// and a repeated line of this signer is read once. Every line that
    /// counts must carry a valid signature over the body as it was
    /// received: ECDSA in DER with the hash of the key's curve, or Ed25519.
    /// At least one line must count.
    pub fn verify_named_signature(&self, key: &PublicKey, name: &str) -> Result<(), SigstoreError> {
        if !is_valid_name(name) {
            return Err(error(format!("{name:?} is not a valid signer name")));
        }
        let controls = |text: &str| text.chars().any(|c| c < ' ' && c != '\n');
        if controls(&self.signed_text) {
            return Err(error("checkpoint contains a control character"));
        }
        if let Some(line) = self
            .signatures
            .iter()
            .find(|line| !is_valid_name(&line.name) || controls(&line.name))
        {
            return Err(error(format!(
                "checkpoint signer name {:?} is malformed",
                line.name
            )));
        }
        let hint = note_key_hint(key, name)?;
        let scheme = match key.algorithm() {
            KeyAlgorithm::EcdsaP256 => SignatureScheme::EcdsaDer(EcdsaHash::Sha256),
            KeyAlgorithm::EcdsaP384 => SignatureScheme::EcdsaDer(EcdsaHash::Sha384),
            KeyAlgorithm::Ed25519 => SignatureScheme::Ed25519,
            other => return Err(error(format!("unsupported log key type {other:?}"))),
        };
        let Some(line) = self
            .signatures
            .iter()
            .find(|line| line.name == name && line.key_hint == hint)
        else {
            return Err(error(format!("checkpoint is not signed by {name}")));
        };
        key.verify(scheme, self.signed_text.as_bytes(), &line.signature)
            .map_err(|cause| error(format!("checkpoint signature by {name}: {cause}")))
    }
}

/// Whether `name` can be the name of a note signer: not empty, without
/// whitespace and without `+`.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(char::is_whitespace) && !name.contains('+')
}

/// The first four bytes of the SHA-256 of a key's SubjectPublicKeyInfo.
fn spki_key_hint(key: &PublicKey) -> [u8; 4] {
    let [a, b, c, d, ..] = key.spki_sha256();
    [a, b, c, d]
}

/// The hint that identifies `key` on the signature lines of a note signed
/// under `name`.
///
/// For an ECDSA key: the first four bytes of the SHA-256 of its
/// SubjectPublicKeyInfo. For an Ed25519 key: the first four bytes of the
/// SHA-256 of the name, a line feed, the byte `01` and the 32-byte key.
/// The hint is always computed from the key; an identifier that a trusted
/// root states for the log plays no part.
pub fn note_key_hint(key: &PublicKey, name: &str) -> Result<[u8; 4], SigstoreError> {
    match key.algorithm() {
        KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => Ok(spki_key_hint(key)),
        KeyAlgorithm::Ed25519 => {
            let raw = key
                .spki_der()
                .last_chunk::<32>()
                .ok_or_else(|| error("Ed25519 key is too short"))?;
            let mut hasher = Sha256::new();
            hasher.update(name.as_bytes());
            hasher.update(b"\n\x01");
            hasher.update(raw);
            let [a, b, c, d, ..] = <[u8; 32]>::from(hasher.finalize());
            Ok([a, b, c, d])
        }
        other => Err(error(format!("unsupported log key type {other:?}"))),
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
    /// 32-byte root hash, and any further lines. The size is written in
    /// digits only, without a sign and without a leading zero.
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
        let canonical = !size.is_empty()
            && size.bytes().all(|byte| byte.is_ascii_digit())
            && (size == "0" || !size.starts_with('0'));
        let size = size
            .parse::<u64>()
            .ok()
            .filter(|_| canonical)
            .ok_or_else(|| error("checkpoint size is not a canonical decimal number"))?;
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
    /// and the base64 of the key hint followed by a non-empty signature,
    /// separated by single spaces.
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
            .filter(|(_, signature)| !signature.is_empty())
            .ok_or_else(|| error("checkpoint signature is too short"))?;
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

/// Verifies a Rekor v1 signed entry timestamp: ECDSA with SHA-256 and a
/// DER signature, under a key on either curve. No other kind of key signs
/// entry timestamps.
pub(super) fn verify_entry_timestamp_signature(
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SigstoreError> {
    match key.algorithm() {
        KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => key
            .verify(
                SignatureScheme::EcdsaDer(EcdsaHash::Sha256),
                message,
                signature,
            )
            .map_err(|cause| error(format!("log signature: {cause}"))),
        other => Err(error(format!(
            "a {other:?} log key cannot sign an entry timestamp"
        ))),
    }
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
            "\u{2014} log.example.org AAAAAA==",
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
        // The last signature line ends with a line feed.
        let one = line("log.example.org").encode();
        let unterminated = format!("{}\n{}", checkpoint.encode(), one.trim_end());
        assert!(SignedCheckpoint::decode(&unterminated).is_err());
        let lines = line("log.example.org").encode().repeat(MAX_NOTE_SIGNATURES);
        assert!(SignedCheckpoint::decode(&format!("{}\n{lines}", checkpoint.encode())).is_ok());
        let lines = line("log.example.org")
            .encode()
            .repeat(MAX_NOTE_SIGNATURES + 1);
        assert!(SignedCheckpoint::decode(&format!("{}\n{lines}", checkpoint.encode())).is_err());
    }

    /// The checkpoint of a production Rekor entry, with its log's key, name
    /// and identifier.
    fn production_envelope() -> String {
        let bundle = testutil::bundle(testutil::REKOR_V1_BUNDLE);
        let proof = bundle.tlog_entries[0].inclusion_proof.as_ref().unwrap();
        proof.checkpoint.clone()
    }

    fn production_checkpoint() -> (SignedCheckpoint, PublicKey) {
        let bundle = testutil::bundle(testutil::REKOR_V1_BUNDLE);
        let entry = &bundle.tlog_entries[0];
        let proof = entry.inclusion_proof.as_ref().unwrap();
        let checkpoint = SignedCheckpoint::decode(&proof.checkpoint).unwrap();
        let log = testutil::log(testutil::PRODUCTION_TRUSTED_ROOT, &entry.log_id);
        (checkpoint, log.key)
    }

    #[test]
    fn a_production_checkpoint_verifies_under_its_log_key() {
        let (checkpoint, key) = production_checkpoint();
        checkpoint.verify_every_signature(&key).unwrap();
    }

    #[test]
    fn a_checkpoint_does_not_verify_under_another_key() {
        let (checkpoint, _) = production_checkpoint();
        let bundle = testutil::bundle(testutil::REKOR_V2_BUNDLE);
        let other = testutil::log(
            testutil::STAGING_TRUSTED_ROOT,
            &bundle.tlog_entries[0].log_id,
        );
        assert!(checkpoint.verify_every_signature(&other.key).is_err());
    }

    #[test]
    fn a_line_of_another_signer_fails_a_checkpoint_that_its_log_alone_signs() {
        let (_, key) = production_checkpoint();
        let envelope = production_envelope();
        let foreign = line("witness.example.org").encode();
        let extended = SignedCheckpoint::decode(&format!("{envelope}{foreign}")).unwrap();
        assert_eq!(extended.signatures.len(), 2);
        let error = extended.verify_every_signature(&key).unwrap_err();
        assert!(error.to_string().contains("another key"), "{error}");

        // The log's own line a second time is still the log's.
        let own = envelope.rsplit_once("\n\n").unwrap().1;
        let doubled = SignedCheckpoint::decode(&format!("{envelope}{own}")).unwrap();
        doubled.verify_every_signature(&key).unwrap();

        // A line with the log's hint and another signature does not verify.
        let mut forged = doubled.clone();
        forged.signatures[1].signature[8] ^= 1;
        assert!(forged.verify_every_signature(&key).is_err());
    }

    #[test]
    fn a_changed_checkpoint_body_is_rejected() {
        let (checkpoint, key) = production_checkpoint();
        let envelope = production_envelope();
        let size = checkpoint.checkpoint.size;
        let changed = envelope.replacen(&format!("\n{size}\n"), &format!("\n{}\n", size + 1), 1);
        assert_ne!(changed, envelope);
        let changed = SignedCheckpoint::decode(&changed).unwrap();
        assert_eq!(changed.checkpoint.size, size + 1);
        assert!(changed.verify_every_signature(&key).is_err());
    }

    #[test]
    fn the_signature_covers_the_text_as_received() {
        let (checkpoint, key) = production_checkpoint();
        let envelope = production_envelope();
        let body = checkpoint.checkpoint.encode();
        assert!(envelope.starts_with(&body));

        // A further body line decodes to the same origin, size and root
        // hash, but it is not the text that the log signed.
        let extended = envelope.replacen(&body, &format!("{body}extra\n"), 1);
        let extended = SignedCheckpoint::decode(&extended).unwrap();
        assert_eq!(extended.checkpoint.size, checkpoint.checkpoint.size);
        assert_eq!(
            extended.checkpoint.root_hash,
            checkpoint.checkpoint.root_hash
        );
        assert!(extended.verify_every_signature(&key).is_err());

        // A size with a leading zero would decode to the same number; it is
        // rejected before any signature is looked at.
        let size = checkpoint.checkpoint.size;
        let padded = envelope.replacen(&format!("\n{size}\n"), &format!("\n0{size}\n"), 1);
        assert_ne!(padded, envelope);
        assert!(SignedCheckpoint::decode(&padded).is_err());
    }

    #[test]
    fn a_size_has_one_decimal_form() {
        let with_size = |size: &str| {
            Checkpoint::decode(&format!(
                "Log\n{size}\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            ))
        };
        assert_eq!(with_size("0").unwrap().size, 0);
        assert_eq!(with_size("123").unwrap().size, 123);
        assert_eq!(with_size("18446744073709551615").unwrap().size, u64::MAX);
        for size in [
            "+123",
            "0123",
            "00",
            "-0",
            " 1",
            "1 ",
            "",
            "1e3",
            "18446744073709551616",
        ] {
            assert!(with_size(size).is_err(), "{size:?}");
        }
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
            .verify_named_signature(&log.key, &log.name)
            .unwrap();
        // The witnesses' lines are not the log's, so a checkpoint that must
        // be signed by the log alone does not verify.
        assert!(checkpoint.verify_every_signature(&log.key).is_err());
        // Under another name the key has another hint.
        assert!(
            checkpoint
                .verify_named_signature(&log.key, "witness.stagemole.eu")
                .is_err()
        );
        assert_ne!(
            note_key_hint(&log.key, &log.name).unwrap(),
            note_key_hint(&log.key, "other.example").unwrap()
        );
    }

    #[test]
    fn a_named_signer_line_that_does_not_verify_fails_the_note() {
        let bundle = testutil::bundle(testutil::REKOR_V2_BUNDLE);
        let entry = &bundle.tlog_entries[0];
        let proof = entry.inclusion_proof.as_ref().unwrap();
        let log = testutil::log(testutil::STAGING_TRUSTED_ROOT, &entry.log_id);
        let mut checkpoint = SignedCheckpoint::decode(&proof.checkpoint).unwrap();
        let hint = note_key_hint(&log.key, &log.name).unwrap();
        let own = checkpoint
            .signatures
            .iter_mut()
            .find(|line| line.key_hint == hint)
            .unwrap();
        own.signature[0] ^= 1;
        assert!(
            checkpoint
                .verify_named_signature(&log.key, &log.name)
                .is_err()
        );
    }

    #[test]
    fn a_note_signer_name_has_no_whitespace_or_plus() {
        assert!(is_valid_name("rekor.sigstore.dev"));
        for name in ["", "a b", "a+b", "a\tb", "a\u{a0}b"] {
            assert!(!is_valid_name(name), "{name:?}");
        }
    }
}
