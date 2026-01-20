// Adapted from sigstore-rs (Apache 2.0 License)
// https://github.com/sigstore/sigstore-rs/blob/main/src/crypto/keyring.rs
//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! CT signing key management adapted from sigstore-rs.
//!
//! This module provides a keyring for Certificate Transparency log public keys,
//! adapted to use the p256 crate instead of aws-lc-rs.

use std::collections::HashMap;

use der::{Decode, Encode};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

/// Errors from keyring operations
#[derive(Error, Debug)]
pub enum KeyringError {
    #[error("malformed key")]
    KeyMalformed(#[from] der::Error),
    #[error("unsupported algorithm")]
    AlgoUnsupported,
    #[error("requested key not in keyring")]
    KeyNotFound,
    #[error("verification failed")]
    VerificationFailed,
}

type Result<T> = std::result::Result<T, KeyringError>;

/// A CT signing key.
struct Key {
    inner: VerifyingKey,
    /// The key's RFC 6962-style "key ID".
    /// <https://datatracker.ietf.org/doc/html/rfc6962#section-3.2>
    fingerprint: [u8; 32],
}

/// OID for EC public key (1.2.840.10045.2.1)
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// OID for P-256 curve (1.2.840.10045.3.1.7)
const SECP_256_R_1: &str = "1.2.840.10045.3.1.7";

impl Key {
    /// Creates a `Key` from a DER blob containing a SubjectPublicKeyInfo object.
    pub fn new(spki_bytes: &[u8]) -> Result<Self> {
        let spki = SubjectPublicKeyInfoOwned::from_der(spki_bytes)?;

        // Check algorithm parameters
        let params = spki.algorithm.parameters.as_ref()
            .ok_or(KeyringError::AlgoUnsupported)?;

        let algo_oid = spki.algorithm.oid.to_string();
        let params_oid = params.decode_as::<der::asn1::ObjectIdentifier>()
            .map_err(|_| KeyringError::AlgoUnsupported)?
            .to_string();

        // Only support EC P-256 keys
        if algo_oid != ID_EC_PUBLIC_KEY || params_oid != SECP_256_R_1 {
            return Err(KeyringError::AlgoUnsupported);
        }

        // Parse the public key
        let inner = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
            .map_err(|_| KeyringError::AlgoUnsupported)?;

        // Compute RFC 6962 key ID (SHA-256 hash of DER-encoded SPKI)
        let fingerprint = {
            let mut hasher = Sha256::new();
            spki.encode(&mut hasher).expect("failed to hash key!");
            hasher.finalize().into()
        };

        Ok(Key { inner, fingerprint })
    }
}

/// Represents a set of CT signing keys, each of which is potentially a valid signer for
/// Signed Certificate Timestamps (SCTs) or Signed Tree Heads (STHs).
///
/// Adapted from sigstore-rs to use p256 instead of aws-lc-rs.
pub struct Keyring(HashMap<[u8; 32], Key>);

impl Keyring {
    /// Creates a `Keyring` from DER encoded SPKI-format public keys.
    pub fn new<'a>(keys: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        Ok(Self(
            keys.into_iter()
                .flat_map(Key::new)
                .map(|k| Ok((k.fingerprint, k)))
                .collect::<Result<_>>()?,
        ))
    }

    /// Verifies `data` against a `signature` with a public key identified by `key_id`.
    pub fn verify(&self, key_id: &[u8; 32], signature: &[u8], data: &[u8]) -> Result<()> {
        let key = self.0.get(key_id).ok_or(KeyringError::KeyNotFound)?;

        let sig = Signature::from_der(signature)
            .map_err(|_| KeyringError::VerificationFailed)?;

        key.inner
            .verify(data, &sig)
            .map_err(|_| KeyringError::VerificationFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_key_not_found() {
        let keyring = Keyring(HashMap::new());
        let result = keyring.verify(&[0u8; 32], &[], &[]);
        assert!(matches!(result, Err(KeyringError::KeyNotFound)));
    }
}
