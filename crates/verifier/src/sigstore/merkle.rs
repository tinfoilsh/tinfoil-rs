// Adapted from sigstore-rs (Apache 2.0 License)
// https://github.com/sigstore/sigstore-rs/blob/34f232af72ba6108f001f1612fdb03c87af8ca62/src/crypto/merkle/proof_verification.rs
// https://github.com/sigstore/sigstore-rs/blob/34f232af72ba6108f001f1612fdb03c87af8ca62/src/crypto/merkle/rfc6962.rs
//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Modifications: fixed to SHA-256, inclusion proofs only, checked
// arithmetic and no indexing.

//! RFC 6962 Merkle tree hashing and inclusion proofs over SHA-256.

use std::fmt;

use sha2::{Digest, Sha256};

/// A node of the tree: a SHA-256 hash.
pub type Hash = [u8; 32];

const LEAF_PREFIX: u8 = 0;
const NODE_PREFIX: u8 = 1;

/// Why an inclusion proof was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// The leaf index is not below the tree size.
    IndexBeyondTree,
    /// The proof has the wrong number of hashes for the index and size.
    WrongProofSize {
        /// The number of hashes supplied.
        got: usize,
        /// The number of hashes that the index and size require.
        want: usize,
    },
    /// The proof leads to a different root.
    RootMismatch,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::IndexBeyondTree => f.write_str("leaf index is not below the tree size"),
            MerkleError::WrongProofSize { got, want } => {
                write!(f, "inclusion proof has {got} hashes, want {want}")
            }
            MerkleError::RootMismatch => {
                f.write_str("inclusion proof does not lead to the expected root")
            }
        }
    }
}

impl std::error::Error for MerkleError {}

/// The hash of a leaf: `SHA-256(0x00 || leaf)`.
pub fn hash_leaf(leaf: &[u8]) -> Hash {
    Sha256::new()
        .chain_update([LEAF_PREFIX])
        .chain_update(leaf)
        .finalize()
        .into()
}

/// The hash of an inner node: `SHA-256(0x01 || left || right)`.
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    Sha256::new()
        .chain_update([NODE_PREFIX])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// Verifies that the leaf with hash `leaf_hash` is at `index` in the tree of
/// `tree_size` leaves whose root is `root`.
pub fn verify_inclusion(
    index: u64,
    leaf_hash: &Hash,
    tree_size: u64,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), MerkleError> {
    let computed = root_from_inclusion_proof(index, leaf_hash, tree_size, proof)?;
    if &computed == root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

/// The root that an inclusion proof leads to, for a leaf at `index` in a
/// tree of `tree_size` leaves. The proof must have exactly the number of
/// hashes that the index and size determine.
pub fn root_from_inclusion_proof(
    index: u64,
    leaf_hash: &Hash,
    tree_size: u64,
    proof: &[Hash],
) -> Result<Hash, MerkleError> {
    if index >= tree_size {
        return Err(MerkleError::IndexBeyondTree);
    }
    let (inner, border) = decompose_inclusion_proof(index, tree_size);
    let want = inner.saturating_add(border);
    if proof.len() != want {
        return Err(MerkleError::WrongProofSize {
            got: proof.len(),
            want,
        });
    }
    let (inner_hashes, border_hashes) =
        proof
            .split_at_checked(inner)
            .ok_or(MerkleError::WrongProofSize {
                got: proof.len(),
                want,
            })?;
    let below_border = chain_inner(leaf_hash, inner_hashes, index);
    Ok(chain_border_right(&below_border, border_hashes))
}

/// Hashes up the levels where the path to the leaf and the path to the last
/// leaf of the tree run together. Bit `i` of `index` says whether the node
/// at level `i` is a right child.
fn chain_inner(seed: &Hash, proof: &[Hash], index: u64) -> Hash {
    let mut hash = *seed;
    let mut path = index;
    for sibling in proof {
        hash = if path & 1 == 0 {
            hash_children(&hash, sibling)
        } else {
            hash_children(sibling, &hash)
        };
        path >>= 1;
    }
    hash
}

/// Hashes up the right border of the tree, where every proof hash is a left
/// sibling.
fn chain_border_right(seed: &Hash, proof: &[Hash]) -> Hash {
    proof
        .iter()
        .fold(*seed, |hash, sibling| hash_children(sibling, &hash))
}

/// Splits the length of an inclusion proof into the levels below and above
/// the point where the paths to `index` and to the last leaf diverge.
/// Requires `index < tree_size`.
fn decompose_inclusion_proof(index: u64, tree_size: u64) -> (usize, usize) {
    let last = tree_size.saturating_sub(1);
    let inner = u64::BITS.saturating_sub((index ^ last).leading_zeros());
    let border = index.checked_shr(inner).unwrap_or(0).count_ones();
    // Both are at most 64.
    (
        usize::try_from(inner).unwrap_or(usize::MAX),
        usize::try_from(border).unwrap_or(usize::MAX),
    )
}

/// The cases are those of the transparency-dev Merkle implementation:
/// <https://github.com/transparency-dev/merkle/blob/036047b5d2f7faf3b1ee643d391e60fe5b1defcf/proof/verify_test.go>
#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::decode_hex;

    fn hash(hex: &str) -> Hash {
        decode_hex(hex).unwrap().try_into().unwrap()
    }

    const SOME_HASH: &str = "abacaba000000000000000000000000000000000000000000060061e00123456";
    const EMPTY_TREE_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// The leaves of the sample tree, as hex.
    const LEAVES: [&str; 8] = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];

    /// `ROOTS[n - 1]` is the root of the tree of the first `n` leaves.
    const ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    /// One-based leaf number, tree size, and the proof.
    const INCLUSION_PROOFS: [(u64, u64, &[&str]); 5] = [
        (1, 1, &[]),
        (
            1,
            8,
            &[
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            6,
            8,
            &[
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            3,
            3,
            &["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
        ),
        (
            2,
            5,
            &[
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
    ];

    #[test]
    fn hashing_matches_rfc_6962() {
        assert_eq!(
            hash_leaf(b""),
            hash("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        );
        assert_eq!(
            hash_leaf(b"L123456"),
            hash("395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56")
        );
        let left: Hash = *b"N123N123N123N123N123N123N123N123";
        let right: Hash = *b"N456N456N456N456N456N456N456N456";
        assert_ne!(hash_children(&left, &right), hash_children(&right, &left));
    }

    #[test]
    fn a_leaf_and_a_node_of_the_same_bytes_hash_differently() {
        let left = hash_leaf(b"Hello");
        let right = hash_leaf(b"World");
        let node = hash_children(&left, &right);
        let forged = hash_leaf(&[left, right].concat());
        assert_ne!(node, forged);
    }

    fn proof_of(hashes: &[&str]) -> Vec<Hash> {
        hashes.iter().map(|h| hash(h)).collect()
    }

    #[test]
    fn sample_proofs_verify() {
        for (leaf, size, proof) in INCLUSION_PROOFS {
            let index = leaf - 1;
            let leaf_hash = hash_leaf(&decode_hex(LEAVES[index as usize]).unwrap());
            let root = hash(ROOTS[size as usize - 1]);
            verify_inclusion(index, &leaf_hash, size, &proof_of(proof), &root)
                .unwrap_or_else(|error| panic!("leaf {leaf} of {size}: {error}"));
        }
    }

    #[test]
    fn every_change_to_a_sample_proof_is_rejected() {
        for (leaf, size, proof) in INCLUSION_PROOFS {
            let index = leaf - 1;
            let leaf_hash = hash_leaf(&decode_hex(LEAVES[index as usize]).unwrap());
            let root = hash(ROOTS[size as usize - 1]);
            let proof = proof_of(proof);
            let with = |extra: Hash, front: bool| {
                let mut changed = proof.clone();
                if front {
                    changed.insert(0, extra);
                } else {
                    changed.push(extra);
                }
                changed
            };
            let wrong_leaf: Hash = *b"WrongLeafWrongLeafWrongLeafWrong";
            type Probe = (&'static str, u64, Hash, u64, Vec<Hash>, Hash);
            let probes: Vec<Probe> = vec![
                (
                    "index - 1",
                    index.wrapping_sub(1),
                    leaf_hash,
                    size,
                    proof.clone(),
                    root,
                ),
                ("index + 1", index + 1, leaf_hash, size, proof.clone(), root),
                ("index ^ 2", index ^ 2, leaf_hash, size, proof.clone(), root),
                ("size / 2", index, leaf_hash, size / 2, proof.clone(), root),
                ("size * 2", index, leaf_hash, size * 2, proof.clone(), root),
                ("wrong leaf", index, wrong_leaf, size, proof.clone(), root),
                (
                    "empty root",
                    index,
                    leaf_hash,
                    size,
                    proof.clone(),
                    hash(EMPTY_TREE_HASH),
                ),
                (
                    "random root",
                    index,
                    leaf_hash,
                    size,
                    proof.clone(),
                    hash(SOME_HASH),
                ),
                (
                    "trailing zero hash",
                    index,
                    leaf_hash,
                    size,
                    with([0; 32], false),
                    root,
                ),
                (
                    "trailing root",
                    index,
                    leaf_hash,
                    size,
                    with(root, false),
                    root,
                ),
                (
                    "leading zero hash",
                    index,
                    leaf_hash,
                    size,
                    with([0; 32], true),
                    root,
                ),
                (
                    "leading root",
                    index,
                    leaf_hash,
                    size,
                    with(root, true),
                    root,
                ),
            ];
            for (what, index, leaf_hash, size, proof, root) in probes {
                assert!(
                    verify_inclusion(index, &leaf_hash, size, &proof, &root).is_err(),
                    "leaf {leaf} of {size}: accepted with {what}"
                );
            }
            if let Some((_, shorter)) = proof.split_last() {
                assert!(verify_inclusion(index, &leaf_hash, size, shorter, &root).is_err());
            }
            for position in 0..proof.len() {
                let mut flipped = proof.clone();
                flipped[position][position] ^= 4;
                assert!(verify_inclusion(index, &leaf_hash, size, &flipped, &root).is_err());
            }
        }
    }

    #[test]
    fn a_single_leaf_tree_has_the_leaf_as_its_root() {
        let leaf = hash_leaf(b"data");
        verify_inclusion(0, &leaf, 1, &[], &leaf).unwrap();
        assert_eq!(
            verify_inclusion(0, &leaf, 1, &[], &[0; 32]),
            Err(MerkleError::RootMismatch)
        );
        assert_eq!(
            verify_inclusion(0, &[0; 32], 1, &[], &leaf),
            Err(MerkleError::RootMismatch)
        );
    }

    #[test]
    fn an_index_outside_the_tree_is_rejected() {
        let any = hash(SOME_HASH);
        for (index, size) in [(0, 0), (1, 0), (1, 1), (2, 1), (u64::MAX, u64::MAX)] {
            assert_eq!(
                verify_inclusion(index, &any, size, &[], &any),
                Err(MerkleError::IndexBeyondTree),
                "index {index} of {size}"
            );
        }
    }

    #[test]
    fn the_proof_length_is_fixed_by_index_and_size() {
        let any = hash(SOME_HASH);
        assert_eq!(
            verify_inclusion(0, &any, 2, &[], &any),
            Err(MerkleError::WrongProofSize { got: 0, want: 1 })
        );
        assert_eq!(
            root_from_inclusion_proof(0, &any, u64::MAX, &[]),
            Err(MerkleError::WrongProofSize { got: 0, want: 64 })
        );
        assert_eq!(
            root_from_inclusion_proof(u64::MAX - 1, &any, u64::MAX, &[]),
            Err(MerkleError::WrongProofSize { got: 0, want: 63 })
        );
    }
}
