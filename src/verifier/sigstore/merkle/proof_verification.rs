// Adapted from sigstore-rs (Apache 2.0 License)
// https://github.com/sigstore/sigstore-rs/blob/34f232af72ba6108f001f1612fdb03c87af8ca62/src/crypto/merkle/proof_verification.rs
//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use super::rfc6962::Rfc6269HasherTrait;
use digest::{Digest, Output};
use std::fmt::Debug;
use MerkleProofError::*;

#[derive(Debug)]
pub enum MerkleProofError {
    MismatchedRoot { expected: String, got: String },
    IndexGtTreeSize,
    UnexpectedNonEmptyProof,
    UnexpectedEmptyProof,
    NewTreeSmaller { new: u64, old: u64 },
    WrongProofSize { got: u64, want: u64 },
    WrongEmptyTreeHash,
}

impl std::fmt::Display for MerkleProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MismatchedRoot { expected, got } => {
                write!(f, "root hash mismatch: expected {expected}, got {got}")
            }
            IndexGtTreeSize => write!(f, "leaf index >= tree size"),
            UnexpectedNonEmptyProof => write!(f, "unexpected non-empty proof"),
            UnexpectedEmptyProof => write!(f, "unexpected empty proof"),
            NewTreeSmaller { new, old } => {
                write!(f, "new tree size {new} < old tree size {old}")
            }
            WrongProofSize { got, want } => {
                write!(f, "wrong proof size: got {got}, want {want}")
            }
            WrongEmptyTreeHash => write!(f, "wrong empty tree hash"),
        }
    }
}

pub(crate) trait MerkleProofVerifier<O>: Rfc6269HasherTrait<O>
where
    O: Eq + AsRef<[u8]> + Clone + Debug,
{
    /// Used to verify hashes.
    fn verify_match(a: &O, b: &O) -> Result<(), ()> {
        (a == b).then_some(()).ok_or(())
    }

    /// `verify_inclusion` verifies the correctness of the inclusion proof for the leaf
    /// with the specified `leaf_hash` and `index`, relatively to the tree of the given `tree_size`
    /// and `root_hash`. Requires `0 <= index < tree_size`.
    fn verify_inclusion(
        index: u64,
        leaf_hash: &O,
        tree_size: u64,
        proof_hashes: &[O],
        root_hash: &O,
    ) -> Result<(), MerkleProofError> {
        if index >= tree_size {
            return Err(IndexGtTreeSize);
        }
        Self::root_from_inclusion_proof(index, leaf_hash, tree_size, proof_hashes).and_then(
            |calc_root| {
                Self::verify_match(calc_root.as_ref(), root_hash).map_err(|_| MismatchedRoot {
                    got: hex::encode(root_hash.as_ref()),
                    expected: hex::encode(calc_root.as_ref()),
                })
            },
        )
    }

    /// `root_from_inclusion_proof` calculates the expected root hash for a tree of the
    /// given size, provided a leaf index and hash with the corresponding inclusion
    /// proof. Requires `0 <= index < tree_size`.
    fn root_from_inclusion_proof(
        index: u64,
        leaf_hash: &O,
        tree_size: u64,
        proof_hashes: &[O],
    ) -> Result<Box<O>, MerkleProofError> {
        if index >= tree_size {
            return Err(IndexGtTreeSize);
        }
        let (inner, border) = Self::decomp_inclusion_proof(index, tree_size);
        match (proof_hashes.len() as u64, inner + border) {
            (got, want) if got != want => {
                return Err(WrongProofSize {
                    got: proof_hashes.len() as u64,
                    want: inner + border,
                });
            }
            _ => {}
        }
        let res_left = Self::chain_inner(leaf_hash, &proof_hashes[..inner as usize], index);
        let res = Self::chain_border_right(&res_left, &proof_hashes[inner as usize..]);
        Ok(Box::new(res))
    }

    /// `chain_inner` computes a subtree hash for a node on or below the tree's right
    /// border. Assumes `proof_hashes` are ordered from lower levels to upper, and
    /// `seed` is the initial subtree/leaf hash on the path located at the specified
    /// `index` on its level.
    fn chain_inner(seed: &O, proof_hashes: &[O], index: u64) -> O {
        proof_hashes
            .iter()
            .enumerate()
            .fold(seed.clone(), |seed, (i, h)| {
                let (left, right) = if ((index >> i) & 1) == 0 {
                    (&seed, h)
                } else {
                    (h, &seed)
                };
                Self::hash_children(left, right)
            })
    }

    /// `chain_border_right` chains proof hashes along tree borders. This differs from
    /// inner chaining because `proof` contains only left-side subtree hashes.
    fn chain_border_right(seed: &O, proof_hashes: &[O]) -> O {
        proof_hashes
            .iter()
            .fold(seed.clone(), |seed, h| Self::hash_children(h, seed))
    }

    /// `decomp_inclusion_proof` breaks down inclusion proof for a leaf at the specified
    /// `index` in a tree of the specified `size` into 2 components. The splitting
    /// point between them is where paths to leaves `index` and `tree_size-1` diverge.
    /// Returns lengths of the bottom and upper proof parts correspondingly. The sum
    /// of the two determines the correct length of the inclusion proof.
    fn decomp_inclusion_proof(index: u64, tree_size: u64) -> (u64, u64) {
        let inner: u64 = Self::inner_proof_size(index, tree_size);
        let border = (index >> inner).count_ones() as u64;
        (inner, border)
    }

    /// `inner_proof_size` computes the number of inner levels (hashes) required in the audit path
    /// given a leaf at index in a tree of tree_size.
    fn inner_proof_size(index: u64, tree_size: u64) -> u64 {
        u64::BITS as u64 - ((index ^ (tree_size - 1)).leading_zeros() as u64)
    }
}

impl<T> MerkleProofVerifier<Output<T>> for T where T: Digest {}

#[cfg(test)]
mod test_verify {
    use super::*;
    use crate::verifier::sigstore::merkle::rfc6962::Rfc6269HasherTrait;
    use crate::verifier::sigstore::merkle::Rfc6269Default;
    use hex_literal::hex;

    #[derive(Debug)]
    struct InclusionProofTestVector<'a> {
        leaf: u64,
        size: u64,
        proof: &'a [[u8; 32]],
    }

    #[derive(Debug)]
    struct InclusionProbe {
        leaf_index: u64,
        tree_size: u64,
        root: [u8; 32],
        leaf_hash: [u8; 32],
        proof: Vec<[u8; 32]>,
        desc: &'static str,
    }

    const SHA256_SOME_HASH: [u8; 32] =
        hex!("abacaba000000000000000000000000000000000000000000060061e00123456");

    const SHA256_EMPTY_TREE_HASH: [u8; 32] =
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const ZERO_HASH: [u8; 32] = [0; 32];

    const INCLUSION_PROOFS: [InclusionProofTestVector; 6] = [
        InclusionProofTestVector {
            leaf: 0,
            size: 0,
            proof: &[],
        },
        InclusionProofTestVector {
            leaf: 1,
            size: 1,
            proof: &[],
        },
        InclusionProofTestVector {
            leaf: 1,
            size: 8,
            proof: &[
                hex!("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
                hex!("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
                hex!("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
            ],
        },
        InclusionProofTestVector {
            leaf: 6,
            size: 8,
            proof: &[
                hex!("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
                hex!("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
                hex!("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
            ],
        },
        InclusionProofTestVector {
            leaf: 3,
            size: 3,
            proof: &[hex!(
                "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"
            )],
        },
        InclusionProofTestVector {
            leaf: 2,
            size: 5,
            proof: &[
                hex!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
                hex!("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
                hex!("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
            ],
        },
    ];

    const ROOTS: [[u8; 32]; 8] = [
        hex!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
        hex!("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
        hex!("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"),
        hex!("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
        hex!("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4"),
        hex!("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef"),
        hex!("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"),
        hex!("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"),
    ];

    const LEAVES: &[&[u8]] = &[
        &hex!(""),
        &hex!("00"),
        &hex!("10"),
        &hex!("2021"),
        &hex!("3031"),
        &hex!("40414243"),
        &hex!("5051525354555657"),
        &hex!("606162636465666768696a6b6c6d6e6f"),
    ];

    fn corrupt_inclusion_proof(
        leaf_index: u64,
        tree_size: u64,
        proof: &[[u8; 32]],
        root: &[u8; 32],
        leaf_hash: &[u8; 32],
    ) -> Vec<InclusionProbe> {
        vec![
            InclusionProbe {
                leaf_index: leaf_index.wrapping_sub(1),
                tree_size,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: proof.to_vec(),
                desc: "leaf_index - 1",
            },
            InclusionProbe {
                leaf_index: leaf_index + 1,
                tree_size,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: proof.to_vec(),
                desc: "leaf_index + 1",
            },
            InclusionProbe {
                leaf_index: leaf_index ^ 2,
                tree_size,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: proof.to_vec(),
                desc: "leaf_index ^ 2",
            },
            InclusionProbe {
                leaf_index,
                tree_size: tree_size / 2,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: proof.to_vec(),
                desc: "tree_size / 2",
            },
            InclusionProbe {
                leaf_index,
                tree_size: tree_size * 2,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: proof.to_vec(),
                desc: "tree_size * 2",
            },
            InclusionProbe {
                leaf_index,
                tree_size,
                root: *root,
                leaf_hash: *b"WrongLeafWrongLeafWrongLeafWrong",
                proof: proof.to_vec(),
                desc: "wrong leaf",
            },
            InclusionProbe {
                leaf_index,
                tree_size,
                root: SHA256_EMPTY_TREE_HASH,
                leaf_hash: *leaf_hash,
                proof: proof.to_vec(),
                desc: "empty root",
            },
            InclusionProbe {
                leaf_index,
                tree_size,
                root: SHA256_SOME_HASH,
                leaf_hash: *leaf_hash,
                proof: proof.to_vec(),
                desc: "random root",
            },
            InclusionProbe {
                leaf_index,
                tree_size,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: [proof.to_vec(), [[0_u8; 32]].to_vec()].concat(),
                desc: "trailing garbage",
            },
            InclusionProbe {
                leaf_index,
                tree_size,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: [proof.to_vec(), [*root].to_vec()].concat(),
                desc: "trailing root",
            },
            InclusionProbe {
                leaf_index,
                tree_size,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: [[[0_u8; 32]].to_vec(), proof.to_vec()].concat(),
                desc: "preceding garbage",
            },
            InclusionProbe {
                leaf_index,
                tree_size,
                root: *root,
                leaf_hash: *leaf_hash,
                proof: [[*root].to_vec(), proof.to_vec()].concat(),
                desc: "preceding root",
            },
        ]
    }

    fn verifier_check(
        leaf_index: u64,
        tree_size: u64,
        proof_hashes: &[[u8; 32]],
        root: &[u8; 32],
        leaf_hash: &[u8; 32],
    ) -> Result<(), String> {
        let probes = corrupt_inclusion_proof(leaf_index, tree_size, proof_hashes, root, leaf_hash);
        let leaf_hash = leaf_hash.into();
        let root_hash = root.into();
        let proof_hashes = proof_hashes.iter().map(|&h| h.into()).collect::<Vec<_>>();
        let got = Rfc6269Default::root_from_inclusion_proof(
            leaf_index,
            leaf_hash,
            tree_size,
            &proof_hashes,
        )
        .map_err(|err| format!("{err:?}"))?;
        Rfc6269Default::verify_match(got.as_ref(), root_hash)
            .map_err(|_| format!("roots did not match got: {got:x?} expected: {root:x?}"))?;
        Rfc6269Default::verify_inclusion(
            leaf_index,
            leaf_hash,
            tree_size,
            &proof_hashes,
            root_hash,
        )
        .map_err(|err| format!("{err:?}"))?;

        probes
            .into_iter()
            .map(|p| {
                Rfc6269Default::verify_inclusion(
                    p.leaf_index,
                    (&p.leaf_hash).into(),
                    p.tree_size,
                    &p.proof.iter().map(|&h| h.into()).collect::<Vec<_>>(),
                    (&p.root).into(),
                )
                .err()
                .ok_or(format!("accepted incorrect inclusion proof: {:?}", p.desc))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    #[test]
    fn test_verify_inclusion_single_entry() {
        let data = b"data";
        let hash = &Rfc6269Default::hash_leaf(data);
        let proof = [];
        let zero_hash = ZERO_HASH.as_slice().into();
        let test_cases = [
            (hash, hash, false),
            (hash, zero_hash, true),
            (zero_hash, hash, true),
        ];
        for (i, (root, leaf, want_err)) in test_cases.into_iter().enumerate() {
            let res = Rfc6269Default::verify_inclusion(0, leaf, 1, &proof, root);
            assert_eq!(
                res.is_err(),
                want_err,
                "unexpected inclusion proof result {res:?} for case {i:?}"
            )
        }
    }

    #[test]
    fn test_verify_inclusion() {
        let proof = [];
        let probes = [(0, 0), (0, 1), (1, 0), (2, 1)];
        probes.into_iter().for_each(|(index, size)| {
            let result = Rfc6269Default::verify_inclusion(
                index,
                SHA256_SOME_HASH.as_slice().into(),
                size,
                &proof,
                ZERO_HASH.as_slice().into(),
            );
            assert!(result.is_err(), "Incorrectly verified invalid root/leaf",);
            let result = Rfc6269Default::verify_inclusion(
                index,
                ZERO_HASH.as_slice().into(),
                size,
                &proof,
                SHA256_EMPTY_TREE_HASH.as_slice().into(),
            );
            assert!(result.is_err(), "Incorrectly verified invalid root/leaf",);
            let result = Rfc6269Default::verify_inclusion(
                index,
                SHA256_SOME_HASH.as_slice().into(),
                size,
                &proof,
                SHA256_EMPTY_TREE_HASH.as_slice().into(),
            );
            assert!(result.is_err(), "Incorrectly verified invalid root/leaf");
        });
        for i in 1..6 {
            let p = &INCLUSION_PROOFS[i];
            let leaf_hash = &Rfc6269Default::hash_leaf(LEAVES[i]).into();
            let result = verifier_check(
                p.leaf - 1,
                p.size,
                p.proof,
                &ROOTS[p.size as usize - 1],
                leaf_hash,
            );
            assert!(result.is_err(), "{result:?}")
        }
    }
}
