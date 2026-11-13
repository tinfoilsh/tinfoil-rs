//! Replays recorded full verifications of changed vector inputs.
//!
//! Each case names a fixture of the shared vectors and a list of changes
//! to its input: another repository pin, nonce, clock or trust anchor, or
//! an edit of the document's collateral. The record holds the exit code
//! and the whole output that an independent implementation of the same
//! rules gave the changed input, which were also this adapter's when the
//! record was made. Both must be reproduced exactly.
//!
//! The documents come from a checkout of the shared vectors, named by
//! `TINFOIL_CONFORMANCE_VECTORS`; without one the tests report a skip. A
//! changed document is written with sorted member names and no white
//! space, and its hash is compared with the recorded one, so that the
//! bytes verified here are the bytes that the record is about.

#![cfg(tinfoil_conformance)]
// Test tooling: indexing a JSON value yields null for a missing member and
// never panics, and a panic is how a test fails.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

const CASES: &str = include_str!("data/full_verification_differential.json");
const VECTORS_ENV: &str = "TINFOIL_CONFORMANCE_VECTORS";
const STAGE: &str = "verify-attestation-v3";

/// JSON text with the members of every object in the order of their names
/// and no white space.
fn canonical(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(members) => {
            let sorted: BTreeMap<&String, &Value> = members.iter().collect();
            let members: Vec<String> = sorted
                .into_iter()
                .map(|(name, member)| format!("{}:{}", json!(name), canonical(member)))
                .collect();
            format!("{{{}}}", members.join(","))
        }
        other => other.to_string(),
    }
}

fn decoded(input: &Value, member: &str) -> Value {
    let bytes = STANDARD.decode(input[member].as_str().unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn encoded(value: &Value) -> Value {
    json!(STANDARD.encode(canonical(value)))
}

fn position(edit: &Value) -> usize {
    usize::try_from(edit["i"].as_u64().unwrap()).unwrap()
}

/// Applies the edits of a `doc` change to a document.
fn edit_document(document: &mut Value, edits: &[Value]) {
    for edit in edits {
        let name = edit["e"].as_str().unwrap();
        match name {
            "set" => document[edit["key"].as_str().unwrap()] = edit["value"].clone(),
            "del" => {
                document
                    .as_object_mut()
                    .unwrap()
                    .remove(edit["key"].as_str().unwrap());
            }
            "set_evidence_format" => document["cpu_evidence"]["format"] = edit["value"].clone(),
            "same" => {}
            _ => {
                let collateral = document["collateral"].as_array_mut().unwrap();
                match name {
                    "remove" => {
                        collateral.remove(position(edit));
                    }
                    "dup" => collateral.push(collateral[position(edit)].clone()),
                    "reverse" => collateral.reverse(),
                    "rotate" => collateral.rotate_left(1),
                    other => panic!("unknown edit {other}"),
                }
            }
        }
    }
}

/// Applies the changes of a case to the input of its fixture.
fn changed(mut input: Value, changes: &[Value]) -> Value {
    for change in changes {
        match change["op"].as_str().unwrap() {
            "set" => input[change["key"].as_str().unwrap()] = change["value"].clone(),
            "del" => {
                input
                    .as_object_mut()
                    .unwrap()
                    .remove(change["key"].as_str().unwrap());
            }
            "add_time" => {
                let time = input["verification_time_unix"].as_i64().unwrap();
                input["verification_time_unix"] = json!(time + change["seconds"].as_i64().unwrap());
            }
            "root" => {
                let mut root = decoded(&input, "sigstore_trusted_root_json_b64");
                root.as_object_mut()
                    .unwrap()
                    .remove(change["drop"].as_str().unwrap());
                input["sigstore_trusted_root_json_b64"] = encoded(&root);
            }
            "doc" => {
                let mut document = decoded(&input, "document_b64");
                edit_document(&mut document, change["edits"].as_array().unwrap());
                input["document_b64"] = encoded(&document);
            }
            other => panic!("unknown change {other}"),
        }
    }
    input
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha256::digest(bytes)
}

/// SHA-256, for the comparison of a changed document with its record. The
/// adapter depends on no hash function, so the test carries one.
mod sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn digest(message: &[u8]) -> String {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut padded = message.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&(message.len() as u64 * 8).to_be_bytes());
        for block in padded.as_chunks::<64>().0 {
            let mut w = [0u32; 64];
            for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
                *slot = u32::from_be_bytes(*word);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let choose = (e & f) ^ (!e & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(choose)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let majority = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(majority);
                (h, g, f, e, d, c, b, a) =
                    (g, f, e, d.wrapping_add(t1), c, b, a, t1.wrapping_add(t2));
            }
            for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
                *slot = slot.wrapping_add(value);
            }
        }
        state.iter().map(|word| format!("{word:08x}")).collect()
    }
}

/// Replays the cases of the fixtures in one directory of the vectors.
fn replay(directory: &str) {
    replay_share(directory, 0, 1);
}

/// Replays one share of the cases of a directory: every case whose
/// position among the directory's cases is `share` modulo `shares`. The
/// shares of a large directory run as separate tests, side by side.
fn replay_share(directory: &str, share: usize, shares: usize) {
    let Some(root) = std::env::var_os(VECTORS_ENV).map(PathBuf::from) else {
        eprintln!("skipped: {VECTORS_ENV} is not set");
        return;
    };
    let record: Value = serde_json::from_str(CASES).unwrap();
    let outputs = record["outputs"].as_array().unwrap();
    let mut fixtures: BTreeMap<String, Value> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut ran = 0;
    let of_directory = record["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["vector"].as_str().unwrap().split('/').next() == Some(directory));
    for (_, case) in of_directory
        .enumerate()
        .filter(|(position, _)| position % shares == share)
    {
        let vector = case["vector"].as_str().unwrap();
        let name = format!("{vector}: {}", case["name"].as_str().unwrap());
        let fixture = fixtures.entry(vector.to_owned()).or_insert_with(|| {
            let path = root.join(format!("{vector}.json"));
            let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{name}: {error}"));
            serde_json::from_slice(&bytes).unwrap()
        });
        let input = changed(fixture["input"].clone(), case["ops"].as_array().unwrap());
        let document = STANDARD
            .decode(input["document_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            sha256_hex(&document),
            case["document_sha256"].as_str().unwrap(),
            "{name}: the changed document is not the recorded one"
        );
        let (output, code) = tinfoil_conformance::run(STAGE, input.to_string().as_bytes());
        let output = serde_json::to_value(&output).unwrap();
        let want_output = &outputs[usize::try_from(case["output"].as_u64().unwrap()).unwrap()];
        if i64::from(code) != case["exit"].as_i64().unwrap() || output != *want_output {
            failures.push(format!(
                "{name}: exit {code}, {output}; recorded {}, {want_output}",
                case["exit"]
            ));
        }
        ran += 1;
    }
    eprintln!("{directory}: {ran} cases");
    assert!(ran > 0, "{directory}: no cases");
    assert!(
        failures.is_empty(),
        "{} of {ran} cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn changed_golden_sev_snp_inputs_first_share() {
    replay_share("golden", 0, 4);
}

#[test]
fn changed_golden_sev_snp_inputs_second_share() {
    replay_share("golden", 1, 4);
}

#[test]
fn changed_golden_sev_snp_inputs_third_share() {
    replay_share("golden", 2, 4);
}

#[test]
fn changed_golden_sev_snp_inputs_fourth_share() {
    replay_share("golden", 3, 4);
}

#[test]
fn changed_golden_tdx_inputs() {
    replay("golden-tdx");
}

#[test]
fn changed_freshness_inputs() {
    replay("freshness");
}

#[test]
fn changed_frozen_inputs() {
    replay("frozen-time");
    replay("real-frozen");
}

#[test]
fn the_document_hash_is_sha256() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(&[b'a'; 119]),
        "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"
    );
}

#[test]
fn canonical_text_sorts_member_names_at_every_level() {
    let value: Value = serde_json::from_str(r#"{"b":[{"z":1,"a":"x\n"}],"a":null}"#).unwrap();
    assert_eq!(canonical(&value), r#"{"a":null,"b":[{"a":"x\n","z":1}]}"#);
}
