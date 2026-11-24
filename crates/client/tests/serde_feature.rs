//! The `serde` feature implements `serde::Serialize` for the verification
//! report through the re-exported verifier, so that a caller needs no direct
//! dependency on `tinfoil-verifier`.
#![cfg(feature = "serde")]

use tinfoil::verifier::{VerificationReport, VerifiedFacts};

fn assert_serialize<T: serde::Serialize>() {}

#[test]
fn report_types_serialize_through_tinfoil() {
    assert_serialize::<VerificationReport>();
    assert_serialize::<VerifiedFacts>();
}
