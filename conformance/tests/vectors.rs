//! Drives the adapter over a checkout of the shared v3 vectors.
//!
//! Set `TINFOIL_CONFORMANCE_VECTORS` to the `vectors/v3` directory of a
//! tinfoil-conformance checkout. Without it the test reports a skip; with it,
//! a directory that yields no fixtures is an error, so a wrong path cannot
//! pass silently.

// Test tooling: indexing a JSON value yields null for a missing member and
// never panics, the counters cannot overflow, and a panic is how a test fails.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tinfoil_conformance::{
    CODE_MALFORMED_INPUT, EXIT_ACCEPTED, EXIT_MALFORMED, EXIT_REJECTED, EXIT_UNSUPPORTED,
};

const VECTORS_ENV: &str = "TINFOIL_CONFORMANCE_VECTORS";

/// The accept facts that a fixture may declare; each declared fact must
/// match the adapter's output exactly.
const FACTS: [&str; 7] = [
    "code_digest",
    "code_measurement",
    "enclave_measurement",
    "tls_public_key_fp",
    "hpke_public_key",
    "signing_key_hint",
    "timestamp",
];

/// Vector directories whose fixtures must all pass, not merely not fail.
/// A directory is added here when the stages behind it are implemented.
#[cfg(tinfoil_conformance)]
const MUST_PASS: &[&str] = &["envelope", "approval-bundle", "rfc3161"];

/// Without the stages compiled in, every fixture is skipped and none is
/// required to pass; a fixture that runs must still not fail.
#[cfg(not(tinfoil_conformance))]
const MUST_PASS: &[&str] = &[];

enum Outcome {
    Pass,
    Skip,
    Fail(String),
}

#[test]
fn shared_vectors() {
    let Some(root) = std::env::var_os(VECTORS_ENV).map(PathBuf::from) else {
        eprintln!("skipped: {VECTORS_ENV} is not set");
        return;
    };
    let fixtures = fixture_paths(&root);
    assert!(!fixtures.is_empty(), "no fixtures under {}", root.display());

    // Per directory: (passed, skipped).
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    for path in &fixtures {
        let directory = directory_name(&root, path);
        let entry = counts.entry(directory.clone()).or_default();
        match run_fixture(path) {
            Outcome::Pass => entry.0 += 1,
            Outcome::Skip => {
                entry.1 += 1;
                if MUST_PASS.contains(&directory.as_str()) {
                    failures.push(format!(
                        "{}: skipped in a must-pass directory",
                        path.display()
                    ));
                }
            }
            Outcome::Fail(reason) => failures.push(format!("{}: {reason}", path.display())),
        }
    }

    for (directory, (passed, skipped)) in &counts {
        eprintln!("{directory}: {passed} passed, {skipped} skipped");
    }
    for directory in MUST_PASS {
        if counts
            .get(*directory)
            .is_none_or(|(passed, _)| *passed == 0)
        {
            failures.push(format!(
                "{directory}: no fixture of a must-pass directory ran"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_fixture(path: &Path) -> Outcome {
    let fixture: Value = match std::fs::read(path).map(|bytes| serde_json::from_slice(&bytes)) {
        Ok(Ok(fixture)) => fixture,
        Ok(Err(error)) => return Outcome::Fail(format!("fixture is not JSON: {error}")),
        Err(error) => return Outcome::Fail(format!("fixture is unreadable: {error}")),
    };
    let Some(stage) = fixture["stage"].as_str() else {
        return Outcome::Fail("fixture has no stage".to_owned());
    };
    let expected = &fixture["expected"];
    let Some(expect_accept) = expected["accepted"].as_bool() else {
        return Outcome::Fail("fixture has no expected verdict".to_owned());
    };

    let (output, code) = tinfoil_conformance::run(stage, fixture["input"].to_string().as_bytes());
    if code == EXIT_UNSUPPORTED {
        return Outcome::Skip;
    }
    let output = match serde_json::to_value(&output) {
        Ok(output) => output,
        Err(error) => return Outcome::Fail(format!("output does not serialise: {error}")),
    };
    let accepted = output["accepted"].as_bool().unwrap_or(false);

    if expect_accept {
        if code != EXIT_ACCEPTED || !accepted {
            return Outcome::Fail(format!("rejected (exit {code}, {})", output["rejection"]));
        }
        for fact in FACTS {
            let want = &expected[fact];
            if !want.is_null() && output["outputs"][fact] != *want {
                return Outcome::Fail(format!(
                    "{fact}: got {}, want {want}",
                    output["outputs"][fact]
                ));
            }
        }
    } else {
        if (code != EXIT_REJECTED && code != EXIT_MALFORMED) || accepted {
            return Outcome::Fail(format!("accepted (exit {code}), want {}", expected["code"]));
        }
        let want = &expected["code"];
        // Malformed input has its own exit code; every other rejection
        // shares one. A fixture that declares its code fixes the exit too.
        if let Some(want) = want.as_str() {
            let want_exit = if want == CODE_MALFORMED_INPUT {
                EXIT_MALFORMED
            } else {
                EXIT_REJECTED
            };
            if code != want_exit {
                return Outcome::Fail(format!("exit: got {code}, want {want_exit} for {want}"));
            }
        }
        if !want.is_null() && output["rejection"]["code"] != *want {
            return Outcome::Fail(format!(
                "code: got {}, want {want}",
                output["rejection"]["code"]
            ));
        }
    }
    Outcome::Pass
}

/// Every `.json` file under `root`, at any depth, in a stable order.
fn fixture_paths(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("reading {}: {error}", directory.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|error| panic!("reading {}: {error}", directory.display()))
                .path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The first path component of `path` below `root`.
fn directory_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .and_then(|relative| relative.components().next())
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_default()
}
