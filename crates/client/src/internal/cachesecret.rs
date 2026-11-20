//! Resolves the user cache secret: the value that scopes the prompt cache,
//! so that requests carrying the same secret share cached prompt prefixes
//! and requests carrying different secrets cannot observe each other's
//! cache timing.
//!
//! A router request's secret is, in order:
//!
//! 1. a non-empty `user_cache_secret` string in the request body;
//! 2. the client's `user_cache_secret` option;
//! 3. a random secret that is generated in memory once per process and
//!    that every router client in the process shares.
//!
//! An explicit enclave does not read the member unless it is a router, so
//! a client for one has no such option and never adds or changes it.
//!
//! The secret is never read from the environment or from the file system.
//! An application that wants a secret that stays the same across processes
//! or machines passes it as the option.

use std::sync::OnceLock;

use crate::error::Error;
use crate::internal::fetch::lower_hex;
use crate::options::Secret;

/// The client-level secret for a router client: the option when it is
/// set and not empty, and otherwise the secret of the process.
///
/// Fails with an error of [`ErrorKind::Random`](crate::ErrorKind::Random)
/// when the secret of the process has to be generated and the operating
/// system supplies no random bytes for it.
pub(crate) fn resolve(explicit: Option<Secret>) -> Result<Option<Secret>, Error> {
    resolve_from(explicit, &PROCESS_SECRET, getrandom::fill)
}

/// The secret of this process, generated on first use and the same for
/// every client after that.
static PROCESS_SECRET: OnceLock<Secret> = OnceLock::new();

/// As [`resolve`], with the secret of the process kept in `process` and
/// generated with `fill`.
fn resolve_from(
    explicit: Option<Secret>,
    process: &OnceLock<Secret>,
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<Option<Secret>, Error> {
    if let Some(explicit) = explicit.filter(|secret| !secret.expose().is_empty()) {
        return Ok(Some(explicit));
    }
    if let Some(secret) = process.get() {
        return Ok(Some(secret.clone()));
    }
    // A failed generation stores nothing, so that the next resolution
    // tries again. Of two threads that generate at once, one secret wins,
    // and both return it.
    let generated = generate_with(fill).map_err(Error::random)?;
    Ok(Some(process.get_or_init(|| generated).clone()))
}

/// A new secret from 32 bytes that `fill` writes, in lowercase
/// hexadecimal.
fn generate_with(
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<Secret, getrandom::Error> {
    let mut bytes = [0u8; 32];
    fill(&mut bytes)?;
    Ok(Secret::new(lower_hex(&bytes)))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::{env, fs};

    use super::*;

    /// The environment variable that earlier versions read the secret
    /// from.
    const LEGACY_ENV: &str = "TINFOIL_USER_CACHE_SECRET";

    /// Set only in the child process of
    /// [`neither_the_environment_nor_a_stored_file_is_read`], and names the
    /// home directory that the child is given.
    const CHILD_MARKER: &str = "TINFOIL_TEST_CACHE_SECRET_CHILD_HOME";

    /// The values that the child process must not end up with.
    const FROM_ENV: &str = "secret-from-the-environment";
    const FROM_FILE: &str = "secret-from-the-file";

    fn exposed(secret: Option<Secret>) -> Option<String> {
        secret.map(|secret| secret.expose().to_owned())
    }

    fn is_generated(secret: &str) -> bool {
        secret.len() == 64
            && secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// A directory of its own for one test, removed when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut suffix = [0u8; 8];
            getrandom::fill(&mut suffix).unwrap();
            let path = env::temp_dir().join(format!("tinfoil-test-{}", lower_hex(&suffix)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The names of the entries under `dir`, sorted.
    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_new_secret_is_32_random_bytes_in_lowercase_hexadecimal() {
        let first = exposed(generate_with(getrandom::fill).ok()).unwrap();
        let second = exposed(generate_with(getrandom::fill).ok()).unwrap();
        assert!(is_generated(&first));
        assert!(first != second, "two generated secrets are equal");
    }

    #[test]
    fn a_failing_generator_returns_its_error_unchanged_and_is_tried_again() {
        let process = OnceLock::new();
        let failure = getrandom::Error::UNSUPPORTED;
        let error = resolve_from(None, &process, |_| Err(failure)).unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Random);
        let source = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<getrandom::Error>())
            .expect("the source is the generator's error");
        assert_eq!(*source, failure);
        assert!(process.get().is_none(), "the failure was kept");

        let explicit = resolve_from(Some(Secret::new("explicit")), &process, |_| Err(failure));
        assert_eq!(
            exposed(explicit.unwrap()).as_deref(),
            Some("explicit"),
            "an explicit secret needs no generation"
        );

        let generated = exposed(resolve_from(None, &process, getrandom::fill).unwrap()).unwrap();
        assert!(is_generated(&generated));
        let again = exposed(resolve_from(None, &process, |_| Err(failure)).unwrap()).unwrap();
        assert!(again == generated, "the generated secret was not kept");
    }

    #[test]
    fn the_option_wins_and_an_empty_option_counts_as_unset() {
        let explicit = resolve(Some(Secret::new("explicit"))).unwrap();
        assert_eq!(exposed(explicit).as_deref(), Some("explicit"));

        let empty = exposed(resolve(Some(Secret::new(""))).unwrap()).unwrap();
        let unset = exposed(resolve(None).unwrap()).unwrap();
        assert!(is_generated(&unset));
        assert!(
            empty == unset,
            "an empty option did not select the process secret"
        );
    }

    #[test]
    fn without_the_option_every_resolution_in_the_process_shares_one_secret() {
        let first = exposed(resolve(None).unwrap()).unwrap();
        let others: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| exposed(resolve(None).unwrap()).unwrap()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(is_generated(&first));
        for other in &others {
            assert!(other == &first, "a thread got a different secret");
        }
    }

    /// Runs this test binary again, with the legacy environment variable
    /// set and with a home directory that holds a secret in the legacy
    /// file, and has [`child_resolves_with_a_planted_environment_and_home`]
    /// check in that process that neither is used.
    ///
    /// The environment is set on the child alone: the tests of this
    /// process run in parallel, and this crate forbids the `unsafe` that
    /// changing its own environment needs.
    #[test]
    fn neither_the_environment_nor_a_stored_file_is_read() {
        for with_file in [true, false] {
            let home = TempDir::new();
            if with_file {
                let dir = home.0.join(".tinfoil");
                fs::create_dir(&dir).unwrap();
                fs::write(dir.join("user_cache_secret"), FROM_FILE).unwrap();
            }
            let before = listing(&home.0);

            let output = Command::new(env::current_exe().unwrap())
                .args([
                    "internal::cachesecret::tests::child_resolves_with_a_planted_environment_and_home",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_MARKER, &home.0)
                .env(LEGACY_ENV, FROM_ENV)
                .env("HOME", &home.0)
                .env("USERPROFILE", &home.0)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "with_file: {with_file}\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            // The child ran its checks: the filter matched one test.
            assert!(stdout.contains("1 passed"), "{stdout}");

            // Nothing was created, changed or removed under the home.
            assert_eq!(listing(&home.0), before);
            if with_file {
                let stored = home.0.join(".tinfoil").join("user_cache_secret");
                assert_eq!(fs::read_to_string(stored).unwrap(), FROM_FILE);
                assert_eq!(listing(&home.0.join(".tinfoil")), ["user_cache_secret"]);
            }
        }
    }

    /// The half of [`neither_the_environment_nor_a_stored_file_is_read`]
    /// that runs in the child process. In any other process it does
    /// nothing.
    #[test]
    fn child_resolves_with_a_planted_environment_and_home() {
        if env::var_os(CHILD_MARKER).is_none() {
            return;
        }
        // The messages never print a secret.
        let first = exposed(resolve(None).unwrap()).unwrap();
        assert!(is_generated(&first), "the secret is not a generated one");
        assert!(first != FROM_ENV, "the secret came from the environment");
        assert!(first != FROM_FILE, "the secret came from the file");
        assert!(
            exposed(resolve(None).unwrap()).unwrap() == first,
            "the process secret changed"
        );
        // The option still wins.
        let explicit = exposed(resolve(Some(Secret::new("explicit"))).unwrap());
        assert_eq!(explicit.as_deref(), Some("explicit"));
    }
}
