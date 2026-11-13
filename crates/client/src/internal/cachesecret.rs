//! Resolves the user cache secret: the value that scopes the prompt cache,
//! so that requests carrying the same secret share cached prompt prefixes
//! and requests carrying different secrets cannot observe each other's
//! cache timing.
//!
//! A request's secret is, in order:
//!
//! 1. a non-empty `user_cache_secret` string in the request body;
//! 2. the client's `user_cache_secret` option;
//! 3. a random secret that is generated in memory once per process and
//!    that every router client in the process shares.
//!
//! Step 3 applies to the router route only: an explicit enclave does not
//! read the member unless it is a router, so a client for one sends a
//! secret only when the option is set.
//!
//! The secret is never read from the environment or from the file system.
//! An application that wants a secret that stays the same across processes
//! or machines passes it as the option.

use std::sync::OnceLock;

use crate::internal::fetch::lower_hex;
use crate::options::Secret;

/// The client-level secret for a router client: the option when it is
/// set and not empty, and otherwise the secret of the process.
///
/// `None` only when the operating system supplies no random bytes for the
/// secret of the process; requests then carry no secret.
pub(crate) fn resolve(explicit: Option<Secret>) -> Option<Secret> {
    explicit
        .filter(|secret| !secret.expose().is_empty())
        .or_else(process_secret)
}

/// The secret of this process, generated on first use and the same for
/// every client after that.
fn process_secret() -> Option<Secret> {
    static SECRET: OnceLock<Option<Secret>> = OnceLock::new();
    SECRET.get_or_init(generate).clone()
}

/// A new secret: 32 random bytes in lowercase hexadecimal.
pub(crate) fn generate() -> Option<Secret> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).ok()?;
    Some(Secret::new(lower_hex(&bytes)))
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
        let first = exposed(generate()).unwrap();
        let second = exposed(generate()).unwrap();
        assert!(is_generated(&first));
        assert_ne!(first, second);
    }

    #[test]
    fn the_option_wins_and_an_empty_option_counts_as_unset() {
        let explicit = resolve(Some(Secret::new("explicit")));
        assert_eq!(exposed(explicit).as_deref(), Some("explicit"));

        let empty = exposed(resolve(Some(Secret::new("")))).unwrap();
        let unset = exposed(resolve(None)).unwrap();
        assert!(is_generated(&unset));
        assert_eq!(empty, unset);
    }

    #[test]
    fn without_the_option_every_resolution_in_the_process_shares_one_secret() {
        let first = exposed(resolve(None)).unwrap();
        let others: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| exposed(resolve(None)).unwrap()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(is_generated(&first));
        for other in &others {
            assert_eq!(other, &first);
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
        let first = exposed(resolve(None)).unwrap();
        assert!(is_generated(&first), "{first}");
        assert_ne!(first, FROM_ENV);
        assert_ne!(first, FROM_FILE);
        assert_eq!(exposed(resolve(None)).unwrap(), first);
        // The option still wins.
        let explicit = exposed(resolve(Some(Secret::new("explicit"))));
        assert_eq!(explicit.as_deref(), Some("explicit"));
    }
}
