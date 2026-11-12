//! Resolves and stores the user cache secret: the value that scopes the
//! prompt cache, so that requests carrying the same secret share cached
//! prompt prefixes and requests carrying different secrets cannot observe
//! each other's cache timing.
//!
//! A request's secret is, in order:
//!
//! 1. a non-empty `user_cache_secret` string in the request body;
//! 2. the client's `user_cache_secret` option;
//! 3. the `TINFOIL_USER_CACHE_SECRET` environment variable, when not empty;
//! 4. the secret stored in `~/.tinfoil/user_cache_secret`, generated on
//!    first use.
//!
//! Steps 3 and 4 apply to the router and gateway routes only: an explicit
//! enclave does not read the member unless it is a router, so a client for
//! one sends a secret only when the option is set.

use std::path::Path;

use crate::options::Secret;

/// The environment variable that supplies the secret.
pub(crate) const ENV: &str = "TINFOIL_USER_CACHE_SECRET";

/// The directory under the home directory that holds the secret's file.
pub(crate) const DIR_NAME: &str = ".tinfoil";

/// The secret's file. The other Tinfoil SDKs read and write the same file,
/// so that one machine has one cache namespace across tools.
pub(crate) const FILE_NAME: &str = "user_cache_secret";

/// The client-level secret for a router or gateway client: the option when
/// it is set, then a non-empty environment value, then the stored secret.
///
/// It never fails. Where no secret can be stored (no home directory, a
/// directory that cannot be created, a file that is not a regular file) it
/// returns one secret kept for the life of the process, so that the cache
/// is still scoped but the scope resets when the process exits. `None`
/// only when the operating system supplies no random bytes; requests then
/// carry no secret.
///
/// It reads the environment and the file system and blocks while it does;
/// the caller runs it once, when a client is created.
pub(crate) fn resolve(explicit: Option<Secret>) -> Option<Secret> {
    explicit
}

/// The stored secret under `home`, generated and stored on first use.
///
/// - The directory is created with mode `0700` if it is missing; a path
///   that exists and is not a directory is refused.
/// - The file is read only if it is a regular file, checked without
///   following a symbolic link and again on the open handle. Its content
///   is the secret, with surrounding whitespace removed; it must be valid
///   UTF-8 and not empty.
/// - A new secret is 32 random bytes in lowercase hexadecimal. It is
///   written to a temporary file with mode `0600` in the same directory and
///   then hard-linked to the final name, which fails if the name exists:
///   two processes that start together end up with the secret of whichever
///   linked first, and the other reads it back.
/// - On a platform without file modes the same steps run without them.
///
/// `None` when any step fails; the caller falls back to the process's own
/// secret.
pub(crate) fn load_or_generate(home: &Path) -> Option<Secret> {
    None
}

/// A new secret: 32 random bytes in lowercase hexadecimal.
pub(crate) fn generate() -> Option<Secret> {
    None
}
