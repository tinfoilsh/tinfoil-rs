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

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::internal::fetch::lower_hex;
use crate::options::Secret;

/// The environment variable that supplies the secret.
pub(crate) const ENV: &str = "TINFOIL_USER_CACHE_SECRET";

/// The directory under the home directory that holds the secret's file.
pub(crate) const DIR_NAME: &str = ".tinfoil";

/// The secret's file. The other Tinfoil SDKs read and write the same file,
/// so that one machine has one cache namespace across tools.
pub(crate) const FILE_NAME: &str = "user_cache_secret";

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a symbolic link or another reparse
/// point itself, not what it leads to.
#[cfg(windows)]
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// How many names are tried for the temporary file of a new secret.
const CANDIDATE_ATTEMPTS: usize = 16;

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
    resolve_from(explicit, std::env::var_os(ENV), home_dir())
}

/// [`resolve`], given the environment's value and the home directory.
///
/// An environment value that is empty, or that is not Unicode and so could
/// not be written into a JSON body, counts as unset.
pub(crate) fn resolve_from(
    explicit: Option<Secret>,
    env: Option<OsString>,
    home: Option<PathBuf>,
) -> Option<Secret> {
    if let Some(secret) = explicit.filter(|secret| !secret.expose().is_empty()) {
        return Some(secret);
    }
    if let Some(value) = env
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty())
    {
        return Some(Secret::new(value));
    }
    home.and_then(|home| load_or_generate(&home))
        .or_else(process_secret)
}

/// The user's home directory as the environment names it: `HOME` on Unix,
/// `USERPROFILE` on Windows. `None` when the variable is unset or empty,
/// and on other platforms.
fn home_dir() -> Option<PathBuf> {
    let name = if cfg!(unix) {
        "HOME"
    } else if cfg!(windows) {
        "USERPROFILE"
    } else {
        return None;
    };
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The secret of this process, generated on first use, for when none can
/// be stored.
fn process_secret() -> Option<Secret> {
    static SECRET: OnceLock<Option<Secret>> = OnceLock::new();
    SECRET.get_or_init(generate).clone()
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
    let dir = home.join(DIR_NAME);
    let path = dir.join(FILE_NAME);
    ensure_dir(&dir).ok()?;
    match read_secret(&path) {
        Ok(stored) => return stored,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }

    let secret = generate()?;
    let candidate = write_candidate(&dir, secret.expose()).ok()?;
    let linked = fs::hard_link(&candidate, &path);
    // Linked or not, the temporary name has done its work.
    let _ = fs::remove_file(&candidate);
    match linked {
        Ok(()) => Some(secret),
        // Another process stored its secret first: that one is used.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            read_secret(&path).ok().flatten()
        }
        Err(_) => None,
    }
}

/// A new secret: 32 random bytes in lowercase hexadecimal.
pub(crate) fn generate() -> Option<Secret> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).ok()?;
    Some(Secret::new(lower_hex(&bytes)))
}

/// An error unless `dir` is a directory, judged without following a
/// symbolic link.
fn check_dir(dir: &Path) -> io::Result<()> {
    if fs::symlink_metadata(dir)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::other(
            "the user cache secret directory is not a directory",
        ))
    }
}

/// Makes sure that `dir` is a directory, creating it, and its parents,
/// when nothing is there.
fn ensure_dir(dir: &Path) -> io::Result<()> {
    match check_dir(dir) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    check_dir(dir)
}

/// The secret in the file at `path`: `Some` when the file holds one, `None`
/// when it holds only whitespace. A missing file is the error
/// `NotFound`; a path that is not a regular file, and content that is not
/// UTF-8, are other errors.
fn read_secret(path: &Path) -> io::Result<Option<Secret>> {
    let not_regular = || io::Error::other("the user cache secret path is not a regular file");
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    // The path was a regular file a moment ago; if a symbolic link has
    // taken its place since, the open fails instead of following it.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    // On Windows the open takes the link itself instead of its target, and
    // the check of the open handle below then refuses it.
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, OPEN_REPARSE_POINT);
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(not_regular());
    }
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    let text = String::from_utf8(content)
        .map_err(|_| io::Error::other("the user cache secret is not valid UTF-8"))?;
    let secret = text.trim();
    Ok((!secret.is_empty()).then(|| Secret::new(secret)))
}

/// Writes `secret` to a new file in `dir` under a random temporary name,
/// with mode `0600`, and returns its path. The file is removed again if
/// the write fails.
fn write_candidate(dir: &Path, secret: &str) -> io::Result<PathBuf> {
    let (path, mut file) = create_candidate(dir)?;
    let written = file
        .write_all(secret.as_bytes())
        .and_then(|()| file.flush());
    drop(file);
    match written {
        Ok(()) => Ok(path),
        Err(error) => {
            let _ = fs::remove_file(&path);
            Err(error)
        }
    }
}

/// A new, empty file in `dir` that did not exist before.
fn create_candidate(dir: &Path) -> io::Result<(PathBuf, File)> {
    let mut last = io::Error::other("no temporary name was free");
    for _ in 0..CANDIDATE_ATTEMPTS {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(io::Error::other)?;
        let path = dir.join(format!("{FILE_NAME}.tmp-{}", lower_hex(&suffix)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own for one test, removed when the test ends.
    struct Home(PathBuf);

    impl Home {
        fn new() -> Self {
            let mut suffix = [0u8; 8];
            getrandom::fill(&mut suffix).unwrap();
            let path = std::env::temp_dir().join(format!("tinfoil-test-{}", lower_hex(&suffix)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn dir(&self) -> PathBuf {
            self.0.join(DIR_NAME)
        }
        fn file(&self) -> PathBuf {
            self.dir().join(FILE_NAME)
        }
        fn store(&self, content: &[u8]) {
            fs::create_dir_all(self.dir()).unwrap();
            fs::write(self.file(), content).unwrap();
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn exposed(secret: Option<Secret>) -> Option<String> {
        secret.map(|secret| secret.expose().to_owned())
    }

    fn is_generated(secret: &str) -> bool {
        secret.len() == 64
            && secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    #[test]
    fn a_new_secret_is_32_random_bytes_in_lowercase_hexadecimal() {
        let first = exposed(generate()).unwrap();
        let second = exposed(generate()).unwrap();
        assert!(is_generated(&first), "{first}");
        assert_ne!(first, second);
    }

    #[test]
    fn the_option_wins_then_the_environment_then_the_stored_secret() {
        let home = Home::new();
        home.store(b"stored\n");
        let env = || Some(OsString::from("from-env"));
        let at_home = || Some(home.0.clone());

        let explicit = resolve_from(Some(Secret::new("explicit")), env(), at_home());
        assert_eq!(exposed(explicit).as_deref(), Some("explicit"));
        assert_eq!(
            exposed(resolve_from(None, env(), at_home())).as_deref(),
            Some("from-env")
        );
        assert_eq!(
            exposed(resolve_from(None, None, at_home())).as_deref(),
            Some("stored")
        );
        // Empty values count as unset.
        let empty = resolve_from(Some(Secret::new("")), Some(OsString::new()), at_home());
        assert_eq!(exposed(empty).as_deref(), Some("stored"));
    }

    #[test]
    fn the_first_use_stores_a_secret_that_later_uses_read_back() {
        let home = Home::new();
        let first = exposed(load_or_generate(&home.0)).unwrap();
        assert!(is_generated(&first), "{first}");
        assert_eq!(fs::read_to_string(home.file()).unwrap(), first);
        assert_eq!(exposed(load_or_generate(&home.0)).unwrap(), first);
        // Nothing but the secret's file is left in the directory.
        let names: Vec<_> = fs::read_dir(home.dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsStr::new(FILE_NAME)]);
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_and_the_file_are_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let home = Home::new();
        load_or_generate(&home.0).unwrap();
        let mode = |path: PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(home.dir()), 0o700);
        assert_eq!(mode(home.file()), 0o600);
    }

    #[test]
    fn a_stored_secret_is_trimmed_and_an_unusable_file_is_never_replaced() {
        let home = Home::new();
        home.store(b"  \t padded-secret \r\n");
        assert_eq!(
            exposed(load_or_generate(&home.0)).as_deref(),
            Some("padded-secret")
        );

        for unusable in [&b" \n"[..], b"", b"\xff\xfe"] {
            home.store(unusable);
            assert!(load_or_generate(&home.0).is_none(), "{unusable:?}");
            assert_eq!(fs::read(home.file()).unwrap(), unusable);
        }
    }

    #[test]
    fn a_path_that_is_not_a_directory_or_not_a_regular_file_is_refused() {
        // The directory's name is taken by a file.
        let home = Home::new();
        fs::write(home.dir(), b"not a directory").unwrap();
        assert!(load_or_generate(&home.0).is_none());

        // The file's name is taken by a directory.
        let home = Home::new();
        fs::create_dir_all(home.file()).unwrap();
        assert!(load_or_generate(&home.0).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_followed_neither_for_the_directory_nor_for_the_file() {
        use std::os::unix::fs::symlink;

        let elsewhere = Home::new();
        elsewhere.store(b"planted");

        let home = Home::new();
        symlink(elsewhere.dir(), home.dir()).unwrap();
        assert!(load_or_generate(&home.0).is_none());

        let home = Home::new();
        fs::create_dir(home.dir()).unwrap();
        symlink(elsewhere.file(), home.file()).unwrap();
        assert!(load_or_generate(&home.0).is_none());
        // And the link is still a link: nothing was written through it.
        assert_eq!(fs::read(elsewhere.file()).unwrap(), b"planted");

        // A link that leads nowhere is not a missing file either.
        let home = Home::new();
        fs::create_dir(home.dir()).unwrap();
        symlink(home.0.join("missing"), home.file()).unwrap();
        assert!(load_or_generate(&home.0).is_none());
        assert!(!home.0.join("missing").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_that_replaces_the_file_after_the_first_check_is_not_followed_by_the_open() {
        use std::os::unix::fs::symlink;
        // The open by itself, as it would meet a link that was put in
        // place after the path had been seen to be a regular file.
        let home = Home::new();
        home.store(b"planted");
        let link = home.0.join("link");
        symlink(home.file(), &link).unwrap();
        let mut options = OpenOptions::new();
        options.read(true);
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
        assert!(options.open(&link).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_symbolic_link_is_not_followed_on_windows() {
        use std::os::windows::fs::symlink_file;

        let elsewhere = Home::new();
        elsewhere.store(b"planted");
        let home = Home::new();
        fs::create_dir(home.dir()).unwrap();
        // Creating a link needs a privilege that a test run may lack.
        if symlink_file(elsewhere.file(), home.file()).is_err() {
            return;
        }
        assert!(load_or_generate(&home.0).is_none());
        assert_eq!(fs::read(elsewhere.file()).unwrap(), b"planted");

        // The open by itself takes the link and not its target, so the
        // check of the open handle refuses it.
        let mut options = OpenOptions::new();
        options.read(true);
        std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, OPEN_REPARSE_POINT);
        let opened = options.open(home.file()).unwrap();
        assert!(!opened.metadata().unwrap().is_file());
    }

    #[test]
    fn without_a_place_to_store_it_the_secret_lasts_for_the_process() {
        let home = Home::new();
        fs::write(home.dir(), b"not a directory").unwrap();
        let first = exposed(resolve_from(None, None, Some(home.0.clone()))).unwrap();
        let second = exposed(resolve_from(None, None, None)).unwrap();
        assert!(is_generated(&first), "{first}");
        assert_eq!(first, second);
    }

    #[test]
    fn processes_that_start_together_end_up_with_one_secret() {
        let home = Home::new();
        let secrets: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| exposed(load_or_generate(&home.0)).unwrap()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let stored = fs::read_to_string(home.file()).unwrap();
        for secret in &secrets {
            assert_eq!(secret, &stored);
        }
    }
}
