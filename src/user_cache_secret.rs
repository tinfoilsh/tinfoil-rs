//! Provisioning of the per-user prompt-cache secret defined by the secure
//! prompt caching contract.
//!
//! The router derives the request's prefix-cache namespace from the
//! `user_cache_secret` request-body field: requests carrying the same secret
//! (under the same API identity) share cached prompt prefixes, requests
//! carrying different secrets cannot observe each other's cache timing.
//!
//! Resolution order, mirroring the other Tinfoil clients:
//!
//! 1. a non-empty per-request `user_cache_secret` field in the body,
//! 2. [`Client::with_user_cache_secret`](crate::Client::with_user_cache_secret),
//! 3. the `TINFOIL_USER_CACHE_SECRET` environment variable,
//! 4. a generated secret persisted at `~/.tinfoil/user_cache_secret` (0600),
//!    shared with other Tinfoil SDKs using the same home directory.
//!
//! Injection happens in [`UserCacheSecretService`], the tower layer between
//! async-openai's request machinery and the pinned reqwest transport, so the
//! field only ever travels over the TLS connection pinned to the verified
//! enclave.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use async_openai::error::OpenAIError;
use async_openai::middleware::HttpRequestFactory;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;

/// Router-only request-body field. A non-empty string scopes the prompt
/// cache to that secret.
pub(crate) const USER_CACHE_SECRET_FIELD: &str = "user_cache_secret";

/// Environment variable that provisions the secret. An empty value is
/// treated as unset.
pub(crate) const USER_CACHE_SECRET_ENV: &str = "TINFOIL_USER_CACHE_SECRET";

/// Persisted-secret path components under the home directory. The other
/// Tinfoil SDKs use the same file, so one machine gets one cache namespace
/// across tools.
pub(crate) const USER_CACHE_SECRET_DIR_NAME: &str = ".tinfoil";
pub(crate) const USER_CACHE_SECRET_FILE_NAME: &str = "user_cache_secret";

/// OpenAI-compatible endpoints whose bodies carry the field. Matched by
/// suffix without requiring a `/v1` prefix so custom base URLs
/// (path-prefixed proxies or `/v1`-less roots) still qualify. Other
/// endpoints (embeddings, audio, files) are excluded: their engines do not
/// prefix-cache and may reject unknown fields.
const USER_CACHE_SECRET_PATHS: [&str; 3] = ["/chat/completions", "/completions", "/responses"];

/// Client-level source of the secret.
///
/// Resolution is deferred to the first request so that
/// [`Client::with_user_cache_secret`](crate::Client::with_user_cache_secret)
/// can replace the source before anything touches the environment or the
/// persisted file.
pub(crate) enum UserCacheSecret {
    /// No explicit choice: environment, then the persisted (or generated)
    /// secret, resolved once and memoized.
    Deferred(OnceLock<String>),
    /// Explicitly pinned by the caller.
    Explicit(String),
}

impl fmt::Debug for UserCacheSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deferred(_) => f.write_str("UserCacheSecret::Deferred(..)"),
            Self::Explicit(_) => f.write_str("UserCacheSecret::Explicit([REDACTED])"),
        }
    }
}

impl UserCacheSecret {
    pub(crate) fn deferred() -> Self {
        Self::Deferred(OnceLock::new())
    }

    pub(crate) fn explicit(secret: String) -> Self {
        if secret.is_empty() {
            Self::deferred()
        } else {
            Self::Explicit(secret)
        }
    }

    /// The resolved client-level secret. Never fails: every resolution
    /// problem degrades to a fallback or to `None`.
    pub(crate) fn get(&self) -> Option<&str> {
        let secret = match self {
            Self::Explicit(secret) => secret.as_str(),
            Self::Deferred(resolved) => resolved.get_or_init(resolve_default).as_str(),
        };
        (!secret.is_empty()).then_some(secret)
    }
}

/// Client-level secret source shared by typed and relaxed request paths.
///
/// The typed async-openai stack (via [`UserCacheSecretService`]) and the
/// relaxed chat path both read the current source through this cell, and
/// [`Client::with_user_cache_secret`](crate::Client::with_user_cache_secret)
/// replaces it in place. Swapping the source is therefore infallible and
/// atomic across paths: there is no stack rebuild that could fail and leave
/// one path injecting a stale secret while the other uses the new one.
#[derive(Debug)]
pub(crate) struct SharedUserCacheSecret {
    inner: RwLock<Arc<UserCacheSecret>>,
}

impl SharedUserCacheSecret {
    pub(crate) fn new(source: UserCacheSecret) -> Self {
        Self {
            inner: RwLock::new(Arc::new(source)),
        }
    }

    /// Replace the source; both automatic request paths observe the new one
    /// on their next request.
    pub(crate) fn replace(&self, source: UserCacheSecret) {
        // The lock is only ever held for an assignment or a clone, neither
        // of which can panic, so poisoning is unreachable; recover anyway
        // rather than unwrap.
        *self.inner.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(source);
    }

    /// Snapshot of the current source.
    pub(crate) fn current(&self) -> Arc<UserCacheSecret> {
        Arc::clone(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Default resolution: a non-empty environment value, otherwise the persisted
/// or generated secret.
fn resolve_default() -> String {
    resolve_env_or_file(
        std::env::var_os(USER_CACHE_SECRET_ENV).map(|v| v.to_string_lossy().into_owned()),
        dirs::home_dir(),
    )
}

/// Testable core of [`resolve_default`]: the environment state and home
/// directory are parameters so the tests stay hermetic (no process-global
/// environment mutation).
fn resolve_env_or_file(env: Option<String>, home: Option<PathBuf>) -> String {
    if let Some(env) = env.filter(|value| !value.is_empty()) {
        return env;
    }
    load_or_generate(home)
}

/// Returns the secret persisted under the home directory, generating and
/// persisting one on first use. When the home directory is unavailable or
/// unwritable it falls back to a process-lifetime in-memory secret.
fn load_or_generate(home: Option<PathBuf>) -> String {
    let Some(home) = home.filter(|h| !h.as_os_str().is_empty()) else {
        return ephemeral_user_cache_secret().to_string();
    };
    let dir = home.join(USER_CACHE_SECRET_DIR_NAME);
    let path = dir.join(USER_CACHE_SECRET_FILE_NAME);
    if create_secret_dir(&dir).is_err() {
        return ephemeral_user_cache_secret().to_string();
    }

    match read_secret_file(&path) {
        Ok(Some(existing)) => return existing,
        Ok(None) => match fs::symlink_metadata(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            _ => return ephemeral_user_cache_secret().to_string(),
        },
        Err(_) => return ephemeral_user_cache_secret().to_string(),
    }

    match publish_secret_file(&dir, &path) {
        Ok(secret) => secret,
        Err(_) => ephemeral_user_cache_secret().to_string(),
    }
}

/// The persisted secret, `None` if the file is missing or blank, or an error
/// if it is unreadable, invalid UTF-8, or not a regular file.
fn read_secret_file(path: &Path) -> io::Result<Option<String>> {
    let Some(mut file) = open_secret_file_for_read(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let contents =
        String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let existing = contents.trim();
    Ok((!existing.is_empty()).then(|| existing.to_string()))
}

fn open_secret_file_for_read(path: &Path) -> io::Result<Option<fs::File>> {
    let Some(file) = open_secret_file(path)? else {
        return Ok(None);
    };
    validate_open_secret_file_type(&file)?;
    Ok(Some(file))
}

fn open_secret_file(path: &Path) -> io::Result<Option<fs::File>> {
    #[cfg(not(unix))]
    if !validate_secret_file_path(path)? {
        return Ok(None);
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    Ok(Some(file))
}

fn validate_open_secret_file_type(file: &fs::File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "user cache secret path is not a regular file",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file_path(path: &Path) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "user cache secret path is not a regular file",
        ));
    }
    Ok(true)
}

#[cfg(not(unix))]
fn validate_secret_directory_path(path: &Path) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "user cache secret directory is not a directory",
        ));
    }
    Ok(true)
}

/// Create the secret directory with owner-only permissions.
fn create_secret_dir(dir: &Path) -> io::Result<()> {
    #[cfg(not(unix))]
    let _ = validate_secret_directory_path(dir)?;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    #[cfg(unix)]
    {
        if fs::symlink_metadata(dir)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "user cache secret directory must not be a symlink",
            ));
        }
        open_secret_dir(dir)?;
    }
    #[cfg(not(unix))]
    {
        validate_secret_directory_path(dir)?;
    }
    Ok(())
}

#[cfg(unix)]
fn open_secret_dir(dir: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let directory = options.open(dir)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "user cache secret directory is not a directory",
        ));
    }
    Ok(directory)
}

/// Open the secret file create-new (the O_EXCL equivalent), owner-only.
fn open_secret_file_exclusive(path: &Path) -> io::Result<fs::File> {
    #[cfg(not(unix))]
    if validate_secret_file_path(path)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "user cache secret file already exists",
        ));
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn write_secret_file_exclusive(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = open_secret_file_exclusive(path)?;
    validate_open_secret_file_type(&file)?;
    file.write_all(contents)
}

/// Publish one complete value for a missing destination without replacing
/// anything another process may have created concurrently.
fn publish_secret_file(dir: &Path, path: &Path) -> io::Result<String> {
    let secret = new_user_cache_secret();
    if secret.is_empty() {
        return Ok(secret);
    }

    let candidate_id = new_user_cache_secret();
    if candidate_id.is_empty() {
        return Ok(candidate_id);
    }
    let candidate_path = dir.join(format!(
        "{}.{}.{}.tmp",
        USER_CACHE_SECRET_FILE_NAME,
        std::process::id(),
        candidate_id,
    ));
    if let Err(err) = write_secret_file_exclusive(&candidate_path, secret.as_bytes()) {
        let _ = fs::remove_file(&candidate_path);
        return Err(err);
    }

    let result = match fs::hard_link(&candidate_path, path) {
        Ok(()) => Ok(secret),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => match read_secret_file(path) {
            Ok(Some(existing)) => Ok(existing),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "user cache secret destination is invalid",
            )),
            Err(err) => Err(err),
        },
        Err(err) => Err(err),
    };

    let _ = fs::remove_file(&candidate_path);
    result
}

/// A fresh 256-bit random secret, hex-encoded, from the same `ring` provider
/// the TLS stack uses.
fn new_user_cache_secret() -> String {
    let mut bytes = [0u8; 32];
    match rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
    {
        Ok(()) => hex::encode(bytes),
        Err(_) => {
            eprintln!(
                "tinfoil: could not generate a user cache secret; \
                 automatic prompt-cache scoping is unavailable"
            );
            String::new()
        }
    }
}

/// Process-lifetime fallback for when the secret cannot be persisted. An
/// unpersisted secret still isolates this process's cache namespace, but
/// continuity is lost on restart — like a session ID, it silently resets the
/// namespace every deploy — so the fallback warns once per process.
fn ephemeral_user_cache_secret() -> &'static str {
    static EPHEMERAL: OnceLock<String> = OnceLock::new();
    EPHEMERAL.get_or_init(|| {
        let secret = new_user_cache_secret();
        if !secret.is_empty() {
            eprintln!(
                "tinfoil: could not persist the user cache secret; using an \
                 in-memory secret, so prompt-cache continuity resets when this \
                 process exits (set {USER_CACHE_SECRET_ENV} or \
                 Client::with_user_cache_secret to pin one)"
            );
        }
        secret
    })
}

/// Tower service that injects the client-level secret into request bodies on
/// the way out. It sits between async-openai's retry layer and the pinned
/// reqwest transport, so the field is added before the request enters the
/// pinned TLS connection, and retries that rebuild the request replay the
/// injected body — never the caller's original.
///
/// A non-empty or non-string field already present in the body is never
/// overwritten. An empty string is replaced with the resolved client secret.
#[derive(Clone, Debug)]
pub(crate) struct UserCacheSecretService<S> {
    secret: Arc<SharedUserCacheSecret>,
    inner: S,
}

impl<S> UserCacheSecretService<S> {
    pub(crate) fn new(secret: Arc<SharedUserCacheSecret>, inner: S) -> Self {
        Self { secret, inner }
    }
}

impl<S> tower::Service<HttpRequestFactory> for UserCacheSecretService<S>
where
    S: tower::Service<HttpRequestFactory, Response = reqwest::Response, Error = OpenAIError>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, factory: HttpRequestFactory) -> Self::Future {
        // Wrap the factory rather than a single built request: every rebuild
        // (initial attempt, retries, replays) passes through the injection,
        // so replayed bodies always describe the injected bytes.
        let secret = Arc::clone(&self.secret);
        let injecting = HttpRequestFactory::new(move || {
            let factory = factory.clone();
            let secret = Arc::clone(&secret);
            async move {
                let mut request = factory.build().await?;
                // Snapshot the source per build so a swap via
                // `with_user_cache_secret` is honored without rebuilding
                // the stack.
                let source = secret.current();
                if let Some(secret) = source.get() {
                    provision_request(&mut request, secret);
                }
                Ok(request)
            }
        });
        self.inner.call(injecting)
    }
}

/// Inject the secret into an eligible request: a POST with a buffered body to
/// one of the supported endpoints. Streaming bodies (e.g. multipart uploads)
/// have no contiguous bytes to rewrite and are forwarded untouched — none of
/// the eligible endpoints take them.
pub(crate) fn provision_request(request: &mut reqwest::Request, secret: &str) {
    if request.method() != reqwest::Method::POST {
        return;
    }
    let path = request.url().path();
    if !USER_CACHE_SECRET_PATHS.iter().any(|p| path.ends_with(p)) {
        return;
    }
    let Some(raw) = request.body().and_then(reqwest::Body::as_bytes) else {
        return;
    };
    if raw.is_empty() {
        return;
    }
    let Some(injected) = inject_user_cache_secret(raw, secret) else {
        return;
    };
    // reqwest derives Content-Length from the body, but keep any explicit
    // header in sync with the injected bytes.
    if request
        .headers()
        .contains_key(reqwest::header::CONTENT_LENGTH)
    {
        request.headers_mut().insert(
            reqwest::header::CONTENT_LENGTH,
            reqwest::header::HeaderValue::from(injected.len()),
        );
    }
    *request.body_mut() = Some(reqwest::Body::from(injected));
}

/// Add the field to a JSON-object body by splicing it in before the closing
/// brace. Every caller-provided byte survives untouched, so number precision
/// (e.g. an int64-range `seed` that would not survive an f64 round trip)
/// cannot be corrupted. Returns `None` — forward the original bytes — for
/// non-object bodies, trailing data, or a body that already carries a
/// non-empty or non-string field. An empty string is replaced with the
/// resolved client secret.
fn inject_user_cache_secret(raw: &[u8], secret: &str) -> Option<Vec<u8>> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let Ok(body) = HashMap::<String, Box<RawValue>>::deserialize(&mut deserializer) else {
        return None; // not a JSON object
    };
    // Trailing whitespace after the object is legal JSON framing; trailing
    // DATA (`{...}}`, `{...} garbage`) is not — splicing into it would turn
    // a request the server rejects into one it accepts.
    if deserializer.end().is_err() {
        return None;
    }
    if let Some(existing) = body.get(USER_CACHE_SECRET_FIELD) {
        if existing.get() != r#""""# {
            return None;
        }
        let range = top_level_value_range(raw, USER_CACHE_SECRET_FIELD)?;
        let value = serde_json::to_string(secret).ok()?;
        let mut injected = Vec::with_capacity(raw.len() + value.len());
        injected.extend_from_slice(&raw[..range.start]);
        injected.extend_from_slice(value.as_bytes());
        injected.extend_from_slice(&raw[range.end..]);
        return Some(injected);
    }

    // The last non-whitespace byte is the object's closing brace.
    let close = raw
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))?;
    if raw[close] != b'}' {
        return None;
    }

    let value = serde_json::to_string(secret).ok()?;
    let mut injected =
        Vec::with_capacity(raw.len() + USER_CACHE_SECRET_FIELD.len() + value.len() + 4);
    injected.extend_from_slice(&raw[..close]);
    if !body.is_empty() {
        injected.push(b',');
    }
    injected.push(b'"');
    injected.extend_from_slice(USER_CACHE_SECRET_FIELD.as_bytes());
    injected.extend_from_slice(b"\":");
    injected.extend_from_slice(value.as_bytes());
    injected.extend_from_slice(&raw[close..]);
    Some(injected)
}

fn top_level_value_range(raw: &[u8], field: &str) -> Option<std::ops::Range<usize>> {
    let mut index = skip_json_whitespace(raw, 0);
    if raw.get(index) != Some(&b'{') {
        return None;
    }
    index += 1;
    let mut found = None;

    while index < raw.len() {
        index = skip_json_whitespace(raw, index);
        if raw.get(index) == Some(&b'}') {
            return found;
        }
        let key_end = json_string_end(raw, index)?;
        let key: String = serde_json::from_slice(&raw[index..key_end]).ok()?;
        index = skip_json_whitespace(raw, key_end);
        if raw.get(index) != Some(&b':') {
            return None;
        }
        let value_start = skip_json_whitespace(raw, index + 1);
        let value_end = json_value_end(raw, value_start)?;
        if key == field {
            if found.is_some() {
                return None;
            }
            found = Some(value_start..value_end);
        }
        index = skip_json_whitespace(raw, value_end);
        match raw.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => return found,
            _ => return None,
        }
    }
    None
}

fn skip_json_whitespace(raw: &[u8], mut index: usize) -> usize {
    while matches!(raw.get(index), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        index += 1;
    }
    index
}

fn json_string_end(raw: &[u8], start: usize) -> Option<usize> {
    if raw.get(start) != Some(&b'"') {
        return None;
    }
    let mut escaped = false;
    for (index, byte) in raw.iter().enumerate().skip(start + 1) {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Some(index + 1);
        }
    }
    None
}

fn json_value_end(raw: &[u8], start: usize) -> Option<usize> {
    match raw.get(start)? {
        b'"' => json_string_end(raw, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut in_string = false;
            let mut escaped = false;
            for (index, byte) in raw.iter().enumerate().skip(start) {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if *byte == b'\\' {
                        escaped = true;
                    } else if *byte == b'"' {
                        in_string = false;
                    }
                } else if *byte == b'"' {
                    in_string = true;
                } else if matches!(*byte, b'{' | b'[') {
                    depth += 1;
                } else if matches!(*byte, b'}' | b']') {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index + 1);
                    }
                }
            }
            None
        }
        _ => {
            let mut end = start;
            while end < raw.len() && !matches!(raw[end], b',' | b'}') {
                end += 1;
            }
            while end > start && matches!(raw[end - 1], b' ' | b'\t' | b'\n' | b'\r') {
                end -= 1;
            }
            (end > start).then_some(end)
        }
    }
}

/// Add the client-level secret to a JSON body built by the relaxed chat path,
/// which posts through the pinned reqwest client directly rather than through
/// async-openai's executor. A non-empty or non-string field the caller already
/// set wins; an empty string is replaced.
pub(crate) fn provision_value(body: &mut Value, secret: &UserCacheSecret) {
    let Some(map) = body.as_object_mut() else {
        return;
    };
    if let Some(existing) = map.get(USER_CACHE_SECRET_FIELD) {
        if existing != "" {
            return;
        }
    }
    let Some(secret) = secret.get() else {
        return;
    };
    map.insert(
        USER_CACHE_SECRET_FIELD.to_string(),
        Value::String(secret.to_string()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    // =====================================================================
    // Resolution and persistence
    // =====================================================================

    /// Minimal unique-per-test home directory; std has no tempdir and the
    /// crate carries no tempfile dev-dependency.
    struct TempHome(PathBuf);

    impl TempHome {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "tinfoil-user-cache-secret-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir_all(&dir).expect("create temp home");
            Self(dir)
        }

        fn path(&self) -> PathBuf {
            self.0.clone()
        }

        fn secret_dir(&self) -> PathBuf {
            self.0.join(USER_CACHE_SECRET_DIR_NAME)
        }

        fn secret_path(&self) -> PathBuf {
            self.secret_dir().join(USER_CACHE_SECRET_FILE_NAME)
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn assert_generated_secret(secret: &str) {
        assert_eq!(secret.len(), 64, "expected a hex-encoded 256-bit secret");
        assert!(
            secret
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected lowercase hex, got {secret}"
        );
    }

    #[test]
    fn explicit_empty_restores_default_resolution() {
        assert_eq!(
            UserCacheSecret::explicit("s1".to_string()).get(),
            Some("s1")
        );
        assert!(matches!(
            UserCacheSecret::explicit(String::new()),
            UserCacheSecret::Deferred(_)
        ));
    }

    /// Restores an environment variable to its pre-test value on drop, so a
    /// failing assert cannot leak test state into the rest of the binary.
    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn deferred_source_reads_the_environment_and_explicit_beats_it() {
        // The one test that mutates the process environment: nothing else in
        // this binary reads TINFOIL_USER_CACHE_SECRET concurrently (the other
        // resolution tests are parameterized precisely to avoid this). The
        // guard restores the variable even if an assert below panics.
        let _guard = EnvVarGuard::set(USER_CACHE_SECRET_ENV, "from-env");
        assert_eq!(
            UserCacheSecret::deferred().get(),
            Some("from-env"),
            "the deferred source must consult the environment"
        );
        assert_eq!(
            UserCacheSecret::explicit("explicit".to_string()).get(),
            Some("explicit"),
            "the explicit option must beat the environment"
        );
        assert_eq!(
            UserCacheSecret::explicit(String::new()).get(),
            Some("from-env"),
            "an explicit empty secret must restore default resolution"
        );
    }

    #[test]
    fn environment_beats_generation_and_touches_no_file() {
        let home = TempHome::new();
        assert_eq!(
            resolve_env_or_file(Some("from-env".to_string()), Some(home.path())),
            "from-env"
        );
        assert!(
            !home.secret_dir().exists(),
            "an environment-provided secret must not create the secret file"
        );
    }

    #[test]
    fn environment_set_but_empty_falls_through() {
        let home = TempHome::new();
        let resolved = resolve_env_or_file(Some(String::new()), Some(home.path()));
        assert_generated_secret(&resolved);
        assert!(home.secret_dir().exists());
    }

    #[test]
    fn generates_persists_and_reuses_a_secret() {
        let home = TempHome::new();
        let first = resolve_env_or_file(None, Some(home.path()));
        assert_generated_secret(&first);
        assert_eq!(fs::read_to_string(home.secret_path()).unwrap(), first);
        assert_eq!(resolve_env_or_file(None, Some(home.path())), first);

        let metadata = fs::metadata(home.secret_path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
            assert_eq!(
                fs::metadata(home.secret_dir())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
        }
        #[cfg(not(unix))]
        assert!(metadata.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn accepts_existing_secret_without_changing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let home = TempHome::new();
        fs::create_dir_all(home.secret_dir()).unwrap();
        fs::set_permissions(home.secret_dir(), fs::Permissions::from_mode(0o777)).unwrap();
        fs::write(home.secret_path(), "shared-secret\n").unwrap();
        fs::set_permissions(home.secret_path(), fs::Permissions::from_mode(0o666)).unwrap();

        assert_eq!(
            resolve_env_or_file(None, Some(home.path())),
            "shared-secret"
        );
        assert_eq!(
            fs::metadata(home.secret_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
        assert_eq!(
            fs::metadata(home.secret_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o666
        );
    }

    #[test]
    fn invalid_existing_destination_is_untouched() {
        for contents in [&b"  \n"[..], &b"corrupt-\xff\xfe-secret\n"[..]] {
            let home = TempHome::new();
            fs::create_dir_all(home.secret_dir()).unwrap();
            fs::write(home.secret_path(), contents).unwrap();

            assert_eq!(
                resolve_env_or_file(None, Some(home.path())),
                ephemeral_user_cache_secret()
            );
            assert_eq!(fs::read(home.secret_path()).unwrap(), contents);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_destination_and_directory_symlinks_without_changing_targets() {
        use std::os::unix::fs::symlink;

        let destination_home = TempHome::new();
        fs::create_dir_all(destination_home.secret_dir()).unwrap();
        let destination_target = destination_home.path().join("destination-target");
        fs::write(&destination_target, "target-secret").unwrap();
        symlink(&destination_target, destination_home.secret_path()).unwrap();
        assert_eq!(
            resolve_env_or_file(None, Some(destination_home.path())),
            ephemeral_user_cache_secret()
        );
        assert_eq!(
            fs::read_to_string(destination_target).unwrap(),
            "target-secret"
        );

        let directory_home = TempHome::new();
        let directory_target = directory_home.path().join("directory-target");
        fs::create_dir(&directory_target).unwrap();
        fs::write(directory_target.join("sentinel"), "unchanged").unwrap();
        symlink(&directory_target, directory_home.secret_dir()).unwrap();
        assert_eq!(
            resolve_env_or_file(None, Some(directory_home.path())),
            ephemeral_user_cache_secret()
        );
        assert_eq!(
            fs::read_to_string(directory_target.join("sentinel")).unwrap(),
            "unchanged"
        );
        assert!(!directory_target.join(USER_CACHE_SECRET_FILE_NAME).exists());
    }

    #[test]
    fn concurrent_first_use_converges_and_removes_temps() {
        const CONTENDER_COUNT: usize = 12;
        let home = TempHome::new();
        create_secret_dir(&home.secret_dir()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(CONTENDER_COUNT));
        let mut contenders = Vec::new();

        for _ in 0..CONTENDER_COUNT {
            let barrier = Arc::clone(&barrier);
            let dir = home.secret_dir();
            let path = home.secret_path();
            contenders.push(std::thread::spawn(move || {
                barrier.wait();
                publish_secret_file(&dir, &path).unwrap()
            }));
        }

        let resolved: Vec<String> = contenders
            .into_iter()
            .map(|contender| contender.join().unwrap())
            .collect();
        let persisted = fs::read_to_string(home.secret_path()).unwrap();
        assert_generated_secret(&persisted);
        assert!(resolved.iter().all(|secret| secret == &persisted));
        assert_eq!(fs::read_dir(home.secret_dir()).unwrap().count(), 1);
    }

    #[test]
    fn falls_back_to_a_stable_in_memory_secret_without_home() {
        let first = resolve_env_or_file(None, None);
        assert!(
            !first.is_empty(),
            "no home directory must still yield a process-lifetime secret"
        );
        assert_eq!(
            first,
            resolve_env_or_file(None, None),
            "the in-memory fallback must be stable within the process"
        );
        // An empty home path is as good as no home at all.
        assert_eq!(first, resolve_env_or_file(None, Some(PathBuf::new())));
    }

    #[test]
    fn falls_back_when_home_is_not_a_directory() {
        let home = TempHome::new();
        let not_a_dir = home.path().join("not-a-dir");
        fs::write(&not_a_dir, "x").unwrap();

        assert!(!resolve_env_or_file(None, Some(not_a_dir)).is_empty());
    }

    // =====================================================================
    // Body injection
    // =====================================================================

    #[test]
    fn injects_into_object_bodies() {
        let injected = inject_user_cache_secret(br#"{"model":"m"}"#, "s1").expect("should inject");
        assert_eq!(injected, br#"{"model":"m","user_cache_secret":"s1"}"#);

        // Empty object: no leading comma.
        let injected = inject_user_cache_secret(b"{}", "s1").expect("should inject");
        assert_eq!(injected, br#"{"user_cache_secret":"s1"}"#);
    }

    #[test]
    fn never_clobbers_a_non_empty_or_non_string_field() {
        for raw in [
            r#"{"model":"m","user_cache_secret":"end-user-7"}"#, // explicit per-request secret
            r#"{"model":"m","user_cache_secret":null}"#,
        ] {
            assert!(
                inject_user_cache_secret(raw.as_bytes(), "client-level").is_none(),
                "a body that already carries the field must pass through byte-identical: {raw}"
            );
        }
    }

    #[test]
    fn replaces_an_empty_existing_field() {
        for (raw, expected) in [
            (
                r#"{"large":9007199254740993,"user_cache_secret":"","nested":{"value":1}}  "#,
                r#"{"large":9007199254740993,"user_cache_secret":"client-level","nested":{"value":1}}  "#,
            ),
            (
                r#"{"user_cache_secre\u0074":""}"#,
                r#"{"user_cache_secre\u0074":"client-level"}"#,
            ),
        ] {
            assert_eq!(
                inject_user_cache_secret(raw.as_bytes(), "client-level").unwrap(),
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn forwards_non_object_bodies_untouched() {
        // The trailing '}' / ']' cases are the classic regression: a decoder
        // that stops at the end of the first value would re-serialize the
        // object and silently drop the trailing bytes, turning a request the
        // server rejects into one it accepts.
        for raw in [
            "not json",
            "[1,2,3]",
            "null",
            r#"{"model":"m"} trailing"#,
            r#"{"model":"m"}}"#,
            r#"{"model":"m"}]"#,
            r#"{"model":"m"}} garbage"#,
        ] {
            assert!(
                inject_user_cache_secret(raw.as_bytes(), "s1").is_none(),
                "bodies the router-side schema would reject must be forwarded untouched: {raw}"
            );
        }
    }

    #[test]
    fn allows_trailing_whitespace_after_the_object() {
        // Trailing whitespace is not trailing data: strict JSON parsers
        // accept it, so the injection must too — clients routinely end
        // bodies with a newline.
        let injected =
            inject_user_cache_secret(b"{\"model\":\"m\"}\n\t ", "s1").expect("should inject");
        let body: Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(body[USER_CACHE_SECRET_FIELD], "s1");
        assert!(
            injected.ends_with(b"}\n\t "),
            "the original framing must be preserved"
        );
    }

    #[test]
    fn preserves_number_precision() {
        let injected = inject_user_cache_secret(br#"{"model":"m","seed":9007199254740993}"#, "s1")
            .expect("should inject");
        let body = std::str::from_utf8(&injected).unwrap();
        assert!(
            body.contains(r#""seed":9007199254740993"#),
            "seed corrupted: {body}"
        );
    }

    #[test]
    fn treats_out_of_range_number_literals_as_a_valid_object() {
        // `1e999` overflows f64, so materializing values through
        // `serde_json::Value` would reject the body ("number out of range")
        // and skip the injection — but it IS a single well-formed JSON
        // object, and tinfoil-go (a `UseNumber()` decoder) injects.
        // The key-only parse keeps the body eligible; the splice preserves
        // the literal byte-for-byte.
        let injected = inject_user_cache_secret(br#"{"model":"m","temperature":1e999}"#, "s1")
            .expect("should inject");
        assert_eq!(
            injected,
            br#"{"model":"m","temperature":1e999,"user_cache_secret":"s1"}"#
        );
    }

    #[test]
    fn debug_output_redacts_explicit_secrets() {
        let secret = UserCacheSecret::explicit("sensitive-cache-secret".to_string());
        let output = format!("{secret:?}");
        assert!(!output.contains("sensitive-cache-secret"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn escapes_the_secret_as_a_json_string() {
        let injected = inject_user_cache_secret(br#"{"model":"m"}"#, r#"we"ird"#).unwrap();
        let body: Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(body[USER_CACHE_SECRET_FIELD], r#"we"ird"#);
    }

    // =====================================================================
    // Relaxed-path injection
    // =====================================================================

    #[test]
    fn provision_value_inserts_the_client_level_secret() {
        let secret = UserCacheSecret::explicit("client-level".to_string());
        let mut body = json!({"model":"m"});
        provision_value(&mut body, &secret);
        assert_eq!(body[USER_CACHE_SECRET_FIELD], "client-level");
    }

    #[test]
    fn provision_value_does_not_resolve_deferred_secret_for_caller_values() {
        for caller_value in [json!("end-user-7"), json!(7)] {
            let secret = UserCacheSecret::deferred();
            let UserCacheSecret::Deferred(resolved) = &secret else {
                unreachable!("deferred constructor must return deferred source");
            };
            let mut body = json!({"model":"m","user_cache_secret":caller_value});

            provision_value(&mut body, &secret);

            assert_eq!(body[USER_CACHE_SECRET_FIELD], caller_value);
            assert!(resolved.get().is_none());
        }
    }

    #[test]
    fn provision_value_replaces_empty_and_never_clobbers_other_values() {
        let secret = UserCacheSecret::explicit("client-level".to_string());

        let mut body = json!({"model":"m","user_cache_secret":"end-user-7"});
        provision_value(&mut body, &secret);
        assert_eq!(body[USER_CACHE_SECRET_FIELD], "end-user-7");

        let mut body = json!({"model":"m","user_cache_secret":""});
        provision_value(&mut body, &secret);
        assert_eq!(body[USER_CACHE_SECRET_FIELD], "client-level");

        // Non-object bodies are forwarded as-is.
        let mut body = json!([1, 2, 3]);
        provision_value(&mut body, &secret);
        assert_eq!(body, json!([1, 2, 3]));
    }

    // =====================================================================
    // Transport service
    // =====================================================================

    type CapturedRequests = Arc<Mutex<Vec<Captured>>>;

    struct Captured {
        content_length_header: Option<String>,
        body: Option<Vec<u8>>,
    }

    /// Inner service that, instead of sending, rebuilds the factory twice —
    /// the second build simulates a retry replaying the request — and records
    /// what each attempt would have put on the wire.
    #[derive(Clone)]
    struct CaptureService {
        seen: CapturedRequests,
    }

    impl tower::Service<HttpRequestFactory> for CaptureService {
        type Response = reqwest::Response;
        type Error = OpenAIError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, factory: HttpRequestFactory) -> Self::Future {
            let seen = Arc::clone(&self.seen);
            Box::pin(async move {
                for _ in 0..2 {
                    let request = factory.build().await?;
                    seen.lock().unwrap().push(Captured {
                        content_length_header: request
                            .headers()
                            .get(reqwest::header::CONTENT_LENGTH)
                            .map(|v| v.to_str().unwrap().to_string()),
                        body: request
                            .body()
                            .and_then(reqwest::Body::as_bytes)
                            .map(<[u8]>::to_vec),
                    });
                }
                Err(OpenAIError::InvalidArgument("capture only".to_string()))
            })
        }
    }

    fn shared_secret(secret: &str) -> Arc<SharedUserCacheSecret> {
        Arc::new(SharedUserCacheSecret::new(UserCacheSecret::explicit(
            secret.to_string(),
        )))
    }

    fn capture_service(secret: &str) -> (UserCacheSecretService<CaptureService>, CapturedRequests) {
        let seen: CapturedRequests = Arc::default();
        let service = UserCacheSecretService::new(
            shared_secret(secret),
            CaptureService {
                seen: Arc::clone(&seen),
            },
        );
        (service, seen)
    }

    /// Replayable factory for a POST with a JSON body and an explicit
    /// Content-Length header (so tests can pin that the header tracks the
    /// injected bytes).
    fn post_json_factory(url: String, body: &'static str) -> HttpRequestFactory {
        crate::ensure_crypto_provider();
        HttpRequestFactory::new(move || {
            let url = url.clone();
            async move {
                reqwest::Client::new()
                    .post(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .header(reqwest::header::CONTENT_LENGTH, body.len())
                    .body(body)
                    .build()
                    .map_err(OpenAIError::Reqwest)
            }
        })
    }

    #[tokio::test]
    async fn service_injects_on_every_eligible_path() {
        use tower::Service;

        for path in [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",
            "/api/v1/chat/completions", // proxy base URL with a path prefix
            "/chat/completions",        // /v1-less custom base URL
        ] {
            let (mut service, seen) = capture_service("s1");
            let factory = post_json_factory(
                format!("https://enclave.example.com{path}"),
                r#"{"model":"m"}"#,
            );
            let _ = service.call(factory).await;

            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2, "{path}: expected the replay to be captured");
            for captured in seen.iter() {
                // Both the initial attempt and the replay must describe the
                // injected bytes.
                let body = captured.body.as_deref().expect("body should be buffered");
                let parsed: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(parsed[USER_CACHE_SECRET_FIELD], "s1", "{path}");
                assert_eq!(
                    captured.content_length_header.as_deref(),
                    Some(body.len().to_string().as_str()),
                    "{path}: Content-Length must track the injected bytes"
                );
            }
        }
    }

    #[tokio::test]
    async fn service_skips_ineligible_requests() {
        use tower::Service;

        // Non-allowlisted endpoints (with or without /v1): body forwarded
        // byte-identical.
        for path in ["/v1/embeddings", "/embeddings"] {
            let (mut service, seen) = capture_service("s1");
            let raw = r#"{"model":"m","input":"text"}"#;
            let factory = post_json_factory(format!("https://enclave.example.com{path}"), raw);
            let _ = service.call(factory).await;
            assert_eq!(
                seen.lock().unwrap()[0].body.as_deref(),
                Some(raw.as_bytes()),
                "{path}"
            );
        }

        // GET with no body is forwarded as-is.
        let (mut service, seen) = capture_service("s1");
        crate::ensure_crypto_provider();
        let factory = HttpRequestFactory::new(|| async {
            reqwest::Client::new()
                .get("https://enclave.example.com/v1/models")
                .build()
                .map_err(OpenAIError::Reqwest)
        });
        let _ = service.call(factory).await;
        assert!(seen.lock().unwrap()[0].body.is_none());

        // An empty client-level secret restores default resolution.
        let (mut service, seen) = capture_service("");
        let factory = post_json_factory(
            "https://enclave.example.com/v1/chat/completions".into(),
            r#"{"model":"m"}"#,
        );
        let _ = service.call(factory).await;
        let seen = seen.lock().unwrap();
        let body: Value = serde_json::from_slice(seen[0].body.as_deref().unwrap()).unwrap();
        assert!(body[USER_CACHE_SECRET_FIELD]
            .as_str()
            .is_some_and(|secret| !secret.is_empty()));
    }

    #[tokio::test]
    async fn service_never_clobbers_a_per_request_field() {
        use tower::Service;

        for raw in [
            r#"{"model":"m","user_cache_secret":"end-user-7"}"#,
            r#"{"model":"m","user_cache_secret":null}"#,
        ] {
            let (mut service, seen) = capture_service("client-level");
            let factory = post_json_factory(
                "https://enclave.example.com/v1/chat/completions".into(),
                raw,
            );
            let _ = service.call(factory).await;

            let seen = seen.lock().unwrap();
            for captured in seen.iter() {
                assert_eq!(
                    captured.body.as_deref(),
                    Some(raw.as_bytes()),
                    "a body that already carries the field must pass through byte-identical"
                );
                assert_eq!(
                    captured.content_length_header.as_deref(),
                    Some(raw.len().to_string().as_str()),
                    "an untouched body must keep its original Content-Length"
                );
            }
        }
    }

    #[tokio::test]
    async fn service_replaces_an_empty_per_request_field_on_every_attempt() {
        use tower::Service;

        let (mut service, seen) = capture_service("client-level");
        let factory = post_json_factory(
            "https://enclave.example.com/v1/chat/completions".into(),
            r#"{"large":9007199254740993,"user_cache_secret":""}"#,
        );
        let _ = service.call(factory).await;

        for captured in seen.lock().unwrap().iter() {
            assert_eq!(
                captured.body.as_deref(),
                Some(
                    br#"{"large":9007199254740993,"user_cache_secret":"client-level"}"#.as_slice()
                )
            );
        }
    }

    // =====================================================================
    // End to end through the real async-openai client machinery
    // =====================================================================

    use crate::test_support::serve_chat_completions;

    /// Drives the real async-openai client through the production-shaped
    /// stack (retry → injection → reqwest) to a local server, pinning that
    /// the client-level secret rides requests exactly as the SDK builds them
    /// — and that a body already carrying the field wins over it.
    #[tokio::test]
    async fn end_to_end_through_the_openai_client() {
        use async_openai::config::OpenAIConfig;
        use async_openai::middleware::retry::OpenAIRetryLayer;
        use async_openai::middleware::ReqwestService;
        use async_openai::types::chat::{
            ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
        };
        use tower::{Layer, Service};

        crate::ensure_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received: Arc<Mutex<Vec<Value>>> = Arc::default();
        tokio::spawn(serve_chat_completions(listener, Arc::clone(&received)));

        let http = reqwest::Client::new();
        let secret = shared_secret("client-level");
        let stack = OpenAIRetryLayer::default().layer(UserCacheSecretService::new(
            Arc::clone(&secret),
            ReqwestService::new(http.clone()),
        ));
        let config = OpenAIConfig::new()
            .with_api_key("test")
            .with_api_base(format!("http://{addr}/v1"));
        let openai = async_openai::Client::with_config(config)
            .with_http_client(http.clone())
            .with_http_service(stack);

        let request = CreateChatCompletionRequestArgs::default()
            .model("m")
            .messages(vec![ChatCompletionRequestUserMessageArgs::default()
                .content("hi")
                .build()
                .unwrap()
                .into()])
            .build()
            .unwrap();
        openai
            .chat()
            .create(request)
            .await
            .expect("chat completion through the injection stack");
        assert_eq!(
            received.lock().unwrap()[0][USER_CACHE_SECRET_FIELD],
            "client-level"
        );

        // A body that already carries the field — how a server holding many
        // end users' conversations scopes per request — must win over the
        // client-level secret all the way to the wire.
        let mut stack = OpenAIRetryLayer::default().layer(UserCacheSecretService::new(
            secret,
            ReqwestService::new(http),
        ));
        let factory = post_json_factory(
            format!("http://{addr}/v1/chat/completions"),
            r#"{"model":"m","user_cache_secret":"end-user-7"}"#,
        );
        stack
            .call(factory)
            .await
            .expect("per-request body through the injection stack");
        assert_eq!(
            received.lock().unwrap()[1][USER_CACHE_SECRET_FIELD],
            "end-user-7",
            "a per-request field must win over the client-level secret"
        );
    }
}
