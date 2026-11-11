//! Release references and the identities that sign releases.

use super::EndorsementError;
use crate::document::collateral::RUNTIME_REPO;

/// The OIDC issuer of GitHub Actions workflow tokens.
pub const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The runner environment of a workflow that ran on GitHub's own runners.
pub const GITHUB_HOSTED_RUNNER: &str = "github-hosted";
/// The repository that publishes the platform policy artifact.
pub const PLATFORM_ENDORSEMENTS_REPO: &str = RUNTIME_REPO;
/// The repository whose workflow witnesses the freshness of releases.
pub const FRESHNESS_WITNESS_REPO: &str = "tinfoilsh/freshness-witness";
/// The immutable identifier of the Tinfoil organization on GitHub.
pub const TINFOIL_ORGANIZATION_ID: &str = "168487856";
/// The immutable identifier of the runtime repository on GitHub.
pub const RUNTIME_REPOSITORY_ID: &str = "902195777";

/// A parsed `owner/name[@tag][@sha256:digest]` release reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// The repository, `owner/name`.
    pub repo: String,
    /// The release tag, when the reference pins one.
    pub tag: Option<String>,
    /// The SHA-256 of the release artifact as 64 lowercase hex digits, when
    /// the reference pins one.
    pub digest: Option<String>,
}

/// Parses `owner/name[@tag][@sha256:digest]`.
///
/// `owner` and `name` are one or more of ASCII letters, digits, `_`, `.`
/// and `-`. A tag is one or more characters other than `@`, `~`, `^`, `:`,
/// `?`, `*`, `[`, `\` and the ASCII whitespace characters space, tab, line
/// feed, form feed and carriage return. A digest is `sha256:` and exactly
/// 64 lowercase hex digits. With one `@` part, it is a digest when it has
/// the digest form and a tag otherwise. Anything else is an error.
pub fn parse_reference(reference: &str) -> Result<Reference, EndorsementError> {
    let invalid = || {
        EndorsementError::new(format!(
            "invalid release reference {reference:?}: want owner/name[@tag][@sha256:digest]"
        ))
    };
    let mut parts = reference.split('@');
    let repo = parts.next().filter(|repo| is_repository_name(repo));
    let (tag, digest) = match (parts.next(), parts.next(), parts.next()) {
        (None, _, _) => (None, None),
        (Some(only), None, _) => match reference_digest(only) {
            Some(digest) => (None, Some(digest)),
            None => (Some(only), None),
        },
        (Some(tag), Some(digest), None) => (
            Some(tag),
            Some(reference_digest(digest).ok_or_else(invalid)?),
        ),
        _ => return Err(invalid()),
    };
    if tag.is_some_and(|tag| !is_reference_tag(tag)) {
        return Err(invalid());
    }
    Ok(Reference {
        repo: repo.ok_or_else(invalid)?.to_string(),
        tag: tag.map(str::to_string),
        digest: digest.map(str::to_string),
    })
}

/// The hex digits of the digest part of a reference, `sha256:` and 64
/// lowercase hex digits.
fn reference_digest(part: &str) -> Option<&str> {
    part.strip_prefix("sha256:")
        .filter(|digest| is_sha256_hex(digest))
}

/// Whether `tag` can be the tag part of a reference.
fn is_reference_tag(tag: &str) -> bool {
    !tag.is_empty()
        && !tag.contains([
            '@', '~', '^', ':', '?', '*', '[', '\\', ' ', '\t', '\n', '\u{c}', '\r',
        ])
}

/// Whether `repo` is a GitHub repository slug: `owner/name`, each one or
/// more of ASCII letters, digits, `_`, `.` and `-`.
pub fn is_repository_name(repo: &str) -> bool {
    let part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    };
    repo.split_once('/')
        .is_some_and(|(owner, name)| part(owner) && part(name))
}

/// Whether `commit` is a Git commit identifier: 40 lowercase hex digits.
pub fn is_git_commit(commit: &str) -> bool {
    commit.len() == 40 && crate::canonical::is_lower_hex(commit)
}

/// Whether `digest` is a SHA-256 in text: 64 lowercase hex digits.
pub fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64 && crate::canonical::is_lower_hex(digest)
}

/// The release that a verified statement and its signing certificate
/// identify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedArtifact {
    /// The repository that the release was verified against.
    pub repo: String,
    /// The tag that the signing workflow ran at.
    pub tag: String,
    /// The commit that the signing workflow ran at: 40 lowercase hex digits.
    pub commit: String,
    /// The name of the statement subject that the digest belongs to.
    pub subject_name: String,
    /// The SHA-256 of the artifact, lowercase hex.
    pub digest: String,
}

impl AuthenticatedArtifact {
    /// Checks that every field has its form: a repository slug, a non-empty
    /// tag, a Git commit, a non-empty subject name, a SHA-256. Checked in
    /// that order.
    pub fn validate(&self) -> Result<(), EndorsementError> {
        let error = |what: &str| {
            Err(EndorsementError::new(format!(
                "authenticated artifact {what}"
            )))
        };
        if !is_repository_name(&self.repo) {
            return error("repository is invalid");
        }
        if self.tag.is_empty() {
            return error("tag is empty");
        }
        if !is_git_commit(&self.commit) {
            return error("commit is malformed");
        }
        if self.subject_name.is_empty() {
            return error("subject name is empty");
        }
        if !is_sha256_hex(&self.digest) {
            return error("digest is malformed");
        }
        Ok(())
    }
}

/// Which workflow file of a repository may sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowFile {
    /// Any one file directly in `.github/workflows`: a name of one or more
    /// characters other than `/` and `@`.
    Any,
    /// Exactly this file name.
    Named(&'static str),
}

/// Which Git ref the signing workflow must have run at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowRef {
    /// Any tag: `refs/tags/` and one or more characters other than `@`.
    AnyTag,
    /// A platform release tag: `refs/tags/platform-v`, a digit, and any
    /// characters other than `@`.
    PlatformTag,
    /// Exactly this ref.
    Exact(String),
}

/// The signing certificate identity of a GitHub Actions workflow: the form
/// that a certificate's subject alternative name must have.
///
/// The name is `https://github.com/<repo>/.github/workflows/<file>@<ref>`,
/// matched as a whole: nothing before, nothing after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowIdentity {
    repo: String,
    file: WorkflowFile,
    git_ref: WorkflowRef,
}

impl WorkflowIdentity {
    /// The identity of release artifacts of `repo`: any workflow file, run
    /// from a tag. An error when `repo` is not a repository slug.
    pub fn tagged_release(repo: &str) -> Result<Self, EndorsementError> {
        if !is_repository_name(repo) {
            return Err(EndorsementError::new(format!(
                "invalid repository name {repo:?}"
            )));
        }
        Ok(Self {
            repo: repo.to_string(),
            file: WorkflowFile::Any,
            git_ref: WorkflowRef::AnyTag,
        })
    }

    /// The identity of the platform policy artifact: the
    /// `platform-release.yml` workflow of [`PLATFORM_ENDORSEMENTS_REPO`],
    /// run from a platform release tag.
    pub fn platform_endorsements() -> Self {
        Self {
            repo: PLATFORM_ENDORSEMENTS_REPO.to_string(),
            file: WorkflowFile::Named("platform-release.yml"),
            git_ref: WorkflowRef::PlatformTag,
        }
    }

    /// The identity of freshness witnesses: the `freshness.yml` workflow of
    /// [`FRESHNESS_WITNESS_REPO`], run from its main branch.
    pub fn freshness_witness() -> Self {
        Self {
            repo: FRESHNESS_WITNESS_REPO.to_string(),
            file: WorkflowFile::Named("freshness.yml"),
            git_ref: WorkflowRef::Exact("refs/heads/main".to_string()),
        }
    }

    /// The identity of one runtime release: the `release.yml` workflow of
    /// the runtime repository, run from exactly the tag `release_tag`.
    pub fn runtime_release(release_tag: &str) -> Self {
        Self {
            repo: RUNTIME_REPO.to_string(),
            file: WorkflowFile::Named("release.yml"),
            git_ref: WorkflowRef::Exact(format!("refs/tags/{release_tag}")),
        }
    }

    /// Whether a certificate's subject alternative name is this identity.
    pub fn matches(&self, subject_alternative_name: &str) -> bool {
        let Some(rest) = subject_alternative_name
            .strip_prefix("https://github.com/")
            .and_then(|rest| rest.strip_prefix(self.repo.as_str()))
            .and_then(|rest| rest.strip_prefix("/.github/workflows/"))
        else {
            return false;
        };
        // Neither a file name nor a ref pattern can contain `@`, so the
        // first one separates them.
        let Some((file, git_ref)) = rest.split_once('@') else {
            return false;
        };
        let file_matches = match &self.file {
            WorkflowFile::Any => !file.is_empty() && !file.contains('/'),
            WorkflowFile::Named(name) => file == *name,
        };
        let ref_matches =
            match &self.git_ref {
                WorkflowRef::AnyTag => git_ref
                    .strip_prefix("refs/tags/")
                    .is_some_and(|tag| !tag.is_empty() && !tag.contains('@')),
                WorkflowRef::PlatformTag => git_ref
                    .strip_prefix("refs/tags/platform-v")
                    .is_some_and(|version| {
                        version.starts_with(|first: char| first.is_ascii_digit())
                            && !version.contains('@')
                    }),
                WorkflowRef::Exact(exact) => git_ref == exact,
            };
        file_matches && ref_matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_names_are_two_plain_parts() {
        for name in ["tinfoilsh/cvmimage", "a/b", "A_1.x-y/Z.z"] {
            assert!(is_repository_name(name), "{name}");
        }
        for name in [
            "", "a", "a/", "/b", "a/b/c", "a b/c", "a/b@c", "a/b\n", "\u{e9}/b",
        ] {
            assert!(!is_repository_name(name), "{name:?}");
        }
    }

    #[test]
    fn commits_and_digests_are_lowercase_hex_of_fixed_length() {
        assert!(is_git_commit(&"a".repeat(40)));
        assert!(!is_git_commit(&"A".repeat(40)));
        assert!(!is_git_commit(&"a".repeat(39)));
        assert!(is_sha256_hex(&"0".repeat(64)));
        assert!(!is_sha256_hex(&"0".repeat(63)));
        assert!(!is_sha256_hex(&"g".repeat(64)));
    }

    const PREFIX: &str = "https://github.com/tinfoilsh/model/.github/workflows/";

    #[test]
    fn a_release_identity_is_any_workflow_file_at_a_tag() {
        let identity = WorkflowIdentity::tagged_release("tinfoilsh/model").unwrap();
        for accepted in [
            "release.yml@refs/tags/v1.2.3",
            "build.yaml@refs/tags/x",
            "a@refs/tags/a/b",
        ] {
            assert!(
                identity.matches(&format!("{PREFIX}{accepted}")),
                "{accepted}"
            );
        }
        for rejected in [
            "release.yml@refs/heads/main",
            "release.yml@refs/tags/",
            "release.yml@refs/tags/v1@v2",
            "dir/release.yml@refs/tags/v1",
            "@refs/tags/v1",
            "release.yml",
            "release.yml@",
        ] {
            assert!(
                !identity.matches(&format!("{PREFIX}{rejected}")),
                "{rejected}"
            );
        }
        let tag = "release.yml@refs/tags/v1";
        assert!(!identity.matches(&format!(" {PREFIX}{tag}")));
        assert!(!identity.matches(&format!(
            "https://github.com/tinfoilsh/model-evil/.github/workflows/{tag}"
        )));
        assert!(!identity.matches(&format!(
            "https://github.com/tinfoilsh/modelX.github/workflows/{tag}"
        )));
        assert!(!identity.matches(&format!(
            "https://github.com/other/tinfoilsh/model/.github/workflows/{tag}"
        )));
        assert!(!identity.matches(&format!(
            "http://github.com/tinfoilsh/model/.github/workflows/{tag}"
        )));
    }

    #[test]
    fn a_release_identity_needs_a_repository_name() {
        assert!(WorkflowIdentity::tagged_release("tinfoilsh").is_err());
        assert!(WorkflowIdentity::tagged_release("tinfoilsh/a/b").is_err());
        assert!(WorkflowIdentity::tagged_release("tinfoilsh/a.*").is_err());
    }

    #[test]
    fn the_platform_identity_is_one_workflow_at_a_platform_tag() {
        let identity = WorkflowIdentity::platform_endorsements();
        let prefix = "https://github.com/tinfoilsh/cvmimage/.github/workflows/";
        assert!(identity.matches(&format!(
            "{prefix}platform-release.yml@refs/tags/platform-v0.1.2"
        )));
        assert!(identity.matches(&format!(
            "{prefix}platform-release.yml@refs/tags/platform-v9"
        )));
        for rejected in [
            "platform-release.yml@refs/tags/platform-vx",
            "platform-release.yml@refs/tags/platform-v",
            "platform-release.yml@refs/tags/v0.1.2",
            "platform-releasexyml@refs/tags/platform-v1",
            "release.yml@refs/tags/platform-v1",
            "platform-release.yml@refs/tags/platform-v1@x",
            "platform-release.yml@refs/heads/platform-v1",
        ] {
            assert!(
                !identity.matches(&format!("{prefix}{rejected}")),
                "{rejected}"
            );
        }
    }

    #[test]
    fn the_witness_identity_is_one_workflow_on_the_main_branch() {
        let identity = WorkflowIdentity::freshness_witness();
        let prefix = "https://github.com/tinfoilsh/freshness-witness/.github/workflows/";
        assert!(identity.matches(&format!("{prefix}freshness.yml@refs/heads/main")));
        assert!(!identity.matches(&format!("{prefix}freshness.yml@refs/heads/main2")));
        assert!(!identity.matches(&format!("{prefix}freshness.yml@refs/tags/main")));
        assert!(!identity.matches(&format!("{prefix}other.yml@refs/heads/main")));
    }

    #[test]
    fn a_runtime_identity_is_one_workflow_at_one_tag() {
        let identity = WorkflowIdentity::runtime_release("v1.2.3");
        let prefix = "https://github.com/tinfoilsh/cvmimage/.github/workflows/";
        assert!(identity.matches(&format!("{prefix}release.yml@refs/tags/v1.2.3")));
        assert!(!identity.matches(&format!("{prefix}release.yml@refs/tags/v1.2.30")));
        assert!(!identity.matches(&format!("{prefix}release.yml@refs/tags/v1x2.3")));
        assert!(!identity.matches(&format!("{prefix}platform-release.yml@refs/tags/v1.2.3")));
    }
}

#[cfg(test)]
mod reference_tests {
    use super::*;

    #[test]
    fn a_reference_has_a_repository_and_optional_pins() {
        let digest = "ab".repeat(32);
        let parsed = |reference: &str| parse_reference(reference).unwrap();
        let pins = |reference: &str| {
            let parsed = parsed(reference);
            (parsed.tag, parsed.digest)
        };
        assert_eq!(parsed("org/repo").repo, "org/repo");
        assert_eq!(pins("org/repo"), (None, None));
        assert_eq!(pins("org/repo@v1.2.3"), (Some("v1.2.3".into()), None));
        assert_eq!(
            pins(&format!("org/repo@sha256:{digest}")),
            (None, Some(digest.clone()))
        );
        assert_eq!(
            pins(&format!("org/repo@v1@sha256:{digest}")),
            (Some("v1".into()), Some(digest.clone()))
        );
        // Characters outside the excluded set are tag characters.
        assert_eq!(pins("org/repo@a/b\u{b}c").0, Some("a/b\u{b}c".into()));
    }

    #[test]
    fn a_malformed_reference_is_an_error() {
        let digest = "ab".repeat(32);
        for reference in [
            "",
            "org/repo@",
            "org/repo@sha256:bad",
            "org/repo@v1@v2",
            "org/repo/extra",
            "org/(repo|other)",
            "org/repo@v 1",
            "org/repo@v1\n",
            "org/repo@a:b",
            "org/repo@a~b",
            "org/repo@a^b",
            "org/repo@a?b",
            "org/repo@a*b",
            "org/repo@a[b",
            "org/repo@a\\b",
            &format!("org/repo@sha256:{}", digest.to_uppercase()),
            &format!("org/repo@sha256:{digest}@v1"),
            &format!("org/repo@v1@sha256:{digest}@x"),
            &format!("org/repo@@sha256:{digest}"),
        ] {
            let error = parse_reference(reference).unwrap_err().to_string();
            assert!(
                error.contains("invalid release reference"),
                "{reference}: {error}"
            );
        }
    }

    fn release() -> AuthenticatedArtifact {
        AuthenticatedArtifact {
            repo: PLATFORM_ENDORSEMENTS_REPO.to_string(),
            tag: "v0.0.4".to_string(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
            subject_name: "platform-endorsements.json".to_string(),
            digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        }
    }

    #[test]
    fn an_authenticated_artifact_has_every_field_in_its_form() {
        assert!(release().validate().is_ok());
        let rejected = |change: fn(&mut AuthenticatedArtifact), message: &str| {
            let mut artifact = release();
            change(&mut artifact);
            let error = artifact.validate().unwrap_err().to_string();
            assert!(error.contains(message), "{error}");
        };
        rejected(
            |artifact| artifact.repo = "cvmimage".into(),
            "repository is invalid",
        );
        rejected(|artifact| artifact.tag.clear(), "tag is empty");
        rejected(
            |artifact| artifact.commit = "abc".into(),
            "commit is malformed",
        );
        rejected(
            |artifact| artifact.subject_name.clear(),
            "subject name is empty",
        );
        rejected(
            |artifact| artifact.digest = "abc".into(),
            "digest is malformed",
        );
        rejected(
            |artifact| artifact.digest = format!("sha256:{}", artifact.digest),
            "digest is malformed",
        );
        rejected(
            |artifact| artifact.digest = artifact.digest.to_uppercase(),
            "digest is malformed",
        );
    }
}
