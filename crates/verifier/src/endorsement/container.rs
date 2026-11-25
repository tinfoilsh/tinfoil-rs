//! Container provenance: the builds that a config requires for its
//! container images, and their authentication.

use super::EndorsementError;
use super::provenance::ProvenanceClient;
use super::reference::is_sha256_hex;
use super::runtime::SLSA_PROVENANCE_V1;
use crate::document::Document;
use crate::json::{self, Value};
use crate::sigstore::statement::STATEMENT_TYPE;

/// The config member that holds the containers.
const CONTAINERS_KEY: &str = "containers";
/// The container member that holds the image reference.
const IMAGE_KEY: &str = "image";
/// The container member that holds the build requirement.
const PROVENANCE_KEY: &str = "provenance";
/// The one kind of build requirement.
const GITHUB_KEY: &str = "github";
/// The members of a GitHub build requirement: all of them, and no others.
const GITHUB_KEYS: [&str; 5] = ["repository", "repository_id", "workflow", "ref", "commit"];

/// What precedes the hex SHA-256 digest that ends a pinned image reference.
const IMAGE_DIGEST_PREFIX: &str = "@sha256:";

/// What the URI of a repository on GitHub, and with it every signing
/// identity of its workflows, starts with.
const GITHUB_URL_PREFIX: &str = "https://github.com/";
/// What separates a repository from a workflow file in a signing identity.
const GITHUB_WORKFLOWS_PATH: &str = "/.github/workflows/";
/// What separates a workflow file from its ref in a signing identity.
const WORKFLOW_REF_SEPARATOR: &str = "@";

/// The build that a config requires for the container image with the
/// SHA-256 `digest`: a run of a GitHub Actions workflow of a repository, at
/// a ref and a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerProvenance {
    /// The SHA-256 of the image, lowercase hex.
    pub digest: String,
    /// The repository, `owner/name`.
    pub repository: String,
    /// The immutable identifier of the repository on GitHub.
    pub repository_id: String,
    /// The file name of the workflow.
    pub workflow: String,
    /// The ref that the workflow ran at.
    pub git_ref: String,
    /// The commit that the workflow ran at.
    pub commit: String,
}

/// Returns the builds that a config requires, in container order. A
/// requirement of any shape but the one that is read here is an error, so
/// that an unknown kind of requirement is never treated as met. The
/// publisher and the guest own the validation of the values.
pub fn container_provenance_from_config(
    data: &[u8],
) -> Result<Vec<ContainerProvenance>, EndorsementError> {
    let config = json::parse(data)
        .map_err(|cause| EndorsementError::new(format!("parsing config containers: {cause}")))?;
    let containers = match &config {
        Value::Null => None,
        Value::Object(config) => config.get(CONTAINERS_KEY),
        other => {
            return Err(EndorsementError::new(format!(
                "parsing config containers: the config is a JSON {}",
                other.kind()
            )));
        }
    };
    let Some(containers) = containers else {
        return Ok(Vec::new());
    };
    let not_objects = || EndorsementError::new("config containers must be an array of objects");
    let mut required = Vec::new();
    for (index, container) in containers
        .as_array()
        .ok_or_else(not_objects)?
        .iter()
        .enumerate()
    {
        let container = container.as_object().ok_or_else(not_objects)?;
        let Some(provenance) = container.get(PROVENANCE_KEY) else {
            continue;
        };
        let github = provenance
            .as_object()
            .filter(|provenance| provenance.len() == 1)
            .and_then(|provenance| provenance.get(GITHUB_KEY))
            .and_then(Value::as_object)
            .filter(|github| github.len() == GITHUB_KEYS.len());
        let [
            Some(repository),
            Some(repository_id),
            Some(workflow),
            Some(git_ref),
            Some(commit),
        ] = GITHUB_KEYS.map(|key| github?.get(key)?.as_str())
        else {
            return Err(EndorsementError::new(format!(
                "containers[{index}].provenance must hold only github, with only the strings repository, repository_id, workflow, ref and commit"
            )));
        };
        let digest = container
            .get(IMAGE_KEY)
            .and_then(Value::as_str)
            .and_then(|image| image.rsplit_once(IMAGE_DIGEST_PREFIX))
            .map(|(_, digest)| digest)
            .filter(|digest| is_sha256_hex(digest));
        let Some(digest) = digest else {
            return Err(EndorsementError::new(format!(
                "containers[{index}].image must be a string that ends with {IMAGE_DIGEST_PREFIX} and a lowercase hex digest"
            )));
        };
        required.push(ContainerProvenance {
            digest: digest.to_owned(),
            repository: repository.to_owned(),
            repository_id: repository_id.to_owned(),
            workflow: workflow.to_owned(),
            git_ref: git_ref.to_owned(),
            commit: commit.to_owned(),
        });
    }
    Ok(required)
}

impl ProvenanceClient {
    /// Verifies the build of every container image for which `config`
    /// requires one, against the build attestation that `document` carries
    /// for the image.
    pub fn authenticate_containers(
        &self,
        config: &[u8],
        document: &Document,
    ) -> Result<(), EndorsementError> {
        for required in container_provenance_from_config(config)? {
            let bundle = document.container_provenance(&required.digest)?;
            self.authenticate_container(bundle, &required)
                .map_err(|cause| {
                    cause.within(format_args!("container image sha256:{}", required.digest))
                })?;
        }
        Ok(())
    }

    /// Verifies that `bundle` is a SLSA build attestation of the image with
    /// `required.digest`, signed on a GitHub-hosted runner by the required
    /// workflow of the required repository, at the required ref and commit.
    fn authenticate_container(
        &self,
        bundle: &Value,
        required: &ContainerProvenance,
    ) -> Result<(), EndorsementError> {
        // Every identity on GitHub is accepted here. It is compared as text
        // below.
        let on_github = |identity: &str| identity.starts_with(GITHUB_URL_PREFIX);
        let verified = self
            .verify_bundle(bundle, on_github, &required.digest, None)
            .map_err(|cause| cause.within("verifying container provenance"))?;
        if verified.statement.statement_type != STATEMENT_TYPE
            || verified.statement.predicate_type != SLSA_PROVENANCE_V1
        {
            return Err(EndorsementError::new(
                "container provenance must use SLSA v1",
            ));
        }
        // The source claims name the repository, the ref and the commit that
        // the run built. The identity names the workflow file that signed,
        // which must be that repository's own file at that ref and not one
        // called from elsewhere.
        let signer = &verified.identity;
        let claims = &signer.extensions;
        let repository = format!("{GITHUB_URL_PREFIX}{}", required.repository);
        let identity = format!(
            "{repository}{GITHUB_WORKFLOWS_PATH}{}{WORKFLOW_REF_SEPARATOR}{}",
            required.workflow, required.git_ref
        );
        let equalities = [
            (
                "source repository",
                &claims.source_repository_uri,
                &repository,
            ),
            (
                "source repository ID",
                &claims.source_repository_identifier,
                &required.repository_id,
            ),
            (
                "workflow identity",
                &signer.subject_alternative_name,
                &identity,
            ),
            (
                "source ref",
                &claims.source_repository_ref,
                &required.git_ref,
            ),
            (
                "source commit",
                &claims.source_repository_digest,
                &required.commit,
            ),
        ];
        for (name, found, wanted) in equalities {
            if found != wanted {
                return Err(EndorsementError::new(format!(
                    "container provenance {name} {found:?} is not {wanted:?}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published build attestation of the image with
    /// [`RECORDED_DIGEST`]. Its certificate names the workflow identity
    /// `https://github.com/tinfoilsh/measure-image-action/.github/workflows/build.yml@refs/tags/build-v0.14.2`.
    const RECORDED_BUNDLE: &[u8] =
        include_bytes!("../../tests/data/endorsement/container_provenance_bundle.json");
    const RECORDED_DIGEST: &str =
        "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1";

    /// A change to a requirement.
    type Change = fn(&mut ContainerProvenance);

    #[test]
    fn a_build_attestation_is_held_to_the_required_workflow_run() {
        let client = ProvenanceClient::embedded().unwrap();
        let bundle = json::parse(RECORDED_BUNDLE).unwrap();
        let recorded = ContainerProvenance {
            digest: RECORDED_DIGEST.to_owned(),
            repository: "tinfoilsh/measure-image-action".to_owned(),
            repository_id: "924941172".to_owned(),
            workflow: "build.yml".to_owned(),
            git_ref: "refs/tags/build-v0.14.2".to_owned(),
            commit: "01a05df207140a8e8e1d2cd26028ab7c51dad9d1".to_owned(),
        };
        assert_eq!(client.authenticate_container(&bundle, &recorded), Ok(()));

        let cases: [(&str, Change, &str); 6] = [
            (
                "another image",
                |required| required.digest.replace_range(..2, "00"),
                "verifying container provenance: ",
            ),
            (
                "another repository",
                |required| required.repository = "tinfoilsh/measure-image".to_owned(),
                "container provenance source repository \"",
            ),
            (
                "another repository ID",
                |required| required.repository_id = "92494117".to_owned(),
                "container provenance source repository ID ",
            ),
            (
                "another workflow",
                |required| required.workflow = "release.yml".to_owned(),
                "container provenance workflow identity ",
            ),
            // The identity ends with the ref, and a `*` stands for itself.
            (
                "ref with an asterisk",
                |required| required.git_ref = "refs/tags/build-v*".to_owned(),
                "container provenance workflow identity ",
            ),
            (
                "another commit",
                |required| required.commit.replace_range(..2, "00"),
                "container provenance source commit ",
            ),
        ];
        for (name, change, want) in cases {
            let mut required = recorded.clone();
            change(&mut required);
            let error = client
                .authenticate_container(&bundle, &required)
                .unwrap_err()
                .to_string();
            assert!(error.starts_with(want), "{name}: {error}");
        }
    }

    #[test]
    fn a_config_states_the_builds_that_its_containers_require() {
        const IMAGE_NAME: &str = r#""ghcr.io/tinfoilsh/inference-vllm"#;
        const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
        const UNCONSTRAINED: &str = r#"{"name":"router","image":"example.com/router:latest"}"#;
        let (digest, other) = ("ab".repeat(32), "cd".repeat(32));
        let image = format!(r#"{IMAGE_NAME}@sha256:{digest}""#);
        let github = format!(
            r#"{{"repository":"tinfoilsh/inference","repository_id":"902195777","workflow":"containers.yml","ref":"refs/tags/vllm-v1.2.3","commit":"{COMMIT}"}}"#
        );
        let provenance = format!(r#"{{"github":{github}}}"#);
        let container = |image: &str, provenance: &str| {
            format!(r#"{{"name":"model","image":{image},"provenance":{provenance}}}"#)
        };
        let config =
            |containers: &str| format!(r#"{{"cvm-version":"0.15.5","containers":{containers}}}"#);
        let requiring =
            |image: &str, provenance: &str| config(&format!("[{}]", container(image, provenance)));
        let edited = |old: &str, new: &str| {
            let github = github.replacen(old, new, 1);
            requiring(&image, &format!(r#"{{"github":{github}}}"#))
        };
        let required = |digest: &str| ContainerProvenance {
            digest: digest.to_owned(),
            repository: "tinfoilsh/inference".to_owned(),
            repository_id: "902195777".to_owned(),
            workflow: "containers.yml".to_owned(),
            git_ref: "refs/tags/vllm-v1.2.3".to_owned(),
            commit: COMMIT.to_owned(),
        };
        let read = |config: &str| container_provenance_from_config(config.as_bytes());

        let both = format!(
            "[{UNCONSTRAINED},{},{}]",
            container(&image, &provenance),
            container(&format!(r#""@sha256:{other}""#), &provenance)
        );
        for (name, config, want) in [
            ("config null", "null".to_owned(), vec![]),
            (
                "no containers",
                r#"{"cvm-version":"0.15.5"}"#.to_owned(),
                vec![],
            ),
            ("empty containers", config("[]"), vec![]),
            (
                "no provenance",
                config(&format!(r#"[{UNCONSTRAINED},{{"image":7}}]"#)),
                vec![],
            ),
            (
                "required",
                config(&both),
                vec![required(&digest), required(&other)],
            ),
        ] {
            assert_eq!(read(&config), Ok(want), "{name}");
        }

        for (name, config) in [
            ("not JSON", "containers: []\n".to_owned()),
            ("trailing data", config("[]") + "{}"),
            ("config not an object", "[]".to_owned()),
            (
                "repeated container member",
                config(&format!(r#"[{{"image":{image},"image":{image}}}]"#)),
            ),
            ("containers null", config("null")),
            ("containers not an array", config("{}")),
            ("container null", config("[null]")),
            ("container not an object", config(r#"["model"]"#)),
            ("provenance null", requiring(&image, "null")),
            ("provenance not an object", requiring(&image, r#""github""#)),
            ("provenance empty", requiring(&image, "{}")),
            (
                "unknown kind",
                requiring(&image, &format!(r#"{{"gitlab":{github}}}"#)),
            ),
            (
                "second kind",
                requiring(&image, &format!(r#"{{"github":{github},"gitlab":{{}}}}"#)),
            ),
            (
                "kind in another case",
                requiring(&image, &format!(r#"{{"GitHub":{github}}}"#)),
            ),
            ("github null", requiring(&image, r#"{"github":null}"#)),
            (
                "github not an object",
                requiring(&image, r#"{"github":"tinfoilsh/inference"}"#),
            ),
            (
                "github without repository",
                edited(r#""repository":"tinfoilsh/inference","#, ""),
            ),
            (
                "github without repository_id",
                edited(r#""repository_id":"902195777","#, ""),
            ),
            (
                "github without workflow",
                edited(r#""workflow":"containers.yml","#, ""),
            ),
            (
                "github without ref",
                edited(r#""ref":"refs/tags/vllm-v1.2.3","#, ""),
            ),
            (
                "github without commit",
                edited(&format!(r#","commit":"{COMMIT}""#), ""),
            ),
            (
                "github commit not a string",
                edited(&format!(r#""{COMMIT}""#), "7"),
            ),
            (
                "github unknown member",
                edited("}", r#","environment":"release"}"#),
            ),
            (
                "github repeated member",
                edited("}", r#","ref":"refs/heads/main"}"#),
            ),
            (
                "github number member",
                edited(r#""902195777""#, "902195777"),
            ),
            (
                "github null member",
                edited(r#""refs/tags/vllm-v1.2.3""#, "null"),
            ),
            (
                "image absent",
                config(&format!(r#"[{{"provenance":{provenance}}}]"#)),
            ),
            ("image null", requiring("null", &provenance)),
            ("image not a string", requiring("7", &provenance)),
            (
                "image by tag",
                requiring(&format!(r#"{IMAGE_NAME}:latest""#), &provenance),
            ),
            (
                "image digest alone",
                requiring(&format!(r#""{digest}""#), &provenance),
            ),
            (
                "image digest uppercase",
                requiring(
                    &format!(r#"{IMAGE_NAME}@sha256:{}""#, digest.to_uppercase()),
                    &provenance,
                ),
            ),
            (
                "image digest short",
                requiring(
                    &format!(r#"{IMAGE_NAME}@sha256:{}""#, &digest[1..]),
                    &provenance,
                ),
            ),
            (
                "image digest long",
                requiring(&format!(r#"{IMAGE_NAME}@sha256:{digest}a""#), &provenance),
            ),
            (
                "image digest not last",
                requiring(&format!(r#"{IMAGE_NAME}@sha256:{digest}/""#), &provenance),
            ),
        ] {
            assert!(read(&config).is_err(), "{name}");
        }
    }
}
