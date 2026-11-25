//! Container provenance: the builds that a config requires for its
//! container images.

use super::EndorsementError;
use super::reference::is_sha256_hex;
use crate::json::{self, Value};

/// The config member that holds the containers.
const CONTAINERS_KEY: &str = "containers";
/// The container member that holds the image reference.
const IMAGE_KEY: &str = "image";
/// The container member that holds the build requirement.
const PROVENANCE_KEY: &str = "provenance";
/// The one kind of build requirement.
const GITHUB_KEY: &str = "github";
/// The members of a GitHub build requirement: all of them, and no others.
const GITHUB_KEYS: [&str; 4] = ["repository", "repository_id", "workflow", "ref"];

/// What precedes the hex SHA-256 digest that ends a pinned image reference.
const IMAGE_DIGEST_PREFIX: &str = "@sha256:";

/// The build that a config requires for the container image with the
/// SHA-256 `digest`: a run of a GitHub Actions workflow of a repository.
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
    /// The ref that the workflow ran at, where `*` stands for any run of
    /// characters other than `/`.
    pub git_ref: String,
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
        ] = GITHUB_KEYS.map(|key| github?.get(key)?.as_str())
        else {
            return Err(EndorsementError::new(format!(
                "containers[{index}].provenance must hold only github, with only the strings repository, repository_id, workflow and ref"
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
        });
    }
    Ok(required)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_states_the_builds_that_its_containers_require() {
        const IMAGE_NAME: &str = r#""ghcr.io/tinfoilsh/inference-vllm"#;
        const GITHUB: &str = r#"{"repository":"tinfoilsh/inference","repository_id":"902195777","workflow":"containers.yml","ref":"refs/tags/vllm-v*"}"#;
        const UNCONSTRAINED: &str = r#"{"name":"router","image":"example.com/router:latest"}"#;
        let (digest, other) = ("ab".repeat(32), "cd".repeat(32));
        let image = format!(r#"{IMAGE_NAME}@sha256:{digest}""#);
        let provenance = format!(r#"{{"github":{GITHUB}}}"#);
        let container = |image: &str, provenance: &str| {
            format!(r#"{{"name":"model","image":{image},"provenance":{provenance}}}"#)
        };
        let config =
            |containers: &str| format!(r#"{{"cvm-version":"0.15.5","containers":{containers}}}"#);
        let requiring =
            |image: &str, provenance: &str| config(&format!("[{}]", container(image, provenance)));
        let edited = |old: &str, new: &str| {
            let github = GITHUB.replacen(old, new, 1);
            requiring(&image, &format!(r#"{{"github":{github}}}"#))
        };
        let required = |digest: &str| ContainerProvenance {
            digest: digest.to_owned(),
            repository: "tinfoilsh/inference".to_owned(),
            repository_id: "902195777".to_owned(),
            workflow: "containers.yml".to_owned(),
            git_ref: "refs/tags/vllm-v*".to_owned(),
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
                requiring(&image, &format!(r#"{{"gitlab":{GITHUB}}}"#)),
            ),
            (
                "second kind",
                requiring(&image, &format!(r#"{{"github":{GITHUB},"gitlab":{{}}}}"#)),
            ),
            (
                "kind in another case",
                requiring(&image, &format!(r#"{{"GitHub":{GITHUB}}}"#)),
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
                edited(r#","ref":"refs/tags/vllm-v*""#, ""),
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
                edited(r#""refs/tags/vllm-v*""#, "null"),
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
