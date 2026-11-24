//! The trust argument of an enclave client.

use std::fmt;

use crate::error::Error;
use crate::verifier::{ConfigAuthorizer, ConfigTrust, EmbeddedConfig, Pin, PublicKey};

/// Who vouches for the config that an enclave runs: the required argument
/// of an [`EnclaveHttpClient`](crate::EnclaveHttpClient).
///
/// There is no empty variant, so that a client cannot be built without
/// naming what it trusts. Only [`RepoPin`](Self::RepoPin) and
/// [`EitherPin`](Self::EitherPin) accept `attestation-collaterals/v2`
/// collateral; every other variant requires `attestation-collaterals/v3`
/// collateral.
///
/// ```
/// use tinfoil::Trust;
///
/// let repo = Trust::repo("owner/name");
/// let project = Trust::project("org/project@v1");
/// let either = Trust::EitherPin {
///     repo: "owner/name".into(),
///     project: "org/project".into(),
/// };
/// # let _ = (repo, project, either);
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub enum Trust {
    /// `attestation-collaterals/v2` collateral for a GitHub repository.
    RepoPin {
        /// The repository, `owner/name[@tag][@sha256:digest]`. It must not
        /// be empty.
        repo: String,
    },
    /// `attestation-collaterals/v3` collateral for a config registry
    /// project, endorsed by one of the trusted registries.
    ProjectPin {
        /// The project, `org/project[@revision][@sha256:digest]`. It must
        /// not be empty.
        project: String,
        /// The trusted registries. `None` trusts Tinfoil's public registry
        /// alone. A list trusts exactly the registries that it names, in
        /// place of the public registry: to trust a private registry
        /// alongside the public one, list
        /// [`PUBLIC_REGISTRY_ID`](crate::verifier::PUBLIC_REGISTRY_ID) too.
        /// An empty list is a configuration error, so that an empty list
        /// that the application computed fails closed rather than
        /// widening trust to the public registry.
        registry_ids: Option<Vec<String>>,
    },
    /// `attestation-collaterals/v3` configs whose endorsements the
    /// caller's keys sign, in place of Tinfoil's registry root.
    SignedBy {
        /// The keys. The list must not be empty.
        keys: Vec<PublicKey>,
        /// A config registry project,
        /// `org/project[@revision][@sha256:digest]`, that restricts the
        /// configs that are accepted. `None` accepts any config that the
        /// keys sign.
        project: Option<String>,
    },
    /// `attestation-collaterals/v3` configs that the caller's function
    /// authorizes, in place of a registry endorsement. The function
    /// receives untrusted material from the document and must return an
    /// error for config bytes that it does not authorize; it may be called
    /// from several threads at once. Runtime, platform and hardware checks
    /// still apply. An authorized config has no authenticated registry
    /// name or approval time, so this variant has no pin. The authorized
    /// bytes must be a JSON config; any other bytes are rejected, such as
    /// the YAML config that earlier enclave versions take.
    AuthorizedBy(ConfigAuthorizer),
    /// `attestation-collaterals/v3` collateral for exactly the config bytes
    /// that the caller supplies, which must come from trusted client
    /// configuration. It has no pin, because a pin would only compare the
    /// caller's input with the caller's input.
    EmbeddedConfig {
        /// The `/org/project/revision` identity that the caller associates
        /// with the config.
        name: Option<String>,
        /// The config, 1 byte to 1 MiB. It is a JSON config; the YAML
        /// config that earlier enclave versions take is a configuration
        /// error.
        bytes: Vec<u8>,
    },
    /// `attestation-collaterals/v2` collateral for `repo` or
    /// `attestation-collaterals/v3` collateral for `project`, as
    /// [`RepoPin`](Self::RepoPin) and [`ProjectPin`](Self::ProjectPin)
    /// accept them. Neither may be empty. It exists for the migration from
    /// v2 to v3 collateral and will be removed with v2.
    EitherPin {
        /// The repository, as in [`RepoPin`](Self::RepoPin).
        repo: String,
        /// The project, as in [`ProjectPin`](Self::ProjectPin), under the
        /// public registry.
        project: String,
    },
}

impl fmt::Debug for Trust {
    /// The variant and its names. The bytes of an embedded config are not
    /// printed, only their length, and keys are counted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Trust::RepoPin { repo } => f.debug_struct("RepoPin").field("repo", repo).finish(),
            Trust::ProjectPin {
                project,
                registry_ids,
            } => f
                .debug_struct("ProjectPin")
                .field("project", project)
                .field("registry_ids", registry_ids)
                .finish(),
            Trust::SignedBy { keys, project } => f
                .debug_struct("SignedBy")
                .field("keys", &keys.len())
                .field("project", project)
                .finish(),
            Trust::AuthorizedBy(_) => f.write_str("AuthorizedBy"),
            Trust::EmbeddedConfig { name, bytes } => f
                .debug_struct("EmbeddedConfig")
                .field("name", name)
                .field("bytes", &format_args!("[{} bytes]", bytes.len()))
                .finish(),
            Trust::EitherPin { repo, project } => f
                .debug_struct("EitherPin")
                .field("repo", repo)
                .field("project", project)
                .finish(),
        }
    }
}

impl Trust {
    /// [`Trust::RepoPin`] for `repo`.
    pub fn repo(repo: impl Into<String>) -> Self {
        Trust::RepoPin { repo: repo.into() }
    }

    /// [`Trust::ProjectPin`] for `project` under Tinfoil's public registry.
    pub fn project(project: impl Into<String>) -> Self {
        Trust::ProjectPin {
            project: project.into(),
            registry_ids: None,
        }
    }

    /// The verifier's config trust and the pin that each verification is
    /// made against. It checks only what the variant itself requires; the
    /// verifier checks the values when it is built and when it checks the
    /// pin.
    pub(crate) fn verifier_inputs(&self) -> Result<(ConfigTrust, Pin), Error> {
        let required = |value: &str, message: &'static str| {
            if value.is_empty() {
                Err(Error::configuration(message))
            } else {
                Ok(())
            }
        };
        Ok(match self {
            Trust::RepoPin { repo } => {
                required(repo, "Trust::RepoPin requires a repository")?;
                (ConfigTrust::PublicRegistry, Pin::repo(repo.as_str()))
            }
            Trust::ProjectPin {
                project,
                registry_ids,
            } => {
                required(project, "Trust::ProjectPin requires a project")?;
                let pin = Pin::project(project.as_str());
                match registry_ids {
                    None => (ConfigTrust::PublicRegistry, pin),
                    Some(ids) if ids.is_empty() => {
                        return Err(Error::configuration(
                            "the registry IDs of Trust::ProjectPin must not be empty; leave them None to trust the public registry",
                        ));
                    }
                    Some(ids) => (ConfigTrust::Registries(ids.clone()), pin),
                }
            }
            Trust::SignedBy { keys, project } => (
                ConfigTrust::SigningKeys(keys.clone()),
                Pin {
                    repo: None,
                    project: project.clone(),
                },
            ),
            Trust::AuthorizedBy(authorizer) => {
                (ConfigTrust::Authorizer(authorizer.clone()), Pin::none())
            }
            Trust::EmbeddedConfig { name, bytes } => (
                ConfigTrust::Embedded(EmbeddedConfig::Bytes {
                    bytes: bytes.clone(),
                    name: name.clone(),
                }),
                Pin::none(),
            ),
            Trust::EitherPin { repo, project } => {
                if repo.is_empty() || project.is_empty() {
                    return Err(Error::configuration(
                        "Trust::EitherPin requires both a repository and a project",
                    ));
                }
                (
                    ConfigTrust::PublicRegistry,
                    Pin::repo(repo.as_str()).with_project(project.as_str()),
                )
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::verifier::PUBLIC_REGISTRY_ID;

    fn refused(trust: Trust) -> String {
        let error = trust.verifier_inputs().expect_err("refused");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        error.to_string()
    }

    #[test]
    fn debug_output_shows_no_config_bytes() {
        let trust = Trust::EmbeddedConfig {
            name: Some("/org/project/v1".into()),
            bytes: br#"{"cvm-version":"secret-config"}"#.to_vec(),
        };
        let printed = format!("{trust:?}");
        assert!(!printed.contains("secret-config"), "{printed}");
        assert!(printed.contains("[31 bytes]"), "{printed}");
        assert!(printed.contains("/org/project/v1"), "{printed}");
    }

    #[test]
    fn a_variant_without_its_required_fields_is_refused() {
        assert!(refused(Trust::repo("")).contains("requires a repository"));
        assert!(refused(Trust::project("")).contains("requires a project"));
        for (repo, project) in [("", "org/project"), ("owner/name", ""), ("", "")] {
            let message = refused(Trust::EitherPin {
                repo: repo.into(),
                project: project.into(),
            });
            assert!(
                message.contains("both a repository and a project"),
                "{message}"
            );
        }
        let message = refused(Trust::ProjectPin {
            project: "org/project".into(),
            registry_ids: Some(Vec::new()),
        });
        assert!(message.contains("must not be empty"), "{message}");
    }

    #[test]
    fn each_variant_selects_a_config_trust_and_a_pin() {
        let (config, pin) = Trust::repo("owner/name").verifier_inputs().unwrap();
        assert!(matches!(config, ConfigTrust::PublicRegistry));
        assert_eq!(pin, Pin::repo("owner/name"));

        let (config, pin) = Trust::project("org/project").verifier_inputs().unwrap();
        assert!(matches!(config, ConfigTrust::PublicRegistry));
        assert_eq!(pin, Pin::project("org/project"));

        let ids = vec![PUBLIC_REGISTRY_ID.to_owned()];
        let (config, pin) = Trust::ProjectPin {
            project: "org/project".into(),
            registry_ids: Some(ids.clone()),
        }
        .verifier_inputs()
        .unwrap();
        assert!(matches!(config, ConfigTrust::Registries(listed) if listed == ids));
        assert_eq!(pin, Pin::project("org/project"));

        let (config, pin) = Trust::SignedBy {
            keys: Vec::new(),
            project: Some("org/project".into()),
        }
        .verifier_inputs()
        .unwrap();
        assert!(matches!(config, ConfigTrust::SigningKeys(_)));
        assert_eq!(pin, Pin::project("org/project"));

        let (config, pin) = Trust::AuthorizedBy(ConfigAuthorizer::new(|_| Ok(())))
            .verifier_inputs()
            .unwrap();
        assert!(matches!(config, ConfigTrust::Authorizer(_)));
        assert_eq!(pin, Pin::none());

        let (config, pin) = Trust::EmbeddedConfig {
            name: None,
            bytes: b"config".to_vec(),
        }
        .verifier_inputs()
        .unwrap();
        assert!(matches!(
            config,
            ConfigTrust::Embedded(EmbeddedConfig::Bytes { .. })
        ));
        assert_eq!(pin, Pin::none());

        let (config, pin) = Trust::EitherPin {
            repo: "owner/name".into(),
            project: "org/project".into(),
        }
        .verifier_inputs()
        .unwrap();
        assert!(matches!(config, ConfigTrust::PublicRegistry));
        assert_eq!(pin, Pin::repo("owner/name").with_project("org/project"));
    }
}
