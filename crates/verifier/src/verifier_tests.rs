//! Tests of the verifier's options, of its checks before any document is
//! read, of the classification of errors by layer, and of the record that a
//! verification returns.

use std::error::Error as StdError;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::canonical::encode_lower_hex;
use crate::differential_tests::{Fixture, instant, pin, text};
use crate::document::DocumentError;
use crate::endorsement::EndorsementError;
use crate::error::{BoxError, Error, Layer};
use crate::instant::Instant;
use crate::json;
use crate::measurement::{Expected, Measurement, REGISTER_SIZE, Register};
use crate::quote::{AssemblyError, QuoteError};
use crate::verification::{
    ArtifactVerification, ConfigVerification, ReferenceSource, VerifiedFacts,
};
use crate::verifier::freshness_expiration;
use crate::{
    ArtifactTrust, CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, ConfigAuthorizer,
    ConfigEndorsement, ConfigTrust, CryptoMaterialItem, EmbeddedConfig,
    KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_SPKI_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT,
    PUBLIC_REGISTRY_ID, Pin, Policy, PublicKey, RuntimeReference, Verifier, crypto_material_data,
    parse_reference,
};

const SEVEN_DAYS: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const PRIVATE_REGISTRY: &str =
    "https://registry.tinfoil.sh/scopes/9c4a7f21e0b836d56a13c8fe42d907ab";
const CONFIG_NAME: &str = "/org/project/v1";

fn register(byte: u8) -> Register {
    Register::new([byte; REGISTER_SIZE])
}

/// A runtime manifest, a config that pins it, and a platform policy
/// artifact: references that a caller may embed.
struct Inputs {
    config: Vec<u8>,
    runtime: Vec<u8>,
    platform: Vec<u8>,
}

impl Inputs {
    fn new() -> Self {
        let zero = "00".repeat(REGISTER_SIZE);
        let runtime = format!(
            r#"{{"version":"v0.15.0","igvm":{{"format_version":1,"snp_launch":{{"measurement":"{}"}},"tdx_launch":{{"mrtd":"{}","rtmr0":"{zero}","rtmr1":"{zero}","rtmr2":"{zero}","rtmr3":"{zero}"}}}}}}"#,
            "ab".repeat(REGISTER_SIZE),
            "cd".repeat(REGISTER_SIZE),
        )
        .into_bytes();
        let config = format!(
            "cvm-version: 0.15.0@sha256:{}\n",
            encode_lower_hex(&Sha256::digest(&runtime))
        )
        .into_bytes();
        let platform =
            br#"{"format":"https://tinfoil.sh/predicate/platform-endorsements/v2"}"#.to_vec();
        Self {
            config,
            runtime,
            platform,
        }
    }

    fn config_digest(&self) -> String {
        encode_lower_hex(&Sha256::digest(&self.config))
    }

    fn runtime_reference(&self) -> RuntimeReference {
        RuntimeReference {
            repo: "tinfoilsh/cvmimage".to_owned(),
            tag: "v0.15.0".to_owned(),
            digest: encode_lower_hex(&Sha256::digest(&self.runtime)),
        }
    }

    fn named_config(&self) -> EmbeddedConfig {
        EmbeddedConfig::Bytes {
            bytes: self.config.clone(),
            name: Some(CONFIG_NAME.to_owned()),
        }
    }

    /// The named config, the runtime and the platform, all embedded.
    fn all(&self) -> Options {
        (ConfigTrust::Embedded(self.named_config()), self.artifacts())
    }

    /// A policy that embeds the runtime and the platform.
    fn artifacts(&self) -> Policy {
        embedded_artifacts(Some(&self.runtime), Some(&self.platform), None)
    }
}

/// The two arguments of [`Verifier::new`].
type Options = (ConfigTrust, Policy);

/// Builds the verifier of a pair of arguments.
trait Build {
    fn build(self) -> Result<Verifier, Error>;
}

impl Build for Options {
    fn build(self) -> Result<Verifier, Error> {
        Verifier::new(self.0, self.1)
    }
}

fn defaults() -> Options {
    Options::default()
}

fn config(config: ConfigTrust) -> Options {
    (config, Policy::default())
}

fn policy(policy: Policy) -> Options {
    (ConfigTrust::default(), policy)
}

fn config_keys(keys: Vec<PublicKey>) -> Options {
    config(ConfigTrust::SigningKeys(keys))
}

fn registries(ids: Vec<String>) -> Options {
    config(ConfigTrust::Registries(ids))
}

fn authorizer(
    authorize: impl Fn(&ConfigEndorsement) -> Result<(), BoxError> + Send + Sync + 'static,
) -> Options {
    config(ConfigTrust::Authorizer(ConfigAuthorizer::new(authorize)))
}

/// Endorsed artifacts whose freshness these keys approve.
fn freshness_keys(keys: Vec<PublicKey>) -> Options {
    policy(Policy {
        artifacts: ArtifactTrust::Endorsed {
            freshness_keys: Some(keys),
        },
        ..Policy::default()
    })
}

/// A policy that embeds the artifacts given.
fn embedded_artifacts(
    runtime: Option<&[u8]>,
    platform: Option<&[u8]>,
    freshness_keys: Option<Vec<PublicKey>>,
) -> Policy {
    Policy {
        artifacts: ArtifactTrust::Embedded {
            runtime: runtime.map(<[u8]>::to_vec),
            platform: platform.map(<[u8]>::to_vec),
            freshness_keys,
        },
        ..Policy::default()
    }
}

fn max_age(age: Duration) -> Options {
    policy(Policy {
        freshness_max_age: age,
        ..Policy::default()
    })
}

fn signing_keys() -> Vec<PublicKey> {
    let pem = std::str::from_utf8(crate::trust::TINFOIL_SIGNING_KEY_PEM).unwrap();
    vec![PublicKey::from_pem(pem).unwrap()]
}

fn accept(_: &ConfigEndorsement) -> Result<(), BoxError> {
    Ok(())
}

/// The message of the usage error that `result` must be.
fn usage<T: fmt::Debug>(result: Result<T, Error>) -> String {
    match result {
        Err(Error::Usage(error)) => error.to_string(),
        other => panic!("want a usage error, got {other:?}"),
    }
}

#[test]
fn the_default_verifier_loads_the_embedded_trust() {
    for verifier in [defaults().build().unwrap(), Verifier::default()] {
        assert!(
            verifier.trust.is_ok(),
            "{:?}",
            verifier.trust.as_ref().err()
        );
        assert_eq!(verifier.freshness_max_age(), SEVEN_DAYS);
        assert_eq!(verifier.pinned_registers(), None);
    }
}

#[test]
fn a_verifier_is_shared_between_threads() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Verifier>();
    assert_send_sync::<VerifiedFacts>();
    assert_send_sync::<crate::VerificationReport>();
    assert_send_sync::<ConfigTrust>();
    assert_send_sync::<Policy>();
}

#[test]
fn a_zero_freshness_bound_keeps_the_default() {
    // An unset policy value must not disable the bound.
    let verifier = max_age(Duration::ZERO).build().unwrap();
    assert_eq!(verifier.freshness_max_age(), SEVEN_DAYS);
    let day = Duration::from_secs(24 * 60 * 60);
    let verifier = max_age(day).build().unwrap();
    assert_eq!(verifier.freshness_max_age(), day);
    let nanosecond = Duration::from_nanos(1);
    let verifier = max_age(nanosecond).build().unwrap();
    assert_eq!(verifier.freshness_max_age(), nanosecond);
}

#[test]
fn a_freshness_bound_beyond_292_years_is_a_usage_error() {
    let longest = Duration::from_nanos(u64::try_from(i64::MAX).unwrap());
    let verifier = max_age(longest).build().unwrap();
    assert_eq!(verifier.freshness_max_age(), longest);
    for age in [longest + Duration::from_nanos(1), Duration::MAX] {
        let message = usage(max_age(age).build());
        assert!(message.contains("out of range"), "{message}");
    }
}

#[test]
fn pinned_registers_are_read_back() {
    let pins = Expected::Tdx {
        mrtd: None,
        rtmr0: None,
        rtmr1: None,
        rtmr2: None,
        rtmr3: Some(register(0xab)),
    };
    let verifier = policy(Policy {
        pinned_registers: Some(pins.clone()),
        ..Policy::default()
    })
    .build()
    .unwrap();
    assert_eq!(verifier.pinned_registers(), Some(&pins));
}

#[test]
fn key_and_registry_options_refuse_empty_and_malformed_values() {
    let cases: Vec<(Options, &str)> = vec![
        (
            config_keys(Vec::new()),
            "config signing keys must not be empty",
        ),
        (
            freshness_keys(Vec::new()),
            "freshness signing keys must not be empty",
        ),
        (registries(Vec::new()), "must not be empty"),
        (registries(vec![String::new()]), "canonical registry URI"),
        (
            registries(vec![PRIVATE_REGISTRY.to_uppercase()]),
            "canonical registry URI",
        ),
        (
            registries(vec![
                PRIVATE_REGISTRY.to_owned(),
                PRIVATE_REGISTRY.to_owned(),
            ]),
            "duplicate config registry ID",
        ),
        (
            config_keys([signing_keys(), signing_keys()].concat()),
            "duplicate signing key",
        ),
        (
            freshness_keys([signing_keys(), signing_keys()].concat()),
            "duplicate signing key",
        ),
    ];
    for (builder, want) in cases {
        let message = usage(builder.build());
        assert!(message.contains(want), "{message}: want {want}");
    }
    let both = vec![PUBLIC_REGISTRY_ID.to_owned(), PRIVATE_REGISTRY.to_owned()];
    registries(both).build().unwrap();
}

#[test]
fn only_ecdsa_p256_keys_sign_approvals() {
    // The Intel root's key is on P-256 and the AMD keys are RSA; both parse
    // as public keys, and only the former can be pinned.
    let spki = |pem: &[u8]| {
        let block = crate::x509::pem_blocks(pem).unwrap().remove(0);
        crate::x509::Certificate::from_der(&block.contents)
            .unwrap()
            .spki_der()
            .unwrap()
    };
    let p256 = PublicKey::from_spki_der(&spki(crate::trust::INTEL_SGX_ROOT_CA_PEM)).unwrap();
    let rsa = PublicKey::from_spki_der(&spki(crate::trust::AMD_GENOA_CERT_CHAIN_PEM)).unwrap();
    freshness_keys(vec![p256.clone()]).build().unwrap();
    config_keys(vec![p256]).build().unwrap();
    usage(config_keys(vec![rsa.clone()]).build());
    usage(freshness_keys(vec![rsa]).build());
}

#[test]
fn a_public_key_parses_from_pem_and_from_der() {
    let pem = std::str::from_utf8(crate::trust::TINFOIL_SIGNING_KEY_PEM).unwrap();
    let key = PublicKey::from_pem(pem).unwrap();
    let der = key.to_spki_der();
    assert_eq!(PublicKey::from_spki_der(&der).unwrap(), key);
    assert_eq!(format!("{key:?}"), "PublicKey(EcdsaP256)");

    usage(PublicKey::from_pem(""));
    usage(PublicKey::from_pem("not a key"));
    usage(PublicKey::from_pem(&format!("{pem}{pem}")));
    usage(PublicKey::from_spki_der(&[]));
    let mut trailing = der.clone();
    trailing.push(0);
    usage(PublicKey::from_spki_der(&trailing));
    usage(PublicKey::from_spki_der(&der[..der.len() - 1]));
}

#[test]
fn embedded_artifacts_need_an_artifact_and_leave_one_for_freshness_keys() {
    let inputs = Inputs::new();
    let refused = [
        (
            embedded_artifacts(None, None, None),
            "embedded artifacts must contain a runtime or a platform",
        ),
        (
            embedded_artifacts(
                Some(&inputs.runtime),
                Some(&inputs.platform),
                Some(signing_keys()),
            ),
            "freshness signing keys have no endorsed artifact to verify",
        ),
        (
            embedded_artifacts(Some(&inputs.runtime), None, Some(Vec::new())),
            "freshness signing keys must not be empty",
        ),
    ];
    for (refused, want) in refused {
        assert_eq!(
            usage(policy(refused).build()),
            format!("usage error: {want}")
        );
    }

    // Each source of config trust goes with any artifact trust.
    let accepted = [
        (ConfigTrust::SigningKeys(signing_keys()), inputs.artifacts()),
        (
            ConfigTrust::Authorizer(ConfigAuthorizer::new(accept)),
            inputs.artifacts(),
        ),
        (
            ConfigTrust::Registries(vec![PRIVATE_REGISTRY.to_owned()]),
            inputs.artifacts(),
        ),
        (
            ConfigTrust::default(),
            embedded_artifacts(Some(&inputs.runtime), None, Some(signing_keys())),
        ),
        (
            ConfigTrust::SigningKeys(signing_keys()),
            freshness_keys(signing_keys()).1,
        ),
    ];
    for options in accepted {
        options.build().unwrap();
    }
}

#[test]
fn the_policy_is_checked_before_the_config_trust() {
    let message = usage(
        (
            ConfigTrust::SigningKeys(Vec::new()),
            freshness_keys(Vec::new()).1,
        )
            .build(),
    );
    assert_eq!(
        message,
        "usage error: freshness signing keys must not be empty"
    );
    let message = usage(
        (
            ConfigTrust::Registries(Vec::new()),
            embedded_artifacts(None, None, None),
        )
            .build(),
    );
    assert!(message.contains("runtime or a platform"), "{message}");
}

#[test]
fn embedded_references_are_checked_when_the_verifier_is_built() {
    let inputs = Inputs::new();
    let only = |config: Option<EmbeddedConfig>, runtime: Option<&[u8]>, platform: Option<&[u8]>| {
        let config = config.map_or_else(ConfigTrust::default, ConfigTrust::Embedded);
        let policy = if runtime.is_some() || platform.is_some() {
            embedded_artifacts(runtime, platform, None)
        } else {
            Policy::default()
        };
        (config, policy)
    };
    let bytes = |bytes: &[u8], name: Option<&str>| {
        Some(EmbeddedConfig::Bytes {
            bytes: bytes.to_vec(),
            name: name.map(str::to_owned),
        })
    };
    let reference = |digest: &str, runtime: RuntimeReference| {
        Some(EmbeddedConfig::Reference {
            digest: digest.to_owned(),
            runtime,
            name: None,
        })
    };
    let pinned = inputs.runtime_reference();
    let mut newline = inputs.runtime.clone();
    newline.push(b'\n');
    let short_version = String::from_utf8(inputs.runtime.clone())
        .unwrap()
        .replace("v0.15.0", "v0.15");
    let refused: Vec<(Options, &str)> = vec![
        (only(bytes(b"", None), None, None), "outside allowed bounds"),
        (
            only(bytes(&vec![b'a'; (1 << 20) + 1], None), None, None),
            "outside allowed bounds",
        ),
        (only(bytes(b"a: b\n", None), None, None), "cvm-version"),
        (
            only(bytes(&inputs.config, Some("/invalid")), None, None),
            "config",
        ),
        (
            only(bytes(&inputs.config, Some("")), None, None),
            "config name has no revision",
        ),
        (
            only(reference("", pinned.clone()), None, None),
            "config digest",
        ),
        (
            only(
                reference(&inputs.config_digest().to_uppercase(), pinned.clone()),
                None,
                None,
            ),
            "config digest",
        ),
        (
            only(
                reference(
                    &inputs.config_digest(),
                    RuntimeReference {
                        repo: "other/repo".to_owned(),
                        ..pinned.clone()
                    },
                ),
                None,
                None,
            ),
            "runtime repository",
        ),
        (
            only(
                reference(
                    &inputs.config_digest(),
                    RuntimeReference {
                        tag: "v0.15".to_owned(),
                        ..pinned.clone()
                    },
                ),
                None,
                None,
            ),
            "full semantic version",
        ),
        // Both come from the caller, so a manifest that the config does not
        // pin is the caller's mistake.
        (
            only(
                reference(
                    &inputs.config_digest(),
                    RuntimeReference {
                        digest: "cd".repeat(32),
                        ..pinned.clone()
                    },
                ),
                Some(&inputs.runtime),
                None,
            ),
            "config's digest pin",
        ),
        (
            only(bytes(&inputs.config, None), Some(&newline), None),
            "config's digest pin",
        ),
        (only(None, Some(b""), None), "outside allowed bounds"),
        (only(None, Some(b"{}"), None), "runtime manifest"),
        // A manifest that no config can pin.
        (
            only(None, Some(short_version.as_bytes()), None),
            "full semantic version",
        ),
        (only(None, None, Some(b"")), "policy artifact"),
        (
            only(None, None, Some(br#"{"format":"unknown"}"#)),
            "unsupported artifact format",
        ),
        (
            only(
                None,
                None,
                Some(br#"{"format":"https://tinfoil.sh/predicate/platform-endorsements/v1"}"#),
            ),
            "embedded platform requires platform-endorsements/v2",
        ),
    ];
    for (references, want) in refused {
        let message = usage(references.build());
        assert!(message.contains(want), "{message}: want {want}");
    }

    let accepted = [
        inputs.all(),
        policy(inputs.artifacts()),
        only(bytes(&inputs.config, None), None, None),
        only(
            reference(&inputs.config_digest(), pinned.clone()),
            None,
            None,
        ),
        only(
            reference(&inputs.config_digest(), pinned),
            Some(&inputs.runtime),
            None,
        ),
        only(None, Some(&inputs.runtime), None),
        only(None, None, Some(&inputs.platform)),
    ];
    for references in accepted {
        references.build().unwrap();
    }
}

#[test]
fn a_project_pin_is_checked_without_a_document() {
    let inputs = Inputs::new();
    let digest = inputs.config_digest();
    let other_digest = "ab".repeat(32);
    let embedded = || inputs.all();
    let unnamed = || {
        (
            ConfigTrust::Embedded(EmbeddedConfig::Bytes {
                bytes: inputs.config.clone(),
                name: None,
            }),
            inputs.artifacts(),
        )
    };
    let reference = || {
        config(ConfigTrust::Embedded(EmbeddedConfig::Reference {
            digest: digest.clone(),
            runtime: inputs.runtime_reference(),
            name: Some(CONFIG_NAME.to_owned()),
        }))
    };
    let authorizer = || authorizer(accept);
    let with_digest = format!("org/project@v1@sha256:{digest}");
    let digest_only = format!("org/project@sha256:{digest}");
    let wrong_digest = format!("org/project@sha256:{other_digest}");
    let cases: Vec<(&str, Options, &str, bool)> = vec![
        ("defaults with a pin", defaults(), "org/repo@v1", true),
        // v2 collateral accepts it, so the check waits for the document.
        (
            "defaults with a mixed-case pin",
            defaults(),
            "Org/My_Repo",
            true,
        ),
        ("defaults without a pin", defaults(), "", false),
        (
            "defaults with a malformed pin",
            defaults(),
            "not a reference",
            false,
        ),
        (
            "defaults with two tags",
            defaults(),
            "org/project@v1@v2",
            false,
        ),
        (
            "defaults with a bad digest",
            defaults(),
            "org/project@sha256:bad",
            false,
        ),
        ("embedded config without a pin", embedded(), "", true),
        (
            "embedded config with its repository",
            embedded(),
            "org/project",
            true,
        ),
        (
            "embedded config with its revision",
            embedded(),
            "org/project@v1",
            true,
        ),
        (
            "embedded config with its digest",
            embedded(),
            &with_digest,
            true,
        ),
        (
            "embedded config with its digest alone",
            embedded(),
            &digest_only,
            true,
        ),
        (
            "embedded config with another repository",
            embedded(),
            "org/repo",
            false,
        ),
        (
            "embedded config with another revision",
            embedded(),
            "org/project@v2",
            false,
        ),
        (
            "embedded config with another digest",
            embedded(),
            &wrong_digest,
            false,
        ),
        (
            "embedded config with a malformed pin",
            embedded(),
            "not a reference",
            false,
        ),
        ("unnamed embedded config without a pin", unnamed(), "", true),
        (
            "unnamed embedded config with a pin",
            unnamed(),
            "org/project",
            false,
        ),
        ("embedded reference without a pin", reference(), "", true),
        (
            "embedded reference with its digest",
            reference(),
            &with_digest,
            true,
        ),
        (
            "embedded reference with another revision",
            reference(),
            "org/project@v2",
            false,
        ),
        (
            "embedded reference with another digest",
            reference(),
            &wrong_digest,
            false,
        ),
        ("config authorizer without a pin", authorizer(), "", true),
        (
            "config authorizer with a pin",
            authorizer(),
            "org/repo",
            false,
        ),
        (
            "config authorizer with a malformed pin",
            authorizer(),
            "not a reference",
            false,
        ),
    ];
    // In this table an empty text stands for no pin.
    for (name, builder, project, valid) in cases {
        let verifier = builder.build().unwrap();
        let pin = if project.is_empty() {
            Pin::none()
        } else {
            Pin::project(project)
        };
        let result = verifier.check_pin_verifiability(&pin);
        if valid {
            result.unwrap_or_else(|error| panic!("{name}: {error}"));
        } else {
            usage(result);
        }
    }
    // An empty pin is refused whatever the verifier; only `None` sets no
    // pin.
    for builder in [defaults(), embedded(), authorizer()] {
        let verifier = builder.build().unwrap();
        let message = usage(verifier.check_pin_verifiability(&Pin::repo("")));
        assert!(message.contains("repository pin is empty"), "{message}");
        let message = usage(verifier.check_pin_verifiability(&Pin::project("")));
        assert!(message.contains("project pin is empty"), "{message}");
    }
}

#[test]
fn a_repository_pin_alone_is_refused_where_only_registry_collateral_is_verified() {
    const REGISTRY_ONLY: &str = "registry collateral only";
    let inputs = Inputs::new();
    let repo = Pin::repo("org/project");
    let project = Pin::project("org/project");
    let both = Pin::repo("Owner/My_Repo").with_project("org/project");

    let defaults = Verifier::default();
    for pin in [&repo, &project, &both] {
        defaults.check_pin_verifiability(pin).unwrap();
    }
    // Either part is checked for its form, whatever the other holds.
    for malformed in [
        Pin::repo("not a reference"),
        Pin::project("not a reference"),
        Pin::repo("not a reference").with_project("org/project"),
        Pin::repo("org/project").with_project("not a reference"),
    ] {
        usage(defaults.check_pin_verifiability(&malformed));
    }

    for (name, builder) in [
        ("embedded references", inputs.all()),
        ("embedded artifacts", policy(inputs.artifacts())),
        ("config signing keys", config_keys(signing_keys())),
        ("freshness signing keys", freshness_keys(signing_keys())),
        (
            "registry IDs",
            registries(vec![PRIVATE_REGISTRY.to_owned()]),
        ),
    ] {
        let verifier = builder.build().unwrap();
        let message = usage(verifier.check_pin_verifiability(&repo));
        assert!(message.contains(REGISTRY_ONLY), "{name}: {message}");
        for pin in [&project, &both] {
            verifier
                .check_pin_verifiability(pin)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    // A config authorizer authenticates neither part.
    let authorizer = authorizer(accept).build().unwrap();
    let message = usage(authorizer.check_pin_verifiability(&repo));
    assert!(message.contains(REGISTRY_ONLY), "{message}");
    usage(authorizer.check_pin_verifiability(&project));
    usage(authorizer.check_pin_verifiability(&both));
    authorizer.check_pin_verifiability(&Pin::none()).unwrap();
}

#[test]
fn the_collateral_of_the_document_selects_the_part_of_the_pin() {
    const REPOSITORY_ONLY: &str =
        "document carries config registry collateral, but only a GitHub repository is pinned";
    const NO_REPOSITORY: &str =
        "document carries GitHub repository collateral, but only a registry project is pinned";
    const OTHER: &str = "other/name";

    let fixture = Fixture::load();
    let verify = |name: &str, pin: &Pin| {
        let case = fixture.case(name);
        let verifier = fixture.verifier(case).unwrap();
        let document = fixture.document(text(case, "doc")).unwrap();
        verifier.verify_at(&document, &Fixture::nonce(case), pin, instant(case))
    };
    let rejected = |name: &str, pin: &Pin, want: &str| match verify(name, pin) {
        Err(Error::Verification(rejected)) => {
            assert_eq!(rejected.layer(), Layer::Provenance, "{name} {pin:?}");
            let message = rejected.to_string();
            assert!(message.contains(want), "{name} {pin:?}: {message}");
        }
        other => panic!("{name} {pin:?}: want a rejection, got {other:?}"),
    };
    let accepted = |name: &str, pin: &Pin| {
        verify(name, pin).unwrap_or_else(|error| panic!("{name} {pin:?}: {error}"));
    };

    // Repository collateral, named and unversioned: only the repository
    // part is matched, and a project stands for no repository.
    for name in ["legacy-sev/doc-format-v2", "legacy-sev/default"] {
        let released = text(fixture.case(name), "repo");
        accepted(name, &Pin::repo(released));
        accepted(name, &Pin::repo(released).with_project(OTHER));
        rejected(name, &Pin::project(released), NO_REPOSITORY);
        usage(verify(name, &Pin::none()));
        rejected(
            name,
            &Pin::repo(OTHER).with_project(released),
            "is not the expected workflow",
        );
    }

    // Registry collateral: only the project part is matched, and a
    // repository of the project's name does not stand for it.
    let name = "config-sev/full-same";
    let approved = text(fixture.case(name), "repo");
    accepted(name, &Pin::project(approved));
    accepted(name, &Pin::repo(OTHER).with_project(approved));
    accepted(name, &Pin::none());
    rejected(name, &Pin::repo(approved), REPOSITORY_ONLY);
    rejected(
        name,
        &Pin::repo(approved).with_project(OTHER),
        "does not match the pinned identity",
    );

    // Trust that requires registry collateral says so of a document that
    // carries a code release, with or without a repository.
    let name = "legacy-sev/v3-only-registry";
    let released = text(fixture.case(name), "repo");
    for pin in [Pin::none(), Pin::repo(released)] {
        rejected(name, &pin, "configured trust requires");
    }

    // A malformed part is the caller's mistake whichever collateral the
    // document carries.
    for name in ["legacy-sev/default", "config-sev/full-same"] {
        let named = text(fixture.case(name), "repo");
        for malformed in [
            Pin::repo("not a reference").with_project(named),
            Pin::repo(named).with_project("not a reference"),
        ] {
            usage(verify(name, &malformed));
        }
    }
}

#[test]
fn a_release_reference_is_parsed_into_its_parts() {
    let digest = "ab".repeat(32);
    let reference = parse_reference(&format!("org/project@v1@sha256:{digest}")).unwrap();
    assert_eq!(reference.repo, "org/project");
    assert_eq!(reference.tag.as_deref(), Some("v1"));
    assert_eq!(reference.digest.as_deref(), Some(digest.as_str()));
    let reference = parse_reference("Org/My_Repo").unwrap();
    assert_eq!((reference.tag, reference.digest), (None, None));
    for malformed in [
        "",
        "not a reference",
        "org",
        "org/project@",
        "org/project@v1@v2",
    ] {
        usage(parse_reference(malformed));
    }
}

#[test]
fn arguments_are_checked_before_the_document() {
    let fixture = Fixture::load();
    let case = fixture.case("legacy-sev/default");
    let verifier = fixture.verifier(case).unwrap();
    let document = fixture.document(text(case, "doc")).unwrap();
    let nonce = Fixture::nonce(case);
    let repo = &pin(&fixture, case);
    let at = instant(case).to_system_time().unwrap();
    verifier.verify_v3_at(&document, &nonce, repo, at).unwrap();

    for bad in [&nonce[..31], &[][..], &[nonce.as_slice(), &[0]].concat()] {
        let message = usage(verifier.verify_v3_at(&document, bad, repo, at));
        assert!(message.contains("32 bytes"), "{message}");
        // The nonce is judged before the document is read.
        usage(verifier.verify_v3_at(b"{", bad, repo, at));
    }
    // A time that the verifier cannot represent is the caller's mistake.
    let year_10000 = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    let message = usage(verifier.verify_v3_at(&document, &nonce, repo, year_10000));
    assert!(message.contains("verification time"), "{message}");
    // The repository pin is the caller's too, once the document carries the
    // code that it would be matched against.
    usage(verifier.verify_v3_at(&document, &nonce, &Pin::repo("not a reference"), at));
    // So is a pin that names nothing, under default config trust.
    let message = usage(verifier.verify_v3_at(&document, &nonce, &Pin::none(), at));
    assert!(message.contains("pin names nothing"), "{message}");
    // An empty pin is refused before the nonce and the document are read;
    // only `None` sets no pin.
    for (empty, part) in [
        (Pin::repo(""), "repository pin is empty"),
        (Pin::project(""), "project pin is empty"),
        (
            Pin::repo("owner/name").with_project(""),
            "project pin is empty",
        ),
    ] {
        for result in [
            verifier.verify_v3_at(&document, &nonce, &empty, at),
            verifier.verify_v3_at(b"{", &nonce[..31], &empty, at),
            verifier.verify_v3(b"{", &nonce[..31], &empty),
        ] {
            let message = usage(result);
            assert!(message.contains(part), "{message}");
        }
    }
}

#[test]
fn verify_v3_reads_the_clock_once_and_reports_it() {
    let fixture = Fixture::load();
    let case = fixture.case("legacy-sev/default");
    let verifier = fixture.verifier(case).unwrap();
    let document = fixture.document(text(case, "doc")).unwrap();
    // The recorded witnesses are stale by now, so the clock that is read is
    // not the recorded one.
    let before = SystemTime::now();
    let error = verifier
        .verify_v3(&document, &Fixture::nonce(case), &pin(&fixture, case))
        .unwrap_err();
    assert!(before > instant(case).to_system_time().unwrap());
    let Error::Verification(rejected) = error else {
        panic!("{error}");
    };
    assert_eq!(rejected.layer(), Layer::Provenance);

    let at = instant(case).to_system_time().unwrap();
    let verified = verifier
        .verify_v3_at(&document, &Fixture::nonce(case), &pin(&fixture, case), at)
        .unwrap();
    assert_eq!(verified.metadata().verified_at, at);
    // A rejection reports the same verifier identity.
    assert_eq!(
        rejected.report().metadata().verifier,
        verified.metadata().verifier
    );
    assert_eq!(verified.metadata().verifier.name, "tinfoil-rs");
    assert_eq!(
        verified.metadata().verifier.version,
        env!("CARGO_PKG_VERSION")
    );
}

/// Verifies a recorded case and returns its rejection.
fn rejection(fixture: &Fixture, name: &str) -> crate::VerificationError {
    let case = fixture.case(name);
    let verifier = fixture.verifier(case).unwrap();
    let document = fixture.document(text(case, "doc")).unwrap();
    let result = verifier.verify_at(
        &document,
        &Fixture::nonce(case),
        &pin(fixture, case),
        instant(case),
    );
    match result {
        Err(Error::Verification(rejected)) => rejected,
        other => panic!("{name}: want a rejection, got {other:?}"),
    }
}

#[test]
fn an_internal_error_becomes_a_rejection_of_its_layer_with_the_cause_attached() {
    let fixture = Fixture::load();
    // One recorded case per layer, each failing with a plain error of the
    // module that owns the step.
    let envelope = rejection(&fixture, "legacy-sev/nonce-flipped");
    assert_eq!(envelope.layer(), Layer::Envelope);
    let cause = envelope.source().unwrap();
    assert!(cause.downcast_ref::<DocumentError>().is_some(), "{cause:?}");

    let provenance = rejection(&fixture, "legacy-sev/roots-embedded-sigstore");
    assert_eq!(provenance.layer(), Layer::Provenance);
    let cause = provenance.source().unwrap();
    assert!(
        cause.downcast_ref::<EndorsementError>().is_some(),
        "{cause:?}"
    );

    let quote = rejection(&fixture, "legacy-sev/roots-embedded-vendor");
    assert_eq!(quote.layer(), Layer::Quote);
    let cause = quote.source().unwrap();
    assert!(cause.downcast_ref::<QuoteError>().is_some(), "{cause:?}");

    // Assembly and validation both belong to the policy layer.
    for name in ["legacy-sev/pins-tdx-empty", "legacy-sev/pins-sev-other"] {
        let policy = rejection(&fixture, name);
        assert_eq!(policy.layer(), Layer::Policy, "{name}");
        let cause = policy.source().unwrap();
        assert!(cause.downcast_ref::<AssemblyError>().is_some(), "{cause:?}");
    }

    for (rejected, layer) in [
        (&envelope, "envelope"),
        (&provenance, "provenance"),
        (&quote, "quote"),
    ] {
        let cause = rejected.source().unwrap().to_string();
        assert!(!cause.is_empty());
        assert_eq!(
            rejected.to_string(),
            format!("verification error: {layer}: {cause}")
        );
        // The public error has the same text and the same cause.
        let error = Error::from(crate::VerificationError::new(
            Layer::Policy,
            cause.clone(),
            crate::VerificationReport::rejected_for_test(Layer::Policy, &cause),
        ));
        assert_eq!(error.source().unwrap().to_string(), cause);
    }
}

/// The statuses of a report's steps, in order.
fn statuses(report: &crate::VerificationReport) -> Vec<crate::StepStatus> {
    report.steps().iter().map(|step| step.status).collect()
}

#[test]
fn a_rejection_reports_the_failed_step_and_what_the_steps_before_it_established() {
    use crate::StepStatus::{Failed, NotRun, Passed};

    let fixture = Fixture::load();
    let check = |name: &str, layer: Layer, want: [crate::StepStatus; 4]| {
        let rejected = rejection(&fixture, name);
        assert_eq!(rejected.layer(), layer, "{name}");
        let report = rejected.report();
        assert_eq!(statuses(report), want, "{name}");
        let layers: Vec<Layer> = report.steps().iter().map(|step| step.layer).collect();
        assert_eq!(
            layers,
            [
                Layer::Envelope,
                Layer::Provenance,
                Layer::Quote,
                Layer::Policy
            ]
        );
        let failed = report.failed_step().unwrap();
        assert_eq!(failed.layer, layer, "{name}");
        // The step's message is the error's cause, so the report adds no
        // failure kinds of its own.
        assert_eq!(
            failed.message,
            rejected.source().unwrap().to_string(),
            "{name}"
        );
        assert!(report.verified_facts().is_none(), "{name}");
        rejected
    };

    let envelope = check(
        "legacy-sev/nonce-flipped",
        Layer::Envelope,
        [Failed, NotRun, NotRun, NotRun],
    );
    let partial = envelope.report().partial_facts().unwrap();
    assert_eq!((&partial.expected, &partial.measured), (&None, &None));

    // Provenance failed: the keys that the document claims, and nothing
    // that a reference value would have set.
    let provenance = check(
        "legacy-sev/roots-embedded-sigstore",
        Layer::Provenance,
        [Passed, Failed, NotRun, NotRun],
    );
    let partial = provenance.report().partial_facts().unwrap();
    assert_eq!(partial.expected, None);
    let measured = partial.measured.as_ref().unwrap();
    assert_eq!(measured.cpu, None);
    assert_eq!(
        measured.tls_public_key_fp.as_ref().map(String::len),
        Some(64)
    );
    assert_eq!(
        measured.hpke_public_key_fp.as_ref().map(String::len),
        Some(64)
    );

    // The quote failed: the reference values, but no CPU measurement, which
    // would have come from a quote that did not authenticate.
    let quote = check(
        "legacy-sev/roots-embedded-vendor",
        Layer::Quote,
        [Passed, Passed, Failed, NotRun],
    );
    let partial = quote.report().partial_facts().unwrap();
    let expected = partial.expected.as_ref().unwrap();
    assert!(!expected.artifact.digest.is_empty());
    assert_eq!(expected.artifact.source, ReferenceSource::Endorsement);
    assert_eq!(
        expected.artifact.repo.as_deref(),
        Some(expected.config_repo.as_str())
    );
    assert_eq!(expected.artifact.approval_time, None);
    assert_eq!((&expected.config, &expected.platform), (&None, &None));
    assert!(matches!(
        expected.code_measurement,
        Some(Expected::SevSnp { launch: Some(_) })
    ));
    assert_eq!(expected.measurement, None);
    assert_eq!(partial.measured.as_ref().unwrap().cpu, None);

    // A policy that fails after it resolved every register shows both sides
    // of the comparison: here a pin on RTMR3 that the quote does not show.
    // For a code release on TDX, the expectation holds the platform
    // registers that the policy artifact supplies for the quote's machine.
    let compared = check(
        "legacy-tdx/pins-tdx-rtmr3-other",
        Layer::Policy,
        [Passed, Passed, Passed, Failed],
    );
    let partial = compared.report().partial_facts().unwrap();
    let expected = partial.expected.as_ref().unwrap();
    let Some(Expected::Tdx {
        mrtd: None,
        rtmr0: None,
        rtmr1: Some(code_rtmr1),
        ..
    }) = expected.code_measurement
    else {
        panic!("the release fixes RTMR1 and RTMR2: {expected:?}");
    };
    let Some(Measurement::Tdx {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr3,
        ..
    }) = expected.measurement
    else {
        panic!("the policy step resolved the expectation: {expected:?}");
    };
    let cpu = partial.measured.as_ref().unwrap().cpu.as_ref().unwrap();
    let Measurement::Tdx {
        mrtd: cpu_mrtd,
        rtmr0: cpu_rtmr0,
        rtmr3: cpu_rtmr3,
        ..
    } = cpu.measurement
    else {
        panic!("{cpu:?}");
    };
    assert_eq!((mrtd, rtmr0), (cpu_mrtd, cpu_rtmr0));
    assert_eq!(rtmr1, code_rtmr1);
    assert_ne!(rtmr3, cpu_rtmr3);

    // One that fails before resolving them has no expected measurement.
    let unresolved = check(
        "legacy-sev/pins-tdx-empty",
        Layer::Policy,
        [Passed, Passed, Passed, Failed],
    );
    let partial = unresolved.report().partial_facts().unwrap();
    assert_eq!(partial.expected.as_ref().unwrap().measurement, None);
    assert!(partial.measured.as_ref().unwrap().cpu.is_some());
}

#[test]
fn an_accepted_document_reports_every_step_and_the_verified_facts() {
    use crate::StepStatus::{Passed, Skipped};

    let fixture = Fixture::load();
    for (name, provenance) in [
        ("legacy-sev/default", Passed),
        ("legacy-tdx/default", Passed),
        ("config-sev/full-same", Passed),
        // Nothing to authenticate when every reference value is embedded.
        ("config-tdx/embedded-all", Skipped),
    ] {
        let case = fixture.case(name);
        let verifier = fixture.verifier(case).unwrap();
        let document = fixture.document(text(case, "doc")).unwrap();
        let report = verifier
            .verify_at(
                &document,
                &Fixture::nonce(case),
                &pin(&fixture, case),
                instant(case),
            )
            .unwrap();
        assert_eq!(
            statuses(&report),
            [Passed, provenance, Passed, Passed],
            "{name}"
        );
        assert_eq!(report.failed_step(), None);
        assert!(report.partial_facts().is_none(), "{name}");
        assert!(report.verified_facts().is_some(), "{name}");
        let skipped = &report.steps()[1];
        assert_eq!(skipped.message.is_empty(), provenance == Passed, "{name}");
    }
}

/// An error type of the caller's own.
#[derive(Debug, PartialEq, Eq)]
struct Refusal(&'static str);

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl StdError for Refusal {}

#[test]
fn a_config_authorizer_never_chooses_the_kind_of_error() {
    let fixture = Fixture::load();
    let case = fixture.case("config-sev/authorizer-accept");
    let document = fixture.document(text(case, "doc")).unwrap();
    let embedded = fixture.verifier(case).unwrap().embedded;
    let artifacts = |(config, policy): Options| {
        let mut verifier = Verifier::with_test_roots(
            config,
            policy,
            fixture.root(text(case, "sigstore")).as_deref(),
            fixture.root(text(case, "amd")),
            None,
        )
        .unwrap();
        verifier.embedded = embedded.clone();
        verifier
    };
    let verify = |verifier: &Verifier| {
        verifier.verify_at(
            &document,
            &Fixture::nonce(case),
            &Pin::none(),
            instant(case),
        )
    };

    // Whatever the authorizer returns, even one of this crate's own usage
    // errors, a refusal is a rejection at the provenance layer with the
    // authorizer's error as the cause of its cause.
    let refuse_plainly = artifacts(authorizer(|_| {
        Err(Box::new(Refusal("config is not authorized")))
    }));
    let Err(Error::Verification(rejected)) = verify(&refuse_plainly) else {
        panic!("want a rejection");
    };
    assert_eq!(rejected.layer(), Layer::Provenance);
    assert_eq!(
        rejected.to_string(),
        "verification error: provenance: authorizing config: config is not authorized"
    );
    let cause = rejected.source().unwrap().source().unwrap();
    assert_eq!(
        cause.downcast_ref::<Refusal>(),
        Some(&Refusal("config is not authorized"))
    );

    let refuse_as_usage = artifacts(authorizer(|_| {
        Err(Box::new(parse_reference("not a reference").unwrap_err()))
    }));
    let Err(Error::Verification(rejected)) = verify(&refuse_as_usage) else {
        panic!("want a rejection");
    };
    assert_eq!(rejected.layer(), Layer::Provenance);
    let cause = rejected.source().unwrap().source().unwrap();
    assert!(matches!(
        cause.downcast_ref::<Error>(),
        Some(Error::Usage(_))
    ));

    let accepting = artifacts(authorizer(accept));
    let report = verify(&accepting).unwrap();
    let verified = report.verified_facts().unwrap();
    let config = verified.config().unwrap();
    assert_eq!(config.source, ReferenceSource::Policy);
    assert_eq!(
        (config.name.as_deref(), config.reference.as_deref()),
        (None, None)
    );
    assert_eq!(
        verified.freshness_expires_at(),
        at("2034-12-30T00:00:00Z").to_system_time()
    );
}

#[test]
fn a_config_authorizer_sees_the_material_of_the_document() {
    use std::sync::{Arc, Mutex};

    let fixture = Fixture::load();
    for (name, signed) in [
        ("config-sev/authorizer-accept", false),
        ("config-sev/endorsed-v1-authorizer-accept", true),
    ] {
        let case = fixture.case(name);
        let document = fixture.document(text(case, "doc")).unwrap();
        let embedded = fixture.verifier(case).unwrap().embedded;
        let seen: Arc<Mutex<Vec<ConfigEndorsement>>> = Arc::default();
        let record = Arc::clone(&seen);
        let (config, policy) = authorizer(move |endorsement| {
            record.lock().unwrap().push(endorsement.clone());
            Ok(())
        });
        let mut verifier = Verifier::with_test_roots(
            config,
            policy,
            fixture.root(text(case, "sigstore")).as_deref(),
            fixture.root(text(case, "amd")),
            None,
        )
        .unwrap();
        verifier.embedded = embedded;
        let verified = verifier
            .verify_at(
                &document,
                &Fixture::nonce(case),
                &Pin::none(),
                instant(case),
            )
            .unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{name}");
        let endorsement = &seen[0];
        assert_eq!(
            encode_lower_hex(&Sha256::digest(endorsement.config())),
            verified.verified_facts().unwrap().config().unwrap().digest
        );
        assert_eq!(endorsement.issuer_certificate_der(), None);
        assert_eq!(endorsement.reference().is_some(), signed, "{name}");
        match endorsement.bundle_json() {
            None => assert!(!signed, "{name}"),
            Some(bundle) => {
                assert!(signed, "{name}");
                // The text is the bundle of the document, as JSON.
                let parsed = json::parse(bundle).unwrap();
                let bundle = parsed.as_object().unwrap();
                assert!(bundle.get("dsseEnvelope").is_some());
                assert!(bundle.get("verificationMaterial").is_some());
                let reference = endorsement.reference().unwrap();
                assert!(reference.starts_with("sha256:"), "{reference}");
            }
        }
    }
}

#[test]
fn the_accepted_registries_are_never_left_open_by_default() {
    // Without a list, a config endorsement of any registry would pass. Only
    // the caller's own config keys, which use no registry, leave it open.
    let public = Some(vec![PUBLIC_REGISTRY_ID.to_owned()]);
    let inputs = Inputs::new();
    for (name, builder) in [
        ("defaults", defaults()),
        ("embedded artifacts", policy(inputs.artifacts())),
        ("freshness keys", freshness_keys(signing_keys())),
        ("authorizer", authorizer(accept)),
        ("embedded config", inputs.all()),
    ] {
        let verifier = builder.build().unwrap();
        assert_eq!(
            verifier.reference_pins("").unwrap().registry_ids,
            public,
            "{name}"
        );
    }
    let listed = vec![PRIVATE_REGISTRY.to_owned()];
    let verifier = registries(listed.clone()).build().unwrap();
    assert_eq!(
        verifier.reference_pins("").unwrap().registry_ids,
        Some(listed)
    );
    let keyed = config_keys(signing_keys()).build().unwrap();
    assert_eq!(keyed.reference_pins("").unwrap().registry_ids, None);

    // End to end: a config endorsement that a private registry certified,
    // under registry roots that would authenticate it, is refused unless
    // the caller lists that registry.
    let fixture = Fixture::load();
    for (name, accepted) in [
        (
            "config-sev/certified-private-with-config-public-only/",
            false,
        ),
        ("config-sev/certified-private-with-config-exclusive/", true),
    ] {
        let case = fixture.case(name);
        let verifier = fixture.verifier(case).unwrap();
        let document = fixture.document(text(case, "doc")).unwrap();
        let result = verifier.verify_at(
            &document,
            &Fixture::nonce(case),
            &Pin::none(),
            instant(case),
        );
        match result {
            Ok(verified) => {
                assert!(accepted, "{name}");
                let registry = verified
                    .verified_facts()
                    .unwrap()
                    .config()
                    .unwrap()
                    .registry_id
                    .as_deref();
                assert_eq!(registry, Some(PRIVATE_REGISTRY));
            }
            Err(Error::Verification(rejected)) => {
                assert!(!accepted, "{name}: {rejected}");
                assert_eq!(rejected.layer(), Layer::Provenance);
                assert!(rejected.to_string().contains("registry"), "{rejected}");
            }
            Err(other) => panic!("{name}: {other}"),
        }
    }
}

#[test]
fn an_embedded_runtime_is_recorded_at_its_release_tag() {
    use crate::endorsement::runtime::release_tag;
    for (version, tag) in [
        ("v0.15.0", "v0.15.0"),
        ("v0.15.0+gpu", "v0.15.0"),
        ("v0.15.0+containers.initrd-1", "v0.15.0"),
        ("v1.2.3-rc.1", "v1.2.3-rc.1"),
        ("v1.2.3-rc.1+build", "v1.2.3-rc.1"),
        ("0.15.0", ""),
        ("", ""),
    ] {
        assert_eq!(release_tag(version), tag, "{version}");
    }
}

fn at(text: &str) -> Instant {
    Instant::parse_rfc3339(text).unwrap()
}

#[test]
fn the_freshness_deadline_follows_the_earliest_authenticated_time() {
    let issued = at("2026-08-06T12:00:00Z");
    let later = at("2026-08-06T13:00:00Z");
    let hour = Duration::from_secs(60 * 60);
    let cases: [(&str, &[Option<Instant>]); 9] = [
        ("code first", &[Some(issued), Some(later)]),
        ("platform first", &[Some(later), Some(issued)]),
        ("same time", &[Some(issued), Some(issued)]),
        ("first component embedded", &[None, Some(issued)]),
        ("second component embedded", &[Some(issued), None]),
        ("config oldest", &[Some(issued), Some(later), Some(later)]),
        ("platform oldest", &[Some(later), Some(issued), Some(later)]),
        ("runtime oldest", &[Some(later), Some(later), Some(issued)]),
        ("one approval", &[None, None, Some(issued)]),
    ];
    for (name, times) in cases {
        for max_age in [hour * 24, SEVEN_DAYS, hour * 24 * 30] {
            assert_eq!(
                freshness_expiration(max_age, times).unwrap(),
                Some(issued.checked_add(max_age).unwrap()),
                "{name}"
            );
        }
    }
    // Embedded components add no deadline.
    assert_eq!(freshness_expiration(hour, &[]).unwrap(), None);
    assert_eq!(
        freshness_expiration(hour, &[None, None, None]).unwrap(),
        None
    );
    // A deadline that no instant holds is an error, not an absent deadline.
    let last = at("9999-12-31T23:59:59Z");
    assert!(freshness_expiration(hour, &[Some(last)]).is_err());
}

fn item(id: &str, format: &str, data: &str) -> CryptoMaterialItem {
    CryptoMaterialItem {
        id: id.to_owned(),
        format: format.to_owned(),
        data: data.to_owned(),
    }
}

fn verification(crypto_material: Vec<CryptoMaterialItem>) -> VerifiedFacts {
    VerifiedFacts {
        config_repo: "org/repo".to_owned(),
        code_digest: "aa".repeat(32),
        code_tag: "v1.2.3".to_owned(),
        code_measurement: Expected::Tdx {
            mrtd: None,
            rtmr0: None,
            rtmr1: Some(register(0x33)),
            rtmr2: Some(register(0x44)),
            rtmr3: None,
        },
        config: None,
        runtime: None,
        platform: None,
        enclave_measurement: Measurement::Tdx {
            mrtd: register(0x11),
            rtmr0: register(0x22),
            rtmr1: register(0x33),
            rtmr2: register(0x44),
            rtmr3: register(0),
        },
        crypto_material,
        freshness_expires_at: at("2026-08-13T12:00:00Z").to_system_time(),
    }
}

#[test]
fn endorsed_keys_are_looked_up_by_exact_id_and_format() {
    const FUTURE_FORMAT: &str = "https://example.com/key/future/v1";
    let verified = verification(vec![
        item(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT, "aabb"),
        item("workload", FUTURE_FORMAT, "010203"),
    ]);
    assert_eq!(
        verified.crypto_material_data("workload", FUTURE_FORMAT),
        Some("010203")
    );
    // An item in another format is not the one asked for.
    assert_eq!(
        verified.crypto_material_data("workload", KEY_SPKI_V1_FORMAT),
        None
    );
    assert_eq!(
        verified.crypto_material_data("missing", FUTURE_FORMAT),
        None
    );
    assert_eq!(verified.tls_public_key_fp(), Some("aabb"));
    assert_eq!(verified.hpke_public_key(), None);
    assert_eq!(verified.crypto_material().len(), 2);
    assert_eq!(
        crypto_material_data(verified.crypto_material(), "workload", FUTURE_FORMAT),
        Some("010203")
    );
    assert_eq!(crypto_material_data(&[], "tls", FUTURE_FORMAT), None);

    // A key in another format is not the channel key.
    let other_formats = verification(vec![
        item(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_V1_FORMAT, "aabb"),
        item(CRYPTO_MATERIAL_ID_HPKE, FUTURE_FORMAT, "ccdd"),
        item("other", KEY_X25519_HPKE_V1_FORMAT, "eeff"),
    ]);
    assert_eq!(other_formats.tls_public_key_fp(), None);
    assert_eq!(other_formats.hpke_public_key(), None);
    let both = verification(vec![
        item(CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT, "ccdd"),
        item(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT, "aabb"),
    ]);
    assert_eq!(both.tls_public_key_fp(), Some("aabb"));
    assert_eq!(both.hpke_public_key(), Some("ccdd"));
}

#[test]
fn a_code_release_verification_has_no_config_records() {
    let verified = verification(Vec::new());
    assert_eq!(verified.config(), None);
    assert_eq!(verified.runtime(), None);
    assert_eq!(verified.platform(), None);
    assert_eq!(verified.code_digest(), "aa".repeat(32));
    assert_eq!(verified.code_tag(), "v1.2.3");
    assert_eq!(verified.config_repo(), "org/repo");
    assert_eq!(verified.clone(), verified);
}

#[test]
fn a_code_release_verification_serialises_its_facts() {
    let verified = verification(vec![item(
        CRYPTO_MATERIAL_ID_TLS,
        KEY_SPKI_FP_SHA256_V1_FORMAT,
        "aabb",
    )]);
    let want = [
        r#"{"code_digest":""#,
        &"aa".repeat(32),
        r#"","code_tag":"v1.2.3","config_repo":"org/repo","#,
        r#""code_measurement":{"platform":"tdx","rtmr1":""#,
        &"33".repeat(48),
        r#"","rtmr2":""#,
        &"44".repeat(48),
        r#""},"enclave_measurement":{"platform":"tdx","mrtd":""#,
        &"11".repeat(48),
        r#"","rtmr0":""#,
        &"22".repeat(48),
        r#"","rtmr1":""#,
        &"33".repeat(48),
        r#"","rtmr2":""#,
        &"44".repeat(48),
        r#"","rtmr3":""#,
        &"00".repeat(48),
        r#""},"crypto_material":[{"id":"tls","format":"https://tinfoil.sh/key/spki-fp-sha256/v1","data":"aabb"}],"#,
        r#""freshness_expires_at":"2026-08-13T12:00:00Z"}"#,
    ]
    .concat();
    assert_eq!(verified.to_json(), want);
    json::parse(want.as_bytes()).unwrap();
}

#[test]
fn a_config_verification_serialises_what_was_established() {
    let mut verified = verification(Vec::new());
    verified.code_measurement = Expected::SevSnp {
        launch: Some(register(0xab)),
    };
    verified.enclave_measurement = Measurement::SevSnp {
        launch: register(0xab),
    };
    verified.freshness_expires_at = None;
    verified.config = Some(ConfigVerification {
        source: ReferenceSource::Endorsement,
        name: Some(CONFIG_NAME.to_owned()),
        digest: "cc".repeat(32),
        reference: Some(format!("sha256:{}", "dd".repeat(32))),
        signing_key_hint: Some("hint=".to_owned()),
        approval_time: at("2026-08-06T11:00:00Z").to_system_time(),
        registry_id: Some(PUBLIC_REGISTRY_ID.to_owned()),
        signature_time: at("2026-08-06T11:00:30Z").to_system_time(),
    });
    verified.runtime = Some(ArtifactVerification {
        source: ReferenceSource::Endorsement,
        repo: Some("tinfoilsh/cvmimage".to_owned()),
        tag: Some("v0.15.0".to_owned()),
        digest: "ee".repeat(32),
        name: Some("tinfoil-inference-v0.15.0-manifest.json".to_owned()),
        commit: Some("ab".repeat(20)),
        approval_time: at("2026-08-06T10:00:00Z").to_system_time(),
    });
    verified.platform = Some(ArtifactVerification {
        source: ReferenceSource::Embedded,
        repo: None,
        tag: None,
        digest: "ff".repeat(32),
        name: None,
        commit: None,
        approval_time: None,
    });
    let launch = "ab".repeat(48);
    let want = [
        r#"{"code_digest":""#,
        &"aa".repeat(32),
        r#"","code_tag":"v1.2.3","config_repo":"org/repo","#,
        &format!(r#""code_measurement":{{"platform":"sev-snp","launch":"{launch}"}},"#),
        &format!(r#""enclave_measurement":{{"platform":"sev-snp","launch":"{launch}"}},"#),
        r#""crypto_material":[],"#,
        r#""config":{"source":"endorsement","name":"/org/project/v1","digest":""#,
        &"cc".repeat(32),
        r#"","reference":"sha256:"#,
        &"dd".repeat(32),
        r#"","signing_key_hint":"hint=","approval_time":"2026-08-06T11:00:00Z","#,
        r#""registry_id":"https://registry.tinfoil.sh/scopes/public","signature_time":"2026-08-06T11:00:30Z"},"#,
        r#""runtime":{"source":"endorsement","repo":"tinfoilsh/cvmimage","tag":"v0.15.0","digest":""#,
        &"ee".repeat(32),
        r#"","name":"tinfoil-inference-v0.15.0-manifest.json","commit":""#,
        &"ab".repeat(20),
        r#"","approval_time":"2026-08-06T10:00:00Z"},"#,
        r#""platform":{"source":"embedded","digest":""#,
        &"ff".repeat(32),
        r#""}}"#,
    ]
    .concat();
    assert_eq!(verified.to_json(), want);

    // A config that the caller's authorizer accepted has a digest only, and
    // an open register is left out.
    verified.config = Some(ConfigVerification {
        source: ReferenceSource::Policy,
        name: None,
        digest: "cc".repeat(32),
        reference: None,
        signing_key_hint: None,
        approval_time: None,
        registry_id: None,
        signature_time: None,
    });
    verified.code_measurement = Expected::SevSnp { launch: None };
    let text = verified.to_json();
    assert!(text.contains(&format!(
        r#""config":{{"source":"policy","digest":"{}"}}"#,
        "cc".repeat(32)
    )));
    assert!(text.contains(r#""code_measurement":{"platform":"sev-snp"},"#));
}

#[test]
fn serialised_strings_are_escaped() {
    let mut verified = verification(vec![item(
        "quote\" slash\\ tab\t line\n return\r bell\u{7} é \u{1F512}",
        "f",
        "",
    )]);
    verified.code_tag = "\u{0}\u{1f}\u{7f}".to_owned();
    let text = verified.to_json();
    assert!(text.contains(
        r#""id":"quote\" slash\\ tab\t line\n return\r bell\u0007 é 🔒","format":"f","data":"""#
    ));
    assert!(text.contains("\"code_tag\":\"\\u0000\\u001f\u{7f}\""));
    let parsed = json::parse(text.as_bytes()).unwrap();
    let parsed = parsed.as_object().unwrap();
    assert_eq!(
        parsed.get("code_tag").unwrap().as_str(),
        Some("\u{0}\u{1f}\u{7f}")
    );
}

#[test]
fn the_record_of_a_real_verification_reads_back_as_json() {
    let fixture = Fixture::load();
    for name in [
        "legacy-sev/default",
        "legacy-tdx/default",
        "config-sev/full-same",
        "config-tdx/embedded-all",
    ] {
        let case = fixture.case(name);
        let verifier = fixture.verifier(case).unwrap();
        let document = fixture.document(text(case, "doc")).unwrap();
        let report = verifier
            .verify_at(
                &document,
                &Fixture::nonce(case),
                &pin(&fixture, case),
                instant(case),
            )
            .unwrap();
        let verified = report.verified_facts().unwrap();
        let text = verified.to_json();
        let parsed = json::parse(text.as_bytes()).unwrap();
        let record = parsed.as_object().unwrap();
        let member = |name: &str| record.get(name).and_then(json::Value::as_str);
        assert_eq!(
            member("code_digest"),
            Some(verified.code_digest()),
            "{name}"
        );
        assert_eq!(member("code_tag"), Some(verified.code_tag()));
        assert_eq!(member("config_repo"), Some(verified.config_repo()));
        for (key, present) in [
            ("config", verified.config().is_some()),
            ("runtime", verified.runtime().is_some()),
            ("platform", verified.platform().is_some()),
            (
                "freshness_expires_at",
                verified.freshness_expires_at().is_some(),
            ),
        ] {
            assert_eq!(record.get(key).is_some(), present, "{name}: {key}");
        }
        let names: Vec<&str> = record.iter().map(|(name, _)| name).collect();
        let mut want = vec![
            "code_digest",
            "code_tag",
            "config_repo",
            "code_measurement",
            "enclave_measurement",
            "crypto_material",
        ];
        if verified.config().is_some() {
            want.extend(["config", "runtime", "platform"]);
        }
        if verified.freshness_expires_at().is_some() {
            want.push("freshness_expires_at");
        }
        assert_eq!(names, want, "{name}");

        // The report holds the facts and the metadata.
        let text = report.to_json();
        let parsed = json::parse(text.as_bytes()).unwrap();
        let record = parsed.as_object().unwrap();
        let names: Vec<&str> = record.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["steps", "verified_facts", "metadata"], "{name}");
        assert!(text.contains(&format!(r#""verified_facts":{}"#, verified.to_json())));
    }
}

/// With the `serde` feature, a serialiser produces the text of `to_json`.
#[cfg(feature = "serde")]
mod serde_feature {
    use super::*;

    #[test]
    fn a_verification_serialises_as_its_json_form() {
        let mut verified = verification(vec![item(
            "quote\" tab\t é",
            KEY_SPKI_FP_SHA256_V1_FORMAT,
            "aabb",
        )]);
        assert_eq!(
            serde_json::to_string(&verified).unwrap(),
            verified.to_json()
        );
        verified.freshness_expires_at = None;
        verified.code_measurement = Expected::SevSnp { launch: None };
        assert_eq!(
            serde_json::to_string(&verified).unwrap(),
            verified.to_json()
        );

        // Every character that a JSON string must or might escape.
        let awkward: String = (0..=0x20u8)
            .chain([0x22, 0x2f, 0x5c, 0x7f])
            .map(char::from)
            .chain(['\u{80}', '\u{2028}', '\u{ffff}', '\u{1f600}'])
            .collect();
        let verified = verification(vec![item(&awkward, KEY_SPKI_FP_SHA256_V1_FORMAT, "aabb")]);
        assert_eq!(
            serde_json::to_string(&verified).unwrap(),
            verified.to_json()
        );

        let fixture = Fixture::load();
        for name in ["legacy-tdx/default", "config-sev/full-same"] {
            let case = fixture.case(name);
            let verifier = fixture.verifier(case).unwrap();
            let document = fixture.document(text(case, "doc")).unwrap();
            let report = verifier
                .verify_at(
                    &document,
                    &Fixture::nonce(case),
                    &pin(&fixture, case),
                    instant(case),
                )
                .unwrap();
            let verified = report.verified_facts().unwrap();
            assert_eq!(
                serde_json::to_string(verified).unwrap(),
                verified.to_json(),
                "{name}"
            );
            assert_eq!(
                serde_json::to_string(&report).unwrap(),
                report.to_json(),
                "{name}"
            );
            let value = serde_json::to_value(&report).unwrap();
            assert_eq!(
                value["verified_facts"]["code_digest"],
                verified.code_digest()
            );
            assert_eq!(value["metadata"]["verifier"]["name"], "tinfoil-rs");
        }
    }

    #[test]
    fn a_rejected_report_serialises_as_its_json_form() {
        let fixture = Fixture::load();
        for name in [
            "legacy-sev/nonce-flipped",
            "legacy-sev/roots-embedded-vendor",
            "legacy-tdx/pins-tdx-rtmr3-other",
        ] {
            let rejected = rejection(&fixture, name);
            let report = rejected.report();
            assert_eq!(
                serde_json::to_string(report).unwrap(),
                report.to_json(),
                "{name}"
            );
        }
        let rejected = rejection(&fixture, "legacy-tdx/pins-tdx-rtmr3-other");
        let value = serde_json::to_value(rejected.report()).unwrap();
        assert_eq!(value["steps"][3]["status"], "failed");
        assert_eq!(
            value["partial_facts"]["expected"]["measurement"]["platform"],
            "tdx"
        );
        assert_eq!(
            value["partial_facts"]["measured"]["cpu"]["measurement"]["platform"],
            "tdx"
        );
        assert!(value.get("verified_facts").is_none());
    }

    #[test]
    fn registers_and_measurements_serialise_as_lowercase_hex() {
        let r = register(0xab);
        let hex = "ab".repeat(REGISTER_SIZE);
        assert_eq!(serde_json::to_value(r).unwrap(), serde_json::json!(hex));
        let measurement = Measurement::SevSnp { launch: r };
        assert_eq!(
            serde_json::to_value(&measurement).unwrap(),
            serde_json::json!({"platform": "sev-snp", "launch": hex})
        );
        let measurement = Measurement::Tdx {
            mrtd: r,
            rtmr0: r,
            rtmr1: r,
            rtmr2: r,
            rtmr3: r,
        };
        assert_eq!(
            serde_json::to_string(&measurement).unwrap(),
            format!(
                r#"{{"platform":"tdx","mrtd":"{hex}","rtmr0":"{hex}","rtmr1":"{hex}","rtmr2":"{hex}","rtmr3":"{hex}"}}"#
            )
        );
        // An open register is left out.
        let expected = Expected::Tdx {
            mrtd: None,
            rtmr0: None,
            rtmr1: Some(r),
            rtmr2: None,
            rtmr3: None,
        };
        assert_eq!(
            serde_json::to_value(&expected).unwrap(),
            serde_json::json!({"platform": "tdx", "rtmr1": hex})
        );
        assert_eq!(
            serde_json::to_value(Expected::SevSnp { launch: None }).unwrap(),
            serde_json::json!({"platform": "sev-snp"})
        );
        assert_eq!(
            serde_json::to_value(measurement.expected()).unwrap(),
            serde_json::to_value(&measurement).unwrap()
        );
    }
}
