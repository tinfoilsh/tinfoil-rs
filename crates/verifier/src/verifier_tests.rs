//! Tests of the verifier's options, of its checks before any document is
//! read, of the classification of errors by layer, and of the record that a
//! verification returns.

use std::error::Error as StdError;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::canonical::encode_lower_hex;
use crate::differential_tests::{Fixture, instant, text};
use crate::document::DocumentError;
use crate::endorsement::EndorsementError;
use crate::error::{BoxError, Error, Layer};
use crate::instant::Instant;
use crate::json;
use crate::measurement::{Expected, Measurement, REGISTER_SIZE, Register};
use crate::quote::{AssemblyError, QuoteError};
use crate::verification::{
    ArtifactVerification, ConfigVerification, ReferenceSource, SoftwareIdentity, Verification,
    VerificationMetadata,
};
use crate::verifier::freshness_expiration;
use crate::{
    CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, ConfigEndorsement, CryptoMaterialItem,
    EmbeddedConfig, EmbeddedReferences, KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_SPKI_V1_FORMAT,
    KEY_X25519_HPKE_V1_FORMAT, PUBLIC_REGISTRY_ID, PublicKey, RuntimeReference, Verifier,
    crypto_material_data, parse_reference,
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

    fn all(&self) -> EmbeddedReferences {
        EmbeddedReferences {
            config: Some(self.named_config()),
            runtime: Some(self.runtime.clone()),
            platform: Some(self.platform.clone()),
        }
    }

    fn artifacts(&self) -> EmbeddedReferences {
        EmbeddedReferences {
            config: None,
            runtime: Some(self.runtime.clone()),
            platform: Some(self.platform.clone()),
        }
    }
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
    for verifier in [Verifier::new(), Verifier::default()] {
        assert!(
            verifier.trust.is_ok(),
            "{:?}",
            verifier.trust.as_ref().err()
        );
        assert_eq!(verifier.freshness_max_age(), SEVEN_DAYS);
        assert_eq!(verifier.pinned_registers(), None);
        assert!(!verifier.caller_authorizes_config());
    }
    let built = Verifier::builder().build().unwrap();
    assert_eq!(built.freshness_max_age(), SEVEN_DAYS);
}

#[test]
fn a_verifier_is_shared_between_threads() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Verifier>();
    assert_send_sync::<Verification>();
    assert_send_sync::<crate::VerifierBuilder>();
}

#[test]
fn a_zero_freshness_bound_keeps_the_default() {
    // An unset policy value must not disable the bound.
    let verifier = Verifier::builder()
        .freshness_max_age(Duration::ZERO)
        .build()
        .unwrap();
    assert_eq!(verifier.freshness_max_age(), SEVEN_DAYS);
    let day = Duration::from_secs(24 * 60 * 60);
    let verifier = Verifier::builder().freshness_max_age(day).build().unwrap();
    assert_eq!(verifier.freshness_max_age(), day);
    let verifier = Verifier::builder()
        .freshness_max_age(day)
        .freshness_max_age(Duration::ZERO)
        .build()
        .unwrap();
    assert_eq!(verifier.freshness_max_age(), day);
    let nanosecond = Duration::from_nanos(1);
    let verifier = Verifier::builder()
        .freshness_max_age(nanosecond)
        .build()
        .unwrap();
    assert_eq!(verifier.freshness_max_age(), nanosecond);
}

#[test]
fn a_freshness_bound_beyond_292_years_is_a_usage_error() {
    let longest = Duration::from_nanos(u64::try_from(i64::MAX).unwrap());
    let verifier = Verifier::builder()
        .freshness_max_age(longest)
        .build()
        .unwrap();
    assert_eq!(verifier.freshness_max_age(), longest);
    for age in [longest + Duration::from_nanos(1), Duration::MAX] {
        let message = usage(Verifier::builder().freshness_max_age(age).build());
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
    let verifier = Verifier::builder()
        .pinned_registers(pins.clone())
        .build()
        .unwrap();
    assert_eq!(verifier.pinned_registers(), Some(&pins));
    // The last pins win.
    let launch = Expected::SevSnp {
        launch: Some(register(1)),
    };
    let verifier = Verifier::builder()
        .pinned_registers(pins)
        .pinned_registers(launch.clone())
        .build()
        .unwrap();
    assert_eq!(verifier.pinned_registers(), Some(&launch));
}

#[test]
fn key_and_registry_options_refuse_empty_and_malformed_values() {
    let cases: Vec<(crate::VerifierBuilder, &str)> = vec![
        (
            Verifier::builder().config_signing_keys(Vec::new()),
            "config signing keys must not be empty",
        ),
        (
            Verifier::builder().freshness_signing_keys(Vec::new()),
            "freshness signing keys must not be empty",
        ),
        (
            Verifier::builder().config_registry_ids(Vec::new()),
            "must not be empty",
        ),
        (
            Verifier::builder().config_registry_ids(vec![String::new()]),
            "canonical registry URI",
        ),
        (
            Verifier::builder().config_registry_ids(vec![PRIVATE_REGISTRY.to_uppercase()]),
            "canonical registry URI",
        ),
        (
            Verifier::builder().config_registry_ids(vec![
                PRIVATE_REGISTRY.to_owned(),
                PRIVATE_REGISTRY.to_owned(),
            ]),
            "duplicate config registry ID",
        ),
        (
            Verifier::builder()
                .config_registry_ids(vec![PRIVATE_REGISTRY.to_owned()])
                .config_registry_ids(vec![PUBLIC_REGISTRY_ID.to_owned()]),
            "must be supplied once",
        ),
        (
            Verifier::builder().config_signing_keys([signing_keys(), signing_keys()].concat()),
            "duplicate signing key",
        ),
        (
            Verifier::builder().freshness_signing_keys([signing_keys(), signing_keys()].concat()),
            "duplicate signing key",
        ),
    ];
    for (builder, want) in cases {
        let message = usage(builder.build());
        assert!(message.contains(want), "{message}: want {want}");
    }
    let both = vec![PUBLIC_REGISTRY_ID.to_owned(), PRIVATE_REGISTRY.to_owned()];
    Verifier::builder()
        .config_registry_ids(both)
        .build()
        .unwrap();
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
    Verifier::builder()
        .freshness_signing_keys(vec![p256.clone()])
        .build()
        .unwrap();
    Verifier::builder()
        .config_signing_keys(vec![p256])
        .build()
        .unwrap();
    usage(
        Verifier::builder()
            .config_signing_keys(vec![rsa.clone()])
            .build(),
    );
    usage(
        Verifier::builder()
            .freshness_signing_keys(vec![rsa])
            .build(),
    );
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
fn options_that_select_conflicting_trust_are_refused() {
    let inputs = Inputs::new();
    let registry = || vec![PRIVATE_REGISTRY.to_owned()];
    let cases: Vec<(crate::VerifierBuilder, &str)> = vec![
        (
            Verifier::builder()
                .embedded_references(inputs.all())
                .config_signing_keys(signing_keys()),
            "embedded config and config signing keys select conflicting trust sources",
        ),
        (
            Verifier::builder()
                .config_signing_keys(signing_keys())
                .embedded_references(inputs.all()),
            "embedded config and config signing keys select conflicting trust sources",
        ),
        (
            Verifier::builder()
                .config_authorizer(accept)
                .embedded_references(inputs.all()),
            "config authorizer conflicts with embedded config or config signing keys",
        ),
        (
            Verifier::builder()
                .embedded_references(inputs.all())
                .config_authorizer(accept),
            "config authorizer conflicts with embedded config or config signing keys",
        ),
        (
            Verifier::builder()
                .config_authorizer(accept)
                .config_signing_keys(signing_keys()),
            "config authorizer conflicts with embedded config or config signing keys",
        ),
        (
            Verifier::builder()
                .config_signing_keys(signing_keys())
                .config_authorizer(accept),
            "config authorizer conflicts with embedded config or config signing keys",
        ),
        (
            Verifier::builder()
                .config_registry_ids(registry())
                .embedded_references(inputs.all()),
            "config authority pins require endorsement verification",
        ),
        (
            Verifier::builder()
                .config_registry_ids(registry())
                .config_authorizer(accept),
            "config authority pins require endorsement verification",
        ),
        (
            Verifier::builder()
                .config_registry_ids(registry())
                .config_signing_keys(signing_keys()),
            "config registry ID policy requires Tinfoil registry root verification",
        ),
        (
            Verifier::builder()
                .embedded_references(inputs.all())
                .freshness_signing_keys(signing_keys()),
            "freshness signing keys have no endorsed artifact to verify",
        ),
        (
            Verifier::builder()
                .freshness_signing_keys(signing_keys())
                .embedded_references(inputs.artifacts()),
            "freshness signing keys have no endorsed artifact to verify",
        ),
    ];
    for (builder, want) in cases {
        assert_eq!(usage(builder.build()), format!("usage error: {want}"));
    }

    // Combinations that leave one source of trust for each component.
    let runtime_only = EmbeddedReferences {
        runtime: Some(inputs.runtime.clone()),
        ..EmbeddedReferences::default()
    };
    let accepted = [
        Verifier::builder()
            .embedded_references(inputs.artifacts())
            .config_signing_keys(signing_keys()),
        Verifier::builder()
            .embedded_references(inputs.artifacts())
            .config_authorizer(accept),
        Verifier::builder()
            .embedded_references(inputs.artifacts())
            .config_registry_ids(registry()),
        Verifier::builder()
            .embedded_references(runtime_only)
            .freshness_signing_keys(signing_keys()),
        Verifier::builder()
            .config_signing_keys(signing_keys())
            .freshness_signing_keys(signing_keys()),
    ];
    for builder in accepted {
        builder.build().unwrap();
    }
}

#[test]
fn the_first_invalid_option_is_the_one_reported() {
    let message = usage(
        Verifier::builder()
            .config_signing_keys(Vec::new())
            .freshness_signing_keys(Vec::new())
            .build(),
    );
    assert_eq!(
        message,
        "usage error: config signing keys must not be empty"
    );
    let message = usage(
        Verifier::builder()
            .freshness_signing_keys(Vec::new())
            .config_signing_keys(Vec::new())
            .embedded_references(EmbeddedReferences::default())
            .build(),
    );
    assert_eq!(
        message,
        "usage error: freshness signing keys must not be empty"
    );
    // An invalid option is reported before a conflict between valid ones.
    let inputs = Inputs::new();
    let message = usage(
        Verifier::builder()
            .embedded_references(inputs.all())
            .config_signing_keys(signing_keys())
            .config_registry_ids(Vec::new())
            .build(),
    );
    assert!(message.contains("must not be empty"), "{message}");
}

#[test]
fn embedded_references_are_checked_when_the_verifier_is_built() {
    let inputs = Inputs::new();
    let only = |config: Option<EmbeddedConfig>, runtime: Option<&[u8]>, platform: Option<&[u8]>| {
        EmbeddedReferences {
            config,
            runtime: runtime.map(<[u8]>::to_vec),
            platform: platform.map(<[u8]>::to_vec),
        }
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
    let refused: Vec<(EmbeddedReferences, &str)> = vec![
        (
            EmbeddedReferences::default(),
            "must contain at least one component",
        ),
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
        let message = usage(Verifier::builder().embedded_references(references).build());
        assert!(message.contains(want), "{message}: want {want}");
    }

    let accepted = [
        inputs.all(),
        inputs.artifacts(),
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
        Verifier::builder()
            .embedded_references(references)
            .build()
            .unwrap();
    }
}

#[test]
fn the_last_embedded_references_replace_the_earlier_ones() {
    let inputs = Inputs::new();
    let verifier = Verifier::builder()
        .embedded_references(inputs.all())
        .embedded_references(inputs.artifacts())
        .build()
        .unwrap();
    assert!(!verifier.caller_authorizes_config());
}

#[test]
fn a_repository_pin_is_checked_without_a_document() {
    let inputs = Inputs::new();
    let digest = inputs.config_digest();
    let other_digest = "ab".repeat(32);
    let embedded = || Verifier::builder().embedded_references(inputs.all());
    let unnamed = || {
        Verifier::builder().embedded_references(EmbeddedReferences {
            config: Some(EmbeddedConfig::Bytes {
                bytes: inputs.config.clone(),
                name: None,
            }),
            ..inputs.artifacts()
        })
    };
    let reference = || {
        Verifier::builder().embedded_references(EmbeddedReferences {
            config: Some(EmbeddedConfig::Reference {
                digest: digest.clone(),
                runtime: inputs.runtime_reference(),
                name: Some(CONFIG_NAME.to_owned()),
            }),
            ..EmbeddedReferences::default()
        })
    };
    let authorizer = || Verifier::builder().config_authorizer(accept);
    let with_digest = format!("org/project@v1@sha256:{digest}");
    let digest_only = format!("org/project@sha256:{digest}");
    let wrong_digest = format!("org/project@sha256:{other_digest}");
    let cases: Vec<(&str, crate::VerifierBuilder, &str, bool)> = vec![
        (
            "defaults with a pin",
            Verifier::builder(),
            "org/repo@v1",
            true,
        ),
        // v2 collateral accepts it, so the check waits for the document.
        (
            "defaults with a mixed-case pin",
            Verifier::builder(),
            "Org/My_Repo",
            true,
        ),
        ("defaults without a pin", Verifier::builder(), "", true),
        (
            "defaults with a malformed pin",
            Verifier::builder(),
            "not a reference",
            false,
        ),
        (
            "defaults with two tags",
            Verifier::builder(),
            "org/project@v1@v2",
            false,
        ),
        (
            "defaults with a bad digest",
            Verifier::builder(),
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
    for (name, builder, repo, valid) in cases {
        let verifier = builder.build().unwrap();
        let result = verifier.check_repo_verifiability(repo);
        if valid {
            result.unwrap_or_else(|error| panic!("{name}: {error}"));
        } else {
            usage(result);
        }
    }
}

#[test]
fn the_caller_authorizes_a_config_that_it_embeds_or_judges() {
    let inputs = Inputs::new();
    let cases = [
        ("defaults", Verifier::builder(), false),
        (
            "embedded runtime and platform",
            Verifier::builder().embedded_references(inputs.artifacts()),
            false,
        ),
        (
            "embedded config",
            Verifier::builder().embedded_references(inputs.all()),
            true,
        ),
        (
            "config authorizer",
            Verifier::builder().config_authorizer(accept),
            true,
        ),
        (
            "config signing keys",
            Verifier::builder().config_signing_keys(signing_keys()),
            false,
        ),
    ];
    for (name, builder, want) in cases {
        let verifier = builder.build().unwrap();
        assert_eq!(verifier.caller_authorizes_config(), want, "{name}");
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
    let repo = text(case, "repo");
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
    usage(verifier.verify_v3_at(&document, &nonce, "not a reference", at));
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
        .verify_v3(&document, &Fixture::nonce(case), text(case, "repo"))
        .unwrap_err();
    assert!(before > instant(case).to_system_time().unwrap());
    let Error::Verification(rejected) = error else {
        panic!("{error}");
    };
    assert_eq!(rejected.layer(), Layer::Provenance);

    let at = instant(case).to_system_time().unwrap();
    let verified = verifier
        .verify_v3_at(&document, &Fixture::nonce(case), text(case, "repo"), at)
        .unwrap();
    assert_eq!(verified.metadata().verified_at, at);
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
        text(case, "repo"),
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
        let cause = cause.clone();
        let error = Error::from(crate::VerificationError::new(Layer::Policy, cause.clone()));
        assert_eq!(error.source().unwrap().to_string(), cause);
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
    let artifacts = |builder: crate::VerifierBuilder| {
        let mut verifier = builder
            .test_roots(
                fixture.root(text(case, "sigstore")).as_deref(),
                fixture.root(text(case, "amd")),
                None,
            )
            .build()
            .unwrap();
        verifier.embedded = embedded.clone();
        verifier
    };
    let verify = |verifier: &Verifier| {
        verifier.verify_at(&document, &Fixture::nonce(case), "", instant(case))
    };

    // Whatever the authorizer returns, even one of this crate's own usage
    // errors, a refusal is a rejection at the provenance layer with the
    // authorizer's error as the cause of its cause.
    let refuse_plainly = artifacts(
        Verifier::builder()
            .config_authorizer(|_| Err(Box::new(Refusal("config is not authorized")))),
    );
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

    let refuse_as_usage = artifacts(
        Verifier::builder()
            .config_authorizer(|_| Err(Box::new(parse_reference("not a reference").unwrap_err()))),
    );
    let Err(Error::Verification(rejected)) = verify(&refuse_as_usage) else {
        panic!("want a rejection");
    };
    assert_eq!(rejected.layer(), Layer::Provenance);
    let cause = rejected.source().unwrap().source().unwrap();
    assert!(matches!(
        cause.downcast_ref::<Error>(),
        Some(Error::Usage(_))
    ));

    let accepting = artifacts(Verifier::builder().config_authorizer(accept));
    let verified = verify(&accepting).unwrap();
    let config = verified.config().unwrap();
    assert_eq!(config.source, ReferenceSource::Policy);
    assert_eq!(
        (config.name.as_deref(), config.reference.as_deref()),
        (None, None)
    );
    assert_eq!(verified.freshness_expires_at(), None);
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
        let mut verifier = Verifier::builder()
            .config_authorizer(move |endorsement| {
                record.lock().unwrap().push(endorsement.clone());
                Ok(())
            })
            .test_roots(
                fixture.root(text(case, "sigstore")).as_deref(),
                fixture.root(text(case, "amd")),
                None,
            )
            .build()
            .unwrap();
        verifier.embedded = embedded;
        let verified = verifier
            .verify_at(&document, &Fixture::nonce(case), "", instant(case))
            .unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{name}");
        let endorsement = &seen[0];
        assert_eq!(
            encode_lower_hex(&Sha256::digest(endorsement.config())),
            verified.config().unwrap().digest
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
        ("defaults", Verifier::builder()),
        (
            "embedded artifacts",
            Verifier::builder().embedded_references(inputs.artifacts()),
        ),
        (
            "freshness keys",
            Verifier::builder().freshness_signing_keys(signing_keys()),
        ),
        ("authorizer", Verifier::builder().config_authorizer(accept)),
        (
            "embedded config",
            Verifier::builder().embedded_references(inputs.all()),
        ),
    ] {
        let verifier = builder.build().unwrap();
        assert_eq!(
            verifier.reference_pins("").unwrap().registry_ids,
            public,
            "{name}"
        );
    }
    let listed = vec![PRIVATE_REGISTRY.to_owned()];
    let verifier = Verifier::builder()
        .config_registry_ids(listed.clone())
        .build()
        .unwrap();
    assert_eq!(
        verifier.reference_pins("").unwrap().registry_ids,
        Some(listed)
    );
    let keyed = Verifier::builder()
        .config_signing_keys(signing_keys())
        .build()
        .unwrap();
    assert_eq!(keyed.reference_pins("").unwrap().registry_ids, None);

    // End to end: a config endorsement that a private registry certified,
    // under registry roots that would authenticate it, is refused unless
    // the caller lists that registry.
    let fixture = Fixture::load();
    for (name, accepted) in [
        (
            "config-sev/certified-private-with-config-default-ids/",
            false,
        ),
        (
            "config-sev/certified-private-with-config-public-only/",
            false,
        ),
        ("config-sev/certified-private-with-config-exclusive/", true),
    ] {
        let case = fixture.case(name);
        let verifier = fixture.verifier(case).unwrap();
        let document = fixture.document(text(case, "doc")).unwrap();
        let result = verifier.verify_at(&document, &Fixture::nonce(case), "", instant(case));
        match result {
            Ok(verified) => {
                assert!(accepted, "{name}");
                let registry = verified.config().unwrap().registry_id.as_deref();
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

fn verification(crypto_material: Vec<CryptoMaterialItem>) -> Verification {
    Verification {
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
        metadata: VerificationMetadata {
            verifier: SoftwareIdentity {
                name: "tinfoil-rs".to_owned(),
                version: "0.1.0".to_owned(),
            },
            verified_at: at("2026-08-06T12:00:00.5Z").to_system_time().unwrap(),
        },
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
        r#""freshness_expires_at":"2026-08-13T12:00:00Z","#,
        r#""metadata":{"verifier":{"name":"tinfoil-rs","version":"0.1.0"},"verified_at":"2026-08-06T12:00:00.5Z"}}"#,
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
        r#""},"#,
        r#""metadata":{"verifier":{"name":"tinfoil-rs","version":"0.1.0"},"verified_at":"2026-08-06T12:00:00.5Z"}}"#,
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
        let verified = verifier
            .verify_at(
                &document,
                &Fixture::nonce(case),
                text(case, "repo"),
                instant(case),
            )
            .unwrap();
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
        want.push("metadata");
        assert_eq!(names, want, "{name}");
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
            let verified = verifier
                .verify_at(
                    &document,
                    &Fixture::nonce(case),
                    text(case, "repo"),
                    instant(case),
                )
                .unwrap();
            assert_eq!(
                serde_json::to_string(&verified).unwrap(),
                verified.to_json(),
                "{name}"
            );
            let value = serde_json::to_value(&verified).unwrap();
            assert_eq!(value["code_digest"], verified.code_digest());
            assert_eq!(value["metadata"]["verifier"]["name"], "tinfoil-rs");
        }
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
