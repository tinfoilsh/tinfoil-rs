//! The public surface of the crate, as a consumer sees it.
//!
//! The first test imports every public name from the crate root and uses
//! each signature once, so that a change to a name, a parameter or a return
//! type fails to compile here.
//!
//! The second test compares the public items of the crate with the listing
//! in `tests/public_api.txt`. The items are read from the source: the names
//! that `lib.rs` exports, and for each exported type its public methods and
//! fields. A new, renamed or removed item changes the listing, so that a
//! change of the surface is also a change of that file. Set
//! `UPDATE_PUBLIC_API=1` to rewrite the listing.
//!
//! The listing is read with a line scanner, not a compiler, so it has blind
//! spots: trait implementations, enum variants, the types in a signature,
//! and items that a macro would generate. The first test covers the
//! signatures.

// Test tooling: a panic is how a test fails, slices of source lines are
// taken at positions that the scanner itself found, and the signatures are
// spelled out in full because they are what the test pins.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::type_complexity,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tinfoil_verifier::{
    ATTESTATION_V3_FORMAT, ArtifactVerification, BoxError, CRYPTO_MATERIAL_ID_HPKE,
    CRYPTO_MATERIAL_ID_TLS, CRYPTO_MATERIAL_V1_FORMAT, ConfigEndorsement, ConfigVerification,
    CryptoMaterialItem, DEVICE_EVIDENCE_V1_FORMAT, EmbeddedConfig, EmbeddedReferences, Error,
    Expected, KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_SPKI_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, Layer,
    Measurement, NONCE_SIZE, NVIDIA_GPU_EVIDENCE_V1_FORMAT, PUBLIC_REGISTRY_ID, PublicKey,
    REGISTER_SIZE, REPORT_DATA_V1_ALGORITHM, Reference, ReferenceSource, Register,
    RuntimeReference, SEV_SNP_REPORT_V1_FORMAT, SoftwareIdentity, TDX_QUOTE_V1_FORMAT, UsageError,
    Verification, VerificationError, VerificationMetadata, Verifier, VerifierBuilder,
    cert_pubkey_fp, crypto_material_data, parse_reference, random_nonce,
};

#[test]
fn every_public_name_is_importable_and_has_its_signature() {
    // The verifier.
    let _: fn() -> Verifier = Verifier::new;
    let _: fn() -> Verifier = Verifier::default;
    let _: fn() -> VerifierBuilder = Verifier::builder;
    let _: fn(&Verifier, &[u8], &[u8], &str) -> Result<Verification, Error> = Verifier::verify_v3;
    let _: fn(&Verifier, &[u8], &[u8], &str, SystemTime) -> Result<Verification, Error> =
        Verifier::verify_v3_at;
    let _: fn(&Verifier, &str) -> Result<(), Error> = Verifier::check_repo_verifiability;
    let _: fn(&Verifier) -> bool = Verifier::caller_authorizes_config;
    let _: for<'a> fn(&'a Verifier) -> Option<&'a Expected> = Verifier::pinned_registers;
    let _: fn(&Verifier) -> Duration = Verifier::freshness_max_age;

    // Its options, one method each.
    let _: fn(VerifierBuilder, Expected) -> VerifierBuilder = VerifierBuilder::pinned_registers;
    let _: fn(VerifierBuilder, Duration) -> VerifierBuilder = VerifierBuilder::freshness_max_age;
    let _: fn(VerifierBuilder, Vec<PublicKey>) -> VerifierBuilder =
        VerifierBuilder::config_signing_keys;
    let _: fn(VerifierBuilder, Vec<PublicKey>) -> VerifierBuilder =
        VerifierBuilder::freshness_signing_keys;
    let _: fn(VerifierBuilder, Vec<String>) -> VerifierBuilder =
        VerifierBuilder::config_registry_ids;
    let _: fn(VerifierBuilder, EmbeddedReferences) -> VerifierBuilder =
        VerifierBuilder::embedded_references;
    let _: fn(VerifierBuilder) -> Result<Verifier, Error> = VerifierBuilder::build;
    let authorize = |endorsement: &ConfigEndorsement| -> Result<(), BoxError> {
        let _: &[u8] = endorsement.config();
        let _: Option<&str> = endorsement.reference();
        let _: Option<&[u8]> = endorsement.bundle_json();
        let _: Option<&[u8]> = endorsement.issuer_certificate_der();
        Err("no config is authorized here".into())
    };
    let builder: VerifierBuilder = VerifierBuilder::default().config_authorizer(authorize);
    let verifier: Verifier = builder.build().unwrap();
    assert!(verifier.caller_authorizes_config());

    let _: fn(&str) -> Result<PublicKey, Error> = PublicKey::from_pem;
    let _: fn(&[u8]) -> Result<PublicKey, Error> = PublicKey::from_spki_der;
    let _: fn(&PublicKey) -> Vec<u8> = PublicKey::to_spki_der;

    let references = EmbeddedReferences {
        config: Some(EmbeddedConfig::Reference {
            digest: String::new(),
            runtime: RuntimeReference {
                repo: String::new(),
                tag: String::new(),
                digest: String::new(),
            },
            name: None,
        }),
        runtime: Some(Vec::new()),
        platform: Some(Vec::new()),
    };
    let _ = EmbeddedReferences {
        config: Some(EmbeddedConfig::Bytes {
            bytes: Vec::new(),
            name: Some(String::new()),
        }),
        ..references.clone()
    };
    assert_eq!(EmbeddedReferences::default().config, None);

    // The record of a verification.
    let _: fn(&Verification) -> &str = Verification::code_digest;
    let _: fn(&Verification) -> &str = Verification::code_tag;
    let _: fn(&Verification) -> &str = Verification::config_repo;
    let _: fn(&Verification) -> &Expected = Verification::code_measurement;
    let _: fn(&Verification) -> &Measurement = Verification::enclave_measurement;
    let _: fn(&Verification) -> Option<&str> = Verification::tls_public_key_fp;
    let _: fn(&Verification) -> Option<&str> = Verification::hpke_public_key;
    let _: fn(&Verification) -> &[CryptoMaterialItem] = Verification::crypto_material;
    let _: for<'a> fn(&'a Verification, &str, &str) -> Option<&'a str> =
        Verification::crypto_material_data;
    let _: fn(&Verification) -> Option<SystemTime> = Verification::freshness_expires_at;
    let _: fn(&Verification) -> Option<&ConfigVerification> = Verification::config;
    let _: fn(&Verification) -> Option<&ArtifactVerification> = Verification::runtime;
    let _: fn(&Verification) -> Option<&ArtifactVerification> = Verification::platform;
    let _: fn(&Verification) -> &VerificationMetadata = Verification::metadata;
    let _: fn(&Verification) -> String = Verification::to_json;
    let _: fn(&Verification) -> Verification = Verification::clone;

    fn config_fields(config: &ConfigVerification) {
        let _: ReferenceSource = config.source;
        let _: (&Option<String>, &String) = (&config.name, &config.digest);
        let _: (&Option<String>, &Option<String>) = (&config.reference, &config.signing_key_hint);
        let _: (Option<SystemTime>, Option<SystemTime>) =
            (config.approval_time, config.signature_time);
        let _: &Option<String> = &config.registry_id;
    }
    fn artifact_fields(artifact: &ArtifactVerification) {
        let _: ReferenceSource = artifact.source;
        let _: (&Option<String>, &Option<String>) = (&artifact.repo, &artifact.tag);
        let _: &String = &artifact.digest;
        let _: (&Option<String>, &Option<String>) = (&artifact.name, &artifact.commit);
        let _: Option<SystemTime> = artifact.approval_time;
    }
    fn metadata_fields(metadata: &VerificationMetadata) {
        let identity: &SoftwareIdentity = &metadata.verifier;
        let _: (&String, &String) = (&identity.name, &identity.version);
        let _: SystemTime = metadata.verified_at;
    }
    let _ = (config_fields, artifact_fields, metadata_fields);
    let sources = [
        ReferenceSource::Endorsement,
        ReferenceSource::Embedded,
        ReferenceSource::Policy,
    ];
    let names: Vec<&str> = sources.iter().map(ReferenceSource::as_str).collect();
    assert_eq!(names, ["endorsement", "embedded", "policy"]);
    assert_eq!(ReferenceSource::Policy.to_string(), "policy");

    // Free functions.
    let reference: Reference = parse_reference("org/project@v1").unwrap();
    let _: (String, Option<String>, Option<String>) =
        (reference.repo, reference.tag, reference.digest);
    let items = [CryptoMaterialItem {
        id: CRYPTO_MATERIAL_ID_TLS.to_owned(),
        format: KEY_SPKI_FP_SHA256_V1_FORMAT.to_owned(),
        data: "aabb".to_owned(),
    }];
    let found: Option<&str> =
        crypto_material_data(&items, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT);
    assert_eq!(found, Some("aabb"));
    let fingerprint: Result<String, Error> = cert_pubkey_fp(b"not a certificate");
    assert!(matches!(fingerprint, Err(Error::Usage(_))));
    let nonce: std::io::Result<[u8; NONCE_SIZE]> = random_nonce();
    assert_eq!(nonce.unwrap().len(), 32);

    // Constants.
    let constants: [&str; 12] = [
        ATTESTATION_V3_FORMAT,
        REPORT_DATA_V1_ALGORITHM,
        CRYPTO_MATERIAL_V1_FORMAT,
        DEVICE_EVIDENCE_V1_FORMAT,
        SEV_SNP_REPORT_V1_FORMAT,
        TDX_QUOTE_V1_FORMAT,
        NVIDIA_GPU_EVIDENCE_V1_FORMAT,
        KEY_SPKI_FP_SHA256_V1_FORMAT,
        KEY_SPKI_V1_FORMAT,
        KEY_X25519_HPKE_V1_FORMAT,
        PUBLIC_REGISTRY_ID,
        CRYPTO_MATERIAL_ID_HPKE,
    ];
    assert!(constants.iter().all(|constant| !constant.is_empty()));
    assert_eq!(
        (CRYPTO_MATERIAL_ID_TLS, CRYPTO_MATERIAL_ID_HPKE),
        ("tls", "hpke")
    );
    assert_eq!((NONCE_SIZE, REGISTER_SIZE), (32, 48));

    // Measurements.
    let register: Register = Register::new([0xab; REGISTER_SIZE]);
    let _: &[u8; REGISTER_SIZE] = register.as_bytes();
    let _: Register = Register::from([0; REGISTER_SIZE]);
    let parsed: Result<Register, Error> = register.to_string().parse();
    assert_eq!(parsed.unwrap(), register);
    let measurement = Measurement::Tdx {
        mrtd: register,
        rtmr0: register,
        rtmr1: register,
        rtmr2: register,
        rtmr3: register,
    };
    let expected: Expected = measurement.expected();
    let _ = Measurement::SevSnp { launch: register };
    let _ = Expected::SevSnp { launch: None };
    let _: fn(&str) -> Result<Expected, Error> = Expected::parse_sev_snp;
    let _: fn(&str, &str, &str, &str, &str) -> Result<Expected, Error> = Expected::parse_tdx;
    assert!(expected.to_string().starts_with("TDX"));

    // Errors.
    let error: Error = verifier.verify_v3(b"{}", &[0; NONCE_SIZE], "").unwrap_err();
    let _: Option<&(dyn StdError + 'static)> = error.source();
    match error {
        Error::Verification(rejected) => {
            let rejected: VerificationError = rejected;
            let layer: Layer = rejected.layer();
            assert_eq!(layer, Layer::Envelope);
            assert_eq!(layer.as_str(), "envelope");
            assert!(rejected.source().is_some());
        }
        Error::Usage(usage) => {
            let usage: UsageError = usage;
            panic!("{usage}");
        }
        other => panic!("{other}"),
    }
    let layers = [
        Layer::Envelope,
        Layer::Provenance,
        Layer::Quote,
        Layer::Policy,
    ];
    assert_eq!(
        layers.map(|layer| layer.to_string()).join(" "),
        "envelope provenance quote policy"
    );
    let usage: Error = verifier
        .verify_v3(b"{}", &[0; NONCE_SIZE - 1], "")
        .unwrap_err();
    assert!(matches!(usage, Error::Usage(_)));
    fn assert_error<T: StdError + Send + Sync + 'static>() {}
    assert_error::<Error>();
    assert_error::<UsageError>();
    assert_error::<VerificationError>();
}

/// The files that define the items of the public types.
const SOURCES: [&str; 8] = [
    "verifier.rs",
    "options.rs",
    "verification.rs",
    "embedded.rs",
    "fingerprint.rs",
    "error.rs",
    "measurement.rs",
    "endorsement/reference.rs",
];

/// The first identifier of `text`.
fn identifier(text: &str) -> &str {
    let end = text
        .find(|character: char| !(character.is_alphanumeric() || character == '_'))
        .unwrap_or(text.len());
    &text[..end]
}

/// The names that the crate root exports in an ordinary build.
fn exported_names(lib: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    // The module for the conformance adapter follows the ordinary exports.
    let ordinary = lib.split("#[cfg(tinfoil_conformance)]").next().unwrap();
    let mut rest = ordinary;
    while let Some(start) = rest.find("\npub use ") {
        let statement = &rest[start + 1..];
        let end = statement.find(';').unwrap();
        let (statement, after) = statement.split_at(end);
        let list = match statement.find('{') {
            Some(open) => &statement[open + 1..statement.rfind('}').unwrap()],
            None => statement.rsplit("::").next().unwrap(),
        };
        for name in list.split(',') {
            let name = name.trim();
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
        rest = after;
    }
    names
}

/// The public items of one source file, as listing lines: free items by
/// their name, methods as `Type::method`, fields as `Type.field`.
fn public_items(source: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut owner = String::new();
    let mut in_struct = false;
    let mut conformance_only = false;
    let mut test_only = false;
    for line in source.lines() {
        if line.starts_with("#[cfg(test)]") {
            // Test modules close a source file.
            break;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(tinfoil_conformance)]") {
            conformance_only = true;
            continue;
        }
        if trimmed.starts_with("#[cfg(test)]") {
            // The item that follows exists only in test builds.
            test_only = true;
            continue;
        }
        let declares = ["pub ", "pub(", "fn "]
            .iter()
            .any(|start| trimmed.starts_with(start));
        if declares && std::mem::take(&mut test_only) {
            continue;
        }
        let suffix = if conformance_only {
            " [conformance build only]"
        } else {
            ""
        };
        let top_level = !line.starts_with(' ');
        if top_level {
            in_struct = false;
            if let Some(rest) = line.strip_prefix("impl") {
                // `impl Type {`, `impl<T> Trait for Type {`.
                let rest = rest.trim_start_matches(|c| c != ' ').trim_start();
                let target = rest.rsplit(" for ").next().unwrap();
                owner = identifier(target).to_owned();
                continue;
            }
            for (keyword, kind) in [
                ("pub struct ", "struct"),
                ("pub enum ", "enum"),
                ("pub type ", "type"),
                ("pub const ", "const"),
                ("pub fn ", "fn"),
            ] {
                if let Some(rest) = line.strip_prefix(keyword) {
                    let name = identifier(rest);
                    items.push(format!("{kind} {name}{suffix}"));
                    if kind == "struct" && line.trim_end().ends_with('{') {
                        owner = name.to_owned();
                        in_struct = true;
                    }
                }
            }
        } else if line.starts_with("    pub fn ") || line.starts_with("    pub const fn ") {
            let rest = trimmed
                .trim_start_matches("pub ")
                .trim_start_matches("const ")
                .trim_start_matches("fn ");
            items.push(format!("fn {owner}::{}{suffix}", identifier(rest)));
        } else if in_struct && line.starts_with("    pub ") && !line.starts_with("    pub(") {
            let rest = trimmed.trim_start_matches("pub ");
            items.push(format!("field {owner}.{}", identifier(rest)));
        }
        if !trimmed.starts_with("#[") && !trimmed.starts_with("//") && !trimmed.is_empty() {
            conformance_only = false;
        }
    }
    items
}

#[test]
fn the_public_items_are_the_listed_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |relative: &str| std::fs::read_to_string(root.join(relative)).unwrap();
    let exported = exported_names(&read("src/lib.rs"));
    assert!(exported.contains("Verifier"), "{exported:?}");

    let mut listing: BTreeSet<String> = BTreeSet::new();
    let mut defined: BTreeSet<String> = BTreeSet::new();
    for file in SOURCES {
        for item in public_items(&read(&format!("src/{file}"))) {
            let (_, name) = item.split_once(' ').unwrap();
            let owner = identifier(name);
            if exported.contains(owner) {
                defined.insert(owner.to_owned());
                listing.insert(item);
            }
        }
    }
    // Names whose definition is outside the scanned files: constants and
    // plain records of the document module.
    for name in exported.difference(&defined) {
        listing.insert(format!("export {name}"));
    }
    let listing: String = listing.into_iter().map(|line| line + "\n").collect();

    let path = root.join("tests/public_api.txt");
    if std::env::var_os("UPDATE_PUBLIC_API").is_some() {
        std::fs::write(&path, &listing).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    let committed: Vec<&str> = committed.lines().collect();
    let current: Vec<&str> = listing.lines().collect();
    let added: Vec<&&str> = current
        .iter()
        .filter(|line| !committed.contains(line))
        .collect();
    let removed: Vec<&&str> = committed
        .iter()
        .filter(|line| !current.contains(line))
        .collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "the public surface changed; if that is intended, rerun with UPDATE_PUBLIC_API=1\n\
         added: {added:#?}\nremoved: {removed:#?}"
    );
}

#[test]
fn an_ordinary_build_lists_no_replaceable_trust_anchor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let listing = std::fs::read_to_string(root.join("tests/public_api.txt")).unwrap();
    let dangerous: Vec<&str> = listing
        .lines()
        .filter(|line| line.contains("dangerous") || line.contains("root"))
        .collect();
    // Both injection methods are in the source, and only for the adapter.
    assert_eq!(
        dangerous,
        [
            "fn VerifierBuilder::dangerous_test_only_sigstore_root [conformance build only]",
            "fn VerifierBuilder::dangerous_test_only_vendor_roots [conformance build only]",
        ]
    );
}
