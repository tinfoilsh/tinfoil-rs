//! Replays recorded verifications through the public verifier.
//!
//! `integration_differential.json` holds documents, verifier options and
//! the outcome that a second, independent implementation of the same rules
//! recorded for each combination: whether the verifier could be built,
//! whether it accepts the repository pin, the verdict with its layer, and
//! on an accept every fact of the verification.
//!
//! The documents are minted under synthetic trust anchors. They cover both
//! collateral flows on both platforms: a code release with its platform
//! artifact and freshness witnesses, and a config with its runtime and
//! platform artifact, each endorsed and approved or supplied by the
//! caller. A document is stored as the text around its collateral and the
//! list of its collateral entries, which the fixture keeps once each; the
//! pieces put together give the document byte for byte. Cases named
//! `vector/…` take their document from a checkout of the shared vectors
//! and are skipped without one.
//!
//! The outcome here must be the recorded one, except for the cases that
//! [`STRICTER`] lists with the rule by which this crate turns down what
//! the other implementation accepts. No case that the other implementation
//! turns down is accepted here.
//!
//! Times are taken as instants with nanoseconds, below the public entry
//! point, because a system time is coarser than that on some platforms.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::canonical::{decode_hex, encode_lower_hex};
use crate::error::{BoxError, Error};
use crate::instant::Instant;
use crate::json::{self, Object, Value};
use crate::measurement::{Expected, Measurement, Register};
use crate::verification::{ArtifactVerification, ConfigVerification, Verification};
use crate::{
    ConfigEndorsement, EmbeddedConfig, EmbeddedReferences, PublicKey, RuntimeReference, Verifier,
    x509,
};

const CASES: &[u8] = include_bytes!("../tests/data/verifier/integration_differential.json");

/// The environment variable that names a checkout of the shared vectors.
const VECTORS_ENV: &str = "TINFOIL_CONFORMANCE_VECTORS";

/// Cases that the other implementation accepts and this crate turns down,
/// each with the rule that makes this crate the stricter one.
const STRICTER: &[(&str, &str)] = &[];

pub(crate) struct Fixture {
    value: Value,
}

pub(crate) fn object(value: &Value) -> &Object {
    value.as_object().expect("an object")
}

pub(crate) fn member<'a>(object: &'a Object, name: &str) -> &'a Value {
    object
        .get(name)
        .unwrap_or_else(|| panic!("member {name} is missing"))
}

pub(crate) fn text<'a>(object: &'a Object, name: &str) -> &'a str {
    object.get(name).and_then(Value::as_str).unwrap_or("")
}

fn integer(object: &Object, name: &str) -> i64 {
    object
        .get(name)
        .and_then(Value::as_number)
        .map_or(0, |number| number.to_i64().expect("an integer"))
}

fn flag(object: &Object, name: &str) -> bool {
    object.get(name).and_then(Value::as_bool).unwrap_or(false)
}

fn index(value: &Value) -> usize {
    let number = value.as_number().expect("an index");
    usize::try_from(number.to_u64().expect("an index")).unwrap()
}

impl Fixture {
    pub(crate) fn load() -> Self {
        Self {
            value: json::parse(CASES).unwrap(),
        }
    }

    fn root_object(&self) -> &Object {
        object(&self.value)
    }

    /// The case called `name`.
    pub(crate) fn case(&self, name: &str) -> &Object {
        member(self.root_object(), "cases")
            .as_array()
            .unwrap()
            .iter()
            .map(object)
            .find(|case| text(case, "name") == name)
            .unwrap_or_else(|| panic!("no case {name}"))
    }

    /// The nonce of a case.
    pub(crate) fn nonce(case: &Object) -> Vec<u8> {
        decode_hex(text(case, "nonce_hex")).unwrap()
    }

    fn string(&self, at: usize) -> &str {
        member(self.root_object(), "strings").as_array().unwrap()[at]
            .as_str()
            .unwrap()
    }

    /// The value of an option: a long one is stored as `@` and its index
    /// in the table of strings.
    fn resolve<'a>(&'a self, value: &'a str) -> &'a str {
        match value.strip_prefix('@') {
            Some(at) => self.string(at.parse().unwrap()),
            None => value,
        }
    }

    pub(crate) fn root(&self, name: &str) -> Option<Vec<u8>> {
        if name.is_empty() {
            return None;
        }
        let at = index(member(object(member(self.root_object(), "roots")), name));
        Some(self.string(at).as_bytes().to_vec())
    }

    /// The bytes of a document; `None` for a document of the shared
    /// vectors when no checkout is at hand.
    pub(crate) fn document(&self, name: &str) -> Option<Vec<u8>> {
        let stored = object(member(
            object(member(self.root_object(), "documents")),
            name,
        ));
        if let Some(vector) = stored.get("vector").and_then(Value::as_str) {
            let directory = std::env::var_os(VECTORS_ENV)?;
            let path = std::path::Path::new(&directory).join(format!("{vector}.json"));
            let fixture = json::parse(&std::fs::read(path).unwrap()).unwrap();
            let input = object(member(object(&fixture), "input"));
            return Some(STANDARD.decode(text(input, "document_b64")).unwrap());
        }
        let mut document = self.string(index(member(stored, "head"))).to_owned();
        // A document without collateral has no list of entries.
        let entries = member(stored, "entries").as_array().unwrap_or_default();
        for (position, entry) in entries.iter().enumerate() {
            if position > 0 {
                document.push(',');
            }
            document.push_str(self.string(index(entry)));
        }
        document.push_str(self.string(index(member(stored, "tail"))));
        Some(document.into_bytes())
    }

    fn keys(&self, options: &Object, name: &str) -> Option<Vec<PublicKey>> {
        let keys = options.get(name)?.as_array()?;
        Some(
            keys.iter()
                .map(|key| PublicKey::from_pem(self.resolve(key.as_str().unwrap())).unwrap())
                .collect(),
        )
    }

    pub(crate) fn blob(&self, object: &Object, name: &str) -> Option<Vec<u8>> {
        let encoded = object.get(name)?.as_str()?;
        Some(STANDARD.decode(self.resolve(encoded)).unwrap())
    }

    /// Builds the verifier of a case, with the options in a fixed order.
    pub(crate) fn verifier(&self, case: &Object) -> Result<Verifier, Error> {
        let options = object(member(case, "options"));
        let mut builder = Verifier::builder();
        if let Some(pins) = options.get("pins").and_then(Value::as_object) {
            let register = |name: &str| self.resolve(text(pins, name));
            let pins = if text(pins, "platform") == "sev-snp" {
                Expected::parse_sev_snp(register("launch"))
            } else {
                Expected::parse_tdx(
                    register("mrtd"),
                    register("rtmr0"),
                    register("rtmr1"),
                    register("rtmr2"),
                    register("rtmr3"),
                )
            };
            builder = builder.pinned_registers(pins.unwrap());
        }
        let max_age = integer(options, "max_age_ns");
        if max_age != 0 {
            builder = builder.freshness_max_age(Duration::from_nanos(max_age.unsigned_abs()));
        }
        if let Some(keys) = self.keys(options, "config_keys_pem") {
            builder = builder.config_signing_keys(keys);
        }
        if let Some(keys) = self.keys(options, "freshness_keys_pem") {
            builder = builder.freshness_signing_keys(keys);
        }
        if let Some(ids) = options.get("registry_ids").and_then(Value::as_array) {
            let ids = ids
                .iter()
                .map(|id| self.resolve(id.as_str().unwrap()).to_owned())
                .collect();
            builder = builder.config_registry_ids(ids);
        }
        let authorizer = self.resolve(text(options, "authorizer")).to_owned();
        if !authorizer.is_empty() {
            builder = builder.config_authorizer(move |endorsement: &ConfigEndorsement| {
                let digest = encode_lower_hex(&Sha256::digest(endorsement.config()));
                let accepted = match authorizer.as_str() {
                    "accept" => true,
                    "refuse" => false,
                    only => only.strip_prefix("sha256:") == Some(digest.as_str()),
                };
                if accepted {
                    Ok(())
                } else {
                    Err(BoxError::from("config is not authorized"))
                }
            });
        }
        if let Some(embedded) = options.get("embedded").and_then(Value::as_object) {
            let name = Some(text(embedded, "config_name"))
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            let config = if let Some(bytes) = self.blob(embedded, "config_b64") {
                Some(EmbeddedConfig::Bytes { bytes, name })
            } else if let Some(digest) = embedded.get("config_ref_digest") {
                let runtime = object(member(embedded, "config_ref_runtime"));
                Some(EmbeddedConfig::Reference {
                    digest: self.resolve(digest.as_str().unwrap()).to_owned(),
                    runtime: RuntimeReference {
                        repo: text(runtime, "repo").to_owned(),
                        tag: text(runtime, "tag").to_owned(),
                        digest: text(runtime, "digest").to_owned(),
                    },
                    name,
                })
            } else {
                None
            };
            builder = builder.embedded_references(EmbeddedReferences {
                config,
                runtime: self.blob(embedded, "runtime_b64"),
                platform: self.blob(embedded, "platform_b64"),
            });
        }
        let mut verifier = builder
            .test_roots(
                self.root(text(case, "sigstore")).as_deref(),
                self.root(text(case, "amd")),
                self.root(text(case, "intel")),
            )
            .build()?;
        // The registry's root keys cannot be minted for, so a case may put
        // its own in their place.
        if let Some(keys) = self.keys(options, "registry_root_keys_pem") {
            let keys: Vec<x509::PublicKey> = keys.into_iter().map(|key| key.0).collect();
            let trust = verifier.trust.as_mut().unwrap();
            trust.config_verifier = trust.endorsements.registry_verifier(&keys).unwrap();
        }
        Ok(verifier)
    }
}

/// The instant of a case: seconds since the epoch, which may be negative,
/// and nanoseconds.
pub(crate) fn instant(case: &Object) -> Instant {
    let nanos = u32::try_from(integer(case, "time_nanos")).unwrap();
    Instant::from_unix(integer(case, "time_unix"), nanos).unwrap()
}

/// A recorded time, at the precision that a system time has on every
/// platform: 100 nanoseconds. Empty when there is none.
fn recorded_time(text: &str) -> Option<(i64, u32)> {
    if text.is_empty() {
        return None;
    }
    let instant = Instant::parse_rfc3339(text).unwrap();
    Some((instant.unix_seconds(), instant.subsec_nanos() / 100))
}

fn system_time(time: Option<std::time::SystemTime>) -> Option<(i64, u32)> {
    let instant = Instant::from_system_time(time?).unwrap();
    Some((instant.unix_seconds(), instant.subsec_nanos() / 100))
}

fn recorded_text(object: &Object, name: &str) -> Option<String> {
    Some(text(object, name))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn registers(registers: &[Option<Register>]) -> Vec<String> {
    registers
        .iter()
        .map(|register| {
            register
                .map(|register| register.to_string())
                .unwrap_or_default()
        })
        .collect()
}

fn expected_registers(expected: &Expected) -> (&'static str, Vec<String>) {
    match *expected {
        Expected::SevSnp { launch } => ("sev-snp", registers(&[launch])),
        Expected::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => ("tdx", registers(&[mrtd, rtmr0, rtmr1, rtmr2, rtmr3])),
    }
}

fn measurement_registers(measurement: &Measurement) -> Vec<String> {
    expected_registers(&measurement.expected()).1
}

fn recorded_list(object: &Object, name: &str) -> Vec<String> {
    member(object, name)
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

/// The differences between a verification and the recorded facts.
fn compare_facts(verified: &Verification, facts: &Object) -> Vec<String> {
    let mut differences = Vec::new();
    let mut check = |name: &str, same: bool| {
        if !same {
            differences.push(name.to_owned());
        }
    };
    check(
        "code_digest",
        verified.code_digest() == text(facts, "code_digest"),
    );
    check("code_tag", verified.code_tag() == text(facts, "code_tag"));
    check(
        "config_repo",
        verified.config_repo() == text(facts, "config_repo"),
    );
    let (platform, code) = expected_registers(verified.code_measurement());
    check("platform", platform == text(facts, "platform"));
    check(
        "code_measurement",
        code == recorded_list(facts, "code_measurement"),
    );
    check(
        "enclave_measurement",
        measurement_registers(verified.enclave_measurement())
            == recorded_list(facts, "enclave_measurement"),
    );
    let items: Vec<(String, String, String)> = verified
        .crypto_material()
        .iter()
        .map(|item| (item.id.clone(), item.format.clone(), item.data.clone()))
        .collect();
    let recorded_items: Vec<(String, String, String)> = member(facts, "crypto_material")
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let item = object(item);
            (
                text(item, "id").to_owned(),
                text(item, "format").to_owned(),
                text(item, "data").to_owned(),
            )
        })
        .collect();
    check("crypto_material", items == recorded_items);
    check(
        "tls",
        verified.tls_public_key_fp() == member(facts, "tls").as_str(),
    );
    check(
        "hpke",
        verified.hpke_public_key() == member(facts, "hpke").as_str(),
    );
    check(
        "freshness_expires_at",
        system_time(verified.freshness_expires_at())
            == recorded_time(text(facts, "freshness_expires_at")),
    );
    check(
        "verified_at",
        system_time(Some(verified.metadata().verified_at))
            == recorded_time(text(facts, "verified_at")),
    );
    check(
        "config",
        config_facts(verified.config()) == recorded_config(member(facts, "config")),
    );
    check(
        "runtime",
        artifact_facts(verified.runtime()) == recorded_artifact(member(facts, "runtime")),
    );
    check(
        "platform_artifact",
        artifact_facts(verified.platform())
            == recorded_artifact(member(facts, "platform_artifact")),
    );
    differences
}

type ConfigFacts = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<(i64, u32)>,
    Option<String>,
    Option<(i64, u32)>,
);

fn config_facts(config: Option<&ConfigVerification>) -> Option<ConfigFacts> {
    config.map(|config| {
        (
            config.source.as_str().to_owned(),
            config.name.clone(),
            config.digest.clone(),
            config.reference.clone(),
            config.signing_key_hint.clone(),
            system_time(config.approval_time),
            config.registry_id.clone(),
            system_time(config.signature_time),
        )
    })
}

fn recorded_config(value: &Value) -> Option<ConfigFacts> {
    let config = value.as_object()?;
    Some((
        text(config, "source").to_owned(),
        recorded_text(config, "name"),
        text(config, "digest").to_owned(),
        recorded_text(config, "reference"),
        recorded_text(config, "signing_key_hint"),
        recorded_time(text(config, "approval_time")),
        recorded_text(config, "registry_id"),
        recorded_time(text(config, "signature_time")),
    ))
}

type ArtifactFacts = (
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<(i64, u32)>,
);

fn artifact_facts(artifact: Option<&ArtifactVerification>) -> Option<ArtifactFacts> {
    artifact.map(|artifact| {
        (
            artifact.source.as_str().to_owned(),
            artifact.repo.clone(),
            artifact.tag.clone(),
            artifact.digest.clone(),
            artifact.name.clone(),
            artifact.commit.clone(),
            system_time(artifact.approval_time),
        )
    })
}

fn recorded_artifact(value: &Value) -> Option<ArtifactFacts> {
    let artifact = value.as_object()?;
    Some((
        text(artifact, "source").to_owned(),
        recorded_text(artifact, "repo"),
        recorded_text(artifact, "tag"),
        text(artifact, "digest").to_owned(),
        recorded_text(artifact, "name"),
        recorded_text(artifact, "commit"),
        recorded_time(text(artifact, "approval_time")),
    ))
}

/// How a case came out against its record.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Agree,
    Skipped,
    /// The record accepts and this crate does not.
    Stricter(String),
    /// Any other difference, which is a failure.
    Differs(String),
}

fn replay(fixture: &Fixture, case: &Object) -> Outcome {
    let recorded = object(member(case, "expected"));
    let verifier = match (fixture.verifier(case), flag(recorded, "build_error")) {
        (Ok(verifier), false) => verifier,
        (Err(Error::Usage(_)), true) => return Outcome::Agree,
        (Err(error), true) => return Outcome::Differs(format!("build fails with {error}")),
        (Err(error), false) => return Outcome::Stricter(format!("build fails: {error}")),
        (Ok(_), true) => return Outcome::Differs("build succeeds".to_owned()),
    };
    let repo = text(case, "repo");
    let repo_check = verifier.check_repo_verifiability(repo);
    if let Err(error) = &repo_check
        && !matches!(error, Error::Usage(_))
    {
        return Outcome::Differs(format!("repository check fails with {error}"));
    }
    if repo_check.is_ok() != flag(recorded, "repo_check") {
        return Outcome::Differs(format!("repository check: {repo_check:?}"));
    }
    if verifier.caller_authorizes_config() != flag(recorded, "caller_authorizes") {
        return Outcome::Differs("caller_authorizes_config".to_owned());
    }
    let name = text(case, "doc");
    if name.is_empty() {
        return Outcome::Agree;
    }
    let Some(document) = fixture.document(name) else {
        return Outcome::Skipped;
    };
    let nonce = decode_hex(text(case, "nonce_hex")).unwrap();
    let result = verifier.verify_at(&document, &nonce, repo, instant(case));
    let verdict = text(recorded, "verdict");
    let got = match &result {
        Ok(_) => "accept".to_owned(),
        Err(Error::Usage(_)) => "usage".to_owned(),
        Err(Error::Verification(rejected)) => format!("reject/{}", rejected.layer()),
    };
    let want = match verdict {
        "reject" => format!("reject/{}", text(recorded, "layer")),
        other => other.to_owned(),
    };
    match result {
        Ok(verified) if verdict == "accept" => {
            let differences = compare_facts(&verified, object(member(recorded, "facts")));
            if differences.is_empty() {
                Outcome::Agree
            } else {
                Outcome::Differs(format!("facts differ: {differences:?}"))
            }
        }
        Err(error) if verdict == "accept" => Outcome::Stricter(format!("{got}: {error}")),
        Ok(_) => Outcome::Differs(format!("accepted, recorded {want}")),
        Err(_) if got == want => Outcome::Agree,
        Err(error) => Outcome::Differs(format!("{got}, recorded {want}: {error}")),
    }
}

/// The groups of cases, by the first part of a case's name. Each group is
/// replayed by its own test, so that the groups run side by side.
const GROUPS: [&str; 6] = [
    "build",
    "vector",
    "legacy-sev",
    "legacy-tdx",
    "config-sev",
    "config-tdx",
];

fn group_of(name: &str) -> &str {
    name.split('/').next().unwrap_or_default()
}

/// Replays the cases of one group and requires every outcome to be the
/// recorded one, or a listed stricter one.
fn replay_group(group: &str) {
    let fixture = Fixture::load();
    let cases = member(fixture.root_object(), "cases").as_array().unwrap();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for case in cases {
        let case = object(case);
        let name = text(case, "name");
        if group_of(name) != group {
            continue;
        }
        let listed = STRICTER.iter().any(|(listed, _)| *listed == name);
        let outcome = replay(&fixture, case);
        let key = match &outcome {
            Outcome::Agree if listed => {
                failures.push(format!("{name}: listed as stricter but agrees"));
                "differs"
            }
            Outcome::Agree => "agree",
            Outcome::Skipped => "skipped",
            Outcome::Stricter(_) if listed => "stricter",
            Outcome::Stricter(reason) => {
                failures.push(format!("{name}: stricter and not listed: {reason}"));
                "differs"
            }
            Outcome::Differs(reason) => {
                failures.push(format!("{name}: {reason}"));
                "differs"
            }
        };
        *counts.entry(key).or_default() += 1;
    }
    eprintln!("{group}: {counts:?}");
    assert!(!counts.is_empty(), "{group}: no cases");
    assert!(
        failures.is_empty(),
        "{group}: {} cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn recorded_builds_and_repository_checks() {
    replay_group("build");
}

#[test]
fn recorded_verifications_of_the_shared_vectors() {
    replay_group("vector");
}

#[test]
fn recorded_code_release_verifications_on_sev_snp() {
    replay_group("legacy-sev");
}

#[test]
fn recorded_code_release_verifications_on_tdx() {
    replay_group("legacy-tdx");
}

#[test]
fn recorded_config_verifications_on_sev_snp() {
    replay_group("config-sev");
}

#[test]
fn recorded_config_verifications_on_tdx() {
    replay_group("config-tdx");
}

#[test]
fn every_recorded_case_is_in_a_group() {
    let fixture = Fixture::load();
    let cases = member(fixture.root_object(), "cases").as_array().unwrap();
    assert!(cases.len() > 600, "{} cases", cases.len());
    for case in cases {
        let name = text(object(case), "name");
        assert!(GROUPS.contains(&group_of(name)), "{name}");
    }
    for (listed, _) in STRICTER {
        assert!(
            cases
                .iter()
                .any(|case| text(object(case), "name") == *listed),
            "{listed} is not a case"
        );
    }
}

#[test]
fn the_fixture_covers_both_flows_on_both_platforms() {
    let fixture = Fixture::load();
    let cases = member(fixture.root_object(), "cases").as_array().unwrap();
    let accepted = |prefix: &str| {
        cases
            .iter()
            .map(object)
            .filter(|case| {
                text(case, "name").starts_with(prefix)
                    && text(object(member(case, "expected")), "verdict") == "accept"
            })
            .count()
    };
    for prefix in ["legacy-sev/", "legacy-tdx/", "config-sev/", "config-tdx/"] {
        assert!(accepted(prefix) >= 10, "{prefix}: {}", accepted(prefix));
    }
    // A config, a runtime and a platform artifact that are all endorsed and
    // approved, with the earliest approval setting the deadline.
    assert!(accepted("config-sev/full-") >= 10);
}
