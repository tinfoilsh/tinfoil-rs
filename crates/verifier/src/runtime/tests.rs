use sha2::{Digest, Sha256};

use super::*;
use crate::canonical;
use crate::document::collateral::RUNTIME_REPO;
use crate::json::Value;
use crate::probes::Probes;

const ZERO: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn reference(tag: &str, digest: &str) -> RuntimeReference {
    RuntimeReference {
        repo: RUNTIME_REPO.to_owned(),
        tag: tag.to_owned(),
        digest: digest.to_owned(),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    canonical::encode_lower_hex(&Sha256::digest(data))
}

/// Each case records whether the manifest decodes on its own, with the
/// version and the registers that it decodes to, and whether it is accepted
/// against a pin of the recorded tag and digest. A case without a digest is
/// pinned to the digest of its own bytes.
#[test]
fn manifests_agree_with_the_recorded_probes() {
    let probes = Probes::parse(include_bytes!("../../tests/data/manifest_probes.json"));
    let mut failures = Vec::new();
    let (mut total, mut decoded, mut accepted) = (0, 0, 0);
    for case in probes.cases() {
        total += 1;
        let name = case.name();
        let input = case.input();
        match (decode_manifest(&input), case.flag("decode_accept")) {
            (Ok(manifest), true) => {
                decoded += 1;
                let launch = &manifest.measurements.tdx_launch;
                let mut registers = vec![manifest.measurements.snp_launch.measurement.as_str()];
                registers.extend(launch.registers());
                let want: Vec<&str> = case
                    .get("registers")
                    .and_then(Value::as_array)
                    .unwrap()
                    .iter()
                    .map(|register| match register.as_str().unwrap() {
                        "zero" => ZERO,
                        other => other,
                    })
                    .collect();
                if manifest.version != case.text("version") || registers != want {
                    failures.push(format!("{name}: decoded to other values"));
                }
            }
            (Err(_), false) => {}
            (Ok(_), false) => failures.push(format!("{name}: decoded, want a rejection")),
            (Err(error), true) => failures.push(format!("{name}: decode rejected: {error}")),
        }
        let digest = match case.text("digest") {
            "" => sha256_hex(&input),
            digest => digest.to_owned(),
        };
        let pin = reference(case.text("tag"), &digest);
        match (parse_manifest(&input, &pin), case.flag("accept")) {
            (Ok(_), true) => accepted += 1,
            (Err(_), false) => {}
            (Ok(_), false) => failures.push(format!("{name}: accepted, want a rejection")),
            (Err(error), true) => failures.push(format!("{name}: rejected: {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(total >= 400, "{total} cases");
    assert!(
        decoded >= 100 && accepted >= 80,
        "{decoded} decoded, {accepted} accepted"
    );
}

/// Cases that are recorded as accepted and refused here by design, by
/// class, with the number of cases in each.
const REFUSED_HERE: &[(&str, usize)] = &[
    // Constructs that would have to be interpreted to find the pin.
    ("merge key at the top level", 13),
    ("interpreted tag on a top-level key or on the pin", 10),
    ("alias as a top-level key", 4),
    // Streams with more than one possible reading, or none as UTF-8.
    (
        "next-line, line separator or paragraph separator character",
        18,
    ),
    ("UTF-16 stream", 2),
    ("byte order mark inside the document", 3),
    // Bounds.
    ("config over the size limit", 2),
    ("flow nesting deeper than 255", 10),
    // Syntax that the parser refuses.
    ("comment not preceded by a blank", 7),
    ("quoted scalar continued at its parent's indentation", 3),
    ("flow collection continued at its parent's indentation", 1),
    ("tab directly after a key's colon", 3),
    ("tab at the start of a continuation line", 2),
    (
        "plain scalar that starts with a dash before a flow indicator",
        1,
    ),
    ("escaped single quote in a double-quoted scalar", 1),
    ("alias glued to the colon of a block key", 1),
    ("alias glued to the colon of a flow key", 1),
    ("tag forms that the parser refuses", 1),
    ("final line break of a block scalar pin", 1),
];

/// Cases that are recorded as rejected and accepted here, by syntax class,
/// with the number of cases in each. The recorded outcome follows a
/// stricter YAML dialect; none of these changes which pin is read.
const ACCEPTED_HERE: &[(&str, usize)] = &[
    ("control character or noncharacter", 13),
    ("tab or reserved indicator where a token starts", 10),
    ("tab in indentation", 3),
    ("empty key or missing node in a flow collection", 11),
    ("empty or misplaced block key", 5),
    ("directive", 6),
    ("directive that ends a bare document", 1),
    (
        "anchor or alias name beyond letters, digits, underscore and dash",
        3,
    ),
    ("tag directly followed by a flow indicator", 2),
    ("empty verbatim tag", 1),
    ("escape sequence outside the YAML 1.1 set", 1),
    (
        "implicit key longer than 1,024 characters or ending its line",
        1,
    ),
];

/// Each case records whether a config yields a runtime pin, and the tag and
/// digest of that pin. The cases fall into three groups:
///
/// - most have the recorded outcome here too, with the same pin;
/// - a case whose `differs` names a class in [`REFUSED_HERE`] is recorded
///   as accepted and is refused here;
/// - a case whose `differs` names a class in [`ACCEPTED_HERE`] is recorded
///   as rejected and yields a pin here; the case carries that pin.
///
/// Every case is checked against its group, and each class must have
/// exactly the listed number of cases.
#[test]
fn configs_agree_with_the_recorded_probes() {
    let probes = Probes::parse(include_bytes!("../../tests/data/config_probes.json"));
    let mut failures = Vec::new();
    let (mut total, mut same_pin) = (0, 0);
    let mut differing = std::collections::BTreeMap::new();
    for case in probes.cases() {
        total += 1;
        let name = case.name();
        let outcome = runtime_from_config(&case.input());
        let recorded = case.flag("accept");
        let class = case.text("differs");
        if !class.is_empty() {
            *differing.entry((recorded, class)).or_insert(0_usize) += 1;
            match outcome {
                Ok(_) if recorded => failures.push(format!("{name}: no longer refused ({class})")),
                Err(_) if !recorded => failures.push(format!("{name}: no longer read ({class})")),
                // The case carries the pin that is read here.
                Ok(pin) if pin != reference(case.text("tag"), case.text("digest")) => {
                    failures.push(format!("{name}: read {pin:?}"));
                }
                _ => {}
            }
            continue;
        }
        match (outcome, recorded) {
            (Ok(pin), true) => {
                same_pin += 1;
                if pin != reference(case.text("tag"), case.text("digest")) {
                    failures.push(format!("{name}: read {pin:?}"));
                }
            }
            (Err(_), false) => {}
            (Ok(_), false) => failures.push(format!("{name}: accepted, want a rejection")),
            (Err(error), true) => failures.push(format!("{name}: rejected: {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    let listed = |recorded: bool, classes: &[(&'static str, usize)]| {
        classes
            .iter()
            .map(|(class, count)| ((recorded, *class), *count))
            .collect::<Vec<_>>()
    };
    let mut expected = listed(true, REFUSED_HERE);
    expected.extend(listed(false, ACCEPTED_HERE));
    expected.sort_unstable();
    assert_eq!(differing.into_iter().collect::<Vec<_>>(), expected);
    assert!(total >= 900, "{total} cases");
    assert!(same_pin >= 350, "{same_pin} with the same pin");
}

fn valid_manifest() -> String {
    let measurement = "cd".repeat(MEASUREMENT_SIZE);
    format!(
        r#"{{"version":"v0.15.0","igvm":{{"format_version":1,"snp_launch":{{"measurement":"{measurement}"}},"tdx_launch":{{"mrtd":"{measurement}","rtmr0":"{ZERO}","rtmr1":"{ZERO}","rtmr2":"{ZERO}","rtmr3":"{ZERO}"}}}}}}"#
    )
}

/// The pin of `manifest`: its digest, and the given tag.
fn pin_of(manifest: &str, tag: &str) -> RuntimeReference {
    reference(tag, &sha256_hex(manifest.as_bytes()))
}

fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from} must occur once");
    text.replace(from, to)
}

fn parsed(manifest: &str, tag: &str) -> Result<Manifest, String> {
    parse_manifest(manifest.as_bytes(), &pin_of(manifest, tag)).map_err(|error| error.to_string())
}

#[test]
fn a_manifest_requires_complete_supported_measurements() {
    let valid = valid_manifest();
    let measurement = "cd".repeat(MEASUREMENT_SIZE);
    let manifest = parsed(&valid, "v0.15.0").unwrap();
    assert_eq!(manifest.version, "v0.15.0");
    assert_eq!(manifest.measurements.format_version, FORMAT_VERSION);
    assert_eq!(manifest.measurements.snp_launch.measurement, measurement);
    assert_eq!(
        manifest.measurements.tdx_launch.registers(),
        [measurement.as_str(), ZERO, ZERO, ZERO, ZERO]
    );

    // The digest covers every byte.
    let with_newline = format!("{valid}\n");
    let error = parse_manifest(with_newline.as_bytes(), &pin_of(&valid, "v0.15.0")).unwrap_err();
    assert_eq!(
        error.to_string(),
        "runtime manifest does not match the config's digest pin"
    );

    let uppercase = measurement.to_uppercase();
    let nonzero = "ab".repeat(MEASUREMENT_SIZE);
    let cases: [(&str, String, &str); 9] = [
        (
            "old manifest",
            r#"{"version":"v0.15.0"}"#.to_owned(),
            "runtime manifest format is unsupported",
        ),
        (
            "unknown format",
            replace_once(&valid, "\"format_version\":1", "\"format_version\":2"),
            "runtime manifest format is unsupported",
        ),
        (
            "wrong release",
            replace_once(&valid, "v0.15.0", "v0.15.1"),
            "runtime manifest version \"v0.15.1\" does not match the config's pin \"v0.15.0\"",
        ),
        (
            "missing SNP launch",
            replace_once(
                &valid,
                &format!("\"snp_launch\":{{\"measurement\":\"{measurement}\"}},"),
                "",
            ),
            "runtime manifest requires complete launch measurements",
        ),
        (
            "null TDX launch",
            format!(
                r#"{{"version":"v0.15.0","igvm":{{"format_version":1,"snp_launch":{{"measurement":"{measurement}"}},"tdx_launch":null}}}}"#
            ),
            "runtime manifest requires complete launch measurements",
        ),
        (
            "nonzero RTMR",
            replace_once(
                &valid,
                &format!("\"rtmr2\":\"{ZERO}\""),
                &format!("\"rtmr2\":\"{nonzero}\""),
            ),
            "runtime format v1 requires zero TDX RTMRs",
        ),
        (
            "missing RTMR",
            replace_once(&valid, &format!(",\"rtmr3\":\"{ZERO}\""), ""),
            "runtime format v1 requires zero TDX RTMRs",
        ),
        (
            "bad MRTD",
            replace_once(
                &valid,
                &format!("\"mrtd\":\"{measurement}\""),
                "\"mrtd\":\"bad\"",
            ),
            "MRTD is not hex: odd number of digits",
        ),
        (
            "uppercase SNP measurement",
            replace_once(
                &valid,
                &format!("\"measurement\":\"{measurement}\""),
                &format!("\"measurement\":\"{uppercase}\""),
            ),
            "SNP measurement is not lowercase hex",
        ),
    ];
    for (name, manifest, want) in cases {
        assert_eq!(parsed(&manifest, "v0.15.0").unwrap_err(), want, "{name}");
    }
}

#[test]
fn a_manifest_may_carry_other_members_but_no_repeated_one() {
    let valid = valid_manifest();
    let rest = valid.strip_prefix('{').unwrap();

    let with_metadata = format!(r#"{{"root":"host image digest",{rest}"#);
    let manifest = parsed(&with_metadata, "v0.15.0").unwrap();
    assert_eq!(manifest, parsed(&valid, "v0.15.0").unwrap());
    // The added member changes the digest, so the old pin no longer fits.
    let error = parse_manifest(with_metadata.as_bytes(), &pin_of(&valid, "v0.15.0")).unwrap_err();
    assert!(error.to_string().contains("digest pin"));

    for repeated in [
        format!(r#"{{"version":"v0.15.0",{rest}"#),
        format!(r#"{{"root":"one","root":"two",{rest}"#),
    ] {
        let error = parsed(&repeated, "v0.15.0").unwrap_err();
        assert!(error.starts_with("parsing runtime manifest: "), "{error}");
    }
}

#[test]
fn manifests_of_two_releases_have_independent_pins() {
    let cpu = valid_manifest();
    let gpu = cpu.replace("v0.15.0", "v0.15.0+gpu").replace(
        &"cd".repeat(MEASUREMENT_SIZE),
        &"ef".repeat(MEASUREMENT_SIZE),
    );
    let manifest = parsed(&gpu, "v0.15.0+gpu").unwrap();
    assert_eq!(manifest.version, "v0.15.0+gpu");
    let (cpu_pin, gpu_pin) = (pin_of(&cpu, "v0.15.0"), pin_of(&gpu, "v0.15.0+gpu"));
    assert_ne!(cpu_pin.digest, gpu_pin.digest);

    let mismatch = |manifest: &str, pin: &RuntimeReference| {
        parse_manifest(manifest.as_bytes(), pin)
            .unwrap_err()
            .to_string()
    };
    assert!(mismatch(&cpu, &gpu_pin).contains("digest pin"));
    assert!(mismatch(&gpu, &cpu_pin).contains("digest pin"));
    // The right digest under the other release's tag.
    assert_eq!(
        mismatch(&gpu, &pin_of(&gpu, "v0.15.0")),
        "runtime manifest version \"v0.15.0+gpu\" does not match the config's pin \"v0.15.0\""
    );
}

#[test]
fn the_digest_is_checked_before_anything_is_parsed() {
    let pin = reference("v0.15.0", &"00".repeat(32));
    for data in [&b""[..], b"not json", b"{}"] {
        assert_eq!(
            parse_manifest(data, &pin).unwrap_err().to_string(),
            "runtime manifest does not match the config's digest pin"
        );
    }
}

#[test]
fn a_manifest_has_size_bounds() {
    let bounds = "runtime manifest size is outside allowed bounds";
    assert_eq!(decode_manifest(b"").unwrap_err().to_string(), bounds);
    let valid = valid_manifest();
    let padded = |size: usize| {
        let mut data = valid.clone().into_bytes();
        data.resize(size, b' ');
        data
    };
    assert!(decode_manifest(&padded(MAX_MANIFEST_SIZE)).is_ok());
    assert_eq!(
        decode_manifest(&padded(MAX_MANIFEST_SIZE + 1))
            .unwrap_err()
            .to_string(),
        bounds
    );
    // An empty manifest that matches its pin is still out of bounds.
    assert_eq!(
        parse_manifest(b"", &pin_of("", "v0.15.0"))
            .unwrap_err()
            .to_string(),
        bounds
    );
}

#[test]
fn a_manifest_version_is_a_full_semantic_version() {
    let valid = valid_manifest();
    for version in ["v0.15", "0.15.0", "v0.15.0+", "", "v0.15.0 "] {
        let manifest = replace_once(&valid, "v0.15.0", version);
        assert_eq!(
            decode_manifest(manifest.as_bytes())
                .unwrap_err()
                .to_string(),
            "runtime manifest version must be a full semantic version",
            "{version:?}"
        );
    }
    // The version is judged before the measurements are.
    assert_eq!(
        decode_manifest(br#"{"version":"v1"}"#)
            .unwrap_err()
            .to_string(),
        "runtime manifest version must be a full semantic version"
    );
    // A member of the wrong type is a parse error, wherever the checks
    // that follow would have stopped.
    let error = decode_manifest(br#"{"version":"v1","igvm":{"format_version":"1"}}"#).unwrap_err();
    assert!(error.to_string().starts_with("parsing runtime manifest: "));
}

const DIGEST: &str = "abababababababababababababababababababababababababababababababab";

fn good() -> String {
    format!("cvm-version: 0.15.0@sha256:{DIGEST}\n")
}

fn config_error(config: &str) -> String {
    runtime_from_config(config.as_bytes())
        .unwrap_err()
        .to_string()
}

/// Whether the YAML parser itself rejected the config.
fn is_syntax_error(config: &str) -> bool {
    config_error(config).starts_with("parsing config runtime pin: yaml: ")
}

#[test]
fn reads_the_runtime_pin_of_a_config() {
    for (version, tag) in [
        ("0.15.0", "v0.15.0"),
        ("v0.15.0", "v0.15.0"),
        ("0.15.0-rc.1", "v0.15.0-rc.1"),
        ("0.15.0+gpu", "v0.15.0+gpu"),
        ("v0.15.0+gpu", "v0.15.0+gpu"),
        ("0.15.0-rc.1+gpu", "v0.15.0-rc.1+gpu"),
        ("0.15.0+mini", "v0.15.0+mini"),
        ("0.15.0+containers.initrd-1", "v0.15.0+containers.initrd-1"),
        ("0.15.0+GPU", "v0.15.0+GPU"),
    ] {
        let config = format!("cvm-version: {version}@sha256:{DIGEST}\ncontainers: []\n");
        assert_eq!(
            runtime_from_config(config.as_bytes()),
            Ok(reference(tag, DIGEST)),
            "{version}"
        );
    }

    let good = good();
    let pin = "cvm-version must pin a runtime manifest SHA-256 digest";
    let tag = "runtime tag must be a full semantic version";
    let cases: [(&str, String, &str); 11] = [
        ("unpinned", "cvm-version: 0.15.0\n".to_owned(), pin),
        (
            "duplicate",
            format!("{good}{good}"),
            "parsing config runtime pin: a top-level mapping key is already defined",
        ),
        (
            "two documents",
            format!("{good}---\n{good}"),
            "config must contain exactly one YAML document",
        ),
        (
            "bad digest",
            good.replace(DIGEST, &DIGEST.to_uppercase()),
            "runtime digest is not lowercase hex",
        ),
        (
            "path metadata",
            good.replace("0.15.0", "0.15.0+mini/other"),
            tag,
        ),
        ("partial version", good.replace("0.15.0", "0.15+gpu"), tag),
        ("empty metadata", good.replace("0.15.0", "0.15.0+"), tag),
        (
            "double metadata",
            good.replace("0.15.0", "0.15.0+gpu+gpu"),
            tag,
        ),
        (
            "short digest",
            good.replace(DIGEST, &DIGEST[2..]),
            "runtime digest must be 32 bytes, got 31",
        ),
        (
            "extra digest",
            good.replace(DIGEST, &format!("{DIGEST}@sha256:{DIGEST}")),
            "runtime digest is not lowercase hex",
        ),
        ("missing version", "containers: []\n".to_owned(), pin),
    ];
    for (name, config, want) in cases {
        assert_eq!(config_error(&config), want, "{name}");
    }
}

#[test]
fn a_config_is_one_document_holding_a_mapping() {
    let good = good();
    assert_eq!(
        config_error(""),
        "parsing config runtime pin: the config is empty"
    );
    assert_eq!(
        config_error("# nothing\n"),
        "parsing config runtime pin: the config is empty"
    );
    let pin = "cvm-version must pin a runtime manifest SHA-256 digest";
    assert_eq!(config_error("---\n"), pin);
    assert_eq!(config_error("~\n"), pin);
    assert_eq!(config_error(&format!("- {good}")), pin);
    assert_eq!(
        config_error(&format!("[cvm-version, 0.15.0@sha256:{DIGEST}]\n")),
        pin
    );
    assert_eq!(config_error(&format!("a:\n  {good}")), pin);
    for second in ["---\n", "--- x\n", "---\na: b\n"] {
        assert_eq!(
            config_error(&format!("{good}{second}")),
            "config must contain exactly one YAML document"
        );
    }
    assert!(is_syntax_error(&format!("{good}a: [\n")));
    assert!(runtime_from_config(format!("---\n{good}...\n# end\n").as_bytes()).is_ok());
    assert!(runtime_from_config(format!("\u{feff}{good}").as_bytes()).is_ok());
}

#[test]
fn top_level_keys_are_scalars_that_do_not_repeat() {
    let good = good();
    let error = |rest: &str| config_error(&format!("{good}{rest}"));
    let repeated = "parsing config runtime pin: a top-level mapping key is already defined";
    assert_eq!(error("a: 1\na: 2\n"), repeated);
    assert_eq!(error("a: 1\n\"a\": 2\n"), repeated);
    assert_eq!(error("1: a\n'1': b\n"), repeated);
    assert_eq!(error("\"cvm-version\": x\n"), repeated);
    assert_eq!(error("!!str cvm-version: x\n"), repeated);
    let scalar = "parsing config runtime pin: a top-level key must be a scalar";
    assert_eq!(error("[a]: b\n"), scalar);
    assert_eq!(error("? {a: b}\n: c\n"), scalar);
    let alias = "parsing config runtime pin: a top-level key cannot be an alias";
    assert_eq!(error("x: &k y\n*k : 1\n"), alias);
    assert_eq!(error("x: &k [y]\n*k : 1\n"), alias);
    // Keys that differ in their text are different keys, whatever they
    // would mean as numbers, and a repeat below the top level is not this
    // module's to judge.
    for accepted in [
        "1: a\n0x1: b\n",
        "~: a\nnull: b\n",
        "a: {b: 1, b: 2}\n",
        "true: a\nTrue: b\n",
    ] {
        let config = format!("{good}{accepted}");
        assert_eq!(
            runtime_from_config(config.as_bytes()),
            Ok(reference("v0.15.0", DIGEST)),
            "{accepted}"
        );
    }
}

#[test]
fn the_pin_is_a_string_scalar_or_an_alias_of_one() {
    let pin = format!("0.15.0@sha256:{DIGEST}");
    let expected = Ok(reference("v0.15.0", DIGEST));
    for config in [
        format!("cvm-version: \"{pin}\"\n"),
        format!("cvm-version: '{pin}'\n"),
        format!("cvm-version: |-\n  {pin}\n"),
        format!("cvm-version: >-\n  {pin}\n"),
        format!("cvm-version: !!str {pin}\n"),
        format!("cvm-version: !custom {pin}\n"),
        format!("cvm-version: ! {pin}\n"),
        format!("!!str cvm-version: {pin}\n"),
        format!("&key cvm-version: &pin {pin}\n"),
        format!("a: &pin {pin}\ncvm-version: *pin\n"),
        format!("a: [x, {{y: &pin {pin}}}]\ncvm-version: *pin\n"),
        format!("a: &pin x\nb: &pin {pin}\ncvm-version: *pin\n"),
        format!("{{\"cvm-version\": \"{pin}\", \"containers\": []}}\n"),
        format!("? cvm-version\n: {pin}\n"),
    ] {
        assert_eq!(runtime_from_config(config.as_bytes()), expected, "{config}");
    }

    let unpinned = "cvm-version must pin a runtime manifest SHA-256 digest";
    let scalar = "parsing config runtime pin: cvm-version must be a scalar";
    for (config, want) in [
        ("cvm-version: 1.2\n".to_owned(), unpinned),
        ("cvm-version: true\n".to_owned(), unpinned),
        ("cvm-version: null\n".to_owned(), unpinned),
        ("cvm-version: ~\n".to_owned(), unpinned),
        ("cvm-version:\n".to_owned(), unpinned),
        ("cvm-version: \"1.2\"\n".to_owned(), unpinned),
        // A literal block keeps its final line break, which is not part of
        // a digest.
        (
            format!("cvm-version: |\n  {pin}\n"),
            "runtime digest is not lowercase hex",
        ),
        (format!("cvm-version: [{pin}]\n"), scalar),
        (format!("cvm-version:\n  a: {pin}\n"), scalar),
        (format!("a: &pin [{pin}]\ncvm-version: *pin\n"), scalar),
        ("&doc\ncvm-version: *doc\n".to_owned(), scalar),
        // A null key names nothing, so its value is not the pin.
        (format!("~: {pin}\n"), unpinned),
        (format!("CVM-VERSION: {pin}\n"), unpinned),
    ] {
        assert_eq!(config_error(&config), want, "{config}");
    }
    // An alias must name an anchor that came before it.
    assert!(is_syntax_error("cvm-version: *pin\n"));
    assert!(is_syntax_error(&format!("cvm-version: {pin}\na: *nope\n")));
    assert!(is_syntax_error(&format!(
        "cvm-version: *pin\na: &pin {pin}\n"
    )));
}

#[test]
fn constructs_that_would_need_interpreting_are_refused() {
    let pin = format!("0.15.0@sha256:{DIGEST}");
    let good = good();
    let merge = "parsing config runtime pin: merge keys are not supported at the top level";
    assert_eq!(
        config_error(&format!("<<: {{cvm-version: {pin}}}\n")),
        merge
    );
    assert_eq!(config_error(&format!("{good}<<: {{a: b}}\n")), merge);
    assert_eq!(
        config_error(&format!("{good}!!merge <<: {{a: b}}\n")),
        merge
    );
    assert_eq!(config_error(&format!("{good}! <<: {{a: b}}\n")), merge);
    for tagged in [
        "cvm-version: !!binary MC4xNS4w\n".to_owned(),
        format!("{good}!!binary YQ==: b\n"),
        format!("{good}!!int 1: b\n"),
        format!("{good}!!null x: b\n"),
        format!("cvm-version: !!timestamp {pin}\n"),
        format!("cvm-version: !<tag:yaml.org,2002:float> {pin}\n"),
        "a: &pin !!binary MC4xNS4w\ncvm-version: *pin\n".to_owned(),
    ] {
        let message = config_error(&tagged);
        assert!(
            message.ends_with("is not supported on a top-level key or on cvm-version"),
            "{tagged}: {message}"
        );
    }
    assert_eq!(
        config_error(&format!("a: &key cvm-version\n*key : {pin}\n")),
        "parsing config runtime pin: a top-level key cannot be an alias"
    );
    // None of this applies below the top level or to a quoted key.
    for accepted in [
        "a:\n  <<: {b: c}\n",
        "\"<<\": {a: b}\n",
        "a: !!binary YQ==\n",
        "a: {!!int 1: b}\n",
        "a: &k b\nc: {*k : d}\n",
    ] {
        let config = format!("{good}{accepted}");
        assert_eq!(
            runtime_from_config(config.as_bytes()),
            Ok(reference("v0.15.0", DIGEST)),
            "{accepted}"
        );
    }
}

/// These three characters end a line for some YAML parsers and are text
/// for others, so a config that contains one can state two different pins.
#[test]
fn ambiguous_line_breaks_are_refused() {
    let good = good();
    let other = good.replace("0.15.0", "0.16.0");
    let refused = "parsing config runtime pin: the config contains a line break other than a line feed or a carriage return";
    for line_break in ['\u{85}', '\u{2028}', '\u{2029}'] {
        // Read with the character as a line break, the first line is a
        // comment and the block scalar holds the second pin. Read with it
        // as text, the comment runs on and the second pin is the only key.
        let two_readings = format!("# c{line_break}{good}x: |\n  {other}");
        assert_eq!(config_error(&two_readings), refused);
        assert_eq!(config_error(&format!("{good}# {line_break}\n")), refused);
        assert_eq!(
            config_error(&format!("{good}a: \"{line_break}\"\n")),
            refused
        );
    }
    let carriage_returns = format!("{}a: b\r", good.replace('\n', "\r\n"));
    assert_eq!(
        runtime_from_config(carriage_returns.as_bytes()),
        Ok(reference("v0.15.0", DIGEST))
    );
}

#[test]
fn a_config_has_size_and_depth_bounds() {
    let good = good();
    let padded = |size: usize| {
        let mut data = good.clone().into_bytes();
        data.resize(size, b'\n');
        data
    };
    assert!(runtime_from_config(&padded(MAX_CONFIG_SIZE)).is_ok());
    assert_eq!(
        runtime_from_config(&padded(MAX_CONFIG_SIZE + 1))
            .unwrap_err()
            .to_string(),
        "parsing config runtime pin: the config is larger than 1048576 bytes"
    );

    let block = |depth: usize| format!("{good}a:\n {}x\n", "- ".repeat(depth));
    assert!(runtime_from_config(block(9_998).as_bytes()).is_ok());
    assert_eq!(
        config_error(&block(10_001)),
        "parsing config runtime pin: exceeded max depth of 10000"
    );
    let flow = |depth: usize| format!("{good}a: {}{}\n", "[".repeat(depth), "]".repeat(depth));
    assert!(runtime_from_config(flow(200).as_bytes()).is_ok());
    assert!(is_syntax_error(&flow(300)));
}

#[test]
fn deep_and_long_configs_need_no_deep_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let good = good();
            for config in [
                format!("{good}a:\n {}x\n", "- ".repeat(9_000)),
                format!("{good}a:\n {}x\n", "- ".repeat(400_000)),
                format!("{good}a: {}", "[".repeat(400_000)),
                format!("{good}a: {}", "{a: ".repeat(200_000)),
                format!("{good}{}", "? ".repeat(400_000)),
                format!("{good}a: [{}]\n", "&a x, *a, ".repeat(50_000)),
            ] {
                // Each returns, with a pin or an error.
                let _ = runtime_from_config(config.as_bytes());
            }
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn a_config_must_be_utf8() {
    let good = good();
    let with = |tail: &[u8]| [good.as_bytes(), tail].concat();
    let not_utf8 = "parsing config runtime pin: the config is not UTF-8";
    assert_eq!(
        runtime_from_config(&with(b"# \xff\n"))
            .unwrap_err()
            .to_string(),
        not_utf8
    );
    let utf16: Vec<u8> = format!("\u{feff}{good}")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(
        runtime_from_config(&utf16).unwrap_err().to_string(),
        not_utf8
    );
    // A byte order mark belongs at the very start.
    let inside = format!("{good}\u{feff}a: b\n");
    assert!(is_syntax_error(&inside));
    assert!(runtime_from_config(&with("# \u{e9} \u{4e2d} \u{1f600} \u{a0}\n".as_bytes())).is_ok());
}

/// A small deterministic generator, so that the inputs are the same on
/// every run.
struct Random(u64);

impl Random {
    fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) as usize) % bound
    }
}

#[test]
fn arbitrary_configs_end_in_a_pin_or_an_error() {
    const PIECES: &[&str] = &[
        "cvm-version: 0.15.0@sha256:abababababababababababababababababababababababababababababababab\n",
        "cvm-version: ",
        "0.15.0@sha256:",
        "abababababababababababababababababababababababababababababababab",
        "a",
        "b: ",
        ": ",
        "- ",
        "? ",
        "\n",
        "\n  ",
        "\n    ",
        " ",
        "\t",
        "[",
        "]",
        "{",
        "}",
        ",",
        "#",
        "&x ",
        "*x",
        "!",
        "!!str ",
        "!<t> ",
        "|",
        ">-",
        "|2+",
        "'",
        "\"",
        "\\",
        "\\x4",
        "%",
        "%YAML 1.1\n",
        "%TAG !e! t\n",
        "---",
        "...",
        "---\n",
        "\r",
        "\u{e9}",
        "\u{feff}",
        "\u{1}",
        "<<",
        "~",
        "@",
        "`",
        "0",
        ":",
        "-",
        "?",
        "\n\n",
        "\n# c",
        " # c\n",
        "k: v\n",
        "\u{a0}",
    ];
    let mut random = Random(1);
    let mut pins = 0;
    for _ in 0..30_000 {
        let pieces = 1 + random.next(24);
        let text: String = (0..pieces)
            .map(|_| PIECES[random.next(PIECES.len())])
            .collect();
        // The read returns: it neither panics nor runs away.
        if runtime_from_config(text.as_bytes()).is_ok() {
            pins += 1;
        }
    }
    assert!(pins > 0, "no input yielded a pin");
}
