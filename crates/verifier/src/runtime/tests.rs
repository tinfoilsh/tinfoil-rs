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

/// A JSON config in its one byte form that pins `version`.
fn json_config(version: &str) -> String {
    format!(
        r#"{{"containers":[],"cpus":2,"cvm-version":"{version}@sha256:{DIGEST}","shim":{{"upstream-port":8080}}}}"#
    )
}

fn yaml_config(version: &str) -> String {
    format!("cvm-version: {version}@sha256:{DIGEST}\ncpus: 2\n")
}

/// A JSON escape of a UTF-16 code unit, given as four hex digits.
fn unicode_escape(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

const NOT_CANONICAL: &str =
    "parsing config runtime pin: JSON config is not in canonical form (RFC 8785)";
const TAKES_JSON: &str = "cvm-version v0.15.5-rc.1 and later take a JSON config";

fn not_an_integer(literal: &str) -> String {
    format!(
        "parsing config runtime pin: number {literal} in a JSON config is not an integer between -(2^53-1) and 2^53-1"
    )
}

#[test]
fn the_format_of_a_config_follows_the_pinned_version() {
    for (name, config, tag) in [
        (
            "JSON at the first JSON version",
            json_config("0.15.5-rc.1"),
            "v0.15.5-rc.1",
        ),
        (
            "JSON with a v prefix",
            json_config("v0.15.5-rc.1"),
            "v0.15.5-rc.1",
        ),
        (
            "JSON with build metadata",
            json_config("0.15.5-rc.1+gpu"),
            "v0.15.5-rc.1+gpu",
        ),
        ("JSON for a later version", json_config("0.16.0"), "v0.16.0"),
        (
            "YAML before the JSON version",
            yaml_config("0.15.5-rc.0"),
            "v0.15.5-rc.0",
        ),
        (
            "YAML for an earlier release",
            yaml_config("0.15.4"),
            "v0.15.4",
        ),
        (
            "flow-style YAML before it",
            json_config("0.15.4"),
            "v0.15.4",
        ),
    ] {
        assert_eq!(
            runtime_from_config(config.as_bytes()),
            Ok(reference(tag, DIGEST)),
            "{name}"
        );
    }

    let canonical = json_config("0.15.5-rc.1");
    let replace = |from: &str, to: &str| replace_once(&canonical, from, to);
    let escaped_name = format!("\"{}pus\"", unicode_escape("0063"));
    for (name, config, want) in [
        (
            "YAML at the first JSON version",
            yaml_config("0.15.5-rc.1"),
            TAKES_JSON.to_owned(),
        ),
        (
            "YAML with build metadata",
            yaml_config("0.15.5-rc.1+gpu"),
            TAKES_JSON.to_owned(),
        ),
        (
            "YAML for a later version",
            yaml_config("1.0.0"),
            TAKES_JSON.to_owned(),
        ),
        (
            "whitespace",
            replace(r#""cpus":2"#, r#""cpus": 2"#),
            NOT_CANONICAL.to_owned(),
        ),
        (
            "trailing newline",
            format!("{canonical}\n"),
            NOT_CANONICAL.to_owned(),
        ),
        (
            "members out of order",
            replace(
                r#""containers":[],"cpus":2,"#,
                r#""cpus":2,"containers":[],"#,
            ),
            NOT_CANONICAL.to_owned(),
        ),
        (
            "escaped character",
            replace(r#""cpus""#, &escaped_name),
            NOT_CANONICAL.to_owned(),
        ),
        (
            "null",
            replace(r#""cpus":2"#, r#""cpus":null"#),
            "parsing config runtime pin: null is not allowed in a JSON config".to_owned(),
        ),
        (
            "fraction",
            replace(r#""cpus":2"#, r#""cpus":2.5"#),
            not_an_integer("2.5"),
        ),
        (
            "exponent",
            replace(r#""cpus":2"#, r#""cpus":2e0"#),
            not_an_integer("2e0"),
        ),
        (
            "integer too large",
            replace(r#""cpus":2"#, r#""cpus":9007199254740992"#),
            not_an_integer("9007199254740992"),
        ),
        // A repeated member is not strict JSON, so the YAML reader judges it.
        (
            "repeated member",
            replace(r#""cpus":2,"#, r#""cpus":2,"cpus":2,"#),
            "parsing config runtime pin: a top-level mapping key is already defined".to_owned(),
        ),
        (
            "unpinned version",
            replace(&format!("@sha256:{DIGEST}"), ""),
            "cvm-version must pin a runtime manifest SHA-256 digest".to_owned(),
        ),
    ] {
        assert_eq!(config_error(&config), want, "{name}");
    }
    // A second value makes the bytes neither JSON nor YAML.
    assert!(is_syntax_error(&format!("{canonical}{canonical}")));
}

#[test]
fn the_first_json_version_is_found_by_precedence() {
    assert!(crate::semver::is_full(JSON_CONFIG_MIN_VERSION));
    // A config in YAML is read below the first JSON version only.
    for (version, below) in [
        ("0.15.4", true),
        ("0.15.5-0", true),
        ("0.15.5-alpha", true),
        ("0.15.5-rc", true),
        ("0.15.5-rc.0", true),
        ("0.15.5-rc.0+gpu", true),
        ("0.15.5-rc.0.9", true),
        ("0.9.0", true),
        ("0.15.5-rc.1", false),
        ("v0.15.5-rc.1", false),
        ("0.15.5-rc.1+gpu", false),
        ("0.15.5-rc.1.0", false),
        ("0.15.5-rc.2", false),
        ("0.15.5-rc.10", false),
        ("0.15.5-rc.x", false),
        ("0.15.5-rd", false),
        ("0.15.5", false),
        ("0.15.5+gpu", false),
        ("0.15.10", false),
        ("0.16.0-rc.0", false),
        ("1.0.0", false),
        ("10.0.0", false),
    ] {
        let yaml = runtime_from_config(yaml_config(version).as_bytes());
        let json = runtime_from_config(json_config(version).as_bytes());
        let tag = format!("v{}", version.trim_start_matches('v'));
        // The JSON spelling is also flow-style YAML, so it is read at every
        // version.
        assert_eq!(json, Ok(reference(&tag, DIGEST)), "{version}");
        if below {
            assert_eq!(yaml, Ok(reference(&tag, DIGEST)), "{version}");
        } else {
            assert_eq!(yaml.unwrap_err().to_string(), TAKES_JSON, "{version}");
        }
    }
    // Below the first JSON version, a config that is JSON is read as the
    // YAML that it also is, in any spelling.
    let spaced = replace_once(&json_config("0.15.4"), r#""cpus":2"#, r#""cpus": null"#);
    assert_eq!(
        runtime_from_config(spaced.as_bytes()),
        Ok(reference("v0.15.4", DIGEST))
    );
    // A release that is not a full version fails as a pin in either format:
    // a shorthand, which is above the first JSON version, and what is not a
    // version, which is below it.
    let tag = "runtime tag must be a full semantic version";
    for version in ["1", "0.16", "0.15.5-rc.01", "0.15.5.1", "vv0.16.0", "x"] {
        assert_eq!(config_error(&yaml_config(version)), tag, "{version}");
        assert_eq!(config_error(&json_config(version)), tag, "{version}");
    }
}

#[test]
fn a_json_config_has_one_byte_form() {
    let pin = format!("0.15.5@sha256:{DIGEST}");
    let read =
        |config: &str| runtime_from_config(config.as_bytes()).map_err(|error| error.to_string());
    let expected = Ok(reference("v0.15.5", DIGEST));

    // Member names sort by their UTF-16 code units. U+FF5E is one unit above
    // the surrogates that encode U+1F600, and a lower code point.
    let by_code_unit =
        format!("{{\"cvm-version\":\"{pin}\",\"\u{e9}\":1,\"\u{1f600}\":2,\"\u{ff5e}\":3}}");
    let by_code_point =
        format!("{{\"cvm-version\":\"{pin}\",\"\u{e9}\":1,\"\u{ff5e}\":3,\"\u{1f600}\":2}}");
    assert_eq!(read(&by_code_unit), expected);
    assert_eq!(read(&by_code_point), Err(NOT_CANONICAL.to_owned()));
    // The same holds below the top level.
    let nested = |members: &str| format!("{{\"a\":[{{{members}}}],\"cvm-version\":\"{pin}\"}}");
    assert_eq!(
        read(&nested("\"\u{1f600}\":true,\"\u{ff5e}\":false")),
        expected
    );
    assert_eq!(
        read(&nested("\"\u{ff5e}\":false,\"\u{1f600}\":true")),
        Err(NOT_CANONICAL.to_owned())
    );

    // Numbers are integers that every implementation reads exactly.
    let with_number = |number: &str| format!("{{\"cpus\":{number},\"cvm-version\":\"{pin}\"}}");
    for number in ["0", "-1", "9007199254740991", "-9007199254740991"] {
        assert_eq!(read(&with_number(number)), expected, "{number}");
    }
    for number in [
        "9007199254740992",
        "-9007199254740992",
        "18446744073709551616",
        "2.0",
        "1e3",
        "1E3",
        "-0.0",
    ] {
        assert_eq!(
            read(&with_number(number)),
            Err(not_an_integer(number)),
            "{number}"
        );
    }
    // Negative zero is an integer, and its canonical form is `0`.
    assert_eq!(read(&with_number("-0")), Err(NOT_CANONICAL.to_owned()));
    // The rule holds at any depth.
    for (value, want) in [
        ("[{\"a\":[1.5]}]", not_an_integer("1.5")),
        (
            "[{\"a\":[null]}]",
            "parsing config runtime pin: null is not allowed in a JSON config".to_owned(),
        ),
        ("[{\"a\":[-0]}]", NOT_CANONICAL.to_owned()),
        ("[{\"a\": []}]", NOT_CANONICAL.to_owned()),
    ] {
        assert_eq!(read(&with_number(value)), Err(want), "{value}");
    }

    // A string has one spelling: an escape only where one is required, in
    // its short form where there is one.
    let with_text = |text: &str| format!("{{\"cvm-version\":\"{pin}\",\"text\":\"{text}\"}}");
    let backslash = '\\';
    for text in [
        format!("{backslash}n{backslash}t{backslash}b{backslash}f{backslash}r"),
        format!("{backslash}\"{backslash}{backslash}"),
        format!("{}{}", unicode_escape("0000"), unicode_escape("001f")),
        "/ \u{7f} \u{e9} \u{2028} \u{2029} \u{85} \u{ffff} \u{1f600}".to_owned(),
    ] {
        assert_eq!(read(&with_text(&text)), expected, "{text}");
    }
    for text in [
        unicode_escape("000a"),
        unicode_escape("001F"),
        unicode_escape("0041"),
        unicode_escape("00e9"),
        unicode_escape("007f"),
        format!("{}{}", unicode_escape("d83d"), unicode_escape("de00")),
        format!("{backslash}/"),
    ] {
        assert_eq!(
            read(&with_text(&text)),
            Err(NOT_CANONICAL.to_owned()),
            "{text}"
        );
    }
    // The name of the pin itself is no exception.
    let escaped_pin_name = format!("{{\"cvm{}version\":\"{pin}\"}}", unicode_escape("002d"));
    assert_eq!(read(&escaped_pin_name), Err(NOT_CANONICAL.to_owned()));
}

#[test]
fn a_json_config_states_its_pin_as_a_string_member() {
    let pin = format!("0.15.5@sha256:{DIGEST}");
    assert_eq!(
        runtime_from_config(format!("{{\"cvm-version\":\"{pin}\"}}").as_bytes()),
        Ok(reference("v0.15.5", DIGEST))
    );
    // The pin of a JSON config is held to the rules of every pin.
    for (pin, want) in [
        (
            format!("0.15.5@sha256:{}", DIGEST.to_uppercase()),
            "runtime digest is not lowercase hex",
        ),
        (
            format!("0.15.5@sha256:{}", &DIGEST[2..]),
            "runtime digest must be 32 bytes, got 31",
        ),
        (
            format!("0.15.5+@sha256:{DIGEST}"),
            "runtime tag must be a full semantic version",
        ),
        (
            "0.15.5".to_owned(),
            "cvm-version must pin a runtime manifest SHA-256 digest",
        ),
    ] {
        let config = format!("{{\"cvm-version\":\"{pin}\"}}");
        assert_eq!(config_error(&config), want, "{pin}");
    }
    // Anything else is not a JSON config, and is read as YAML: a pin that is
    // not a string, a pin below the top level, and a value that is not an
    // object.
    let unpinned = "cvm-version must pin a runtime manifest SHA-256 digest";
    for config in [
        "{\"cvm-version\":1}".to_owned(),
        "{\"cvm-version\":null}".to_owned(),
        format!("{{\"a\":{{\"cvm-version\":\"{pin}\"}}}}"),
        format!("[{{\"cvm-version\":\"{pin}\"}}]"),
        format!("\"{pin}\""),
    ] {
        assert_eq!(config_error(&config), unpinned, "{config}");
    }
    assert_eq!(
        config_error(&format!("{{\"cvm-version\":[\"{pin}\"]}}")),
        "parsing config runtime pin: cvm-version must be a scalar"
    );
    // A byte order mark is not JSON, and the YAML that follows it pins a
    // JSON version.
    assert_eq!(
        config_error(&format!("\u{feff}{{\"cvm-version\":\"{pin}\"}}")),
        TAKES_JSON
    );
}

#[test]
fn a_json_config_has_size_and_depth_bounds() {
    let pin = format!("0.15.5@sha256:{DIGEST}");
    let padded = |size: usize| {
        let empty = format!("{{\"cvm-version\":\"{pin}\",\"pad\":\"\"}}");
        let pad = "a".repeat(size - empty.len());
        format!("{{\"cvm-version\":\"{pin}\",\"pad\":\"{pad}\"}}")
    };
    assert_eq!(
        runtime_from_config(padded(MAX_CONFIG_SIZE).as_bytes()),
        Ok(reference("v0.15.5", DIGEST))
    );
    assert_eq!(
        config_error(&padded(MAX_CONFIG_SIZE + 1)),
        "parsing config runtime pin: the config is larger than 1048576 bytes"
    );

    // The deepest JSON that parses is read without a deep stack. One level
    // more is not JSON, and not YAML that is read here either.
    let handle = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || {
            let nested = |depth: usize| {
                format!(
                    "{{\"a\":{}{},\"cvm-version\":\"{pin}\"}}",
                    "[".repeat(depth),
                    "]".repeat(depth)
                )
            };
            assert_eq!(
                runtime_from_config(nested(crate::json::MAX_DEPTH - 1).as_bytes()),
                Ok(reference("v0.15.5", DIGEST))
            );
            assert!(is_syntax_error(&nested(crate::json::MAX_DEPTH)));
        })
        .unwrap();
    handle.join().unwrap();
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
