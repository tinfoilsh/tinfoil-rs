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

/// A JSON config in its one byte form that pins `version`.
fn json_config(version: &str) -> String {
    format!(
        r#"{{"containers":[],"cpus":2,"cvm-version":"{version}@sha256:{DIGEST}","shim":{{"upstream-port":8080}}}}"#
    )
}

fn yaml_config(version: &str) -> String {
    format!("cvm-version: {version}@sha256:{DIGEST}\ncpus: 2\n")
}

fn config_error(config: &str) -> String {
    runtime_from_config(config.as_bytes())
        .unwrap_err()
        .to_string()
}

/// A JSON escape of a UTF-16 code unit, given as four hex digits.
fn unicode_escape(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

const NOT_JSON_HEAD: &str =
    "parsing config runtime pin: not a JSON config that states cvm-version (";
const NOT_JSON_TAIL: &str = "); the YAML configs of versions before v0.15.5-rc.1 are not read";

/// The error for JSON that is not an object with a string `cvm-version`.
fn no_pin_member() -> String {
    format!("{NOT_JSON_HEAD}no cvm-version string member{NOT_JSON_TAIL}")
}

/// Whether `message` is the error for bytes that are not JSON, and names a
/// fault of this kind as the cause.
fn is_invalid_json(message: &str, fault: &str) -> bool {
    message
        .strip_prefix(NOT_JSON_HEAD)
        .and_then(|rest| rest.strip_suffix(NOT_JSON_TAIL))
        .is_some_and(|cause| cause.starts_with(&format!("invalid JSON: {fault} at offset ")))
}

const NOT_CANONICAL: &str =
    "parsing config runtime pin: JSON config is not in canonical form (RFC 8785)";
const BEFORE_JSON: &str = "a JSON config pins cvm-version v0.15.5-rc.1 or later";

fn not_an_integer(literal: &str) -> String {
    format!(
        "parsing config runtime pin: number {literal} in a JSON config is not an integer between -(2^53-1) and 2^53-1"
    )
}

#[test]
fn reads_the_runtime_pin_of_a_config() {
    for (version, tag) in [
        ("0.15.5", "v0.15.5"),
        ("v0.15.5", "v0.15.5"),
        ("0.15.5-rc.1", "v0.15.5-rc.1"),
        ("0.15.5+gpu", "v0.15.5+gpu"),
        ("v0.15.5+gpu", "v0.15.5+gpu"),
        ("0.15.5-rc.1+gpu", "v0.15.5-rc.1+gpu"),
        ("0.15.5+mini", "v0.15.5+mini"),
        ("0.15.5+containers.initrd-1", "v0.15.5+containers.initrd-1"),
        ("0.15.5+GPU", "v0.15.5+GPU"),
    ] {
        assert_eq!(
            runtime_from_config(json_config(version).as_bytes()),
            Ok(reference(tag, DIGEST)),
            "{version}"
        );
    }

    let good = json_config("0.15.5");
    let pin = "cvm-version must pin a runtime manifest SHA-256 digest";
    let tag = "runtime tag must be a full semantic version";
    let no_member = no_pin_member();
    let cases: [(&str, String, &str); 9] = [
        (
            "unpinned",
            replace_once(&good, &format!("@sha256:{DIGEST}"), ""),
            pin,
        ),
        (
            "bad digest",
            good.replace(DIGEST, &DIGEST.to_uppercase()),
            "runtime digest is not lowercase hex",
        ),
        (
            "path metadata",
            good.replace("0.15.5", "0.15.5+mini/other"),
            tag,
        ),
        ("partial version", good.replace("0.15.5", "0.15+gpu"), tag),
        ("empty metadata", good.replace("0.15.5", "0.15.5+"), tag),
        (
            "double metadata",
            good.replace("0.15.5", "0.15.5+gpu+gpu"),
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
        (
            "missing version",
            r#"{"containers":[]}"#.to_owned(),
            &no_member,
        ),
    ];
    for (name, config, want) in cases {
        assert_eq!(config_error(&config), want, "{name}");
    }
}

#[test]
fn only_a_json_config_of_a_json_version_is_read() {
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
    // YAML is not read, whatever it pins, and neither is anything else that
    // is not JSON. The error names the fault.
    for (name, config, fault) in [
        (
            "YAML at the first JSON version",
            yaml_config("0.15.5-rc.1"),
            "unexpected character",
        ),
        (
            "YAML with build metadata",
            yaml_config("0.15.5-rc.1+gpu"),
            "unexpected character",
        ),
        (
            "YAML for a later version",
            yaml_config("1.0.0"),
            "unexpected character",
        ),
        (
            "YAML before the first JSON version",
            yaml_config("0.15.5-rc.0"),
            "unexpected character",
        ),
        (
            "YAML for an earlier release",
            yaml_config("0.15.4"),
            "unexpected character",
        ),
        (
            "flow-style YAML for an earlier release",
            format!("{{cvm-version: 0.15.4@sha256:{DIGEST}}}\n"),
            "unexpected character",
        ),
        (
            "repeated member",
            replace(r#""cpus":2,"#, r#""cpus":2,"cpus":2,"#),
            "duplicate object member name",
        ),
        (
            "second value",
            format!("{canonical}{canonical}"),
            "data after the top-level value",
        ),
        ("empty", String::new(), "unexpected end of input"),
    ] {
        let message = config_error(&config);
        assert!(is_invalid_json(&message, fault), "{name}: {message}");
    }

    for (name, config, want) in [
        (
            "JSON before the first JSON version",
            json_config("0.15.5-rc.0"),
            BEFORE_JSON.to_owned(),
        ),
        (
            "JSON for an earlier release",
            json_config("0.15.4"),
            BEFORE_JSON.to_owned(),
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
    ] {
        assert_eq!(config_error(&config), want, "{name}");
    }
}

#[test]
fn the_first_json_version_is_found_by_precedence() {
    assert!(crate::semver::is_full(JSON_CONFIG_MIN_VERSION));
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
        let json = runtime_from_config(json_config(version).as_bytes());
        let tag = format!("v{}", version.trim_start_matches('v'));
        if below {
            assert_eq!(json.unwrap_err().to_string(), BEFORE_JSON, "{version}");
        } else {
            assert_eq!(json, Ok(reference(&tag, DIGEST)), "{version}");
        }
        // YAML is read at no version.
        let yaml = config_error(&yaml_config(version));
        assert!(is_invalid_json(&yaml, "unexpected character"), "{yaml}");
    }
    // A JSON config of an earlier version is refused in any spelling.
    let spaced = replace_once(&json_config("0.15.4"), r#""cpus":2"#, r#""cpus": null"#);
    assert_eq!(config_error(&spaced), BEFORE_JSON);
    // A release that is not a full version fails as a pin: a shorthand,
    // which is above the first JSON version, and what is not a version,
    // which is below it.
    let tag = "runtime tag must be a full semantic version";
    for version in ["1", "0.16", "0.15.5-rc.01", "0.15.5.1", "vv0.16.0", "x"] {
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
    // Any other JSON is not a config: a pin that is not a string, a pin
    // below the top level, and a value that is not an object.
    for config in [
        "{\"cvm-version\":1}".to_owned(),
        "{\"cvm-version\":null}".to_owned(),
        format!("{{\"cvm-version\":[\"{pin}\"]}}"),
        format!("{{\"a\":{{\"cvm-version\":\"{pin}\"}}}}"),
        format!("{{\"CVM-VERSION\":\"{pin}\"}}"),
        format!("[{{\"cvm-version\":\"{pin}\"}}]"),
        format!("\"{pin}\""),
    ] {
        assert_eq!(config_error(&config), no_pin_member(), "{config}");
    }
    // A byte order mark before the object is not JSON.
    let marked = config_error(&format!("\u{feff}{{\"cvm-version\":\"{pin}\"}}"));
    assert!(is_invalid_json(&marked, "unexpected character"), "{marked}");
}

#[test]
fn a_config_must_be_utf8() {
    let pin = format!("0.15.5@sha256:{DIGEST}");
    let with_text = |text: &[u8]| {
        let head = format!("{{\"cvm-version\":\"{pin}\",\"text\":\"");
        [head.as_bytes(), text, b"\"}"].concat()
    };
    assert_eq!(
        runtime_from_config(&with_text("\u{e9} \u{4e2d} \u{1f600} \u{a0}".as_bytes())),
        Ok(reference("v0.15.5", DIGEST))
    );
    let utf16: Vec<u8> = format!("{{\"cvm-version\":\"{pin}\"}}")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    for (config, fault) in [
        (with_text(b"\xff"), "invalid UTF-8"),
        (with_text(b"\xed\xa0\x80"), "invalid UTF-8"),
        (utf16, "unexpected character"),
    ] {
        let message = runtime_from_config(&config).unwrap_err().to_string();
        assert!(is_invalid_json(&message, fault), "{message}");
    }
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
    // more is not JSON.
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
            let deeper = config_error(&nested(crate::json::MAX_DEPTH));
            assert!(
                is_invalid_json(&deeper, "exceeded the maximum nesting depth"),
                "{deeper}"
            );
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
        "{\"cvm-version\":\"0.15.5@sha256:abababababababababababababababababababababababababababababababab\"}",
        "\"cvm-version\":",
        "\"0.15.5@sha256:",
        "\"0.15.4@sha256:",
        "abababababababababababababababababababababababababababababababab",
        "cvm-version: ",
        "a",
        "\"a\":",
        "\"b\"",
        "{",
        "}",
        "[",
        "]",
        ",",
        ":",
        "\"",
        "\\",
        "\\u",
        "0041",
        "d83d",
        "null",
        "true",
        "0",
        "-0",
        "1.5",
        "1e3",
        "9007199254740992",
        "-",
        " ",
        "\t",
        "\n",
        "\r",
        "#",
        "---\n",
        "\u{e9}",
        "\u{feff}",
        "\u{1}",
        "\u{1f600}",
        "\u{2028}",
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
