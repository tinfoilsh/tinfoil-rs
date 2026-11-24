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

/// A JSON config that pins `version`.
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

const NOT_JSON_HEAD: &str =
    "parsing config runtime pin: not a JSON config that states cvm-version (";
const NOT_JSON_TAIL: &str = "); YAML configs are not read";

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
        assert_eq!(
            runtime_from_config(json_config(version).as_bytes()),
            Ok(reference(tag, DIGEST)),
            "{version}"
        );
    }

    let good = json_config("0.15.0");
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

/// A config is read only as JSON, for its `cvm-version` member alone.
/// Neither the release that it pins nor the spelling of the JSON decides
/// the outcome, and YAML is refused.
#[test]
fn a_config_is_read_only_as_json() {
    let config = json_config("0.15.5-rc.1");
    let replace = |from: &str, to: &str| replace_once(&config, from, to);
    for (name, config, tag) in [
        ("release candidate", config.clone(), "v0.15.5-rc.1"),
        ("earlier version", json_config("0.15.4"), "v0.15.4"),
        ("later version", json_config("0.16.0"), "v0.16.0"),
        (
            "whitespace",
            replace(r#""cpus":2"#, r#""cpus": 2"#) + "\n",
            "v0.15.5-rc.1",
        ),
        (
            "members in any order",
            replace(
                r#""containers":[],"cpus":2,"#,
                r#""cpus":2,"containers":[],"#,
            ),
            "v0.15.5-rc.1",
        ),
        (
            "other member is null",
            replace(r#""cpus":2"#, r#""cpus":null"#),
            "v0.15.5-rc.1",
        ),
        (
            "other member fraction",
            replace(r#""cpus":2"#, r#""cpus":2.5"#),
            "v0.15.5-rc.1",
        ),
    ] {
        assert_eq!(
            runtime_from_config(config.as_bytes()),
            Ok(reference(tag, DIGEST)),
            "{name}"
        );
    }

    // What is not JSON is not read, whatever it pins. The error names the
    // fault.
    for (name, config, fault) in [
        ("YAML", yaml_config("0.15.5-rc.1"), "unexpected character"),
        (
            "YAML, earlier version",
            yaml_config("0.15.4"),
            "unexpected character",
        ),
        (
            "flow-style YAML",
            format!("{{cvm-version: 0.15.4@sha256:{DIGEST}}}\n"),
            "unexpected character",
        ),
        (
            "repeated member",
            replace(r#""cpus":2,"#, r#""cpus":2,"cpus":2,"#),
            "duplicate object member name",
        ),
        (
            "repeated cvm-version",
            replace(r#""shim""#, r#""cvm-version":"x","shim""#),
            "duplicate object member name",
        ),
        (
            "second value",
            format!("{config}{config}"),
            "data after the top-level value",
        ),
        (
            "byte order mark",
            format!("\u{feff}{config}"),
            "unexpected character",
        ),
        ("empty", String::new(), "unexpected end of input"),
    ] {
        let message = config_error(&config);
        assert!(is_invalid_json(&message, fault), "{name}: {message}");
    }

    // Any other JSON is not a config: one without the pin, with a pin that
    // is not a string or is below the top level, and a value that is not an
    // object.
    let pin = format!("0.15.5-rc.1@sha256:{DIGEST}");
    for (name, config) in [
        (
            "no cvm-version",
            replace(r#""cvm-version""#, r#""cvm-versions""#),
        ),
        (
            "cvm-version in another case",
            replace(r#""cvm-version""#, r#""CVM-VERSION""#),
        ),
        (
            "cvm-version not a string",
            r#"{"cvm-version":2}"#.to_owned(),
        ),
        ("cvm-version null", r#"{"cvm-version":null}"#.to_owned()),
        (
            "cvm-version in an array",
            format!(r#"{{"cvm-version":["{pin}"]}}"#),
        ),
        (
            "cvm-version below the top level",
            format!(r#"{{"a":{config}}}"#),
        ),
        ("not an object", format!("[{config}]")),
        ("a string", format!(r#""{pin}""#)),
    ] {
        assert_eq!(config_error(&config), no_pin_member(), "{name}");
    }
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
