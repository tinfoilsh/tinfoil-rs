use super::*;
use crate::json::Value;
use crate::probes::{Case, Probes, count};

/// Hardware identifiers of two machines in the sample artifact.
const TURIN_CHIP_ID: &str = "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const TDX_PPID: &str = "3b064a0f58d5dd3688780aeb40e0b5d2";

const SAMPLE: &[u8] = include_bytes!("../../tests/data/platform_endorsements.json");

fn sample() -> Artifact {
    parse(SAMPLE).unwrap()
}

fn sample_text() -> String {
    String::from_utf8(SAMPLE.to_vec()).unwrap()
}

fn probes() -> Probes {
    Probes::parse(include_bytes!("../../tests/data/policy_probes.json"))
}

fn rejection(data: &str) -> String {
    parse(data.as_bytes()).unwrap_err().to_string()
}

/// Replaces the one occurrence of `from`.
fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from} must occur once");
    text.replace(from, to)
}

fn shape_field(value: Option<&Value>) -> Option<Shape> {
    let shape = value?.as_object()?;
    let field = |name: &str| shape.get(name).map(|v| i64::try_from(count(v)).unwrap());
    Some(Shape {
        cpus: field("cpus").unwrap(),
        memory_mb: field("memory_mb").unwrap(),
        gpus: field("gpus"),
        disks: field("disks").unwrap(),
    })
}

/// Compares a recorded lookup outcome, `accept` and `name`, with an actual
/// one.
fn check(outcome: Result<&str, PolicyError>, recorded: Case<'_>, what: &str) -> Option<String> {
    match (outcome, recorded.flag("accept")) {
        (Ok(name), true) if name == recorded.text("name") => None,
        (Ok(name), true) => Some(format!("{what}: resolved {name}")),
        (Err(_), false) => None,
        (Ok(_), false) => Some(format!("{what}: resolved, want a rejection")),
        (Err(error), true) => Some(format!("{what}: rejected: {error}")),
    }
}

/// Each case records whether an artifact parses. For an accepted artifact
/// it also records the sizes of its three maps, and for some the outcome of
/// policy lookups (`id`, `platform`) and of measurement resolutions
/// (`policy`, `shape`, `mrtd`, `rtmr0`).
#[test]
fn agrees_with_the_recorded_probes() {
    let probes = probes();
    let mut failures = Vec::new();
    let (mut total, mut accepted, mut lookups, mut resolutions) = (0, 0, 0, 0);
    for case in probes.cases() {
        total += 1;
        let name = case.name();
        let artifact = match (parse(&case.input()), case.flag("accept")) {
            (Ok(artifact), true) => artifact,
            (Err(_), false) => continue,
            (Ok(_), false) => {
                failures.push(format!("{name}: accepted, want a rejection"));
                continue;
            }
            (Err(error), true) => {
                failures.push(format!("{name}: rejected: {error}"));
                continue;
            }
        };
        accepted += 1;
        let sizes: Vec<usize> = case
            .get("counts")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(count)
            .collect();
        let actual = [
            artifact.machines.len(),
            artifact.policies.len(),
            artifact.measurements.len(),
        ];
        if sizes != actual {
            failures.push(format!("{name}: map sizes {actual:?}"));
        }
        let records = |field: &str| {
            let items = case.get(field).and_then(Value::as_array).unwrap_or(&[]);
            items.iter().map(|item| item.as_object().unwrap())
        };
        for record in records("lookups") {
            lookups += 1;
            let record = Case::of(record);
            let outcome = artifact
                .policy_for(record.text("id"), record.text("platform"))
                .map(|(name, _)| name);
            failures.extend(check(outcome, record, &format!("{name}: lookup")));
        }
        for record in records("resolves") {
            resolutions += 1;
            let record = Case::of(record);
            let required = shape_field(record.get("shape"));
            let outcome = match artifact
                .policies
                .get(record.text("policy"))
                .and_then(Policy::as_tdx)
            {
                None => Err(PolicyError::new("not a tdx policy")),
                Some(policy) => artifact
                    .resolve_platform_measurement(
                        policy,
                        required.as_ref(),
                        record.text("mrtd"),
                        record.text("rtmr0"),
                    )
                    .map(|(name, _)| name),
            };
            failures.extend(check(outcome, record, &format!("{name}: resolution")));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(total >= 1500, "{total} cases");
    assert!(accepted >= 250, "{accepted} accepted");
    assert!(
        lookups >= 100 && resolutions >= 50,
        "{lookups} lookups, {resolutions} resolutions"
    );
}

#[test]
fn an_artifact_reads_the_same_from_a_predicate_inside_a_statement() {
    // The artifact as the predicate member of a larger signed document,
    // with an integer above 2^53 that a float could not carry.
    let big = sample_text().replacen(
        "\"minimum_launch_mitigation_vector\": 0",
        "\"minimum_launch_mitigation_vector\": 9007199254740993",
        1,
    );
    assert!(big.contains("9007199254740993"));
    let statement = format!(r#"{{"predicateType":"x","predicate":{big}}}"#);
    let parsed = crate::json::parse(statement.as_bytes()).unwrap();
    let mut members = decode::object(parsed, "statement")
        .unwrap()
        .unwrap()
        .into_members();
    let (_, predicate) = members.pop().unwrap();
    assert_eq!(
        parse_value(predicate).unwrap(),
        parse(big.as_bytes()).unwrap()
    );

    let not_an_object = crate::json::parse(b"[]").unwrap();
    assert!(parse_value(not_an_object).is_err());
}

#[test]
fn parses_the_sample_artifact() {
    let artifact = sample();
    assert_eq!(artifact.format, ARTIFACT_FORMAT);
    assert_eq!(artifact.machines.len(), 12);
    assert_eq!(artifact.policies.len(), 6);
    assert_eq!(artifact.measurements.len(), 16);
}

#[test]
fn validates_platform_measurements() {
    let hex = |pair: &str, bytes: usize| pair.repeat(bytes);
    let valid = (
        hex("ab", 48),
        hex("cd", 48),
        r#"{"cpus":1,"memory_mb":1,"disks":1}"#,
    );
    let shape = |cpus: i64, memory_mb: i64, disks: i64| {
        format!(r#"{{"cpus":{cpus},"memory_mb":{memory_mb},"disks":{disks}}}"#)
    };
    let with_gpus = |gpus: i64| format!(r#"{{"cpus":1,"memory_mb":1,"disks":1,"gpus":{gpus}}}"#);
    let cases: Vec<(&str, String, String, String, &str)> = vec![
        (
            "optional GPUs",
            valid.0.clone(),
            valid.1.clone(),
            valid.2.into(),
            "",
        ),
        (
            "zero GPUs",
            valid.0.clone(),
            valid.1.clone(),
            with_gpus(0),
            "",
        ),
        (
            "positive GPUs",
            valid.0.clone(),
            valid.1.clone(),
            with_gpus(1),
            "",
        ),
        (
            "missing shape",
            valid.0.clone(),
            valid.1.clone(),
            "null".into(),
            "shape is required",
        ),
        (
            "zero CPUs",
            valid.0.clone(),
            valid.1.clone(),
            shape(0, 1, 1),
            "must be positive",
        ),
        (
            "negative CPUs",
            valid.0.clone(),
            valid.1.clone(),
            shape(-1, 1, 1),
            "must be positive",
        ),
        (
            "zero memory",
            valid.0.clone(),
            valid.1.clone(),
            shape(1, 0, 1),
            "must be positive",
        ),
        (
            "negative memory",
            valid.0.clone(),
            valid.1.clone(),
            shape(1, -1, 1),
            "must be positive",
        ),
        (
            "zero disks",
            valid.0.clone(),
            valid.1.clone(),
            shape(1, 1, 0),
            "must be positive",
        ),
        (
            "negative disks",
            valid.0.clone(),
            valid.1.clone(),
            shape(1, 1, -1),
            "must be positive",
        ),
        (
            "negative GPUs",
            valid.0.clone(),
            valid.1.clone(),
            with_gpus(-1),
            "gpus must be non-negative",
        ),
        (
            "missing MRTD",
            String::new(),
            valid.1.clone(),
            valid.2.into(),
            "mrtd",
        ),
        (
            "short MRTD",
            hex("ab", 47),
            valid.1.clone(),
            valid.2.into(),
            "mrtd",
        ),
        (
            "oversized MRTD",
            hex("AB", 1 << 19),
            valid.1.clone(),
            valid.2.into(),
            "mrtd must be 96 hex chars",
        ),
        (
            "nonhex MRTD",
            hex("z", 96),
            valid.1.clone(),
            valid.2.into(),
            "mrtd",
        ),
        (
            "uppercase MRTD",
            hex("AB", 48),
            valid.1.clone(),
            valid.2.into(),
            "mrtd must be lowercase hex",
        ),
        (
            "missing RTMR0",
            valid.0.clone(),
            String::new(),
            valid.2.into(),
            "rtmr0",
        ),
        (
            "short RTMR0",
            valid.0.clone(),
            hex("ab", 47),
            valid.2.into(),
            "rtmr0",
        ),
        (
            "oversized RTMR0",
            valid.0.clone(),
            hex("AB", 1 << 19),
            valid.2.into(),
            "rtmr0 must be 96 hex chars",
        ),
        (
            "nonhex RTMR0",
            valid.0.clone(),
            hex("z", 96),
            valid.2.into(),
            "rtmr0",
        ),
        (
            "uppercase RTMR0",
            valid.0.clone(),
            hex("CD", 48),
            valid.2.into(),
            "rtmr0 must be lowercase hex",
        ),
    ];
    for (name, mrtd, rtmr0, shape, want) in cases {
        // An entry that no policy uses must be well formed all the same.
        let artifact = format!(
            r#"{{"format":"{ARTIFACT_FORMAT}","measurements":{{"test":{{"mrtd":"{mrtd}","rtmr0":"{rtmr0}","shape":{shape}}}}},"machines":null,"policies":null}}"#
        );
        match (parse(artifact.as_bytes()), want) {
            (Ok(_), "") => {}
            (Err(error), want) if !want.is_empty() => {
                let message = error.to_string();
                assert!(
                    message.starts_with("measurement \"test\": ") && message.contains(want),
                    "{name}: {message}"
                );
            }
            (outcome, _) => panic!("{name}: {outcome:?}"),
        }
    }
}

#[test]
fn rejects_what_it_cannot_enforce() {
    let text = sample_text();
    let wrong_format = replace_once(
        &text,
        "platform-endorsements/v1",
        "platform-endorsements/v9",
    );
    assert!(rejection(&wrong_format).contains("unsupported artifact format"));

    let dangling = text.replacen("\"amd-genoa-prod\"", "\"no-such-policy\"", 1);
    assert_ne!(dangling, text);
    assert!(rejection(&dangling).contains("unknown policy"));

    // A negative minimum would let any collateral satisfy the floor.
    let negative = text.replacen(
        "\"minimum_tcb_evaluation_data_number\": 19",
        "\"minimum_tcb_evaluation_data_number\": -1",
        1,
    );
    assert_ne!(negative, text);
    assert!(rejection(&negative).contains("must not be negative"));
}

#[test]
fn looks_up_the_policy_of_a_machine() {
    let artifact = sample();

    let (name, policy) = artifact
        .policy_for(TURIN_CHIP_ID, PLATFORM_SEV_SNP)
        .unwrap();
    assert_eq!(name, "amd-turin-prod");
    assert!(policy.as_sev_snp().is_some() && policy.as_tdx().is_none());
    assert_eq!(policy.platform(), PLATFORM_SEV_SNP);

    let (name, policy) = artifact.policy_for(TDX_PPID, PLATFORM_TDX).unwrap();
    assert_eq!(name, "tdx-h200-prod");
    assert!(policy.as_tdx().is_some() && policy.as_sev_snp().is_none());
    assert_eq!(policy.platform(), PLATFORM_TDX);

    // A TDX identifier presented with SEV-SNP evidence.
    let mismatch = artifact.policy_for(TDX_PPID, PLATFORM_SEV_SNP).unwrap_err();
    assert_eq!(
        mismatch.to_string(),
        "policy \"tdx-h200-prod\" is for platform \"tdx\", evidence is \"sev-snp\""
    );

    // A machine that the artifact does not list is never endorsed.
    let unknown = artifact
        .policy_for(&"ab".repeat(64), PLATFORM_SEV_SNP)
        .unwrap_err();
    assert_eq!(
        unknown.to_string(),
        "platform identifier abababababababab... is not endorsed"
    );
}

#[test]
fn a_machine_whose_policy_is_gone_is_a_platform_mismatch() {
    let artifact = Artifact {
        machines: [("aa".to_owned(), "gone".to_owned())].into(),
        ..Artifact::default()
    };
    assert_eq!(
        artifact
            .policy_for("aa", PLATFORM_TDX)
            .unwrap_err()
            .to_string(),
        "policy \"gone\" is for platform \"\", evidence is \"tdx\""
    );
}

#[test]
fn resolves_measurements_within_the_required_shape() {
    let shape_a = Shape {
        cpus: 8,
        memory_mb: 65536,
        gpus: Some(1),
        disks: 4,
    };
    let shape_b = Shape {
        cpus: 32,
        memory_mb: 524_288,
        gpus: Some(2),
        disks: 5,
    };
    let entry = |mrtd: &str, rtmr0: &str, shape: Option<Shape>| PlatformMeasurement {
        mrtd: mrtd.to_owned(),
        rtmr0: rtmr0.to_owned(),
        shape,
        stack: None,
    };
    let artifact = Artifact {
        measurements: [
            ("one-disk".to_owned(), entry("aa", "bb", Some(shape_a))),
            ("two-disk".to_owned(), entry("cc", "dd", Some(shape_b))),
            (
                "no-gpus".to_owned(),
                entry(
                    "11",
                    "22",
                    Some(Shape {
                        gpus: None,
                        ..shape_a
                    }),
                ),
            ),
            ("legacy".to_owned(), entry("ee", "ff", None)),
        ]
        .into(),
        ..Artifact::default()
    };
    let policy = TdxPolicy {
        platform_measurements: ["one-disk", "two-disk", "no-gpus", "legacy", "missing"]
            .map(str::to_owned)
            .into(),
        ..TdxPolicy::default()
    };
    let resolve = |required: Option<&Shape>, mrtd: &str, rtmr0: &str| {
        artifact
            .resolve_platform_measurement(&policy, required, mrtd, rtmr0)
            .map_err(|error| error.to_string())
    };

    // The required shape is not optional.
    assert_eq!(
        resolve(None, "ee", "ff").unwrap_err(),
        "required VM shape is missing"
    );

    // The shape restricts the candidates before the registers are compared.
    let (name, measurement) = resolve(Some(&shape_a), "aa", "bb").unwrap();
    assert_eq!(name, "one-disk");
    assert_eq!(measurement.shape, Some(shape_a));

    // An entry without a GPU count satisfies any required GPU count.
    assert_eq!(resolve(Some(&shape_a), "11", "22").unwrap().0, "no-gpus");

    // A quote from an endorsed machine that runs another shape of VM.
    let mismatch = "platform measurements (mrtd cc...) do not match any allowed configuration";
    assert_eq!(resolve(Some(&shape_a), "cc", "dd").unwrap_err(), mismatch);

    // An entry without a shape is never a candidate.
    assert!(
        resolve(Some(&shape_a), "ee", "ff")
            .unwrap_err()
            .contains("do not match any allowed configuration")
    );

    // A shape that nothing was measured for is reported as such.
    let unmeasured = Shape {
        cpus: 1,
        ..Shape::default()
    };
    assert_eq!(
        resolve(Some(&unmeasured), "aa", "bb").unwrap_err(),
        "no endorsed platform measurement matches the required VM shape {CPUs:1 MemoryMB:0 GPUs:<nil> Disks:0}"
    );
    assert!(
        format!("{shape_a}").ends_with("GPUs:1 Disks:4}"),
        "{shape_a}"
    );
}

#[test]
fn a_missing_shape_satisfies_nothing() {
    let shape = Shape {
        cpus: 4,
        memory_mb: 4096,
        gpus: None,
        disks: 3,
    };
    assert!(satisfies(Some(&shape), Some(&shape)));
    assert!(!satisfies(Some(&shape), None));
    assert!(!satisfies(None, Some(&shape)));
    assert!(!satisfies(None, None));
}

#[test]
fn the_gpu_count_is_compared_only_when_both_sides_state_it() {
    let shape = |gpus| Shape {
        cpus: 4,
        memory_mb: 4096,
        gpus,
        disks: 3,
    };
    assert!(shape(Some(1)).satisfies(&shape(Some(1))));
    assert!(!shape(Some(1)).satisfies(&shape(Some(2))));
    assert!(shape(None).satisfies(&shape(Some(2))));
    assert!(shape(Some(1)).satisfies(&shape(None)));
    assert!(!shape(None).satisfies(&Shape {
        disks: 4,
        ..shape(None)
    }));
}

#[test]
fn an_artifact_without_workload_measurements() {
    let probes = probes();
    let v2 = probes.base("v2");
    let artifact = parse(v2.as_bytes()).unwrap();
    assert_eq!(artifact.format, ARTIFACT_FORMAT_V2);
    assert!(artifact.measurements.is_empty());
    assert!(!v2.contains("\"measurements\""));
    for policy in artifact.policies.values() {
        match policy {
            Policy::SevSnp(policy) => assert!(policy.host_data.is_empty()),
            Policy::Tdx(policy) => assert!(policy.platform_measurements.is_empty()),
        }
    }

    // The older format requires what this one excludes.
    let as_v1 = replace_once(v2, ARTIFACT_FORMAT_V2, ARTIFACT_FORMAT);
    assert!(rejection(&as_v1).contains("required in v1 and excluded in v2"));

    let host_data = replace_once(
        v2,
        "\"image_id\"",
        &format!("\"host_data\":\"{}\",\"image_id\"", "00".repeat(32)),
    );
    assert!(rejection(&host_data).contains("host_data is required in v1 and excluded in v2"));

    let references = replace_once(
        v2,
        "\"qe_vendor_id\"",
        "\"platform_measurements\":[\"legacy\"],\"qe_vendor_id\"",
    );
    assert!(
        rejection(&references)
            .contains("platform_measurements are required in v1 and excluded in v2")
    );

    let measurements = replace_once(
        v2,
        "\"machines\"",
        "\"measurements\":{\"legacy\":{}},\"machines\"",
    );
    assert_eq!(
        rejection(&measurements),
        "platform endorsement v2 excludes workload measurements"
    );

    // A member that this version does not know is never skipped.
    for marker in ["\"image_id\"", "\"qe_vendor_id\""] {
        let marked = replace_once(
            v2,
            marker,
            &format!("\"config_binding\":\"sha256\",{marker}"),
        );
        assert!(rejection(&marked).contains("config_binding"));
    }
}

type SevSnpMutation = fn(&mut SevSnpPolicy);
type TdxMutation = fn(&mut TdxPolicy);

fn valid_sev_snp_policy() -> SevSnpPolicy {
    let tcb = Tcb {
        fmc_spl: None,
        bl_spl: Some(0),
        tee_spl: Some(0),
        snp_spl: Some(0),
        ucode_spl: Some(0),
    };
    SevSnpPolicy {
        minimum_build: Some(0),
        minimum_api_version: "1.55".to_owned(),
        minimum_abi_version: "0.31".to_owned(),
        minimum_guest_svn: Some(0),
        minimum_tcb: tcb,
        minimum_launch_tcb: tcb,
        vmpl: Some(0),
        host_data: "ab".repeat(32),
        image_id: "cd".repeat(16),
        family_id: "ef".repeat(16),
        minimum_launch_mitigation_vector: Some(0),
        minimum_current_mitigation_vector: Some(0),
        ..SevSnpPolicy::default()
    }
}

#[test]
fn sev_snp_policy_validates_its_encoded_fields() {
    let valid = valid_sev_snp_policy();
    assert_eq!(valid.validate(), Ok(()));
    let mutations: &[(&str, SevSnpMutation)] = &[
        ("malformed api version", |p| {
            p.minimum_api_version = "1.2.3".to_owned()
        }),
        ("version component overflow", |p| {
            p.minimum_abi_version = "256.0".to_owned()
        }),
        ("uppercase hex", |p| {
            p.host_data = p.host_data.to_uppercase()
        }),
        ("short hex", |p| {
            p.image_id.truncate(30);
        }),
        ("non-hex", |p| p.family_id = "z".repeat(32)),
    ];
    for (name, mutate) in mutations {
        let mut policy = valid.clone();
        mutate(&mut policy);
        assert!(policy.validate().is_err(), "{name}");
    }
}

#[test]
fn sev_snp_policy_requires_every_member_in_order() {
    let valid = valid_sev_snp_policy();
    let mutations: &[(&str, SevSnpMutation)] = &[
        ("minimum_build is required", |p| p.minimum_build = None),
        ("minimum_api_version is required", |p| {
            p.minimum_api_version.clear()
        }),
        ("minimum_abi_version is required", |p| {
            p.minimum_abi_version.clear()
        }),
        ("minimum_guest_svn is required", |p| {
            p.minimum_guest_svn = None
        }),
        ("vmpl is required", |p| p.vmpl = None),
        ("vmpl must be between 0 and 3", |p| p.vmpl = Some(4)),
        ("vmpl must be between 0 and 3", |p| p.vmpl = Some(-1)),
        ("image_id is required", |p| p.image_id.clear()),
        ("family_id is required", |p| p.family_id.clear()),
        ("minimum_launch_mitigation_vector is required", |p| {
            p.minimum_launch_mitigation_vector = None;
        }),
        ("minimum_current_mitigation_vector is required", |p| {
            p.minimum_current_mitigation_vector = None;
        }),
        (
            "require_author_key and require_id_block are not supported (no trusted key material is modeled)",
            |p| p.require_author_key = true,
        ),
        (
            "require_author_key and require_id_block are not supported (no trusted key material is modeled)",
            |p| p.require_id_block = true,
        ),
        ("minimum_tcb: bl_spl is required", |p| {
            p.minimum_tcb.bl_spl = None
        }),
        ("minimum_launch_tcb: ucode_spl is required", |p| {
            p.minimum_launch_tcb.ucode_spl = None;
        }),
        ("minimum_api_version \"1\" is not maj.min", |p| {
            p.minimum_api_version = "1".to_owned();
        }),
        ("family_id must be 32 hex chars, got 30", |p| {
            p.family_id.truncate(30)
        }),
    ];
    for (want, mutate) in mutations {
        let mut policy = valid.clone();
        mutate(&mut policy);
        assert_eq!(policy.validate().unwrap_err().to_string(), *want);
    }

    // The first missing member is the one reported.
    let mut policy = valid.clone();
    policy.vmpl = None;
    policy.image_id.clear();
    assert_eq!(
        policy.validate().unwrap_err().to_string(),
        "vmpl is required"
    );

    // Host data may be left to the config, and every privilege level from 0
    // to 3 is a valid one.
    let mut policy = valid;
    policy.host_data.clear();
    for vmpl in 0..=3 {
        policy.vmpl = Some(vmpl);
        assert_eq!(policy.validate(), Ok(()));
    }
}

#[test]
fn tcb_requires_every_level_but_the_fmc_level() {
    let full = Tcb {
        fmc_spl: Some(1),
        bl_spl: Some(1),
        tee_spl: Some(2),
        snp_spl: Some(3),
        ucode_spl: Some(4),
    };
    assert_eq!(full.validate(), Ok(()));
    assert_eq!(
        Tcb {
            fmc_spl: None,
            ..full
        }
        .validate(),
        Ok(())
    );
    for (want, tcb) in [
        (
            "bl_spl is required",
            Tcb {
                bl_spl: None,
                ..full
            },
        ),
        (
            "tee_spl is required",
            Tcb {
                tee_spl: None,
                ..full
            },
        ),
        (
            "snp_spl is required",
            Tcb {
                snp_spl: None,
                ..full
            },
        ),
        (
            "ucode_spl is required",
            Tcb {
                ucode_spl: None,
                ..full
            },
        ),
        ("bl_spl is required", Tcb::default()),
    ] {
        assert_eq!(tcb.validate().unwrap_err().to_string(), want);
    }
}

fn valid_tdx_policy() -> TdxPolicy {
    TdxPolicy {
        qe_vendor_id: "ab".repeat(16),
        minimum_tee_tcb_svn: "00".repeat(16),
        mr_seam: "cd".repeat(48),
        td_attributes: "00".repeat(8),
        xfam: "00".repeat(8),
        minimum_tcb_evaluation_data_number: Some(0),
        platform_measurements: vec!["sample".to_owned()],
    }
}

#[test]
fn tdx_policy_validates_its_hex_fields() {
    let valid = valid_tdx_policy();
    assert_eq!(valid.validate(), Ok(()));
    let mutations: &[(&str, TdxMutation)] = &[
        ("uppercase", |p| {
            p.qe_vendor_id = p.qe_vendor_id.to_uppercase()
        }),
        ("odd length", |p| {
            p.mr_seam.pop();
        }),
        ("non-hex", |p| p.xfam = "z".repeat(16)),
    ];
    for (name, mutate) in mutations {
        let mut policy = valid.clone();
        mutate(&mut policy);
        assert!(policy.validate().is_err(), "{name}");
    }
}

#[test]
fn tdx_policy_requires_every_member_in_order() {
    let valid = valid_tdx_policy();
    let mutations: &[(&str, TdxMutation)] = &[
        ("qe_vendor_id is required", |p| p.qe_vendor_id.clear()),
        ("minimum_tee_tcb_svn is required", |p| {
            p.minimum_tee_tcb_svn.clear()
        }),
        ("mr_seam is required", |p| p.mr_seam.clear()),
        ("td_attributes is required", |p| p.td_attributes.clear()),
        ("xfam is required", |p| p.xfam.clear()),
        ("minimum_tcb_evaluation_data_number is required", |p| {
            p.minimum_tcb_evaluation_data_number = None;
        }),
        (
            "minimum_tcb_evaluation_data_number must not be negative",
            |p| {
                p.minimum_tcb_evaluation_data_number = Some(-1);
            },
        ),
        ("td_attributes must be lowercase hex", |p| {
            p.td_attributes = "0A".repeat(8);
        }),
    ];
    for (want, mutate) in mutations {
        let mut policy = valid.clone();
        mutate(&mut policy);
        assert_eq!(policy.validate().unwrap_err().to_string(), *want);
    }
    // The references are the artifact's to check, not the block's.
    let mut policy = valid;
    policy.platform_measurements.clear();
    assert_eq!(policy.validate(), Ok(()));
}

#[test]
fn integers_keep_their_exact_value() {
    let v2 = probes().base("v2").to_owned();
    for (literal, want) in [
        ("9007199254740993", 9_007_199_254_740_993_u64),
        ("18446744073709551615", u64::MAX),
        ("0", 0),
    ] {
        let text = replace_once(
            &v2,
            "\"minimum_launch_mitigation_vector\":3",
            &format!("\"minimum_launch_mitigation_vector\":{literal}"),
        );
        let artifact = parse(text.as_bytes()).unwrap();
        let policy = artifact.policies.get("amd").and_then(Policy::as_sev_snp);
        assert_eq!(policy.unwrap().minimum_launch_mitigation_vector, Some(want));
    }
    for literal in ["18446744073709551616", "-1", "1.0", "1e0", "\"1\""] {
        let text = replace_once(
            &v2,
            "\"minimum_launch_mitigation_vector\":3",
            &format!("\"minimum_launch_mitigation_vector\":{literal}"),
        );
        assert!(
            rejection(&text).starts_with("parsing policy artifact: "),
            "{literal}"
        );
    }
}

#[test]
fn an_absent_integer_is_not_a_zero() {
    let v2 = probes().base("v2").to_owned();
    for absent in ["", "\"minimum_build\":null,"] {
        let text = replace_once(&v2, "\"minimum_build\":21,", absent);
        assert_eq!(
            rejection(&text),
            "policy \"amd\": minimum_build is required"
        );
    }
    let zero = replace_once(&v2, "\"minimum_build\":21,", "\"minimum_build\":0,");
    let artifact = parse(zero.as_bytes()).unwrap();
    let policy = artifact.policies.get("amd").and_then(Policy::as_sev_snp);
    assert_eq!(policy.unwrap().minimum_build, Some(0));
}

#[test]
fn a_policy_names_exactly_its_own_block() {
    let block = |platform: &str, blocks: &str| {
        format!(
            r#"{{"format":"{ARTIFACT_FORMAT_V2}","policies":{{"p":{{"platform":"{platform}"{blocks}}}}}}}"#
        )
    };
    for (platform, blocks, want) in [
        (
            "sev-snp",
            "",
            "policy \"p\": platform sev-snp requires exactly the sev_snp block",
        ),
        (
            "sev-snp",
            r#","tdx":{}"#,
            "policy \"p\": platform sev-snp requires exactly the sev_snp block",
        ),
        (
            "sev-snp",
            r#","sev_snp":{},"tdx":{}"#,
            "policy \"p\": platform sev-snp requires exactly the sev_snp block",
        ),
        (
            "sev-snp",
            r#","sev_snp":null"#,
            "policy \"p\": platform sev-snp requires exactly the sev_snp block",
        ),
        (
            "tdx",
            "",
            "policy \"p\": platform tdx requires exactly the tdx block",
        ),
        (
            "tdx",
            r#","sev_snp":{}"#,
            "policy \"p\": platform tdx requires exactly the tdx block",
        ),
        (
            "tdx",
            r#","sev_snp":{},"tdx":{}"#,
            "policy \"p\": platform tdx requires exactly the tdx block",
        ),
        (
            "nvidia",
            "",
            "policy \"p\": unsupported platform \"nvidia\"",
        ),
        (
            "",
            r#","tdx":{}"#,
            "policy \"p\": unsupported platform \"\"",
        ),
        // The right block alone gets as far as its own validation, and a
        // null for the other block is the same as leaving it out.
        (
            "sev-snp",
            r#","sev_snp":{}"#,
            "policy \"p\": minimum_build is required",
        ),
        (
            "sev-snp",
            r#","sev_snp":{},"tdx":null"#,
            "policy \"p\": minimum_build is required",
        ),
        (
            "tdx",
            r#","tdx":{}"#,
            "policy \"p\": qe_vendor_id is required",
        ),
    ] {
        assert_eq!(rejection(&block(platform, blocks)), want);
    }
}

#[test]
fn machines_are_keyed_by_identifiers_of_their_platform() {
    let v2 = probes().base("v2").to_owned();
    let with_machine = |id: &str, policy: &str| {
        replace_once(
            &v2,
            "\"machines\":{",
            &format!("\"machines\":{{\"{id}\":\"{policy}\","),
        )
    };
    for (id, policy, want) in [
        ("ab", "nope", "machine ab...: unknown policy \"nope\""),
        ("", "amd", "machine ...: identifier is not lowercase hex"),
        (
            "AB",
            "amd",
            "machine AB...: identifier is not lowercase hex",
        ),
        (
            "abcdefg",
            "tdx",
            "machine abcdefg...: identifier is not lowercase hex",
        ),
        (
            "ab",
            "amd",
            "machine ab...: sev-snp identifier must be 128 hex chars, got 2",
        ),
        (
            "abc",
            "tdx",
            "machine abc...: tdx identifier must be 32 hex chars, got 3",
        ),
    ] {
        assert_eq!(rejection(&with_machine(id, policy)), want);
    }
    let long = "0123456789abcdef".repeat(8);
    assert_eq!(
        rejection(&with_machine(&long, "tdx")),
        "machine 0123456789abcdef...: tdx identifier must be 32 hex chars, got 128"
    );
    assert!(parse(with_machine(&long, "amd").as_bytes()).is_ok());
}

#[test]
fn reports_json_errors_as_parse_errors() {
    for text in [
        "",
        "{",
        "[]",
        "\"x\"",
        r#"{"format":1}"#,
        r#"{"extra":1}"#,
        r#"{"format":"a","format":"b"}"#,
    ] {
        assert!(
            rejection(text).starts_with("parsing policy artifact: "),
            "{text}"
        );
    }
    assert_eq!(rejection("null"), "unsupported artifact format \"\"");
    assert_eq!(rejection("{}"), "unsupported artifact format \"\"");
    assert_eq!(
        rejection(r#"{"format":"https://tinfoil.sh/predicate/platform-endorsements/v3"}"#),
        "unsupported artifact format \"https://tinfoil.sh/predicate/platform-endorsements/v3\""
    );
    assert!(parse(format!(r#"{{"format":"{ARTIFACT_FORMAT}"}}"#).as_bytes()).is_ok());
}

#[test]
fn decodes_policy_hex_of_either_case() {
    assert_eq!(decode_hex("f", "0aFF", 2), Ok(vec![0x0a, 0xff]));
    assert_eq!(
        decode_hex("f", "0af", 2).unwrap_err().to_string(),
        "f is not hex: odd number of digits"
    );
    assert_eq!(
        decode_hex("f", "0g", 1).unwrap_err().to_string(),
        "f is not hex: invalid digit"
    );
    assert_eq!(
        decode_hex("f", "0a", 2).unwrap_err().to_string(),
        "f must be 2 bytes, got 1"
    );
    assert_eq!(validate_policy_hex("f", "0aff", 2), Ok(()));
    assert_eq!(
        validate_policy_hex("f", "0aFF", 2).unwrap_err().to_string(),
        "f must be lowercase hex"
    );
    assert_eq!(
        validate_policy_hex("f", "0aff", 3).unwrap_err().to_string(),
        "f must be 6 hex chars, got 4"
    );
    assert_eq!(
        validate_policy_hex("f", "0agg", 2).unwrap_err().to_string(),
        "f is not hex: invalid digit"
    );
}

#[test]
fn parses_policy_versions() {
    assert_eq!(parse_policy_version("v", "1.55"), Ok((1, 55)));
    assert_eq!(parse_policy_version("v", "0.0"), Ok((0, 0)));
    assert_eq!(parse_policy_version("v", "255.255"), Ok((255, 255)));
    assert_eq!(parse_policy_version("v", "001.0002"), Ok((1, 2)));
    for malformed in [
        "", "1", "1.", ".1", "1.2.3", "+1.2", "1.-2", " 1.2", "1.2 ", "a.b", "1,2",
    ] {
        assert_eq!(
            parse_policy_version("v", malformed)
                .unwrap_err()
                .to_string(),
            format!("v {malformed:?} is not maj.min")
        );
    }
    assert_eq!(
        parse_policy_version("v", "256.0").unwrap_err().to_string(),
        "v major: \"256\" is out of range"
    );
    assert_eq!(
        parse_policy_version("v", "0.99999999999999999999")
            .unwrap_err()
            .to_string(),
        "v minor: \"99999999999999999999\" is out of range"
    );
}

#[test]
fn identifiers_are_cut_to_sixteen_bytes_in_messages() {
    assert_eq!(truncated(""), "");
    assert_eq!(truncated("abc"), "abc");
    assert_eq!(truncated("0123456789abcdefXYZ"), "0123456789abcdef");
    // A cut never falls inside a character.
    assert_eq!(truncated("0123456789abcde\u{e9}f"), "0123456789abcde");
}
