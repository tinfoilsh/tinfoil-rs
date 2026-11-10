use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::*;
use crate::json;

pub(crate) fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

/// An entry whose data is the given JSON text; empty text leaves the data
/// out.
pub(crate) fn entry(id: &str, role: &str, format: &str, subjects: &[&str], data: &str) -> Entry {
    Entry {
        id: id.to_owned(),
        role: role.to_owned(),
        format: format.to_owned(),
        subjects: subjects.iter().map(|s| (*s).to_owned()).collect(),
        data: (!data.is_empty()).then(|| json::parse(data.as_bytes()).unwrap()),
    }
}

fn cpu(id: &str, format: &str, data: &str) -> Entry {
    entry(id, ROLE_ENDORSEMENT, format, &[SUBJECT_CPU], data)
}

fn reference(id: &str, format: &str, data: &str) -> Entry {
    entry(id, ROLE_REFERENCE_VALUES, format, &[], data)
}

fn vcek_data(der: &str) -> String {
    format!(r#"{{"vcek_der_base64":"{der}","cert_chain_pem":"chain"}}"#)
}

fn crl_data(der: &str) -> String {
    format!(r#"{{"crl_der_base64":"{der}"}}"#)
}

fn sev_entries() -> Vec<Entry> {
    vec![
        cpu(
            "cpu-endorsement",
            AMD_VCEK_V1_FORMAT,
            &vcek_data(&b64("vcek der")),
        ),
        cpu("cpu-crl", AMD_CRL_V1_FORMAT, &crl_data(&b64("crl der"))),
    ]
}

fn pcs_data(url: &str) -> String {
    format!(
        r#"{{"responses":[{{"url":"{url}","body_base64":"{}"}}]}}"#,
        b64("body")
    )
}

fn rejection(entries: Vec<Entry>) -> String {
    let error = decode(entries).unwrap_err();
    assert!(!error.is_not_found(), "malformed is not missing: {error}");
    error.to_string()
}

fn object(text: &str) -> Value {
    json::parse(text.as_bytes()).unwrap()
}

#[test]
fn decodes_sev_collateral() {
    let set = decode(sev_entries()).unwrap();
    assert_eq!(
        set.cpu,
        CpuEndorsements {
            amd_vcek: Some(AmdVcek {
                vcek_der: b"vcek der".to_vec(),
                cert_chain_pem: "chain".to_owned(),
            }),
            amd_crl: Some(AmdCrl {
                crl_der: b"crl der".to_vec(),
            }),
            intel_pcs: None,
        }
    );
}

#[test]
fn decodes_tdx_collateral() {
    let url = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity";
    let body = r#"{"enclaveIdentity":{}}"#;
    let data = format!(
        r#"{{"responses":[{{"url":"{url}","headers":{{"Sgx-Enclave-Identity-Issuer-Chain":["chain"]}},"body_base64":"{}"}}]}}"#,
        b64(body)
    );
    let set = decode(vec![cpu("pcs", INTEL_PCS_V1_FORMAT, &data)]).unwrap();
    let pcs = set.cpu.intel_pcs.unwrap();
    assert_eq!(
        pcs.responses,
        [PcsResponse {
            url: url.to_owned(),
            headers: [(
                "Sgx-Enclave-Identity-Issuer-Chain".to_owned(),
                vec!["chain".to_owned()]
            )]
            .into(),
            body: body.as_bytes().to_vec(),
        }]
    );
    assert_eq!(set.cpu.amd_vcek, None);
}

#[test]
fn decodes_tdx_collateral_with_absent_and_null_members() {
    for data in ["{}", r#"{"responses":null}"#, r#"{"responses":[]}"#] {
        let set = decode(vec![cpu("pcs", INTEL_PCS_V1_FORMAT, data)]).unwrap();
        assert_eq!(set.cpu.intel_pcs, Some(IntelPcs::default()), "{data}");
    }
    for data in [
        r#"{"responses":[null]}"#,
        r#"{"responses":[{}]}"#,
        r#"{"responses":[{"url":null,"headers":null,"body_base64":null}]}"#,
    ] {
        let set = decode(vec![cpu("pcs", INTEL_PCS_V1_FORMAT, data)]).unwrap();
        assert_eq!(
            set.cpu.intel_pcs.unwrap().responses,
            [PcsResponse::default()],
            "{data}"
        );
    }
    let data = r#"{"responses":[{"headers":{"a":null,"b":[null,"x"]}}]}"#;
    let set = decode(vec![cpu("pcs", INTEL_PCS_V1_FORMAT, data)]).unwrap();
    let headers = &set.cpu.intel_pcs.unwrap().responses[0].headers;
    assert_eq!(headers["a"], Vec::<String>::new());
    assert_eq!(headers["b"], ["", "x"]);

    for data in [
        r#"{"responses":{}}"#,
        r#"{"responses":[[]]}"#,
        r#"{"responses":[{"url":1}]}"#,
        r#"{"responses":[{"headers":[]}]}"#,
        r#"{"responses":[{"headers":{"a":"b"}}]}"#,
        r#"{"responses":[{"headers":{"a":[1]}}]}"#,
        r#"{"responses":[{"extra":1}]}"#,
    ] {
        let error = rejection(vec![cpu("pcs", INTEL_PCS_V1_FORMAT, data)]);
        assert!(
            error.contains(r#"parsing intel-pcs collateral entry "pcs""#),
            "{data}: {error}"
        );
    }
}

#[test]
fn decodes_no_entries() {
    let set = decode(Vec::new()).unwrap();
    assert_eq!(set, Set::default());
    assert_eq!(set.cpu, CpuEndorsements::default());
    assert!(set.sigstore_code.is_none());
    assert!(set.sigstore_platform.is_none());
    assert!(set.freshness.is_empty());
}

#[test]
fn an_endorsement_requires_the_cpu_subject() {
    let mut entries = sev_entries();
    entries[0].subjects = vec!["gpu0".to_owned()];
    let set = decode(entries).unwrap();
    assert!(
        set.cpu.amd_vcek.is_none(),
        "an entry for another subject does not endorse the CPU"
    );
    assert!(set.cpu.amd_crl.is_some());
}

#[test]
fn rejects_a_malformed_entry_list() {
    const UNKNOWN: &str = "https://tinfoil.sh/collateral/unknown/v9";
    let good = || entry("crl", ROLE_ENDORSEMENT, UNKNOWN, &[], "{}");
    let with_data = |data: &str| vec![entry("crl", ROLE_ENDORSEMENT, UNKNOWN, &[], data)];
    let not_an_object = r#"collateral entry "crl" data is not a valid JSON object"#;
    let cases = [
        (
            "missing id",
            vec![entry("", ROLE_ENDORSEMENT, AMD_CRL_V1_FORMAT, &[], "")],
            "collateral entry 0 is incomplete",
        ),
        (
            "missing format",
            vec![good(), entry("x", ROLE_ENDORSEMENT, "", &[], "")],
            "collateral entry 1 is incomplete",
        ),
        (
            "duplicate id",
            vec![good(), good()],
            r#"duplicate collateral entry id "crl""#,
        ),
        (
            "unknown role",
            vec![entry("crl", "unknown", UNKNOWN, &[], "{}")],
            r#"collateral entry "crl" has unknown role "unknown""#,
        ),
        (
            "empty role",
            vec![entry("crl", "", UNKNOWN, &[], "{}")],
            r#"collateral entry "crl" has unknown role """#,
        ),
        // Unknown formats are not decoded, but their data is still an object.
        ("missing data", with_data(""), not_an_object),
        ("null data", with_data("null"), not_an_object),
        ("array data", with_data("[]"), not_an_object),
        ("string data", with_data(r#""x""#), not_an_object),
        ("number data", with_data("1"), not_an_object),
    ];
    for (name, entries, want) in cases {
        let error = rejection(entries);
        assert!(error.contains(want), "{name}: {error}");
    }
}

#[test]
fn the_shape_of_every_entry_is_checked_before_any_is_decoded() {
    let entries = vec![
        cpu("vcek", AMD_VCEK_V1_FORMAT, r#"{"unknown":1}"#),
        entry("x", "unknown", AMD_CRL_V1_FORMAT, &[], "{}"),
    ];
    let error = rejection(entries);
    assert!(error.contains("unknown role"), "{error}");
}

#[test]
fn rejects_malformed_known_formats() {
    let good = sev_entries;
    let unused_body = b64(r#"{"unused":true}"#);
    let pcs = format!(
        r#"{{"responses":[{{"url":"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000","body_base64":"{}"}},{{"url":"https://example.com/never-requested","body_base64":"{}\n{}"}}]}}"#,
        b64(r#"{"tcbInfo":{}}"#),
        &unused_body[..4],
        &unused_body[4..],
    )
    .replace('\n', "\\n");
    let cases = [
        (
            "malformed intel-pcs",
            vec![cpu("pcs", INTEL_PCS_V1_FORMAT, r#"{"unknown":1}"#)],
            r#"parsing intel-pcs collateral entry "pcs""#.to_owned(),
        ),
        (
            "entry for another subject",
            vec![entry(
                "vcek",
                ROLE_ENDORSEMENT,
                AMD_VCEK_V1_FORMAT,
                &["gpu0"],
                r#"{"unknown":1}"#,
            )],
            r#"parsing amd-vcek collateral entry "vcek""#.to_owned(),
        ),
        (
            "non-canonical vcek",
            vec![
                cpu(
                    "cpu-endorsement",
                    AMD_VCEK_V1_FORMAT,
                    &vcek_data(&(b64("vcek der") + "\\n")),
                ),
                good().remove(1),
            ],
            r#"amd-vcek collateral entry "cpu-endorsement": vcek_der_base64 is not canonical base64"#
                .to_owned(),
        ),
        (
            "non-canonical crl",
            vec![
                good().remove(0),
                cpu(
                    "cpu-crl",
                    AMD_CRL_V1_FORMAT,
                    &crl_data(&(b64("crl der") + "\\r\\n")),
                ),
            ],
            r#"amd-crl collateral entry "cpu-crl": crl_der_base64 is not canonical base64"#
                .to_owned(),
        ),
        (
            "invalid crl base64",
            vec![cpu("cpu-crl", AMD_CRL_V1_FORMAT, &crl_data("not base64!"))],
            r#"amd-crl collateral entry "cpu-crl": decoding crl_der_base64"#.to_owned(),
        ),
        (
            "unused pcs response",
            vec![cpu("pcs", INTEL_PCS_V1_FORMAT, &pcs)],
            r#"intel-pcs collateral entry "pcs" response 1: body_base64 is not canonical base64"#
                .to_owned(),
        ),
        (
            "malformed sigstore reference",
            vec![reference(
                "code",
                SIGSTORE_CODE_V1_FORMAT,
                r#"{"repo":"org/code","unknown":1}"#,
            )],
            format!(r#"parsing {SIGSTORE_CODE_V1_FORMAT} collateral entry "code""#),
        ),
        (
            "malformed freshness witness",
            vec![reference(
                FRESHNESS_ID_CODE,
                SIGSTORE_FRESHNESS_V1_FORMAT,
                r#"{"unknown":1}"#,
            )],
            format!(r#"parsing {SIGSTORE_FRESHNESS_V1_FORMAT} collateral entry "code-freshness""#),
        ),
        (
            "mistyped member",
            vec![cpu("vcek", AMD_VCEK_V1_FORMAT, r#"{"cert_chain_pem":1}"#)],
            r#"parsing amd-vcek collateral entry "vcek""#.to_owned(),
        ),
        (
            "member name in another case",
            vec![cpu("crl", AMD_CRL_V1_FORMAT, r#"{"CRL_der_base64":""}"#)],
            r#"parsing amd-crl collateral entry "crl""#.to_owned(),
        ),
    ];
    for (name, entries, want) in cases {
        let error = rejection(entries);
        assert!(error.contains(&want), "{name}: {error}");
    }
}

#[test]
fn ignores_formats_without_a_decoder() {
    // Unknown formats, and known formats under a role that they do not
    // serve, are never decoded: only the shape checks apply to them.
    let entries = [
        entry(
            "future",
            ROLE_ENDORSEMENT,
            "https://tinfoil.sh/collateral/unknown/v9",
            &[],
            r#"{"x":1}"#,
        ),
        entry(
            "misrole",
            ROLE_REFERENCE_VALUES,
            AMD_VCEK_V1_FORMAT,
            &[],
            r#"{"unknown":1}"#,
        ),
        entry(
            "misrole-reference",
            ROLE_ENDORSEMENT,
            SIGSTORE_CODE_V1_FORMAT,
            &[],
            r#"{"unknown":1}"#,
        ),
    ];
    for entry in entries {
        let id = entry.id.clone();
        let set = decode(vec![entry]).unwrap();
        assert_eq!(set, Set::default(), "{id}");
    }
}

#[test]
fn the_first_entry_for_a_purpose_wins() {
    let pcs = |id: &str, url: &str| cpu(id, INTEL_PCS_V1_FORMAT, &pcs_data(url));
    let sigstore = |id: &str, format: &str, repo: &str| {
        let data = format!(r#"{{"repo":"{repo}","tag":"","digest":"ab","sigstore_bundle":{{}}}}"#);
        reference(id, format, &data)
    };
    let set = decode(vec![
        cpu("vcek-1", AMD_VCEK_V1_FORMAT, &vcek_data(&b64("first vcek"))),
        cpu(
            "vcek-2",
            AMD_VCEK_V1_FORMAT,
            &vcek_data(&b64("second vcek")),
        ),
        cpu("crl-1", AMD_CRL_V1_FORMAT, &crl_data(&b64("first crl"))),
        cpu("crl-2", AMD_CRL_V1_FORMAT, &crl_data(&b64("second crl"))),
        pcs("pcs-1", "https://first.example"),
        pcs("pcs-2", "https://second.example"),
        sigstore("code-1", SIGSTORE_CODE_V1_FORMAT, "org/first"),
        sigstore("code-2", SIGSTORE_CODE_V1_FORMAT, "org/second"),
        sigstore(
            "platform-1",
            SIGSTORE_PLATFORM_V1_FORMAT,
            "org/first-platform",
        ),
        sigstore(
            "platform-2",
            SIGSTORE_PLATFORM_V1_FORMAT,
            "org/second-platform",
        ),
    ])
    .unwrap();
    assert_eq!(set.cpu.amd_vcek.unwrap().vcek_der, b"first vcek");
    assert_eq!(set.cpu.amd_crl.unwrap().crl_der, b"first crl");
    assert_eq!(
        set.cpu.intel_pcs.unwrap().responses[0].url,
        "https://first.example"
    );
    assert_eq!(set.sigstore_code.unwrap().repo, "org/first");
    assert_eq!(set.sigstore_platform.unwrap().repo, "org/first-platform");
}

#[test]
fn a_later_entry_for_a_purpose_is_still_decoded() {
    let entries = vec![
        cpu("vcek-1", AMD_VCEK_V1_FORMAT, &vcek_data(&b64("first vcek"))),
        cpu("vcek-2", AMD_VCEK_V1_FORMAT, &vcek_data("not base64!")),
    ];
    assert!(rejection(entries).contains(r#"amd-vcek collateral entry "vcek-2""#));
}

#[test]
fn freshness_is_keyed_by_entry_id() {
    let witness = |id: &str, bundle: &str| {
        let data = format!(r#"{{"sigstore_bundle":{bundle}}}"#);
        reference(id, SIGSTORE_FRESHNESS_V1_FORMAT, &data)
    };
    let set = decode(vec![
        witness(FRESHNESS_ID_CODE, r#"{"a":1}"#),
        witness(FRESHNESS_ID_PLATFORM, r#"{"b":2}"#),
    ])
    .unwrap();
    let want = |bundle: &str| Freshness {
        format: SIGSTORE_FRESHNESS_V1_FORMAT.to_owned(),
        bundle: object(bundle),
    };
    assert_eq!(set.freshness.len(), 2);
    assert_eq!(set.freshness[FRESHNESS_ID_CODE], want(r#"{"a":1}"#));
    assert_eq!(set.freshness[FRESHNESS_ID_PLATFORM], want(r#"{"b":2}"#));
}

/// A reference carries what verification needs: a bundle and a digest.
/// Whether a present bundle verifies is not decided here, and the tag is an
/// optional hint.
#[test]
fn a_reference_requires_its_bundle_and_digest() {
    let cases = [
        (
            "code without bundle",
            SIGSTORE_CODE_V1_FORMAT,
            r#"{"repo":"o/r","tag":"v1","digest":"ab"}"#,
            "is missing sigstore_bundle",
        ),
        (
            "code with null bundle",
            SIGSTORE_CODE_V1_FORMAT,
            r#"{"repo":"o/r","tag":"v1","digest":"ab","sigstore_bundle":null}"#,
            "is missing sigstore_bundle",
        ),
        (
            "platform without digest",
            SIGSTORE_PLATFORM_V1_FORMAT,
            r#"{"repo":"o/r","tag":"v1","sigstore_bundle":{}}"#,
            "is missing digest",
        ),
        (
            "code with empty digest",
            SIGSTORE_CODE_V1_FORMAT,
            r#"{"repo":"o/r","tag":"v1","digest":"","sigstore_bundle":{}}"#,
            "is missing digest",
        ),
        (
            "code with null digest",
            SIGSTORE_CODE_V1_FORMAT,
            r#"{"repo":"o/r","tag":"v1","digest":null,"sigstore_bundle":{}}"#,
            "is missing digest",
        ),
        (
            "freshness without bundle",
            SIGSTORE_FRESHNESS_V1_FORMAT,
            "{}",
            "is missing sigstore_bundle",
        ),
        (
            "freshness with null bundle",
            SIGSTORE_FRESHNESS_V1_FORMAT,
            r#"{"sigstore_bundle":null}"#,
            "is missing sigstore_bundle",
        ),
    ];
    for (name, format, data, want) in cases {
        let error = rejection(vec![reference("ref", format, data)]);
        assert!(error.contains(want), "{name}: {error}");
    }

    let accepted = [
        (
            "empty tag and repo",
            SIGSTORE_CODE_V1_FORMAT,
            r#"{"repo":"","tag":"","digest":"ab","sigstore_bundle":{"mediaType":"x"}}"#,
        ),
        (
            "absent tag and repo",
            SIGSTORE_CODE_V1_FORMAT,
            r#"{"digest":"ab","sigstore_bundle":{"mediaType":"x"}}"#,
        ),
        (
            "bundle that is not an object",
            SIGSTORE_PLATFORM_V1_FORMAT,
            r#"{"digest":"ab","sigstore_bundle":"x"}"#,
        ),
        (
            "present invalid bundle",
            SIGSTORE_FRESHNESS_V1_FORMAT,
            r#"{"sigstore_bundle":{}}"#,
        ),
    ];
    for (name, format, data) in accepted {
        assert!(
            decode(vec![reference("ref", format, data)]).is_ok(),
            "{name}"
        );
    }
}

#[test]
fn a_bundle_keeps_members_that_the_decoder_does_not_know() {
    let data =
        r#"{"digest":"ab","sigstore_bundle":{"mediaType":"x","future":{"deep":[1,{"k":null}]}}}"#;
    let set = decode(vec![reference("code", SIGSTORE_CODE_V1_FORMAT, data)]).unwrap();
    assert_eq!(
        set.sigstore_code.unwrap().bundle,
        object(r#"{"mediaType":"x","future":{"deep":[1,{"k":null}]}}"#)
    );
}

// ---- config

const DIGEST: &str = "abababababababababababababababababababababababababababababababab";

fn config_data(config: &str) -> String {
    format!(
        r#"{{"endorsement_ref":"sha256:{DIGEST}","config_base64":"{config}","sigstore_bundle":{{"mediaType":"test"}}}}"#
    )
}

fn config_entry(format: &str, data: &str) -> Entry {
    reference(CONFIG_ID, format, data)
}

#[test]
fn plain_config_collateral() {
    let plain = || config_entry(CONFIG_V1_FORMAT, r#"{"config_base64":"Y29uZmln"}"#);
    let set = decode(vec![plain()]).unwrap();
    let config = set.config.unwrap();
    assert_eq!(
        config,
        ConfigEndorsement::Plain {
            config: b"config".to_vec()
        }
    );
    assert_eq!(config.config(), Some(&b"config"[..]));
    assert_eq!(config.reference(), None);
    assert_eq!(config.bundle(), None);
    assert_eq!(config.issuer(), None);

    assert!(decode(vec![plain(), plain()]).is_err());

    let endorsed = config_entry(
        CONFIG_ENDORSEMENT_V1_FORMAT,
        r#"{"config_base64":"Y29uZmln"}"#,
    );
    assert!(rejection(vec![endorsed]).contains("endorsement_ref"));

    for data in [
        r#"{"config_base64":"Y29uZmln","sigstore_bundle":{}}"#,
        r#"{"config_base64":"Y29uZmln","sigstore_bundle":null}"#,
        r#"{"config_base64":"Y29uZmln","endorsement_ref":"x"}"#,
    ] {
        let error = rejection(vec![config_entry(CONFIG_V1_FORMAT, data)]);
        assert!(
            error.contains("cannot contain an endorsement"),
            "{data}: {error}"
        );
    }
    for data in [
        r#"{"config_base64":"Y29uZmln","endorsement_ref":""}"#,
        r#"{"config_base64":"Y29uZmln","endorsement_ref":null,"issuer_certificate_der":""}"#,
    ] {
        assert!(
            decode(vec![config_entry(CONFIG_V1_FORMAT, data)]).is_ok(),
            "{data}"
        );
    }
    for (data, want) in [
        ("{}", "config_base64 must not be empty"),
        (r#"{"config_base64":""}"#, "config_base64 must not be empty"),
        (
            r#"{"config_base64":"Y29uZmln\n"}"#,
            "config_base64 is not canonical base64",
        ),
        (
            r#"{"config_base64":"Y29uZmln","issuer_certificate_der":"Yg=="}"#,
            "issuer certificates require v2",
        ),
    ] {
        let error = rejection(vec![config_entry(CONFIG_V1_FORMAT, data)]);
        assert!(error.contains(want), "{data}: {error}");
    }
}

#[test]
fn v2_config_collateral_allows_optional_bytes() {
    let reference = format!("sha256:{DIGEST}");
    let data =
        format!(r#"{{"endorsement_ref":"{reference}","sigstore_bundle":{{"mediaType":"test"}}}}"#);
    let set = decode(vec![config_entry(CONFIG_ENDORSEMENT_V2_FORMAT, &data)]).unwrap();
    let config = set.config.unwrap();
    assert_eq!(config.reference(), Some(reference.as_str()));
    assert_eq!(config.bundle(), Some(&object(r#"{"mediaType":"test"}"#)));
    assert_eq!(config.config(), None);
    assert_eq!(config.issuer(), None);

    let data = config_data(&b64("public config"));
    let set = decode(vec![config_entry(CONFIG_ENDORSEMENT_V2_FORMAT, &data)]).unwrap();
    assert_eq!(set.config.unwrap().config(), Some(&b"public config"[..]));

    let set = decode(vec![config_entry(
        CONFIG_ENDORSEMENT_V2_FORMAT,
        &config_data(""),
    )])
    .unwrap();
    assert_eq!(set.config.unwrap().config(), None);
}

#[test]
fn config_endorsement() {
    let config = "cvm-version: 1.0.0\n";
    let reference = format!("sha256:{DIGEST}");
    let data = config_data(&b64(config));
    let good = || config_entry(CONFIG_ENDORSEMENT_V1_FORMAT, &data);
    let set = decode(vec![good()]).unwrap();
    assert_eq!(
        set.config.unwrap(),
        ConfigEndorsement::Signed {
            reference: reference.clone(),
            bundle: object(r#"{"mediaType":"test"}"#),
            config: Some(config.as_bytes().to_vec()),
            issuer: None,
        }
    );

    let with_data = |data: String| vec![config_entry(CONFIG_ENDORSEMENT_V1_FORMAT, &data)];
    let other = |id: &str| reference_entry_with_id(id, &data);
    let encoded = b64(config);
    let cases: Vec<(&str, Vec<Entry>)> = vec![
        (
            "wrong role",
            vec![entry(
                CONFIG_ID,
                ROLE_ENDORSEMENT,
                CONFIG_ENDORSEMENT_V1_FORMAT,
                &[],
                &data,
            )],
        ),
        (
            "wrong format",
            vec![config_entry(SIGSTORE_CODE_V1_FORMAT, &data)],
        ),
        ("wrong id", vec![other("other")]),
        ("duplicate", vec![good(), good()]),
        ("ambiguous format", vec![good(), other("other")]),
        (
            "noncanonical base64",
            with_data(data.replace(r#""config_base64":""#, r#""config_base64":"\n"#)),
        ),
        ("empty config", with_data(data.replace(&encoded, ""))),
        (
            "missing config",
            with_data(data.replace(&format!(r#""config_base64":"{encoded}","#), "")),
        ),
        (
            "bad reference",
            with_data(data.replace(&reference, "sha256:bad")),
        ),
        (
            "uppercase reference digest",
            with_data(data.replace(DIGEST, &DIGEST.to_uppercase())),
        ),
        (
            "reference without the prefix",
            with_data(data.replace("sha256:", "")),
        ),
        (
            "unknown member",
            with_data(data.replacen('{', r#"{"unknown":true,"#, 1)),
        ),
        (
            "missing bundle",
            with_data(data.replace(r#"{"mediaType":"test"}"#, "null")),
        ),
        (
            "bundle that is not an object",
            with_data(data.replace(r#"{"mediaType":"test"}"#, "[]")),
        ),
        (
            "absent bundle",
            with_data(data.replace(r#","sigstore_bundle":{"mediaType":"test"}"#, "")),
        ),
    ];
    for (name, entries) in cases {
        assert!(decode(entries).is_err(), "{name}");
    }
}

fn reference_entry_with_id(id: &str, data: &str) -> Entry {
    reference(id, CONFIG_ENDORSEMENT_V1_FORMAT, data)
}

#[test]
fn the_issuer_certificate_encoding_is_canonical() {
    let data = |config: &str, issuer: &str| {
        format!(
            r#"{{"endorsement_ref":"sha256:{DIGEST}","config_base64":"{config}","sigstore_bundle":{{"mediaType":"test"}},"issuer_certificate_der":"{issuer}"}}"#
        )
    };
    let set = decode(vec![config_entry(
        CONFIG_ENDORSEMENT_V2_FORMAT,
        &data("", "Yg=="),
    )])
    .unwrap();
    let config = set.config.unwrap();
    assert_eq!(config.issuer(), Some(&b"b"[..]));
    assert_eq!(config.config(), None);

    let entry = config_entry(CONFIG_ENDORSEMENT_V2_FORMAT, &data("Y29uZmln", "Yg=="));
    let config = decode(vec![entry]).unwrap().config.unwrap();
    assert_eq!(config.config(), Some(&b"config"[..]));
    assert_eq!(config.issuer(), Some(&b"b"[..]));

    for noncanonical in ["YR==", "YQ==\\n"] {
        let entry = config_entry(
            CONFIG_ENDORSEMENT_V2_FORMAT,
            &data("Y29uZmln", noncanonical),
        );
        assert!(rejection(vec![entry]).contains("issuer_certificate_der"));
    }
    let entry = config_entry(CONFIG_ENDORSEMENT_V1_FORMAT, &data("", "Yg=="));
    assert!(rejection(vec![entry]).contains("issuer certificates require v2"));
}

// ---- runtime

fn runtime_reference(repo: &str, tag: &str, digest: &str) -> RuntimeReference {
    RuntimeReference {
        repo: repo.to_owned(),
        tag: tag.to_owned(),
        digest: digest.to_owned(),
    }
}

#[test]
fn runtime_reference_validation() {
    let tag = "v0.15.0-rc.1";
    assert!(
        runtime_reference(RUNTIME_REPO, tag, DIGEST)
            .validate()
            .is_ok()
    );
    let rejected = [
        runtime_reference("other/runtime", tag, DIGEST),
        runtime_reference(RUNTIME_REPO, "0.15.0", DIGEST),
        runtime_reference(RUNTIME_REPO, "v0.15", DIGEST),
        runtime_reference(RUNTIME_REPO, "v0.15.0+mini/other", DIGEST),
        runtime_reference(RUNTIME_REPO, tag, &DIGEST.to_uppercase()),
        runtime_reference(RUNTIME_REPO, tag, "ab"),
        runtime_reference(RUNTIME_REPO, "", DIGEST),
        runtime_reference("", tag, DIGEST),
    ];
    for reference in rejected {
        assert!(reference.validate().is_err(), "{reference:?}");
    }
}

fn runtime_data(manifest: &str) -> String {
    format!(
        r#"{{"repo":"{RUNTIME_REPO}","tag":"v0.15.0","digest":"{DIGEST}","manifest_base64":"{}","sigstore_bundle":{{}}}}"#,
        b64(manifest)
    )
}

#[test]
fn runtime_collateral() {
    let manifest = r#"{"version":"v0.15.0"}"#;
    let data = runtime_data(manifest);
    let good = || reference(RUNTIME_ID, RUNTIME_V1_FORMAT, &data);
    let set = decode(vec![good()]).unwrap();
    assert_eq!(
        set.runtime.unwrap(),
        Runtime {
            reference: runtime_reference(RUNTIME_REPO, "v0.15.0", DIGEST),
            manifest: manifest.as_bytes().to_vec(),
            bundle: object("{}"),
        }
    );

    let other = reference("other-runtime", RUNTIME_V1_FORMAT, &data);
    assert!(rejection(vec![good(), other]).contains("conflicting collateral"));
    let other_format = reference(RUNTIME_ID, SIGSTORE_CODE_V1_FORMAT, &data);
    assert!(rejection(vec![other_format]).contains("conflicting collateral"));
    let other_role = entry(RUNTIME_ID, ROLE_ENDORSEMENT, RUNTIME_V1_FORMAT, &[], &data);
    assert!(rejection(vec![other_role]).contains("conflicting collateral"));

    let cases = [
        ("unknown member", data.replacen('{', r#"{"unknown":1,"#, 1)),
        (
            "other repository",
            data.replace(RUNTIME_REPO, "other/runtime"),
        ),
        ("short tag", data.replace("v0.15.0", "v0.15")),
        (
            "uppercase digest",
            data.replace(DIGEST, &DIGEST.to_uppercase()),
        ),
        (
            "null bundle",
            data.replace(r#""sigstore_bundle":{}"#, r#""sigstore_bundle":null"#),
        ),
        (
            "array bundle",
            data.replace(r#""sigstore_bundle":{}"#, r#""sigstore_bundle":[]"#),
        ),
        (
            "absent bundle",
            data.replace(r#","sigstore_bundle":{}"#, ""),
        ),
        (
            "non-canonical manifest",
            data.replace(r#""manifest_base64":""#, r#""manifest_base64":"\n"#),
        ),
    ];
    for (name, data) in cases {
        let entry = reference(RUNTIME_ID, RUNTIME_V1_FORMAT, &data);
        assert!(decode(vec![entry]).is_err(), "{name}");
    }

    // The manifest may be empty; whether it matches its digest is checked
    // when the runtime is authenticated.
    let empty = reference(RUNTIME_ID, RUNTIME_V1_FORMAT, &runtime_data(""));
    assert_eq!(decode(vec![empty]).unwrap().runtime.unwrap().manifest, b"");
}

#[test]
fn config_platform() {
    let data = r#"{"repo":"tinfoilsh/cvmimage","tag":"platform-v1.0.0","digest":"ab","sigstore_bundle":{}}"#;
    let good = || reference(PLATFORM_ID, SIGSTORE_PLATFORM_V1_FORMAT, data);
    let set = decode(vec![good()]).unwrap();
    let platform = set.config_platform().unwrap();
    assert_eq!(platform.repo, "tinfoilsh/cvmimage");
    assert_eq!(platform.bundle, object("{}"));

    let missing = decode(Vec::new()).unwrap();
    assert!(missing.config_platform().unwrap_err().is_not_found());

    let conflicting = [
        (
            "wrong id",
            vec![reference("other", SIGSTORE_PLATFORM_V1_FORMAT, data)],
        ),
        (
            "wrong role",
            vec![entry(
                PLATFORM_ID,
                ROLE_ENDORSEMENT,
                SIGSTORE_PLATFORM_V1_FORMAT,
                &[],
                data,
            )],
        ),
        (
            "wrong format",
            vec![reference(
                PLATFORM_ID,
                "https://tinfoil.sh/collateral/unknown/v1",
                data,
            )],
        ),
        (
            "multiple references",
            vec![
                good(),
                reference("other", SIGSTORE_PLATFORM_V1_FORMAT, data),
            ],
        ),
        (
            "multiple references, reserved id second",
            vec![
                reference("other", SIGSTORE_PLATFORM_V1_FORMAT, data),
                good(),
            ],
        ),
    ];
    for (name, entries) in conflicting {
        let set = decode(entries).unwrap();
        let error = set.config_platform().unwrap_err();
        assert!(!error.is_not_found(), "{name}");
        assert!(
            error
                .to_string()
                .contains("conflicting platform collateral"),
            "{name}: {error}"
        );
    }
}

#[test]
fn artifact_freshness_requires_its_reserved_profile() {
    let data = r#"{"sigstore_bundle":{}}"#;
    for id in [FRESHNESS_ID_PLATFORM, FRESHNESS_ID_RUNTIME] {
        let set = decode(vec![reference(id, ARTIFACT_FRESHNESS_V1_FORMAT, data)]).unwrap();
        assert_eq!(set.freshness[id].format, ARTIFACT_FRESHNESS_V1_FORMAT);

        let cases = [
            (
                "unknown id",
                reference("other", ARTIFACT_FRESHNESS_V1_FORMAT, data),
            ),
            (
                "wrong role",
                entry(
                    id,
                    ROLE_ENDORSEMENT,
                    ARTIFACT_FRESHNESS_V1_FORMAT,
                    &[],
                    data,
                ),
            ),
            (
                "missing bundle",
                reference(id, ARTIFACT_FRESHNESS_V1_FORMAT, "{}"),
            ),
        ];
        for (name, entry) in cases {
            assert!(decode(vec![entry]).is_err(), "{id}/{name}");
        }
    }
    let entry = reference(FRESHNESS_ID_RUNTIME, SIGSTORE_FRESHNESS_V1_FORMAT, data);
    assert!(rejection(vec![entry]).contains("conflicting artifact freshness collateral"));
}

#[test]
fn an_entry_decodes_from_a_document_value() {
    let value = object(
        r#"{"id":"vcek","role":"endorsement","format":"f","subjects":["cpu",null],"data":{"a":1}}"#,
    );
    let entry = Entry::from_value(value, "collateral").unwrap();
    assert_eq!(
        entry,
        Entry {
            id: "vcek".to_owned(),
            role: "endorsement".to_owned(),
            format: "f".to_owned(),
            subjects: vec!["cpu".to_owned(), String::new()],
            data: Some(object(r#"{"a":1}"#)),
        }
    );
    assert_eq!(
        Entry::from_value(Value::Null, "collateral").unwrap(),
        Entry::default()
    );
    let nulls = object(r#"{"id":null,"role":null,"format":null,"subjects":null,"data":null}"#);
    let entry = Entry::from_value(nulls, "collateral").unwrap();
    assert_eq!(entry.data, Some(Value::Null));
    assert_eq!(entry.subjects, Vec::<String>::new());

    for text in [
        "[]",
        r#""x""#,
        r#"{"id":1}"#,
        r#"{"subjects":"cpu"}"#,
        r#"{"subjects":[1]}"#,
        r#"{"extra":1}"#,
        r#"{"ID":"x"}"#,
    ] {
        assert!(
            Entry::from_value(object(text), "collateral").is_err(),
            "{text}"
        );
    }
}
