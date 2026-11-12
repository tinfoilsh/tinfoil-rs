use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::collateral::tests::{b64, entry};
use super::collateral::{
    AMD_CRL_V1_FORMAT, AMD_VCEK_V1_FORMAT, AmdCrl, AmdVcek, CONFIG_ENDORSEMENT_V1_FORMAT,
    CONFIG_ID, FORMAT_V2, FORMAT_V3, FRESHNESS_ID_CODE, FRESHNESS_ID_PLATFORM, INTEL_PCS_V1_FORMAT,
    ROLE_ENDORSEMENT, ROLE_REFERENCE_VALUES, SIGSTORE_CODE_V1_FORMAT, SIGSTORE_FRESHNESS_V1_FORMAT,
    SIGSTORE_PLATFORM_V1_FORMAT, SUBJECT_CPU,
};
use super::*;

fn hex(bytes: &[u8]) -> String {
    canonical::encode_lower_hex(bytes)
}

fn unhex(text: &str) -> Vec<u8> {
    canonical::decode_hex(text).unwrap()
}

fn test_nonce() -> Vec<u8> {
    (0..NONCE_SIZE as u8).collect()
}

fn tls_key() -> String {
    "aa".repeat(32)
}

fn default_crypto_material() -> String {
    format!(
        r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}","items":[{{"id":"tls","format":"{KEY_SPKI_FP_SHA256_V1_FORMAT}","data":"{}"}},{{"id":"hpke","format":"{KEY_X25519_HPKE_V1_FORMAT}","data":"{}"}}]}}"#,
        tls_key(),
        "bb".repeat(32)
    )
}

fn default_device_evidence() -> String {
    format!(r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":[]}}"#)
}

/// The parts of a well-formed document around a dummy quote. Rendering
/// serializes the endorsed sections once, hashes those bytes, wraps them in
/// base64 and derives the report data, as an enclave does.
#[derive(Clone)]
struct TestDocument {
    nonce: Vec<u8>,
    evidence_format: String,
    crypto_material: Vec<u8>,
    device_evidence: Vec<u8>,
    collateral_format: Option<String>,
    /// The JSON text of the collateral array.
    collateral: Option<String>,
}

impl TestDocument {
    fn new(nonce: &[u8]) -> Self {
        Self {
            nonce: nonce.to_vec(),
            evidence_format: SEV_SNP_REPORT_V1_FORMAT.to_owned(),
            crypto_material: default_crypto_material().into_bytes(),
            device_evidence: default_device_evidence().into_bytes(),
            collateral_format: None,
            collateral: None,
        }
    }

    fn with_crypto_material(mut self, section: &str) -> Self {
        self.crypto_material = section.as_bytes().to_vec();
        self
    }

    fn with_collateral(mut self, format: Option<&str>, entries: &str) -> Self {
        self.collateral_format = format.map(str::to_owned);
        self.collateral = Some(entries.to_owned());
        self
    }

    fn report_data(&self) -> [u8; REPORT_DATA_SIZE] {
        compute_report_data(
            &self.nonce,
            &Sha256::digest(&self.crypto_material),
            &Sha256::digest(&self.device_evidence),
        )
        .unwrap()
    }

    fn render(&self) -> String {
        let mut out = format!(
            r#"{{"format":"{ATTESTATION_V3_FORMAT}","challenge":{{"nonce":"{}","report_data":"{}","report_data_algorithm":"{REPORT_DATA_V1_ALGORITHM}"}},"cpu_evidence":{{"format":"{}","report_base64":"{}","endorsed":{{"crypto_material_hash":"{}","device_evidence_hash":"{}"}}}},"crypto_material":"{}","device_evidence":"{}""#,
            hex(&self.nonce),
            hex(&self.report_data()),
            self.evidence_format,
            STANDARD.encode([1u8; 8]),
            hex(&Sha256::digest(&self.crypto_material)),
            hex(&Sha256::digest(&self.device_evidence)),
            STANDARD.encode(&self.crypto_material),
            STANDARD.encode(&self.device_evidence),
        );
        if let Some(format) = &self.collateral_format {
            out.push_str(&format!(r#","collateral_format":"{format}""#));
        }
        if let Some(collateral) = &self.collateral {
            out.push_str(&format!(r#","collateral":{collateral}"#));
        }
        out.push('}');
        out
    }
}

fn parse_text(text: &str, nonce: &[u8]) -> Result<Document, DocumentError> {
    parse(text.as_bytes(), nonce)
}

/// The rejection of `text`, which must be a verdict on the document and not
/// on the caller's input.
fn rejection(text: &str) -> String {
    let error = parse_text(text, &test_nonce()).unwrap_err();
    assert!(!error.is_invalid_input(), "{error}");
    error.to_string()
}

/// Replaces the document's `crypto_material` or `device_evidence` string
/// with the base64 of other section bytes, leaving the endorsed hashes as
/// they were.
fn swap_section(document: &str, original: &[u8], replacement: &[u8]) -> String {
    let (old, new) = (STANDARD.encode(original), STANDARD.encode(replacement));
    assert!(document.contains(&old));
    assert_ne!(old, new);
    document.replacen(&old, &new, 1)
}

fn replace_once(text: &str, old: &str, new: &str) -> String {
    assert!(text.contains(old), "{old} is not in the document");
    text.replacen(old, new, 1)
}

#[test]
fn parses_a_well_formed_document() {
    let nonce = test_nonce();
    let built = TestDocument::new(&nonce);
    let document = parse_text(&built.render(), &nonce).unwrap();
    assert_eq!(document.expected_report_data(), Some(built.report_data()));
    assert_eq!(document.collateral_format(), FORMAT_V2);

    let items = document.crypto_material_items();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].id, CRYPTO_MATERIAL_ID_TLS);
    assert_eq!(items[1].id, CRYPTO_MATERIAL_ID_HPKE);
    let tls = document
        .crypto_material_item(CRYPTO_MATERIAL_ID_TLS)
        .unwrap();
    assert_eq!(
        tls,
        &CryptoMaterialItem {
            id: "tls".to_owned(),
            format: KEY_SPKI_FP_SHA256_V1_FORMAT.to_owned(),
            data: tls_key(),
        }
    );
    assert!(document.crypto_material_item("missing").is_none());
    assert!(document.device_evidence_items().is_empty());

    let evidence = document.cpu_evidence();
    assert_eq!(evidence.format, SEV_SNP_REPORT_V1_FORMAT);
    assert_eq!(evidence.report, [1u8; 8]);
    assert_eq!(document.cpu_endorsements(), &CpuEndorsements::default());
}

#[test]
fn a_document_without_a_checked_challenge_has_no_expected_report_data() {
    let nonce = test_nonce();
    let text = TestDocument::new(&nonce).render();
    let decoded = decode(text.as_bytes()).unwrap();
    assert_eq!(decoded.expected_report_data(), None);
    // A replayed document decodes; only the nonce check tells it apart.
    let other: Vec<u8> = nonce.iter().map(|byte| !byte).collect();
    assert!(parse_text(&text, &other).is_err());
}

#[test]
fn rejects_a_nonce_mismatch() {
    let nonce = test_nonce();
    let text = TestDocument::new(&nonce).render();
    let mut other = nonce.clone();
    other[0] ^= 0xff;
    let error = parse_text(&text, &other).unwrap_err();
    assert!(!error.is_invalid_input());
    assert!(
        error
            .to_string()
            .contains("challenge nonce does not match the expected nonce")
    );
}

#[test]
fn a_nonce_of_the_wrong_length_is_the_callers_mistake() {
    let nonce = test_nonce();
    let text = TestDocument::new(&nonce).render();
    let mut long = nonce.clone();
    long.push(0);
    for wrong in [&[][..], &nonce[..NONCE_SIZE - 1], &long] {
        let error = parse_text(&text, wrong).unwrap_err();
        assert!(error.is_invalid_input(), "nonce of {} bytes", wrong.len());
        assert!(error.to_string().starts_with("invalid input: "));
    }
    // The nonce is checked before the document is read.
    assert!(parse(b"not json", &[]).unwrap_err().is_invalid_input());
    assert!(!parse(b"not json", &nonce).unwrap_err().is_invalid_input());
}

#[test]
fn rejects_tampered_device_evidence() {
    let built = TestDocument::new(&test_nonce());
    let section = default_device_evidence().replace(r#"{"format""#, r#"{ "format""#);
    let tampered = swap_section(&built.render(), &built.device_evidence, section.as_bytes());
    assert!(rejection(&tampered).contains("device_evidence hash does not match"));
}

/// Only `challenge.report_data` changes: both section hashes still match, so
/// the recomputation of the report data is what rejects.
#[test]
fn rejects_a_report_data_mismatch() {
    let built = TestDocument::new(&test_nonce());
    let tampered = replace_once(
        &built.render(),
        &hex(&built.report_data()),
        &"11".repeat(64),
    );
    assert!(
        rejection(&tampered).contains("challenge report_data does not match the recomputed value")
    );
}

/// The endorsed hashes cover the exact section bytes: any change to the
/// decoded section, even whitespace that leaves the JSON equivalent, breaks
/// the binding.
#[test]
fn the_hashes_cover_the_transported_bytes() {
    let built = TestDocument::new(&test_nonce());
    let section = default_crypto_material().replace(r#"{"format""#, r#"{ "format""#);
    let tampered = swap_section(&built.render(), &built.crypto_material, section.as_bytes());
    assert!(rejection(&tampered).contains("crypto_material hash"));
}

#[test]
fn rejects_a_tampered_key() {
    let built = TestDocument::new(&test_nonce());
    let section = default_crypto_material().replace(&tls_key(), &"ac".repeat(32));
    let tampered = swap_section(&built.render(), &built.crypto_material, section.as_bytes());
    assert!(rejection(&tampered).contains("crypto_material hash"));
}

#[test]
fn rejects_unknown_members_at_every_level() {
    let text = TestDocument::new(&test_nonce())
        .with_collateral(
            None,
            r#"[{"id":"x","role":"endorsement","format":"f","data":{}}]"#,
        )
        .render();
    assert!(parse_text(&text, &test_nonce()).is_ok());
    let cases = [
        (
            "top level",
            r#"{"format""#,
            r#"{"generated_at":"2026-01-01T00:00:00Z","format""#,
        ),
        (
            "challenge",
            r#""challenge":{"#,
            r#""challenge":{"extra":1,"#,
        ),
        (
            "cpu_evidence",
            r#""cpu_evidence":{"#,
            r#""cpu_evidence":{"extra":1,"#,
        ),
        ("endorsed", r#""endorsed":{"#, r#""endorsed":{"extra":1,"#),
        (
            "collateral entry",
            r#"{"id":"x","#,
            r#"{"extra":1,"id":"x","#,
        ),
        ("name in another case", r#"{"format""#, r#"{"Format""#),
        ("name in another case, nested", r#""nonce""#, r#""Nonce""#),
    ];
    for (name, old, new) in cases {
        let error = rejection(&replace_once(&text, old, new));
        assert!(
            error.contains("parsing attestation document"),
            "{name}: {error}"
        );
        assert!(error.contains("unknown member"), "{name}: {error}");
    }

    let sections = [
        (
            "crypto_material section",
            default_crypto_material().replacen('{', r#"{"extra":1,"#, 1),
        ),
        (
            "crypto_material item",
            default_crypto_material().replace(r#"{"id":"tls","#, r#"{"id":"tls","extra":1,"#),
        ),
    ];
    for (name, section) in sections {
        let text = TestDocument::new(&test_nonce())
            .with_crypto_material(&section)
            .render();
        let error = rejection(&text);
        assert!(error.contains("parsing crypto_material"), "{name}: {error}");
    }
    for section in [
        format!(r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":[],"extra":1}}"#),
        format!(r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":[{{"id":"gpu","extra":1}}]}}"#),
    ] {
        let mut built = TestDocument::new(&test_nonce());
        built.device_evidence = section.into_bytes();
        assert!(rejection(&built.render()).contains("parsing device_evidence"));
    }
}

#[test]
fn rejects_duplicate_member_names_at_every_depth() {
    let text = TestDocument::new(&test_nonce())
        .with_collateral(
            None,
            r#"[{"id":"x","role":"endorsement","format":"f","data":{"a":{"b":1}}}]"#,
        )
        .render();
    assert!(parse_text(&text, &test_nonce()).is_ok());
    let format = format!(r#""format":"{ATTESTATION_V3_FORMAT}","#);
    let cases = [
        ("top level, equal values", format.clone(), format.repeat(2)),
        (
            "top level, escaped name",
            format.clone(),
            format!(r#"{format}"\u0066ormat":"{ATTESTATION_V3_FORMAT}","#),
        ),
        (
            "challenge",
            r#""challenge":{"#.to_owned(),
            r#""challenge":{"report_data_algorithm":"x","#.to_owned(),
        ),
        (
            "data of an entry that is not decoded",
            r#"{"b":1}"#.to_owned(),
            r#"{"b":1,"b":1}"#.to_owned(),
        ),
    ];
    for (name, old, new) in cases {
        let error = rejection(&replace_once(&text, &old, &new));
        assert!(
            error.contains("duplicate object member name"),
            "{name}: {error}"
        );
    }

    let section =
        default_crypto_material().replace(r#"{"id":"tls","#, r#"{"id":"tls","id":"tls","#);
    let text = TestDocument::new(&test_nonce())
        .with_crypto_material(&section)
        .render();
    assert!(rejection(&text).contains("duplicate object member name"));
}

#[test]
fn rejects_input_that_is_not_one_strict_json_document() {
    let nonce = test_nonce();
    let text = TestDocument::new(&nonce).render();
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("null", b"null".to_vec()),
        ("array", format!("[{text}]").into_bytes()),
        ("string", b"\"x\"".to_vec()),
        ("empty object", b"{}".to_vec()),
        ("trailing value", format!("{text}{{}}").into_bytes()),
        ("trailing garbage", format!("{text}x").into_bytes()),
        (
            "byte-order mark",
            [&b"\xef\xbb\xbf"[..], text.as_bytes()].concat(),
        ),
        (
            "lone surrogate escape",
            replace_once(&text, "attestation/v3", "attestation/v3\\ud800").into_bytes(),
        ),
    ];
    let mut invalid = text.clone().into_bytes();
    let at = invalid.iter().position(|&b| b == b':').unwrap() + 2;
    invalid.insert(at, 0xff);
    cases.push(("invalid UTF-8", invalid));
    for (name, document) in cases {
        let error = parse(&document, &nonce).unwrap_err();
        assert!(!error.is_invalid_input(), "{name}");
    }
    assert!(parse(format!(" \n{text}\t\r\n").as_bytes(), &nonce).is_ok());
}

#[test]
fn null_members_decode_as_absent_ones() {
    let nonce = test_nonce();
    let text = TestDocument::new(&nonce).render();
    let with_nulls = replace_once(
        &text,
        "}",
        r#"},"collateral_format":null,"collateral":null"#,
    );
    // The first closing brace ends the challenge, so the members land in the
    // document itself.
    assert!(with_nulls.contains(
        r#""report_data_algorithm":"https://tinfoil.sh/report-data/v1"},"collateral_format":null"#
    ));
    let document = parse_text(&with_nulls, &nonce).unwrap();
    assert_eq!(document.collateral_format(), FORMAT_V2);

    for (name, old, new, want) in [
        (
            "format",
            format!(r#""format":"{ATTESTATION_V3_FORMAT}""#),
            r#""format":null"#.to_owned(),
            "unsupported document format",
        ),
        (
            "challenge",
            text[text.find(r#""challenge":"#).unwrap()..text.find(r#","cpu_evidence""#).unwrap()]
                .to_owned(),
            r#""challenge":null"#.to_owned(),
            "unsupported challenge.report_data_algorithm",
        ),
        (
            "crypto_material",
            format!(
                r#""crypto_material":"{}""#,
                STANDARD.encode(default_crypto_material())
            ),
            r#""crypto_material":null"#.to_owned(),
            "crypto_material section is missing",
        ),
    ] {
        let error = rejection(&replace_once(&text, &old, &new));
        assert!(error.contains(want), "{name}: {error}");
    }
}

#[test]
fn rejects_members_of_the_wrong_type() {
    let text = TestDocument::new(&test_nonce()).render();
    let format = format!(r#""format":"{ATTESTATION_V3_FORMAT}""#);
    for new in [
        r#""format":3"#,
        r#""format":["x"]"#,
        r#""format":{}"#,
        r#""format":true"#,
    ] {
        let error = rejection(&replace_once(&text, &format, new));
        assert!(error.contains("cannot decode JSON"), "{new}: {error}");
    }
    let with_collateral = |collateral: &str| {
        TestDocument::new(&test_nonce())
            .with_collateral(None, collateral)
            .render()
    };
    for collateral in [
        "{}",
        r#""x""#,
        "1",
        "[[]]",
        r#"[{"id":1}]"#,
        r#"[{"subjects":"cpu"}]"#,
    ] {
        let error = rejection(&with_collateral(collateral));
        assert!(
            error.contains("parsing attestation document"),
            "{collateral}: {error}"
        );
    }
}

#[test]
fn rejects_an_unknown_report_data_algorithm() {
    let text = TestDocument::new(&test_nonce()).render();
    let tampered = replace_once(
        &text,
        REPORT_DATA_V1_ALGORITHM,
        "https://tinfoil.sh/report-data/v2",
    );
    assert!(rejection(&tampered).contains("report_data_algorithm"));
}

#[test]
fn rejects_an_unsupported_document_format() {
    let text = TestDocument::new(&test_nonce()).render();
    let tampered = replace_once(&text, "attestation/v3", "attestation/v2");
    assert!(rejection(&tampered).contains("unsupported document format"));
}

#[test]
fn rejects_duplicate_item_ids() {
    let filler = "cc".repeat(32);
    let section = default_crypto_material().replace(
        r#""items":[{"id":"tls""#,
        &format!(
            r#""items":[{{"id":"tls","format":"{KEY_SPKI_FP_SHA256_V1_FORMAT}","data":"{filler}"}},{{"id":"tls""#
        ),
    );
    let text = TestDocument::new(&test_nonce())
        .with_crypto_material(&section)
        .render();
    assert!(rejection(&text).contains(r#"duplicate crypto_material item id "tls""#));

    let mut built = TestDocument::new(&test_nonce());
    built.device_evidence = format!(
        r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":[{{"id":"gpu"}},{{"id":"gpu"}}]}}"#
    )
    .into_bytes();
    assert!(rejection(&built.render()).contains(r#"duplicate device_evidence item id "gpu""#));
}

#[test]
fn rejects_malformed_key_material() {
    // The known key formats carry exactly 32 bytes of lowercase hex.
    for (name, data, want) in [
        ("truncated", "aa".repeat(8), "must be 32 bytes"),
        ("too long", "aa".repeat(33), "must be 32 bytes"),
        ("uppercase", "AA".repeat(32), "is not lowercase hex"),
        ("empty", String::new(), "must be 32 bytes"),
    ] {
        let section = default_crypto_material().replace(&tls_key(), &data);
        let text = TestDocument::new(&test_nonce())
            .with_crypto_material(&section)
            .render();
        let error = rejection(&text);
        assert!(error.contains(want), "{name}: {error}");
    }
}

#[test]
fn rejects_malformed_sections() {
    let crypto = |section: String| {
        rejection(
            &TestDocument::new(&test_nonce())
                .with_crypto_material(&section)
                .render(),
        )
    };
    let items = r#"[{"id":"k","format":"f","data":"ab"}]"#;
    for (name, section, want) in [
        (
            "section is null",
            "null".to_owned(),
            "unsupported crypto_material section format",
        ),
        (
            "section is an array",
            "[]".to_owned(),
            "parsing crypto_material",
        ),
        (
            "section is not JSON",
            "not json".to_owned(),
            "parsing crypto_material",
        ),
        (
            "other format",
            format!(r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":{items}}}"#),
            "unsupported crypto_material section format",
        ),
        (
            "no items member",
            format!(r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}"}}"#),
            "crypto_material.items is missing",
        ),
        (
            "null items",
            format!(r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}","items":null}}"#),
            "crypto_material.items is missing",
        ),
        (
            "null item",
            format!(r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}","items":[null]}}"#),
            "crypto_material item is incomplete",
        ),
        (
            "item without a format",
            format!(
                r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}","items":[{{"id":"k","data":"ab"}}]}}"#
            ),
            "crypto_material item is incomplete",
        ),
        (
            "item without an id",
            format!(
                r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}","items":[{{"format":"f","data":"ab"}}]}}"#
            ),
            "crypto_material item is incomplete",
        ),
        (
            "trailing value",
            default_crypto_material() + "{}",
            "parsing crypto_material",
        ),
    ] {
        let error = crypto(section);
        assert!(error.contains(want), "{name}: {error}");
    }

    let device = |section: String| {
        let mut built = TestDocument::new(&test_nonce());
        built.device_evidence = section.into_bytes();
        rejection(&built.render())
    };
    for (name, section, want) in [
        (
            "other format",
            format!(r#"{{"format":"{CRYPTO_MATERIAL_V1_FORMAT}","items":[]}}"#),
            "unsupported device_evidence section format",
        ),
        (
            "no items member",
            format!(r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}"}}"#),
            "device_evidence.items is missing",
        ),
        (
            "item without an id",
            format!(r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":[{{"kind":"gpu"}}]}}"#),
            "device_evidence item has no id",
        ),
        (
            "null item",
            format!(r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":[null]}}"#),
            "device_evidence item has no id",
        ),
    ] {
        let error = device(section);
        assert!(error.contains(want), "{name}: {error}");
    }

    let text = TestDocument::new(&test_nonce()).render();
    for (section, want) in [
        ("crypto_material", "crypto_material section is missing"),
        ("device_evidence", "device_evidence section is missing"),
    ] {
        let start = text.find(&format!(r#""{section}":""#)).unwrap();
        let end = start
            + text[start..]
                .find(r#"","#)
                .unwrap_or(text.len() - start - 2)
            + 1;
        let emptied = format!(r#"{}"{section}":""{}"#, &text[..start], &text[end..]);
        assert!(rejection(&emptied).contains(want), "{section}");
    }
}

#[test]
fn device_evidence_items_keep_their_payload() {
    let section = format!(
        r#"{{"format":"{DEVICE_EVIDENCE_V1_FORMAT}","items":[{{"id":"gpu0","kind":"gpu","vendor":"nvidia","format":"{NVIDIA_GPU_EVIDENCE_V1_FORMAT}","evidence":{{"nonce":"original","other":[1]}}}},{{"id":"bare"}},{{"id":"null","evidence":null}}]}}"#
    );
    let mut built = TestDocument::new(&test_nonce());
    built.device_evidence = section.into_bytes();
    let document = parse_text(&built.render(), &test_nonce()).unwrap();
    let items = document.device_evidence_items();
    assert_eq!(items.len(), 3);
    assert_eq!(
        (
            items[0].id.as_str(),
            items[0].kind.as_str(),
            items[0].vendor.as_str()
        ),
        ("gpu0", "gpu", "nvidia")
    );
    assert_eq!(items[0].format, NVIDIA_GPU_EVIDENCE_V1_FORMAT);
    let evidence = items[0].evidence.as_ref().unwrap().as_object().unwrap();
    assert_eq!(evidence.get("nonce").unwrap().as_str(), Some("original"));
    assert_eq!(
        items[1],
        DeviceEvidenceItem {
            id: "bare".to_owned(),
            ..Default::default()
        }
    );
    assert_eq!(items[2].evidence, Some(Value::Null));
}

#[test]
fn rejects_uppercase_hex() {
    // Every byte has a letter in its hex form.
    let nonce: Vec<u8> = (0..NONCE_SIZE as u8).map(|i| 0xa0 | (i & 0x0f)).collect();
    let text = TestDocument::new(&nonce).render();
    let upper = replace_once(&text, &hex(&nonce), &hex(&nonce).to_uppercase());
    let error = parse_text(&upper, &nonce).unwrap_err();
    assert!(error.to_string().contains("lowercase hex"), "{error}");
}

/// A line break in the base64 of a section leaves the decoded bytes, and so
/// the endorsed hash, unchanged: accepting it would mean two distinct
/// documents with identical endorsed content.
#[test]
fn rejects_non_canonical_section_base64() {
    let text = TestDocument::new(&test_nonce()).render();
    let encoded = STANDARD.encode(default_crypto_material());
    let mangled = format!("{}\\n{}", &encoded[..8], &encoded[8..]);
    let error = rejection(&replace_once(&text, &encoded, &mangled));
    assert!(
        error.contains("crypto_material is not canonical base64"),
        "{error}"
    );
}

#[test]
fn rejects_non_canonical_report_base64() {
    let text = TestDocument::new(&test_nonce()).render();
    let encoded = STANDARD.encode([1u8; 8]);
    assert_eq!(encoded, "AQEBAQEBAQE=");
    // Each variant decodes to the same report bytes under a lenient decoder.
    let variants = [
        (
            "embedded newline",
            format!("{}\\n{}", &encoded[..8], &encoded[8..]),
        ),
        ("trailing CRLF", format!("{encoded}\\r\\n")),
        ("nonzero padding bits", "AQEBAQEBAQF=".to_owned()),
    ];
    for (name, variant) in variants {
        let error = rejection(&replace_once(&text, &encoded, &variant));
        assert!(
            error.contains("cpu_evidence.report_base64"),
            "{name}: {error}"
        );
    }
}

#[test]
fn rejects_incomplete_cpu_evidence() {
    let text = TestDocument::new(&test_nonce()).render();
    for (old, new) in [
        (
            format!(r#""format":"{SEV_SNP_REPORT_V1_FORMAT}""#),
            r#""format":"""#,
        ),
        (
            r#""report_base64":"AQEBAQEBAQE=""#.to_owned(),
            r#""report_base64":"""#,
        ),
    ] {
        let error = rejection(&replace_once(&text, &old, new));
        assert!(error.contains("cpu_evidence is incomplete"), "{error}");
    }
    // The endorsed hashes are checked first.
    let no_format = replace_once(
        &text,
        &format!(r#""format":"{SEV_SNP_REPORT_V1_FORMAT}""#),
        r#""format":"""#,
    );
    let hash = hex(&Sha256::digest(default_crypto_material()));
    let error = rejection(&replace_once(&no_format, &hash, &hash.to_uppercase()));
    assert!(
        error.contains("crypto_material_hash is not lowercase hex"),
        "{error}"
    );
}

#[test]
fn rejects_malformed_data_of_other_key_formats() {
    let insert = |item: &str| {
        let section =
            default_crypto_material().replace(r#""items":["#, &format!(r#""items":[{item},"#));
        TestDocument::new(&test_nonce())
            .with_crypto_material(&section)
            .render()
    };
    let item = |data: &str| {
        format!(r#"{{"id":"x","format":"https://example.com/key/v9","data":"{data}"}}"#)
    };
    // "abc" matches the character class but is not whole bytes.
    for data in ["abc", "ABCD", "wxyz"] {
        let error = rejection(&insert(&item(data)));
        assert!(
            error.contains(r#"crypto_material item "x" data is not lowercase hex"#),
            "{data}: {error}"
        );
    }
    assert!(rejection(&insert(&item(""))).contains(r#"crypto_material item "x" data is empty"#));

    let document = parse_text(&insert(&item("abcd")), &test_nonce()).unwrap();
    assert_eq!(document.crypto_material_item("x").unwrap().data, "abcd");
}

#[test]
fn rejects_duplicate_collateral_ids() {
    let collateral = format!(
        r#"[{{"id":"cpu-endorsement","role":"endorsement","format":"{AMD_VCEK_V1_FORMAT}","subjects":["cpu"],"data":{{"vcek_der_base64":"","cert_chain_pem":""}}}},{{"id":"cpu-endorsement","role":"reference-values","format":"{SIGSTORE_CODE_V1_FORMAT}","data":{{}}}}]"#
    );
    let text = TestDocument::new(&test_nonce())
        .with_collateral(None, &collateral)
        .render();
    assert!(rejection(&text).contains(r#"duplicate collateral entry id "cpu-endorsement""#));
}

#[test]
fn rejects_a_duplicate_freshness_id() {
    let witness = format!(
        r#"{{"id":"{FRESHNESS_ID_CODE}","role":"reference-values","format":"{SIGSTORE_FRESHNESS_V1_FORMAT}","data":{{"sigstore_bundle":{{}}}}}}"#
    );
    let text = TestDocument::new(&test_nonce())
        .with_collateral(None, &format!("[{witness},{witness}]"))
        .render();
    assert!(rejection(&text).contains(r#"duplicate collateral entry id "code-freshness""#));
}

/// A document carrying the given collateral entries, for CPU evidence of the
/// given format.
fn document_with_collateral(evidence_format: &str, entries: &str) -> Document {
    let mut built = TestDocument::new(&test_nonce()).with_collateral(None, entries);
    built.evidence_format = evidence_format.to_owned();
    parse_text(&built.render(), &test_nonce()).unwrap()
}

#[test]
fn freshness_is_selected_by_entry_id() {
    let witness = |id: &str, media_type: &str| {
        format!(
            r#"{{"id":"{id}","role":"reference-values","format":"{SIGSTORE_FRESHNESS_V1_FORMAT}","data":{{"sigstore_bundle":{{"mediaType":"{media_type}"}}}}}}"#
        )
    };
    let entries = format!(
        "[{},{}]",
        witness(FRESHNESS_ID_CODE, "code"),
        witness(FRESHNESS_ID_PLATFORM, "platform")
    );
    let document = document_with_collateral(SEV_SNP_REPORT_V1_FORMAT, &entries);
    let media_type = |id: &str| {
        let witness = document.freshness(id).unwrap();
        assert_eq!(witness.format, SIGSTORE_FRESHNESS_V1_FORMAT);
        let bundle = witness.bundle.as_object().unwrap();
        bundle
            .get("mediaType")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(media_type(FRESHNESS_ID_CODE), "code");
    assert_eq!(media_type(FRESHNESS_ID_PLATFORM), "platform");
    for id in ["", "missing-freshness"] {
        assert!(document.freshness(id).unwrap_err().is_not_found());
    }
}

#[test]
fn sigstore_references() {
    let digest = "ab".repeat(32);
    let reference = |format: &str, repo: &str| {
        format!(
            r#"{{"id":"{format}","role":"reference-values","format":"{format}","data":{{"repo":"{repo}","tag":"v1","digest":"{digest}","sigstore_bundle":{{"mediaType":"{repo}"}}}}}}"#
        )
    };
    let entries = format!(
        "[{},{}]",
        reference(SIGSTORE_CODE_V1_FORMAT, "org/code"),
        reference(SIGSTORE_PLATFORM_V1_FORMAT, "org/platform")
    );
    let document = document_with_collateral(SEV_SNP_REPORT_V1_FORMAT, &entries);

    let code = document.sigstore_code().unwrap();
    assert_eq!(code.repo, "org/code");
    assert_eq!(code.tag, "v1");
    assert_eq!(code.digest, digest);
    let bundle = code.bundle.as_object().unwrap();
    assert_eq!(bundle.get("mediaType").unwrap().as_str(), Some("org/code"));
    assert_eq!(document.sigstore_platform().unwrap().repo, "org/platform");

    let empty = document_with_collateral(SEV_SNP_REPORT_V1_FORMAT, "[]");
    for error in [
        empty.sigstore_code().unwrap_err(),
        empty.sigstore_platform().unwrap_err(),
        empty.config_endorsement().unwrap_err(),
        empty.runtime().unwrap_err(),
        empty.config_platform().unwrap_err(),
        empty.freshness(FRESHNESS_ID_CODE).unwrap_err(),
    ] {
        assert!(error.is_not_found(), "{error}");
        assert!(
            error
                .to_string()
                .starts_with("collateral entry not found: ")
        );
    }

    let malformed = entry(
        "code",
        ROLE_REFERENCE_VALUES,
        SIGSTORE_CODE_V1_FORMAT,
        &[],
        r#"{"repo":"org/code","unknown":1}"#,
    );
    let error = collateral::decode(vec![malformed]).unwrap_err();
    assert!(!error.is_not_found(), "malformed is not missing");
    assert!(error.to_string().contains(&format!(
        "parsing {SIGSTORE_CODE_V1_FORMAT} collateral entry"
    )));
}

#[test]
fn computes_report_data() {
    let nonce = test_nonce();
    let crypto_hash = Sha256::digest(b"crypto");
    let device_hash = Sha256::digest(b"device");
    let got = compute_report_data(&nonce, &crypto_hash, &device_hash).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(REPORT_DATA_V1_ALGORITHM);
    hasher.update(&nonce);
    hasher.update(crypto_hash);
    hasher.update(device_hash);
    assert_eq!(got[..32], hasher.finalize()[..]);
    assert_eq!(got[32..], [0u8; 32]);
    // A fixed vector, so that the derivation cannot drift with the code.
    assert_eq!(
        hex(&compute_report_data(&nonce, &[1; 32], &[2; 32]).unwrap()),
        hex(&Sha256::digest(
            [
                REPORT_DATA_V1_ALGORITHM.as_bytes(),
                &nonce[..],
                &[1; 32],
                &[2; 32]
            ]
            .concat()
        )) + &"00".repeat(32)
    );

    assert!(compute_report_data(&nonce[..16], &crypto_hash, &device_hash).is_err());
    assert!(compute_report_data(&nonce, &crypto_hash[..31], &device_hash).is_err());
    assert!(compute_report_data(&nonce, &crypto_hash, &[]).is_err());
}

#[test]
fn random_nonces_differ() {
    let first = random_nonce().unwrap();
    let second = random_nonce().unwrap();
    assert_eq!(first.len(), NONCE_SIZE);
    assert_ne!(first, second);
    assert_ne!(first, [0; NONCE_SIZE]);
}

/// Key formats that the parser does not interpret are accepted and kept as
/// they are.
#[test]
fn attested_key_vectors() {
    let vectors = json::parse(include_bytes!(
        "../../tests/data/attested_keys_vectors.json"
    ))
    .unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 3);
    for vector in vectors {
        let vector = vector.as_object().unwrap();
        let field = |name: &str| vector.get(name).unwrap().as_str().unwrap();
        let nonce = unhex(field("nonce"));
        let mut built = TestDocument::new(&nonce);
        built.crypto_material = STANDARD.decode(field("crypto_material")).unwrap();
        built.device_evidence = STANDARD.decode(field("device_evidence")).unwrap();
        let text = built.render();
        // The vector's own hashes and report data are what the document
        // carries.
        assert!(
            text.contains(field("crypto_material_hash")),
            "{}",
            field("algorithm")
        );
        assert!(text.contains(field("device_evidence_hash")));
        assert!(text.contains(field("report_data")));

        let document = parse_text(&text, &nonce).unwrap();
        assert_eq!(
            hex(&document.expected_report_data().unwrap()),
            field("report_data")
        );
        let item = vector.get("item").unwrap().as_object().unwrap();
        let item_field = |name: &str| item.get(name).unwrap().as_str().unwrap().to_owned();
        assert_eq!(item_field("format"), KEY_SPKI_V1_FORMAT);
        assert_eq!(
            document.crypto_material_items(),
            [CryptoMaterialItem {
                id: item_field("id"),
                format: item_field("format"),
                data: item_field("data"),
            }]
        );
    }
}

// ---- collateral accessors

fn cpu_entry(id: &str, format: &str, data: &str) -> String {
    format!(
        r#"{{"id":"{id}","role":"{ROLE_ENDORSEMENT}","format":"{format}","subjects":["{SUBJECT_CPU}"],"data":{data}}}"#
    )
}

/// The CPU collateral of both platforms.
fn all_platform_entries() -> String {
    format!(
        "[{},{},{}]",
        cpu_entry(
            "vcek",
            AMD_VCEK_V1_FORMAT,
            &format!(
                r#"{{"vcek_der_base64":"{}","cert_chain_pem":"chain"}}"#,
                b64("vcek der")
            )
        ),
        cpu_entry(
            "crl",
            AMD_CRL_V1_FORMAT,
            &format!(r#"{{"crl_der_base64":"{}"}}"#, b64("crl der"))
        ),
        cpu_entry(
            "pcs",
            INTEL_PCS_V1_FORMAT,
            &format!(
                r#"{{"responses":[{{"url":"https://pcs.example","headers":{{}},"body_base64":"{}"}}]}}"#,
                b64("body")
            )
        ),
    )
}

#[test]
fn cpu_endorsements_are_those_of_the_evidence_platform() {
    let sev = document_with_collateral(SEV_SNP_REPORT_V1_FORMAT, &all_platform_entries());
    assert_eq!(
        sev.cpu_endorsements(),
        &CpuEndorsements {
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

    let tdx = document_with_collateral(TDX_QUOTE_V1_FORMAT, &all_platform_entries());
    let endorsements = tdx.cpu_endorsements();
    assert_eq!(endorsements.amd_vcek, None);
    assert_eq!(endorsements.amd_crl, None);
    let responses = &endorsements.intel_pcs.as_ref().unwrap().responses;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].url, "https://pcs.example");
    assert!(responses[0].headers.is_empty());
    assert_eq!(responses[0].body, b"body");

    let unknown = document_with_collateral(
        "https://example.com/format/unknown",
        &all_platform_entries(),
    );
    assert_eq!(unknown.cpu_endorsements(), &CpuEndorsements::default());
}

#[test]
fn missing_cpu_endorsements_are_none() {
    for format in [SEV_SNP_REPORT_V1_FORMAT, TDX_QUOTE_V1_FORMAT] {
        let document = document_with_collateral(format, "[]");
        assert_eq!(document.cpu_endorsements(), &CpuEndorsements::default());
    }
}

// ---- collateral format

#[test]
fn the_collateral_format_defaults_to_v2() {
    for (format, want) in [
        (None, FORMAT_V2),
        (Some(FORMAT_V2), FORMAT_V2),
        (Some(FORMAT_V3), FORMAT_V3),
    ] {
        let mut built = TestDocument::new(&test_nonce());
        built.collateral_format = format.map(str::to_owned);
        let document = parse_text(&built.render(), &test_nonce()).unwrap();
        assert_eq!(document.collateral_format(), want);
    }
    let mut built = TestDocument::new(&test_nonce());
    built.collateral_format = Some(String::new());
    let document = parse_text(&built.render(), &test_nonce()).unwrap();
    assert_eq!(document.collateral_format(), FORMAT_V2);
}

fn config_entry() -> String {
    format!(
        r#"{{"id":"{CONFIG_ID}","role":"reference-values","format":"{CONFIG_ENDORSEMENT_V1_FORMAT}","data":{{"endorsement_ref":"sha256:{}","config_base64":"eA==","sigstore_bundle":{{}}}}}}"#,
        "a".repeat(64)
    )
}

#[test]
fn rejects_collateral_that_does_not_fit_its_format() {
    let legacy = format!(
        r#"{{"id":"code","role":"reference-values","format":"{SIGSTORE_CODE_V1_FORMAT}","data":{{"digest":"digest","sigstore_bundle":{{}}}}}}"#
    );
    let witness = |id: &str, format: &str| {
        format!(
            r#"{{"id":"{id}","role":"reference-values","format":"{format}","data":{{"sigstore_bundle":{{}}}}}}"#
        )
    };
    let artifact = witness(
        FRESHNESS_ID_PLATFORM,
        collateral::ARTIFACT_FRESHNESS_V1_FORMAT,
    );
    let sigstore = witness(FRESHNESS_ID_CODE, SIGSTORE_FRESHNESS_V1_FORMAT);
    let cases = [
        (
            "unknown",
            Some("unknown"),
            String::new(),
            "unsupported collateral format",
        ),
        (
            "legacy code in v3",
            Some(FORMAT_V3),
            legacy.clone(),
            "legacy code collateral",
        ),
        (
            "config without version",
            None,
            config_entry(),
            "config and runtime collateral require",
        ),
        (
            "config in v2",
            Some(FORMAT_V2),
            config_entry(),
            "config and runtime collateral require",
        ),
        (
            "sigstore freshness in v3",
            Some(FORMAT_V3),
            sigstore.clone(),
            "freshness collateral is incompatible",
        ),
        (
            "artifact freshness in v2",
            Some(FORMAT_V2),
            artifact.clone(),
            "freshness collateral is incompatible",
        ),
        (
            "artifact freshness without version",
            None,
            artifact.clone(),
            "freshness collateral is incompatible",
        ),
    ];
    for (name, format, entries, want) in cases {
        let text = TestDocument::new(&test_nonce())
            .with_collateral(format, &format!("[{entries}]"))
            .render();
        let error = rejection(&text);
        assert!(error.contains(want), "{name}: {error}");
    }

    let accepted = [
        ("legacy code in v2", Some(FORMAT_V2), legacy),
        ("config in v3", Some(FORMAT_V3), config_entry()),
        ("artifact freshness in v3", Some(FORMAT_V3), artifact),
        ("sigstore freshness without version", None, sigstore),
    ];
    for (name, format, entries) in accepted {
        let text = TestDocument::new(&test_nonce())
            .with_collateral(format, &format!("[{entries}]"))
            .render();
        assert!(parse_text(&text, &test_nonce()).is_ok(), "{name}");
    }
}

#[test]
fn config_and_runtime_accessors() {
    let runtime = format!(
        r#"{{"id":"runtime","role":"reference-values","format":"{}","data":{{"repo":"{}","tag":"v0.15.0","digest":"{}","manifest_base64":"{}","sigstore_bundle":{{}}}}}}"#,
        collateral::RUNTIME_V1_FORMAT,
        collateral::RUNTIME_REPO,
        "ab".repeat(32),
        b64("manifest"),
    );
    let platform = format!(
        r#"{{"id":"platform","role":"reference-values","format":"{SIGSTORE_PLATFORM_V1_FORMAT}","data":{{"repo":"o/p","digest":"ab","sigstore_bundle":{{}}}}}}"#
    );
    let text = TestDocument::new(&test_nonce())
        .with_collateral(
            Some(FORMAT_V3),
            &format!("[{},{runtime},{platform}]", config_entry()),
        )
        .render();
    let document = parse_text(&text, &test_nonce()).unwrap();
    assert_eq!(document.collateral_format(), FORMAT_V3);
    let config = document.config_endorsement().unwrap();
    assert_eq!(config.config(), Some(&b"x"[..]));
    assert_eq!(
        config.reference(),
        Some(format!("sha256:{}", "a".repeat(64)).as_str())
    );
    let runtime = document.runtime().unwrap();
    assert_eq!(runtime.manifest, b"manifest");
    assert_eq!(runtime.reference.tag, "v0.15.0");
    assert_eq!(document.config_platform().unwrap().repo, "o/p");
    assert_eq!(document.sigstore_platform().unwrap().repo, "o/p");
}

// ---- recorded documents

/// Assembles a recorded case into the document bytes that it stands for.
fn recorded_document(case: &json::Object) -> Vec<u8> {
    let text = |name: &str| case.get(name).and_then(Value::as_str);
    let bytes = |name: &str| match (text(name), text(&format!("{name}_hex"))) {
        (Some(text), _) => Some(text.as_bytes().to_vec()),
        (None, Some(hex)) => Some(unhex(hex)),
        (None, None) => None,
    };
    let mut built = TestDocument::new(&text("built_nonce_hex").map_or_else(test_nonce, unhex));
    if let Some(format) = text("evidence_format") {
        built.evidence_format = format.to_owned();
    }
    if let Some(section) = bytes("crypto_material") {
        built.crypto_material = section;
    }
    if let Some(section) = bytes("device_evidence") {
        built.device_evidence = section;
    }
    built.collateral_format = text("collateral_format").map(str::to_owned);
    built.collateral = text("collateral").map(str::to_owned);
    let mut document = built.render().into_bytes();

    if let Some(splice) = case.get("splice").and_then(Value::as_object) {
        let number = |name: &str| decode::u64(splice.get(name).unwrap(), name).unwrap() as usize;
        let (at, remove) = (number("at"), number("remove"));
        let insert = match splice.get("insert").and_then(Value::as_str) {
            Some(text) => text.as_bytes().to_vec(),
            None => unhex(splice.get("insert_hex").unwrap().as_str().unwrap()),
        };
        document.splice(at..at + remove, insert);
    }
    document
}

/// Each recorded case is a document and the verdict that a strict parser
/// gives it for the stated nonce.
///
/// A case describes its document by the parts that differ from a default
/// one: the nonce that it was built for, the evidence format, the section
/// bytes, the collateral, and an optional splice that replaces a byte range
/// of the assembled text. `sha256_prefix` pins the bytes that the case
/// stands for, so that the assembly here cannot drift from the record.
#[test]
fn agrees_with_the_recorded_documents() {
    let cases = json::parse(include_bytes!("../../tests/data/document_probes.json")).unwrap();
    let cases = cases.as_array().unwrap();
    assert!(cases.len() >= 300, "{} cases", cases.len());
    let (mut accepted, mut failures) = (0, Vec::new());
    for case in cases {
        let case = case.as_object().unwrap();
        let name = case.get("name").unwrap().as_str().unwrap();
        let want = case.get("accept").unwrap().as_bool().unwrap();
        let document = recorded_document(case);
        let digest = hex(&Sha256::digest(&document));
        let prefix = case.get("sha256_prefix").unwrap().as_str().unwrap();
        assert!(
            digest.starts_with(prefix),
            "{name}: the assembled document differs"
        );

        let nonce = case
            .get("nonce_hex")
            .and_then(Value::as_str)
            .map_or_else(test_nonce, unhex);
        match (parse(&document, &nonce), want) {
            (Ok(_), true) => accepted += 1,
            (Err(_), false) => {}
            (Ok(_), false) => failures.push(format!("{name}: accepted, want a rejection")),
            (Err(error), true) => failures.push(format!("{name}: rejected: {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(accepted >= 80, "{accepted} accepted");
}
