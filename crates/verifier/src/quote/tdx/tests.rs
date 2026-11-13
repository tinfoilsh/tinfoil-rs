//! Tests of TDX quote decoding, collateral decoding, replay, verification
//! and validation, over a production quote with Intel's collateral and over
//! material minted under a test root.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::authenticate::{
    CollateralRecorder, Evidence, PcsReplay, Quote, authenticate, canonical_header_name,
    embedded_root_pem, work,
};
use super::differential_tests::{Pool, index, integer, member};
use super::expectations::assemble;
use super::identity::identity;
use super::lib::abi::{
    ATTESTATION_KEY_TYPE_ECDSA_P256, QUOTE_MIN_SIZE, QUOTE_VERSION, QuoteV4, TEE_TYPE_TDX,
};
use super::lib::pcs::{
    Observed, TcbStatus, observe, parse_qe_identity, parse_tcb_info, pck_crl_url, pck_extensions,
    qe_identity_url, tcb_info_url,
};
use super::lib::verify::pck_certificate_chain;
use crate::canonical::{decode_hex, encode_lower_hex};
use crate::document::collateral::PcsResponse;
use crate::instant::{Civil, Instant};
use crate::json::{self, Value};
use crate::measurement::{Measurement, Register};
use crate::policy::{self, PLATFORM_TDX, TdxPolicy};
use crate::x509::{Certificate, KeyPurpose, pem_blocks, verify_chain};

const CASES: &str = include_str!("../../../tests/data/quote-tdx/authenticate_differential.json");
const ENDORSEMENTS: &str = include_str!("../../../tests/data/platform_endorsements.json");

const TCB_URL: &str =
    "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000";
const QE_URL: &str = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity";
const PCK_CRL_URL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der";
const ROOT_CRL_URL: &str = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

/// One recorded case: a quote, its collateral, the verification time and
/// the trust anchor (`None` is the embedded Intel root).
struct Recorded {
    quote: Vec<u8>,
    pcs: Vec<PcsResponse>,
    now: Instant,
    root: Option<Vec<u8>>,
}

impl Recorded {
    fn load(id: &str) -> Self {
        Self::load_from(CASES, id)
    }

    fn load_from(cases: &str, id: &str) -> Self {
        let document = json::parse(cases.as_bytes()).unwrap();
        let mut pool = Pool::new(&document);
        let case = member(&document, "cases")
            .as_array()
            .unwrap()
            .iter()
            .find(|case| member(case, "id").as_str() == Some(id))
            .unwrap_or_else(|| panic!("no case {id}"));
        let responses = member(&document, "responses").as_array().unwrap();
        let pcs = member(case, "pcs")
            .as_array()
            .unwrap()
            .iter()
            .map(|at| {
                let recorded = &responses[index(at)];
                let mut headers = BTreeMap::new();
                for (name, values) in member(recorded, "h").as_object().unwrap().iter() {
                    let values = values
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| String::from_utf8(pool.get(index(value))).unwrap())
                        .collect();
                    headers.insert(name.to_string(), values);
                }
                PcsResponse {
                    url: String::from_utf8(pool.get(index(member(recorded, "u")))).unwrap(),
                    headers,
                    body: pool.get(index(member(recorded, "b"))),
                }
            })
            .collect();
        let now = member(case, "now").as_array().unwrap();
        let root = integer(member(case, "root"));
        Recorded {
            quote: pool.get(index(member(case, "quote"))),
            pcs,
            now: Instant::from_unix(integer(&now[0]), 0).unwrap(),
            root: (root >= 0).then(|| pool.get(usize::try_from(root).unwrap())),
        }
    }

    /// The quote and collateral minted under a test root.
    fn minted() -> Self {
        Self::load("base")
    }

    /// A production quote of an Intel Sapphire Rapids platform with the
    /// collateral that Intel served for it in June 2023, cut to the length
    /// that its signed data states.
    fn production() -> Self {
        Self::load("real/exact/at-2023-07-01")
    }

    fn body(&self, url: &str) -> &[u8] {
        &self
            .pcs
            .iter()
            .find(|response| response.url == url)
            .unwrap()
            .body
    }

    fn authenticate(&self) -> Result<Quote, String> {
        self.authenticate_at(self.now)
    }

    fn authenticate_at(&self, now: Instant) -> Result<Quote, String> {
        authenticate(
            Evidence {
                quote: &self.quote,
                pcs: &self.pcs,
            },
            now,
            self.root.as_deref(),
        )
        .map_err(|error| error.to_string())
    }
}

fn at(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Instant {
    Instant::from_civil(Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos: 0,
    })
    .unwrap()
}

fn seconds(instant: Instant, delta: i64) -> Instant {
    Instant::from_unix(instant.unix_seconds() + delta, instant.subsec_nanos()).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    decode_hex(text).unwrap()
}

fn response(url: &str, body: &[u8]) -> PcsResponse {
    PcsResponse {
        url: url.to_string(),
        headers: BTreeMap::new(),
        body: body.to_vec(),
    }
}

// ---- The quote format.

#[test]
fn a_production_quote_decodes() {
    let sample = Recorded::production();
    let quote = QuoteV4::parse(&sample.quote).unwrap();
    assert_eq!(quote.header.version, QUOTE_VERSION);
    assert_eq!(
        quote.header.attestation_key_type,
        ATTESTATION_KEY_TYPE_ECDSA_P256
    );
    assert_eq!(quote.header.tee_type, TEE_TYPE_TDX);
    assert_eq!(quote.header.pce_svn, [0, 0]);
    assert_eq!(quote.header.qe_svn, [0, 0]);
    assert_eq!(
        encode_lower_hex(&quote.header.qe_vendor_id),
        "939a7233f79c4ca9940a0db3957f0607"
    );
    assert_eq!(
        encode_lower_hex(&quote.body.tee_tcb_svn),
        "03000400000000000000000000000000"
    );
    assert_eq!(
        encode_lower_hex(&quote.body.mr_seam),
        "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656"
    );
    assert_eq!(quote.body.mr_signer_seam, [0; 48]);
    assert_eq!(
        encode_lower_hex(&quote.body.td_attributes),
        "0000004000000000"
    );
    assert_eq!(encode_lower_hex(&quote.body.xfam), "e71a060000000000");
    assert_eq!(
        encode_lower_hex(&quote.body.mr_td),
        "6363b8043668a3ad953278e10389574d326c6749fb78aa810ecd9336923db86f22fc00b8dcd404bc10d5e119d7215cbb"
    );
    assert_eq!(quote.body.rtmrs[3], [0; 48]);
    assert_eq!(quote.body.report_data[..4], [0x6c, 0x62, 0xde, 0xc1]);
    assert_eq!(quote.signed_bytes, sample.quote[..632]);
    assert!(quote.extra_bytes.is_empty());

    let signed = &quote.signed_data;
    assert_eq!(signed.signature[..], sample.quote[636..700]);
    assert_eq!(signed.attestation_key[..], sample.quote[700..764]);
    assert_eq!(signed.qe_report_bytes[..], sample.quote[770..1154]);
    assert_eq!(signed.qe_report.isv_prod_id, 2);
    assert_eq!(signed.qe_report.misc_select, 0);
    assert_eq!(
        encode_lower_hex(&signed.qe_report.mr_signer),
        "dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5"
    );
    // The report data binds the attestation key and the authentication
    // data.
    let mut hasher = Sha256::new();
    hasher.update(signed.attestation_key);
    hasher.update(&signed.qe_auth_data);
    assert_eq!(signed.qe_report.report_data[..32], hasher.finalize()[..]);
    assert_eq!(signed.qe_report.report_data[32..], [0; 32]);
    assert!(
        signed
            .pck_cert_chain
            .starts_with(b"-----BEGIN CERTIFICATE-----")
    );
    assert!(
        signed
            .pck_cert_chain
            .ends_with(b"-----END CERTIFICATE-----\n")
    );
}

#[test]
fn bytes_after_the_signed_data_are_kept_apart() {
    let sample = Recorded::minted();
    let mut padded = sample.quote.clone();
    padded.extend_from_slice(&[0, 0, 7]);
    let quote = QuoteV4::parse(&padded).unwrap();
    assert_eq!(quote.extra_bytes, [0, 0, 7]);
    assert_eq!(
        quote.signed_data,
        QuoteV4::parse(&sample.quote).unwrap().signed_data
    );
}

/// The smallest well-formed quote: no authentication data and an empty
/// certificate chain.
fn smallest_quote() -> Vec<u8> {
    let mut quote = Recorded::minted().quote;
    quote.truncate(QUOTE_MIN_SIZE);
    quote[632..636].copy_from_slice(&590u32.to_le_bytes());
    quote[766..770].copy_from_slice(&456u32.to_le_bytes());
    quote[1218..1220].copy_from_slice(&0u16.to_le_bytes());
    quote[1220..1222].copy_from_slice(&5u16.to_le_bytes());
    quote[1222..1226].copy_from_slice(&0u32.to_le_bytes());
    quote
}

#[test]
fn the_smallest_quote_decodes_and_nothing_shorter_does() {
    let quote = smallest_quote();
    let decoded = QuoteV4::parse(&quote).unwrap();
    assert!(decoded.signed_data.qe_auth_data.is_empty());
    assert!(decoded.signed_data.pck_cert_chain.is_empty());
    assert!(decoded.extra_bytes.is_empty());
    for length in 0..QUOTE_MIN_SIZE {
        assert!(QuoteV4::parse(&quote[..length]).is_err(), "{length} bytes");
    }
}

#[test]
fn a_quote_must_have_the_version_4_form() {
    let quote = smallest_quote();
    let changed = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut quote = quote.clone();
        edit(&mut quote);
        QuoteV4::parse(&quote)
            .map(|_| ())
            .map_err(|error| error.to_string())
    };
    assert_eq!(changed(&|_| {}), Ok(()));
    for version in [0u16, 1, 3, 5, 0x0104] {
        let error = changed(&|quote| quote[..2].copy_from_slice(&version.to_le_bytes()));
        assert!(error.unwrap_err().contains("version"), "version {version}");
    }
    for key_type in [0u16, 1, 3] {
        let error = changed(&|quote| quote[2..4].copy_from_slice(&key_type.to_le_bytes()));
        assert!(error.unwrap_err().contains("attestation key type"));
    }
    for tee_type in [0u32, 0x80, 0x82, 0x8100_0000] {
        let error = changed(&|quote| quote[4..8].copy_from_slice(&tee_type.to_le_bytes()));
        assert!(error.unwrap_err().contains("TEE type"));
    }
    // The signed data must fit the quote; one byte less of it is a byte
    // that the certification data no longer covers.
    assert!(changed(&|quote| quote[632..636].copy_from_slice(&591u32.to_le_bytes())).is_err());
    assert!(changed(&|quote| quote[632..636].copy_from_slice(&589u32.to_le_bytes())).is_err());
    assert!(changed(&|quote| quote[632..636].copy_from_slice(&0u32.to_le_bytes())).is_err());
    assert!(changed(&|quote| quote[632..636].copy_from_slice(&u32::MAX.to_le_bytes())).is_err());
    for certification_type in [0u16, 5, 7] {
        let error =
            changed(&|quote| quote[764..766].copy_from_slice(&certification_type.to_le_bytes()));
        assert!(error.unwrap_err().contains("certification data type"));
    }
    for size in [455u32, 457, 0, u32::MAX] {
        let error = changed(&|quote| quote[766..770].copy_from_slice(&size.to_le_bytes()));
        assert!(error.unwrap_err().contains("certification data is"));
    }
    for size in [1u16, 7, u16::MAX] {
        assert!(changed(&|quote| quote[1218..1220].copy_from_slice(&size.to_le_bytes())).is_err());
    }
    for chain_type in [0u16, 4, 6] {
        let error = changed(&|quote| quote[1220..1222].copy_from_slice(&chain_type.to_le_bytes()));
        assert!(error.unwrap_err().contains("chain data type"));
    }
    for size in [1u32, u32::MAX] {
        let error = changed(&|quote| quote[1222..1226].copy_from_slice(&size.to_le_bytes()));
        assert!(error.unwrap_err().contains("chain is"));
    }
}

// ---- Collateral and the PCK certificate.

#[test]
fn collateral_urls_have_the_published_form() {
    assert_eq!(pck_crl_url("platform"), PCK_CRL_URL);
    assert_eq!(tcb_info_url("50806f000000"), TCB_URL);
    assert_eq!(qe_identity_url(), QE_URL);
}

#[test]
fn a_production_pck_certificate_states_its_platform() {
    let sample = Recorded::production();
    let quote = QuoteV4::parse(&sample.quote).unwrap();
    let chain = pck_certificate_chain(&quote.signed_data.pck_cert_chain).unwrap();
    let extensions = pck_extensions(&chain.pck).unwrap();
    assert_eq!(extensions.ppid, "089ddfdb9c0359c82a3bc7719239574e");
    assert_eq!(extensions.fmspc, "50806f000000");
    assert_eq!(extensions.pce_id, "0000");
    assert_eq!(extensions.tcb.pce_svn, 11);
    let components = [3, 3, 2, 2, 2, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(extensions.tcb.cpu_svn, components);
    assert_eq!(extensions.tcb.cpu_svn_components, components);
    assert_eq!(
        identity(&quote).unwrap(),
        "089ddfdb9c0359c82a3bc7719239574e"
    );
    // The other certificates of the chain have no SGX extension.
    assert!(pck_extensions(&chain.intermediate).is_err());
    assert!(pck_extensions(&chain.root).is_err());
}

#[test]
fn a_production_pck_chain_reaches_the_embedded_intel_root() {
    let sample = Recorded::production();
    let quote = QuoteV4::parse(&sample.quote).unwrap();
    let chain = pck_certificate_chain(&quote.signed_data.pck_cert_chain).unwrap();
    let anchor = pem_blocks(embedded_root_pem()).unwrap();
    let anchor = Certificate::from_der(&anchor[0].contents).unwrap();
    let intermediates = [chain.intermediate.clone()];
    let roots = [anchor];
    let verify = |now| {
        verify_chain(
            &chain.pck,
            &intermediates,
            &roots,
            now,
            KeyPurpose::ServerAuth,
        )
        .map(|path| path.len())
    };
    assert_eq!(verify(at(2023, 7, 1, 1, 0, 0)).unwrap(), 3);
    assert!(verify(at(2018, 1, 1, 0, 0, 0)).is_err());
    assert!(verify(at(2053, 7, 1, 1, 0, 0)).is_err());
}

#[test]
fn the_pck_chain_is_three_certificates_and_at_most_one_nul() {
    let sample = Recorded::production();
    let chain = QuoteV4::parse(&sample.quote)
        .unwrap()
        .signed_data
        .pck_cert_chain;
    let text = chain.strip_suffix(b"\0").unwrap_or(&chain);
    let with = |suffix: &[u8]| pck_certificate_chain(&[text, suffix].concat()).is_ok();
    assert!(with(b""));
    assert!(with(b"\0"));
    assert!(!with(b"\x01"));
    assert!(!with(b"\0\0"));
    assert!(!with(b"\n"));
    assert!(!with(b"\n\0"));
    assert!(!with(b"\0\n"));
    assert!(!with(b"x"));
    // Without its line end, the last block cannot be followed by a NUL.
    let bare = text.strip_suffix(b"\n").unwrap();
    assert!(pck_certificate_chain(bare).is_ok());
    assert!(pck_certificate_chain(&[bare, b"\0"].concat()).is_err());
    assert!(pck_certificate_chain(&[bare, b"\r\n"].concat()).is_ok());
    assert!(pck_certificate_chain(&[bare, b"\r"].concat()).is_err());
    assert!(pck_certificate_chain(&[bare, b"\r\r\n"].concat()).is_err());
    assert!(pck_certificate_chain(&[bare, b" \n"].concat()).is_err());

    let end = b"-----END CERTIFICATE-----\n";
    let first = text
        .windows(end.len())
        .position(|window| window == end)
        .unwrap()
        + end.len();
    let (leaf, rest) = text.split_at(first);
    assert!(pck_certificate_chain(leaf).is_err());
    assert!(pck_certificate_chain(rest).is_err());
    assert!(pck_certificate_chain(&[text, leaf].concat()).is_err());
    assert!(pck_certificate_chain(&[leaf, b"\n", rest].concat()).is_ok());
    assert!(pck_certificate_chain(&[leaf, b"text\n", rest].concat()).is_err());
    assert!(pck_certificate_chain(&[b"text\n", text].concat()).is_err());
    assert!(pck_certificate_chain(b"").is_err());
    assert!(pck_certificate_chain(b"\0").is_err());
}

#[test]
fn production_collateral_decodes() {
    let sample = Recorded::production();
    let tcb_info = parse_tcb_info(sample.body(TCB_URL)).unwrap();
    assert_eq!(tcb_info.value.fmspc, "50806f000000");
    assert_eq!(tcb_info.value.pce_id, "0000");
    assert_eq!(tcb_info.value.tcb_evaluation_data_number, 15);
    assert_eq!(tcb_info.value.issue_date, at(2023, 6, 18, 8, 42, 58));
    assert_eq!(tcb_info.value.next_update, at(2023, 7, 18, 8, 42, 58));
    assert_eq!(tcb_info.value.tdx_module.mr_signer, [0; 48]);
    assert_eq!(tcb_info.value.tdx_module.attributes_mask, [0xff; 8]);
    assert!(tcb_info.value.tdx_module_identities.is_empty());
    let first = &tcb_info.value.tcb_levels[0];
    assert_eq!(first.status, TcbStatus::UpToDate);
    assert_eq!(first.tcb.sgx_tcb_components.len(), 16);
    assert_eq!(first.tcb.tdx_tcb_components.len(), 16);
    assert_eq!(first.tcb.sgx_tcb_components[0].svn, 5);
    assert_eq!(first.tcb.pce_svn, 11);
    // The signed bytes are the member as it stands in the body.
    let body = sample.body(TCB_URL);
    let start = br#"{"tcbInfo":"#.len();
    let end = start + tcb_info.signed_bytes.len();
    assert_eq!(tcb_info.signed_bytes, body[start..end]);
    assert!(body[end..].starts_with(br#","signature":""#));

    let identity = parse_qe_identity(sample.body(QE_URL)).unwrap();
    assert_eq!(identity.value.tcb_evaluation_data_number, 15);
    assert_eq!(identity.value.issue_date, at(2023, 6, 8, 7, 24, 59));
    assert_eq!(identity.value.misc_select, [0; 4]);
    assert_eq!(identity.value.misc_select_mask, [0xff; 4]);
    assert_eq!(identity.value.attributes.len(), 16);
    assert_eq!(identity.value.mr_signer.len(), 32);
    assert_eq!(identity.value.isv_prod_id, 2);
    assert_eq!(identity.value.tcb_levels.len(), 1);
    assert_eq!(identity.value.tcb_levels[0].tcb.isv_svn, 4);
    assert_eq!(encode_lower_hex(&identity.signature[..4]), "b6a601f0");
}

/// A TCB info body around the given `tcbInfo` text.
fn tcb_info_body(document: &str) -> Vec<u8> {
    format!(
        r#"{{"tcbInfo":{document},"signature":"{}"}}"#,
        "ab".repeat(64)
    )
    .into_bytes()
}

fn components(svn: u8) -> String {
    let component = format!(r#"{{"svn":{svn},"category":"BIOS","type":"x"}}"#);
    format!("[{}]", vec![component; 16].join(","))
}

/// A complete `tcbInfo` object with the given members replaced or added.
/// A replacement of `REMOVE` removes the member.
fn tcb_info(changes: &[(&str, &str)]) -> String {
    let level = format!(
        r#"[{{"tcb":{{"sgxtcbcomponents":{},"pcesvn":11,"tdxtcbcomponents":{}}},"tcbDate":"2024-03-13T00:00:00Z","tcbStatus":"UpToDate"}}]"#,
        components(2),
        components(3)
    );
    let module = format!(
        r#"{{"mrsigner":"{}","attributes":"0000000000000000","attributesMask":"FFFFFFFFFFFFFFFF"}}"#,
        "00".repeat(48)
    );
    let mut members: Vec<(String, String)> = [
        ("id", r#""TDX""#),
        ("version", "3"),
        ("issueDate", r#""2026-05-20T10:00:00Z""#),
        ("nextUpdate", r#""2026-06-19T10:00:00Z""#),
        ("fmspc", r#""50806f000000""#),
        ("pceId", r#""0000""#),
        ("tcbType", "0"),
        ("tcbEvaluationDataNumber", "17"),
        ("tdxModule", module.as_str()),
        ("tdxModuleIdentities", "[]"),
        ("tcbLevels", level.as_str()),
    ]
    .iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect();
    for (name, value) in changes {
        match members.iter_mut().find(|(member, _)| member == name) {
            Some(_) if *value == REMOVE => members.retain(|(member, _)| member != name),
            Some(member) => member.1 = value.to_string(),
            None => members.push((name.to_string(), value.to_string())),
        }
    }
    let members: Vec<String> = members
        .iter()
        .map(|(name, value)| format!(r#""{name}":{value}"#))
        .collect();
    format!("{{{}}}", members.join(","))
}

const REMOVE: &str = "\u{0}remove";

fn tcb_info_with(changes: &[(&str, &str)]) -> Result<(), String> {
    parse_tcb_info(&tcb_info_body(&tcb_info(changes)))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[test]
fn the_signed_bytes_are_the_top_level_member_as_written() {
    let document = tcb_info(&[]).replace(',', " ,\n\t").replace("\":", "\" : ");
    let body = format!(
        "\n {{ \"x\" : {{\"tcbInfo\":{{\"id\":\"decoy\"}}}}, \"y\":\"\\\"tcbInfo\\\":{{}}\", \"tcbInfo\" :\t{document} , \"signature\" : \"{}\" }}\r\n",
        "AB".repeat(64)
    );
    let decoded = parse_tcb_info(body.as_bytes()).unwrap();
    assert_eq!(decoded.signed_bytes, document.as_bytes());
    assert_eq!(decoded.signature, [0xab; 64]);
    assert_eq!(decoded.value.tcb_evaluation_data_number, 17);

    // A member name may be written with escapes; it is still the member.
    let escaped = tcb_info_body(&tcb_info(&[])).to_vec();
    let escaped =
        String::from_utf8(escaped)
            .unwrap()
            .replacen("\"tcbInfo\"", "\"tcb\\u0049nfo\"", 1);
    assert_eq!(
        parse_tcb_info(escaped.as_bytes()).unwrap().signed_bytes,
        tcb_info(&[]).as_bytes()
    );
}

#[test]
fn a_collateral_body_is_strict_json() {
    let good = tcb_info(&[]);
    assert!(parse_tcb_info(&tcb_info_body(&good)).is_ok());
    let signature = "ab".repeat(64);
    let bodies = [
        // The signed member twice, in either order of decoy and original.
        format!(r#"{{"tcbInfo":{{}},"tcbInfo":{good},"signature":"{signature}"}}"#),
        format!(r#"{{"tcbInfo":{good},"tcbInfo":{{}},"signature":"{signature}"}}"#),
        format!(r#"{{"tcbInfo":{good},"signature":"{signature}","signature":"{signature}"}}"#),
        // A repeated name deep inside a member that is not read.
        format!(r#"{{"tcbInfo":{good},"signature":"{signature}","x":[{{"a":{{"b":1,"b":2}}}}]}}"#),
        // Data after the value, and values that are not the object.
        format!(r#"{{"tcbInfo":{good},"signature":"{signature}"}} x"#),
        format!(r#"[{{"tcbInfo":{good},"signature":"{signature}"}}]"#),
        "null".to_string(),
        String::new(),
        // Spellings that a reader matching names loosely would accept.
        format!(r#"{{"TcbInfo":{good},"signature":"{signature}"}}"#),
        format!(r#"{{"tcbInfo":{good},"Signature":"{signature}"}}"#),
        format!(r#"{{"tcbInfo":{good},"signature":"{signature}","TCBINFO":{{}}}}"#),
        // Signatures of the wrong form.
        format!(r#"{{"tcbInfo":{good},"signature":"{}"}}"#, "ab".repeat(63)),
        format!(r#"{{"tcbInfo":{good},"signature":"{}"}}"#, "ab".repeat(65)),
        format!(r#"{{"tcbInfo":{good},"signature":"{}g"}}"#, "a".repeat(127)),
        format!(r#"{{"tcbInfo":{good},"signature":null}}"#),
        format!(r#"{{"tcbInfo":{good}}}"#),
        format!(r#"{{"signature":"{signature}"}}"#),
        format!(r#"{{"tcbInfo":null,"signature":"{signature}"}}"#),
        format!(r#"{{"tcbInfo":[{good}],"signature":"{signature}"}}"#),
    ];
    for body in &bodies {
        assert!(parse_tcb_info(body.as_bytes()).is_err(), "{body}");
    }
    let mut invalid_utf8 = tcb_info_body(&tcb_info(&[("x", "\"a\"")]));
    let at = invalid_utf8
        .windows(3)
        .position(|window| window == b"\"a\"")
        .unwrap();
    invalid_utf8[at + 1] = 0xff;
    assert!(parse_tcb_info(&invalid_utf8).is_err());
    // Unknown members are ignored, at the top level and inside.
    let extra = format!(r#"{{"tcbInfo":{good},"signature":"{signature}","x":[1,{{"y":null}}]}}"#);
    assert!(parse_tcb_info(extra.as_bytes()).is_ok());
    assert_eq!(tcb_info_with(&[("nextThing", r#"{"a":[1]}"#)]), Ok(()));
}

#[test]
fn every_appraised_member_of_tcb_info_is_required() {
    assert_eq!(tcb_info_with(&[]), Ok(()));
    for name in [
        "id",
        "version",
        "issueDate",
        "nextUpdate",
        "fmspc",
        "pceId",
        "tcbEvaluationDataNumber",
        "tdxModule",
        "tcbLevels",
    ] {
        assert!(tcb_info_with(&[(name, REMOVE)]).is_err(), "{name} removed");
        assert!(tcb_info_with(&[(name, "null")]).is_err(), "{name} null");
    }
    // Members that are not read may be absent; the module identities are
    // absent in older documents.
    assert_eq!(tcb_info_with(&[("tcbType", REMOVE)]), Ok(()));
    assert_eq!(tcb_info_with(&[("tcbType", "null")]), Ok(()));
    assert_eq!(tcb_info_with(&[("tdxModuleIdentities", REMOVE)]), Ok(()));
    assert_eq!(tcb_info_with(&[("tdxModuleIdentities", "null")]), Ok(()));
    // When present, they have their type.
    assert!(tcb_info_with(&[("tcbType", r#""0""#)]).is_err());
    assert!(tcb_info_with(&[("tcbType", "256")]).is_err());
    assert!(tcb_info_with(&[("tdxModuleIdentities", "{}")]).is_err());

    assert!(tcb_info_with(&[("id", r#""SGX""#)]).is_err());
    assert!(tcb_info_with(&[("id", r#""tdx""#)]).is_err());
    for version in ["2", "4", "3.0", "3e0", "\"3\"", "-3", "259"] {
        assert!(tcb_info_with(&[("version", version)]).is_err(), "{version}");
    }
    assert!(tcb_info_with(&[("tcbLevels", "[]")]).is_err());
    assert!(tcb_info_with(&[("tcbLevels", "{}")]).is_err());
    // A name that differs only in letter case is not the member, and is
    // not ignored either.
    assert!(tcb_info_with(&[("ID", r#""TDX""#)]).is_err());
    assert!(tcb_info_with(&[("fmspc", REMOVE), ("FMSPC", r#""50806f000000""#)]).is_err());
    assert!(tcb_info_with(&[("tcbLevel\u{17f}", "[]")]).is_err());
}

#[test]
fn the_edition_number_is_a_64_bit_integer() {
    let number = |literal: &str| {
        parse_tcb_info(&tcb_info_body(&tcb_info(&[(
            "tcbEvaluationDataNumber",
            literal,
        )])))
        .map(|decoded| decoded.value.tcb_evaluation_data_number)
        .ok()
    };
    assert_eq!(number("0"), Some(0));
    assert_eq!(number("-0"), Some(0));
    assert_eq!(number("-1"), Some(-1));
    assert_eq!(number("4294967296"), Some(1 << 32));
    assert_eq!(number("9223372036854775807"), Some(i64::MAX));
    assert_eq!(number("-9223372036854775808"), Some(i64::MIN));
    for literal in [
        "9223372036854775808",
        "17.0",
        "1e1",
        "\"17\"",
        "true",
        "[17]",
    ] {
        assert_eq!(number(literal), None, "{literal}");
    }
}

#[test]
fn collateral_timestamps_are_rfc_3339() {
    let issued = |text: &str| {
        parse_tcb_info(&tcb_info_body(&tcb_info(&[("issueDate", text)])))
            .map(|decoded| decoded.value.issue_date)
            .ok()
    };
    let instant = at(2026, 6, 1, 0, 0, 0);
    assert_eq!(issued(r#""2026-06-01T00:00:00Z""#), Some(instant));
    assert_eq!(issued(r#""2026-06-01T02:00:00+02:00""#), Some(instant));
    assert_eq!(issued(r#""2026-05-31T19:00:00-05:00""#), Some(instant));
    assert_eq!(issued(r#""2026-06-01T00:00:00.000Z""#), Some(instant));
    assert_eq!(
        issued(r#""2026-06-01T00:00:00.5Z""#),
        Instant::from_unix(instant.unix_seconds(), 500_000_000)
    );
    for text in [
        r#""2026-06-01t00:00:00Z""#,
        r#""2026-06-01T00:00:00z""#,
        r#""2026-06-01 00:00:00Z""#,
        r#""2026-06-01T0:00:00Z""#,
        r#""2026-06-01T00:00:00,5Z""#,
        r#""2026-06-01T00:00:00+24:00""#,
        r#""2026-06-01T00:00:00+00:60""#,
        r#""2026-06-01T00:00:00""#,
        r#""2026-06-01T00:00:60Z""#,
        r#""2026-02-30T00:00:00Z""#,
        r#""2026-06-01T00:00:00Z ""#,
        r#""""#,
        "1780000000",
    ] {
        assert_eq!(issued(text), None, "{text}");
    }
    // A timestamp may be written with escapes, like any JSON string.
    assert_eq!(issued(r#""2026-06-01T00:00:00\u005a""#), Some(instant));
    assert_eq!(issued(r#""\u0032026-06-01T00:00:00Z""#), Some(instant));
}

fn level(tcb: &str, status: &str) -> String {
    format!(r#"{{"tcb":{tcb},"tcbStatus":{status}}}"#)
}

fn platform_tcb(sgx: &str, pce_svn: &str, tdx: &str) -> String {
    format!(r#"{{"sgxtcbcomponents":{sgx},"pcesvn":{pce_svn},"tdxtcbcomponents":{tdx}}}"#)
}

#[test]
fn a_tcb_level_states_its_components_and_its_status() {
    let levels = |levels: &str| tcb_info_with(&[("tcbLevels", levels)]);
    let good = platform_tcb(&components(2), "11", &components(3));
    assert_eq!(
        levels(&format!("[{}]", level(&good, r#""UpToDate""#))),
        Ok(())
    );
    for status in [
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded",
        "OutOfDate",
        "OutOfDateConfigurationNeeded",
        "Revoked",
    ] {
        let text = format!("[{}]", level(&good, &format!("\"{status}\"")));
        assert_eq!(levels(&text), Ok(()), "{status}");
        assert_eq!(TcbStatus::from_name(status).unwrap().name(), status);
    }
    // A status is never defaulted, in any level.
    for status in ["\"Unknown\"", "\"uptodate\"", "\"\"", "null", "1"] {
        let text = format!(
            "[{},{}]",
            level(&good, r#""UpToDate""#),
            level(&good, status)
        );
        assert!(levels(&text).is_err(), "{status}");
    }
    assert!(levels(&format!("[{{\"tcb\":{good}}}]")).is_err());
    assert!(levels(r#"[{"tcbStatus":"UpToDate"}]"#).is_err());
    assert!(levels("[null]").is_err());

    let with_tcb = |tcb: &str| levels(&format!("[{}]", level(tcb, r#""UpToDate""#)));
    let fifteen = format!("[{}]", vec![r#"{"svn":2}"#; 15].join(","));
    let seventeen = format!("[{}]", vec![r#"{"svn":2}"#; 17].join(","));
    assert!(with_tcb(&platform_tcb(&fifteen, "11", &components(3))).is_err());
    assert!(with_tcb(&platform_tcb(&components(2), "11", &seventeen)).is_err());
    assert!(with_tcb(&platform_tcb("[]", "11", &components(3))).is_err());
    assert!(with_tcb(&platform_tcb("null", "11", &components(3))).is_err());
    for pce_svn in ["65536", "-1", "\"11\"", "11.0", "null"] {
        assert!(with_tcb(&platform_tcb(&components(2), pce_svn, &components(3))).is_err());
    }
    assert_eq!(
        with_tcb(&platform_tcb(&components(255), "65535", &components(0))),
        Ok(())
    );
    for svn in ["256", "-1", "2.0", "\"2\"", "null"] {
        let list = format!("[{}]", vec![format!(r#"{{"svn":{svn}}}"#); 16].join(","));
        assert!(
            with_tcb(&platform_tcb(&list, "11", &components(3))).is_err(),
            "{svn}"
        );
    }
    let untyped = format!("[{}]", vec![r#"{"svn":2,"category":5}"#; 16].join(","));
    assert!(with_tcb(&platform_tcb(&untyped, "11", &components(3))).is_err());
    // Members that are not read have their type when present.
    let dated = |date: &str| {
        levels(&format!(
            r#"[{{"tcb":{good},"tcbDate":{date},"tcbStatus":"UpToDate"}}]"#
        ))
    };
    assert_eq!(dated(r#""2024-03-13T00:00:00Z""#), Ok(()));
    assert_eq!(dated("null"), Ok(()));
    assert!(dated("5").is_err());
    let advised = |ids: &str| {
        levels(&format!(
            r#"[{{"tcb":{good},"tcbStatus":"UpToDate","advisoryIDs":{ids}}}]"#
        ))
    };
    assert_eq!(advised(r#"["INTEL-SA-00837",null]"#), Ok(()));
    assert!(advised("[1]").is_err());
    assert!(advised(r#""x""#).is_err());
}

#[test]
fn a_module_identity_states_its_name_and_levels() {
    let identities = |identities: &str| {
        parse_tcb_info(&tcb_info_body(&tcb_info(&[(
            "tdxModuleIdentities",
            identities,
        )])))
        .map(|decoded| decoded.value.tdx_module_identities)
        .map_err(|error| error.to_string())
    };
    let decoded = identities(
        r#"[{"id":"TDX_03","mrsigner":"00","attributes":"","attributesMask":"FF","tcbLevels":[{"tcb":{"isvsvn":4},"tcbStatus":"UpToDate"},{"tcb":{"isvsvn":2},"tcbStatus":"OutOfDate"}]}]"#,
    )
    .unwrap();
    assert_eq!(decoded[0].id, "TDX_03");
    assert_eq!(decoded[0].tcb_levels[0].tcb.isv_svn, 4);
    assert_eq!(decoded[0].tcb_levels[1].status, TcbStatus::OutOfDate);
    for bad in [
        r#"[{"tcbLevels":[]}]"#,
        r#"[{"id":"TDX_03"}]"#,
        r#"[{"id":3,"tcbLevels":[]}]"#,
        r#"[{"id":"TDX_03","mrsigner":"zz","tcbLevels":[]}]"#,
        r#"[{"id":"TDX_03","mrsigner":null,"tcbLevels":[]}]"#,
        r#"[{"id":"TDX_03","tcbLevels":[{"tcb":{},"tcbStatus":"UpToDate"}]}]"#,
        r#"[{"id":"TDX_03","tcbLevels":[{"tcb":{"isvsvn":4}}]}]"#,
        r#"[{"id":"TDX_03","tcbLevels":[{"tcb":{"isvsvn":4294967296},"tcbStatus":"UpToDate"}]}]"#,
        r#"[{"id":"TDX_03","tcbLevels":[{"tcb":{"isvsvn":4,"pcesvn":70000},"tcbStatus":"UpToDate"}]}]"#,
        "[null]",
    ] {
        assert!(identities(bad).is_err(), "{bad}");
    }
    assert!(identities(r#"[{"id":"TDX_03","tcbLevels":[]}]"#).is_ok());
}

#[test]
fn hex_members_are_hex_of_either_case() {
    let module = |mrsigner: &str| {
        let module = format!(
            r#"{{"mrsigner":{mrsigner},"attributes":"0000000000000000","attributesMask":"ffFFffFFffFFffFF"}}"#
        );
        parse_tcb_info(&tcb_info_body(&tcb_info(&[("tdxModule", &module)])))
            .map(|decoded| decoded.value.tdx_module.mr_signer)
            .ok()
    };
    assert_eq!(module(r#""5E5e""#), Some(vec![0x5e, 0x5e]));
    assert_eq!(module(r#""\u0035e""#), Some(vec![0x5e]));
    assert_eq!(module(r#""""#), Some(Vec::new()));
    for bad in [
        r#""5e5""#,
        r#""zz""#,
        r#""0x5e""#,
        r#""5e 5e""#,
        "null",
        "5",
    ] {
        assert_eq!(module(bad), None, "{bad}");
    }
}

#[test]
fn a_qe_identity_states_every_appraised_member() {
    let body = Recorded::production().body(QE_URL).to_vec();
    let text = String::from_utf8(body).unwrap();
    assert!(parse_qe_identity(text.as_bytes()).is_ok());
    for (from, to) in [
        (r#""id":"TD_QE""#, r#""id":"QE""#),
        (r#""version":2"#, r#""version":3"#),
        (r#""version":2"#, r#""version":2.0"#),
        (r#""isvprodid":2,"#, ""),
        (r#""isvprodid":2"#, r#""isvprodid":65536"#),
        (r#""isvprodid":2"#, r#""isvProdId":2"#),
        (r#""miscselect":"00000000","#, ""),
        (r#""miscselectMask":"FFFFFFFF","#, ""),
        (
            r#""attributesMask":"FBFFFFFFFFFFFFFF0000000000000000","#,
            "",
        ),
        (r#""mrsigner":"DC"#, r#""mrsigner":"DG"#),
        (r#""tcb":{"isvsvn":4}"#, r#""tcb":{}"#),
        (r#""tcb":{"isvsvn":4}"#, r#""tcb":{"isvsvn":-1}"#),
        (r#","tcbStatus":"UpToDate""#, ""),
        (r#""tcbStatus":"UpToDate""#, r#""tcbStatus":"Fine""#),
        (r#""enclaveIdentity""#, r#""EnclaveIdentity""#),
        (r#""issueDate":"2023-06-08T07:24:59Z","#, ""),
        (r#""nextUpdate":"2023-07-08T07:24:59Z","#, ""),
        (r#""tcbEvaluationDataNumber":15,"#, ""),
    ] {
        assert!(text.contains(from), "{from}");
        let changed = text.replacen(from, to, 1);
        assert!(
            parse_qe_identity(changed.as_bytes()).is_err(),
            "{from} -> {to}"
        );
    }
    // The other kind of document is not a QE identity.
    assert!(parse_qe_identity(Recorded::production().body(TCB_URL)).is_err());
    assert!(parse_tcb_info(text.as_bytes()).is_err());
}

#[test]
fn a_response_is_observed_for_its_edition_and_issue_time() {
    let seen = |body: &str| observe(body.as_bytes(), "tcbInfo");
    assert_eq!(
        seen(r#"{"tcbInfo":{"tcbEvaluationDataNumber":20}}"#),
        Observed::Edition {
            number: 20,
            issued: None
        }
    );
    assert_eq!(
        seen(
            r#"{"tcbInfo":{"tcbEvaluationDataNumber":-3,"issueDate":"2026-01-15T00:00:00Z","x":1}}"#
        ),
        Observed::Edition {
            number: -3,
            issued: Some(at(2026, 1, 15, 0, 0, 0))
        }
    );
    assert_eq!(
        seen(r#"{"tcbInfo":{"tcbEvaluationDataNumber":20,"issueDate":null}}"#),
        Observed::Edition {
            number: 20,
            issued: None
        }
    );
    assert_eq!(
        seen(r#"{"tcbInfo":{"tcbEvaluationDataNumber":20,"issueDate":"soon"}}"#),
        Observed::Unreadable
    );
    for nothing in [
        r#"{"tcbInfo":{"issueDate":"2026-01-15T00:00:00Z"}}"#,
        r#"{"tcbInfo":{"tcbEvaluationDataNumber":null,"issueDate":"soon"}}"#,
        r#"{"tcbInfo":{"tcbEvaluationDataNumber":20.0}}"#,
        r#"{"tcbInfo":{"tcbEvaluationDataNumber":"20"}}"#,
        r#"{"tcbInfo":{"tcbEvaluationDataNumber":20,"issueDate":5}}"#,
        r#"{"tcbInfo":{"tcbEvaluationDataNumber":20},"x":{"a":1,"a":2}}"#,
        r#"{"tcbInfo":{"tcbEvaluationDataNumber":20}} x"#,
        r#"{"TcbInfo":{"tcbEvaluationDataNumber":20}}"#,
        r#"{"tcbInfo":{"TcbEvaluationDataNumber":20}}"#,
        r#"{"enclaveIdentity":{"tcbEvaluationDataNumber":20}}"#,
        r#"{"tcbInfo":null}"#,
        r#"{"tcbInfo":[]}"#,
        "null",
        "",
        "not JSON",
    ] {
        assert_eq!(seen(nothing), Observed::Nothing, "{nothing}");
    }
    assert_eq!(
        observe(
            br#"{"enclaveIdentity":{"tcbEvaluationDataNumber":19}}"#,
            "enclaveIdentity"
        ),
        Observed::Edition {
            number: 19,
            issued: None
        }
    );
}

// ---- Replay of recorded responses.

#[test]
fn a_response_recorded_for_an_edition_answers_the_plain_request() {
    let body = br#"{"tcbInfo":{"tcbEvaluationDataNumber":19}}"#;
    let mut recorded = response(
        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000&tcbEvaluationDataNumber=19",
        body,
    );
    recorded.headers.insert(
        "tcb-info-issuer-chain".to_string(),
        vec!["chain".to_string()],
    );
    let responses = [recorded];
    let replay = PcsReplay::new(&responses, at(2026, 1, 1, 0, 0, 0)).unwrap();
    let served = replay
        .get("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000")
        .unwrap();
    assert_eq!(served.body, body);
    assert_eq!(served.headers["Tcb-Info-Issuer-Chain"], ["chain"]);
    let missing = replay.get(QE_URL).unwrap_err();
    assert!(missing.to_string().contains("no recorded response"));
}

#[test]
fn lookup_keys_drop_the_edition_and_order_the_parameters() {
    let key = |url: &str| PcsReplay::key(url).ok();
    assert_eq!(key(TCB_URL).as_deref(), Some(TCB_URL));
    assert_eq!(
        key(&format!("{TCB_URL}&tcbEvaluationDataNumber=17")).as_deref(),
        Some(TCB_URL)
    );
    assert_eq!(
        key("https://h/p?tcbEvaluationDataNumber=1&b=2&tcbEvaluationDataNumber&a=1").as_deref(),
        Some("https://h/p?a=1&b=2")
    );
    assert_eq!(
        key("https://h/p?tcbEvaluationDataNumber=1").as_deref(),
        Some("https://h/p")
    );
    assert_eq!(
        key("HTTPS://H.Example/P?B=x&a=Y").as_deref(),
        Some("https://h.example/p?b=x&a=y")
    );
    assert_eq!(
        key("https://h/p?a=2&b&a=1").as_deref(),
        Some("https://h/p?a=2&a=1&b=")
    );
    assert_eq!(
        key("https://h/p?a=b=c").as_deref(),
        Some("https://h/p?a=b%3dc")
    );
    assert_eq!(key("https://h/p?").as_deref(), Some("https://h/p?"));
    assert_eq!(key("https://h/p?&").as_deref(), Some("https://h/p"));
    assert_eq!(key("https://h:8443").as_deref(), Some("https://h:8443"));
    assert_eq!(
        key("https://h/p?TCBEVALUATIONDATANUMBER=1").as_deref(),
        Some("https://h/p?tcbevaluationdatanumber=1")
    );
    for outside in [
        "",
        "h/p",
        "https:/p",
        "https:///p",
        "https://u@h/p",
        "https://h/p#f",
        "https://h/a%20b",
        "https://h/p?a=%41",
        "https://h/p?a=b+c",
        "https://h/p?a=1;b=2",
        "https://h/a b",
        "https://[::1]/p",
        "https://h:x/p",
        "https://h/p?a=?",
        "https://h\u{e9}/p",
        "1https://h/p",
    ] {
        assert_eq!(key(outside), None, "{outside}");
    }
}

const KEYS: &str = include_str!("../../../tests/data/quote-tdx/replay_keys.json");

/// Recorded URLs with the key that an independent implementation of URL
/// parsing gives them, or `null` where it rejects the URL. A URL in the
/// plain form has that very key; no URL that it rejects has one here.
#[test]
fn lookup_keys_of_plain_urls_are_the_recorded_ones() {
    let document = json::parse(KEYS.as_bytes()).unwrap();
    let cases = member(&document, "cases").as_array().unwrap();
    let mut plain = 0;
    let mut stricter = 0;
    for case in cases {
        let url = member(case, "url").as_str().unwrap();
        let recorded = member(case, "key").as_str();
        if let Ok(key) = PcsReplay::key(url) {
            plain += 1;
            assert_eq!(Some(key.as_str()), recorded, "{url}");
        } else if recorded.is_some() {
            stricter += 1;
        }
    }
    assert!(cases.len() > 150);
    // Of 156 URLs, 138 have a key on record; 60 of those are in the plain
    // form, and the rest are refused here.
    assert_eq!((cases.len(), plain, stricter), (156, 60, 78));
    for url in [TCB_URL, QE_URL, PCK_CRL_URL, ROOT_CRL_URL] {
        assert!(PcsReplay::key(url).is_ok());
    }
}

#[test]
fn a_recorded_url_outside_the_plain_form_is_an_error() {
    let responses = [response(TCB_URL, b"{}"), response("https://h/a%20b", b"{}")];
    assert!(PcsReplay::new(&responses, at(2026, 1, 1, 0, 0, 0)).is_err());
}

#[test]
fn the_later_of_two_responses_for_a_key_is_served() {
    let responses = [
        response(TCB_URL, b"first"),
        response(&TCB_URL.to_uppercase(), b"second"),
    ];
    let replay = PcsReplay::new(&responses, at(2026, 1, 1, 0, 0, 0)).unwrap();
    assert_eq!(replay.get(TCB_URL).unwrap().body, b"second");
}

#[test]
fn a_replayed_revocation_list_is_within_its_validity() {
    let sample = Recorded::minted();
    // The minted PCK list is valid from 2026-05-10 to 2026-06-10.
    let list = sample.body(PCK_CRL_URL);
    let start = at(2026, 5, 10, 0, 0, 0);
    let end = at(2026, 6, 10, 0, 0, 0);
    let served = |url: &str, body: &[u8], now: Instant| {
        let responses = [response(url, body)];
        PcsReplay::new(&responses, now)
            .unwrap()
            .get(url)
            .map(|served| served.body.to_vec())
            .map_err(|error| error.to_string())
    };
    assert_eq!(served(PCK_CRL_URL, list, start).unwrap(), list);
    assert_eq!(served(PCK_CRL_URL, list, end).unwrap(), list);
    assert!(
        served(PCK_CRL_URL, list, seconds(start, -1))
            .unwrap_err()
            .contains("not valid until")
    );
    assert!(
        served(PCK_CRL_URL, list, seconds(end, 1))
            .unwrap_err()
            .contains("expired")
    );
    // The window holds whatever the URL says the body is.
    assert_eq!(served(ROOT_CRL_URL, list, start).unwrap(), list);
    assert!(served(ROOT_CRL_URL, list, seconds(end, 1)).is_err());
    assert!(served(TCB_URL, list, seconds(end, 1)).is_err());
    // A body that is no list is an error only where the URL says that it
    // is one.
    let error = served(PCK_CRL_URL, b"not a CRL", start).unwrap_err();
    assert!(error.contains("parsing recorded revocation list"));
    assert_eq!(
        served(ROOT_CRL_URL, b"not a CRL", start).unwrap(),
        b"not a CRL"
    );
}

#[test]
fn header_names_are_served_in_canonical_form() {
    for (name, canonical) in [
        ("tcb-info-issuer-chain", "Tcb-Info-Issuer-Chain"),
        ("TCB-INFO-ISSUER-CHAIN", "Tcb-Info-Issuer-Chain"),
        ("sgx-pck-crl-issuer-chain", "Sgx-Pck-Crl-Issuer-Chain"),
        ("content-type", "Content-Type"),
        ("x_y-z", "X_y-Z"),
        ("a--b", "A--B"),
        ("-a", "-A"),
        ("9a-b", "9a-B"),
        ("", ""),
        // A name with a byte that header names do not allow stays as it is.
        ("tcb info", "tcb info"),
        ("tcb-info:", "tcb-info:"),
        ("t\u{e9}-b", "t\u{e9}-b"),
    ] {
        assert_eq!(canonical_header_name(name), canonical, "{name}");
    }
}

#[test]
fn a_header_recorded_under_two_spellings_must_agree() {
    let mut recorded = response(TCB_URL, b"{}");
    recorded
        .headers
        .insert("Tcb-Info-Issuer-Chain".to_string(), vec!["a".to_string()]);
    recorded
        .headers
        .insert("tcb-info-issuer-chain".to_string(), vec!["a".to_string()]);
    let now = at(2026, 1, 1, 0, 0, 0);
    let same = [recorded.clone()];
    let served = PcsReplay::new(&same, now).unwrap().get(TCB_URL).unwrap();
    assert_eq!(served.headers.len(), 1);
    assert_eq!(served.headers["Tcb-Info-Issuer-Chain"], ["a"]);

    recorded
        .headers
        .insert("TCB-INFO-ISSUER-CHAIN".to_string(), vec!["b".to_string()]);
    let different = [recorded];
    let replay = PcsReplay::new(&different, now).unwrap();
    assert!(
        replay
            .get(TCB_URL)
            .unwrap_err()
            .to_string()
            .contains("twice")
    );
}

fn edition_body(member: &str, number: i64, issued: Option<&str>) -> Vec<u8> {
    match issued {
        Some(issued) => format!(
            r#"{{"{member}":{{"tcbEvaluationDataNumber":{number},"issueDate":"{issued}"}}}}"#
        ),
        None => format!(r#"{{"{member}":{{"tcbEvaluationDataNumber":{number}}}}}"#),
    }
    .into_bytes()
}

#[test]
fn the_recorder_notes_the_lower_edition_once_both_were_served() {
    let responses = [
        response(TCB_URL, &edition_body("tcbInfo", 20, None)),
        response(QE_URL, &edition_body("enclaveIdentity", 19, None)),
    ];
    let now = at(2026, 1, 15, 0, 0, 0);
    let mut recorder = CollateralRecorder::new(PcsReplay::new(&responses, now).unwrap());
    assert!(recorder.minimum().is_err());
    recorder.get(TCB_URL).unwrap();
    assert!(recorder.minimum().is_err());
    recorder.get(QE_URL).unwrap();
    assert_eq!(recorder.minimum().unwrap(), 19);
    assert!(recorder.get(PCK_CRL_URL).is_err());
    assert_eq!(recorder.minimum().unwrap(), 19);
}

#[test]
fn the_recorder_rejects_collateral_issued_after_the_verification_time() {
    let now = at(2026, 1, 15, 0, 0, 0);
    let at_now = "2026-01-15T00:00:00Z";
    let later = "2026-01-15T00:00:01Z";
    for (name, tcb_info, qe_identity, want) in [
        (
            "issued at the verification time",
            Some(at_now),
            Some(at_now),
            None,
        ),
        (
            "TCB info issued later",
            Some(later),
            Some(at_now),
            Some("TCB info is not yet valid"),
        ),
        (
            "QE identity issued later",
            Some(at_now),
            Some(later),
            Some("QE identity is not yet valid"),
        ),
        (
            "no issue date",
            None,
            Some(at_now),
            Some("issueDate was not observed"),
        ),
        (
            "no QE issue date",
            Some(at_now),
            None,
            Some("issueDate was not observed"),
        ),
    ] {
        let responses = [
            response(TCB_URL, &edition_body("tcbInfo", 20, tcb_info)),
            response(QE_URL, &edition_body("enclaveIdentity", 20, qe_identity)),
        ];
        let mut recorder = CollateralRecorder::new(PcsReplay::new(&responses, now).unwrap());
        recorder.get(TCB_URL).unwrap();
        recorder.get(QE_URL).unwrap();
        let outcome = recorder
            .check_issue_dates(now)
            .map_err(|error| error.to_string());
        match want {
            None => assert_eq!(outcome, Ok(()), "{name}"),
            Some(want) => assert!(outcome.unwrap_err().contains(want), "{name}"),
        }
    }
}

#[test]
fn the_recorder_goes_by_the_path_of_the_request() {
    let now = at(2026, 1, 15, 0, 0, 0);
    let body = edition_body("tcbInfo", 20, Some("2026-01-01T00:00:00Z"));
    let higher = edition_body("tcbInfo", 99, Some("2026-01-02T00:00:00Z"));
    let unreadable = edition_body("tcbInfo", 99, Some("soon"));
    let responses = [
        response(TCB_URL, &body),
        response(
            QE_URL,
            &edition_body("enclaveIdentity", 30, Some("2026-01-01T00:00:00Z")),
        ),
        response("https://pki.example.com/v1/tcb", &higher),
        response("https://pki.example.com/xtcb", &higher),
        response("https://pki.example.com/TCB", &higher),
        response("https://pki.example.com/other", &higher),
        response("https://pki.example.com/bad/tcb", &unreadable),
    ];
    let mut recorder = CollateralRecorder::new(PcsReplay::new(&responses, now).unwrap());
    recorder.get(TCB_URL).unwrap();
    recorder.get(QE_URL).unwrap();
    assert_eq!(recorder.minimum().unwrap(), 20);
    // Paths that do not end in `/tcb` change nothing.
    for url in [
        "https://pki.example.com/xtcb",
        "https://pki.example.com/TCB",
        "https://pki.example.com/other",
    ] {
        recorder.get(url).unwrap();
        assert_eq!(recorder.minimum().unwrap(), 20, "{url}");
    }
    // A later response of the kind replaces the earlier statement.
    recorder.get("https://pki.example.com/v1/tcb").unwrap();
    assert_eq!(recorder.minimum().unwrap(), 30);
    // A statement that cannot be read leaves nothing to conclude, until a
    // readable one replaces it.
    recorder.get("https://pki.example.com/bad/tcb").unwrap();
    assert!(recorder.minimum().is_err());
    assert!(recorder.check_issue_dates(now).is_err());
    recorder.get(TCB_URL).unwrap();
    assert_eq!(recorder.minimum().unwrap(), 20);
    assert_eq!(recorder.check_issue_dates(now), Ok(()));
}

#[test]
fn a_response_is_read_once_and_noted_every_time_it_is_served() {
    let now = at(2026, 1, 15, 0, 0, 0);
    let first = "https://pki.example.com/a/tcb";
    let second = "https://pki.example.com/b/tcb";
    let responses = [
        response(
            first,
            &edition_body("tcbInfo", 20, Some("2026-01-01T00:00:00Z")),
        ),
        response(
            second,
            &edition_body("tcbInfo", 99, Some("2026-01-02T00:00:00Z")),
        ),
        response(
            QE_URL,
            &edition_body("enclaveIdentity", 500, Some("2026-01-01T00:00:00Z")),
        ),
    ];
    work::reset();
    let mut recorder = CollateralRecorder::new(PcsReplay::new(&responses, now).unwrap());
    recorder.get(QE_URL).unwrap();
    // The last response served is the one noted, however often each was
    // served before and under whatever spelling of its URL.
    for (url, noted) in [
        (first, 20),
        (second, 99),
        (first, 20),
        (first, 20),
        ("https://PKI.example.com/b/tcb", 99),
        (
            "HTTPS://pki.example.com/a/tcb?tcbEvaluationDataNumber=7",
            20,
        ),
        (second, 99),
        // The same response under a path that does not end in `/tcb`
        // is served and not noted.
        ("https://pki.example.com/A/TCB", 99),
        (first, 20),
    ] {
        let served = recorder.get(url).unwrap();
        assert!(served.revocation_list.is_none());
        assert_eq!(recorder.minimum().unwrap(), noted, "{url}");
    }
    for _ in 0..1000 {
        recorder.get(first).unwrap();
        recorder.get(second).unwrap();
        assert!(recorder.get("https://pki.example.com/absent").is_err());
    }
    assert_eq!(recorder.minimum().unwrap(), 99);
    // Three responses were judged and three bodies read, once each.
    assert_eq!(work::counts(), (3, 3));
}

const DISTRIBUTION_POINTS: &str =
    include_str!("../../../tests/data/quote-tdx/distribution_points.json");

/// A quote whose QE identity root names many CRL distribution points: the
/// same two locations over and over, each recorded with a body that states
/// nothing, between locations that were not recorded, and the true one
/// last. The root that names them is read before it is authenticated, so
/// the work that the list causes must not grow with its length.
#[test]
fn the_work_of_authentication_does_not_grow_with_the_distribution_points() {
    let filler = format!(r#"{{"filler":[{}0]}}"#, "0,".repeat(1 << 20)).into_bytes();
    let mut counts = Vec::new();
    for (id, points) in [
        ("distribution-points/370", 371),
        ("distribution-points/2", 3),
    ] {
        let mut sample = Recorded::load_from(DISTRIBUTION_POINTS, id);
        // The root certificate is close to the largest that is parsed.
        let header = &sample.pcs[1].headers["Sgx-Enclave-Identity-Issuer-Chain"][0];
        assert_eq!(header.len() > 20_000, points > 3, "{id}");
        // The bodies at the repeated locations are large, and not signed.
        let mut repeated = 0;
        for response in &mut sample.pcs {
            if response.url.starts_with("https://pki.example.com/") {
                response.body = filler.clone();
                repeated += 1;
            }
        }
        assert_eq!(repeated, 2);
        work::reset();
        let quote = sample.authenticate().unwrap();
        assert_eq!(quote.tcb_evaluation_data_number(), 17);
        counts.push(work::counts());
    }
    // Six responses are judged (TCB info, QE identity, both revocation
    // lists and the two repeated locations), and four bodies are read for
    // an edition, whether the root names 371 locations or 3.
    assert_eq!(counts, [(6, 4), (6, 4)]);
}

#[test]
fn a_quote_with_many_distribution_points_has_its_recorded_outcome() {
    for id in ["base", "distribution-points/370", "distribution-points/2"] {
        let quote = Recorded::load_from(DISTRIBUTION_POINTS, id)
            .authenticate()
            .unwrap();
        assert_eq!(quote.tcb_evaluation_data_number(), 17, "{id}");
        assert_eq!(quote.identity(), "ab".repeat(16), "{id}");
    }
}

// ---- Authentication.

#[test]
fn the_embedded_intel_root_parses() {
    let blocks = pem_blocks(embedded_root_pem()).unwrap();
    assert_eq!(blocks.len(), 1);
    let root = Certificate::from_der(&blocks[0].contents).unwrap();
    assert_eq!(root.subject_der(), root.issuer_der());
}

#[test]
fn a_minted_quote_authenticates_under_its_root() {
    let sample = Recorded::minted();
    let quote = sample.authenticate().unwrap();
    assert_eq!(quote.identity(), "ab".repeat(16));
    // The TCB info states edition 17, the QE identity 19.
    assert_eq!(quote.tcb_evaluation_data_number(), 17);
    assert_eq!(quote.quote_bytes(), sample.quote);
    let Measurement::Tdx {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
    } = quote.measurement()
    else {
        panic!("not a TDX measurement");
    };
    assert_eq!(mrtd.as_bytes(), &[0xa1; 48]);
    assert_eq!(rtmr0.as_bytes(), &[0xb0; 48]);
    assert_eq!(rtmr1.as_bytes(), &[0xb1; 48]);
    assert_eq!(rtmr2.as_bytes(), &[0xb2; 48]);
    assert_eq!(rtmr3.as_bytes(), &[0xb3; 48]);
    assert_eq!(
        quote.platform_measurements(),
        ("a1".repeat(48), "b0".repeat(48))
    );
    assert_eq!(quote.quote().body.report_data, [0xcd; 64]);

    // Under the embedded Intel root, the same quote is not authentic.
    let embedded = Recorded {
        root: None,
        ..Recorded::minted()
    };
    assert!(embedded.authenticate().is_err());
}

#[test]
fn a_minted_quote_is_authentic_only_inside_its_collateral_window() {
    let sample = Recorded::minted();
    // From the issue of the QE identity to the next update of the PCK
    // revocation list.
    let start = at(2026, 5, 21, 11, 0, 0);
    let end = at(2026, 6, 10, 0, 0, 0);
    assert!(sample.authenticate_at(start).is_ok());
    assert!(sample.authenticate_at(end).is_ok());
    let early = sample.authenticate_at(seconds(start, -1)).unwrap_err();
    assert!(early.contains("QE identity is not yet valid"), "{early}");
    let late = sample.authenticate_at(seconds(end, 1)).unwrap_err();
    assert!(late.contains("expired"), "{late}");
}

#[test]
fn reserved_header_bytes_and_trailing_bytes_must_be_zero() {
    let sample = Recorded::minted();
    let changed = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut quote = sample.quote.clone();
        edit(&mut quote);
        Recorded {
            quote,
            ..Recorded::minted()
        }
        .authenticate()
        .map(|_| ())
    };
    assert_eq!(changed(&|_| {}), Ok(()));
    for offset in 8..12 {
        let error = changed(&|quote| quote[offset] = 1).unwrap_err();
        assert!(error.contains("non-zero reserved bytes"), "{error}");
    }
    assert_eq!(changed(&|quote| quote.extend_from_slice(&[0; 64])), Ok(()));
    let error = changed(&|quote| quote.extend_from_slice(&[0, 0, 1])).unwrap_err();
    assert!(
        error.contains("non-zero bytes after the signed data"),
        "{error}"
    );
}

#[test]
fn every_kind_of_collateral_is_required() {
    for (url, want) in [
        (TCB_URL, "TCB info"),
        (QE_URL, "QE identity"),
        (PCK_CRL_URL, "PCK revocation list"),
        (ROOT_CRL_URL, "root revocation list"),
    ] {
        let mut sample = Recorded::minted();
        sample.pcs.retain(|response| response.url != url);
        let error = sample.authenticate().unwrap_err();
        assert!(error.contains(want), "{url}: {error}");
        assert!(error.contains("no recorded response"), "{url}: {error}");
    }
    let mut none = Recorded::minted();
    none.pcs.clear();
    assert!(none.authenticate().is_err());
}

#[test]
fn a_changed_quote_or_collateral_is_not_authentic() {
    let sample = Recorded::minted();
    for (offset, want) in [
        (48 + 0x208, "quote signature"),
        (636, "quote signature"),
        (700, "attestation key"),
        (770 + 0x100, "QE report signature"),
        (770 + 384, "QE report signature"),
    ] {
        let mut changed = Recorded::minted();
        changed.quote[offset] ^= 1;
        let error = changed.authenticate().unwrap_err();
        assert!(error.contains(want), "offset {offset}: {error}");
    }
    for url in [TCB_URL, QE_URL] {
        let mut changed = Recorded::minted();
        let body = &mut changed
            .pcs
            .iter_mut()
            .find(|response| response.url == url)
            .unwrap()
            .body;
        // A digit of the edition number.
        let at = body
            .windows(26)
            .position(|window| window == br#""tcbEvaluationDataNumber":"#)
            .unwrap()
            + 27;
        body[at] ^= 1;
        let error = changed.authenticate().unwrap_err();
        assert!(error.contains("response signature"), "{url}: {error}");
    }
    assert!(sample.authenticate().is_ok());
}

#[test]
fn a_production_quote_passes_every_check_before_the_tcb_level() {
    // Intel's sample TCB info lists higher component SVNs than the
    // platform of the sample quote has, so the quote reaches no TCB level.
    // Everything before that is checked first and passes under the
    // embedded Intel root: the PCK chain, both revocation lists, both
    // collateral signatures, the quote signature and the QE report.
    let sample = Recorded::production();
    assert!(sample.root.is_none());
    let error = sample.authenticate().unwrap_err();
    assert!(
        error.contains("no TCB level of the TCB info is reached"),
        "{error}"
    );
    // One second after the PCK revocation list's next update, replay
    // fails first.
    let late = sample
        .authenticate_at(at(2023, 7, 18, 8, 42, 59))
        .unwrap_err();
    assert!(late.contains("expired"), "{late}");
}

// ---- Validation.

/// A policy that the given quote satisfies, with the measurement, report
/// data and config identifier that it shows.
fn matching(quote: &QuoteV4) -> (TdxPolicy, Measurement, [u8; 64], [u8; 48]) {
    let body = &quote.body;
    let policy = TdxPolicy {
        qe_vendor_id: encode_lower_hex(&quote.header.qe_vendor_id),
        minimum_tee_tcb_svn: encode_lower_hex(&body.tee_tcb_svn),
        mr_seam: encode_lower_hex(&body.mr_seam),
        td_attributes: encode_lower_hex(&body.td_attributes),
        xfam: encode_lower_hex(&body.xfam),
        minimum_tcb_evaluation_data_number: Some(5),
        platform_measurements: vec!["sample".to_string()],
    };
    let [rtmr0, rtmr1, rtmr2, rtmr3] = body.rtmrs.map(Register::new);
    let measurement = Measurement::Tdx {
        mrtd: Register::new(body.mr_td),
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
    };
    (policy, measurement, body.report_data, body.mr_config_id)
}

fn production_quote() -> Vec<u8> {
    Recorded::production().quote
}

#[test]
fn a_policy_translates_into_options() {
    let artifact = policy::parse(ENDORSEMENTS.as_bytes()).unwrap();
    let (_, policy) = artifact
        .policy_for("3b064a0f58d5dd3688780aeb40e0b5d2", PLATFORM_TDX)
        .unwrap();
    let policy = policy.as_tdx().unwrap();
    assert_eq!(policy.qe_vendor_id, "939a7233f79c4ca9940a0db3957f0607");
    assert_eq!(policy.td_attributes, "0000001000000000");
    assert!(!policy.mr_seam.is_empty());

    // A quote that shows exactly what the policy states satisfies it, with
    // MR_CONFIG_ID, MR_OWNER and MR_OWNER_CONFIG zero.
    let mut bytes = production_quote();
    bytes[12..28].copy_from_slice(&hex(&policy.qe_vendor_id));
    bytes[48..64].copy_from_slice(&hex(&policy.minimum_tee_tcb_svn));
    bytes[64..112].copy_from_slice(&hex(&policy.mr_seam));
    bytes[168..176].copy_from_slice(&hex(&policy.td_attributes));
    bytes[176..184].copy_from_slice(&hex(&policy.xfam));
    let minimum = policy.minimum_tcb_evaluation_data_number.unwrap();
    let quote = Quote::unauthenticated(&bytes, minimum).unwrap();
    let (_, measurement, report_data, _) = matching(quote.quote());
    let expectations = assemble(policy, &measurement, &report_data, &[0; 48]).unwrap();
    assert_eq!(expectations.validate(&quote), Ok(()));
    for offset in [0xb8, 0xe8, 0x118] {
        let mut bytes = bytes.clone();
        bytes[48 + offset] = 1;
        let quote = Quote::unauthenticated(&bytes, minimum).unwrap();
        assert!(expectations.validate(&quote).is_err(), "offset {offset:#x}");
    }
}

#[test]
fn every_dimension_of_the_policy_is_enforced() {
    let bytes = production_quote();
    let quote = Quote::unauthenticated(&bytes, 5).unwrap();
    let (policy, measurement, report_data, config_id) = matching(quote.quote());
    let expectations = assemble(&policy, &measurement, &report_data, &config_id).unwrap();
    assert_eq!(expectations.validate(&quote), Ok(()));

    let flipped = |text: &str| {
        let mut bytes = hex(text);
        bytes[0] ^= 1;
        encode_lower_hex(&bytes)
    };
    for (field, name) in [
        ("mr_seam", "MR_SEAM"),
        ("qe_vendor_id", "QE_VENDOR_ID"),
        ("xfam", "XFAM"),
        ("td_attributes", "TD_ATTRIBUTES"),
    ] {
        let mut bad = policy.clone();
        let target = match field {
            "mr_seam" => &mut bad.mr_seam,
            "qe_vendor_id" => &mut bad.qe_vendor_id,
            "xfam" => &mut bad.xfam,
            _ => &mut bad.td_attributes,
        };
        *target = flipped(target);
        let expectations = assemble(&bad, &measurement, &report_data, &config_id).unwrap();
        let error = expectations.validate(&quote).unwrap_err().to_string();
        assert!(error.contains(name), "{field}: {error}");
    }

    // A collateral floor above the observed number rejects.
    let stale = Quote::unauthenticated(&bytes, 4).unwrap();
    let error = expectations.validate(&stale).unwrap_err().to_string();
    assert!(error.contains("below the policy minimum"), "{error}");

    // A register or report data that differs from the expected one rejects.
    let Measurement::Tdx {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
    } = measurement.clone()
    else {
        panic!("not a TDX measurement");
    };
    for which in 0..5 {
        let mut registers = [mrtd, rtmr0, rtmr1, rtmr2, rtmr3];
        let mut changed = *registers[which].as_bytes();
        changed[0] ^= 1;
        registers[which] = Register::new(changed);
        let [mrtd, rtmr0, rtmr1, rtmr2, rtmr3] = registers;
        let other = Measurement::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        };
        let expectations = assemble(&policy, &other, &report_data, &config_id).unwrap();
        assert!(expectations.validate(&quote).is_err(), "register {which}");
    }
    let mut other_report_data = report_data;
    other_report_data[0] ^= 1;
    let other = assemble(&policy, &measurement, &other_report_data, &config_id).unwrap();
    assert!(other.validate(&quote).is_err());

    // Only a TDX measurement can be expected of a TDX quote.
    let sev = Measurement::SevSnp {
        launch: Register::new([0; 48]),
    };
    assert!(assemble(&policy, &sev, &report_data, &config_id).is_err());
}

#[test]
fn a_config_binding_fixes_the_config_identifier_and_every_register() {
    let mut bytes = production_quote();
    let config_hash = Sha256::digest(b"approved YAML bytes");
    let mut config_id = [0u8; 48];
    config_id[..32].copy_from_slice(&config_hash);
    bytes[48 + 0xb8..48 + 0xe8].copy_from_slice(&config_id);
    // A config runtime fixes MRTD and zero RTMRs.
    bytes[48 + 0x148..48 + 0x208].fill(0);
    let quote = Quote::unauthenticated(&bytes, 5).unwrap();
    let (policy, measurement, report_data, _) = matching(quote.quote());
    let expectations = assemble(&policy, &measurement, &report_data, &config_id).unwrap();
    assert_eq!(expectations.validate(&quote), Ok(()));

    for (name, offset, mask) in [
        ("config hash", 0xb8, 1),
        ("config padding", 0xb8 + 32, 1),
        ("MRTD", 0x88, 1),
        ("RTMR0", 0x148, 1),
        ("RTMR1", 0x178, 1),
        ("RTMR2", 0x1a8, 1),
        ("RTMR3", 0x1d8, 1),
        ("MRSEAM", 0x10, 1),
        ("attributes", 0x78, 1),
        ("REPORT_DATA", 0x208, 1),
    ] {
        let mut bad = bytes.clone();
        bad[48 + offset] ^= mask;
        let bad = Quote::unauthenticated(&bad, 5).unwrap();
        assert!(expectations.validate(&bad).is_err(), "{name}");
    }
    let stale = Quote::unauthenticated(&bytes, 4).unwrap();
    let error = expectations.validate(&stale).unwrap_err().to_string();
    assert!(error.contains("below the policy minimum"), "{error}");
}

#[test]
fn a_policy_without_a_usable_member_does_not_assemble() {
    let bytes = production_quote();
    let quote = Quote::unauthenticated(&bytes, 5).unwrap();
    let (policy, measurement, report_data, config_id) = matching(quote.quote());
    let with = |edit: &dyn Fn(&mut TdxPolicy)| {
        let mut policy = policy.clone();
        edit(&mut policy);
        assemble(&policy, &measurement, &report_data, &config_id).map(|_| ())
    };
    assert_eq!(with(&|_| {}), Ok(()));
    assert!(with(&|policy| policy.qe_vendor_id.clear()).is_err());
    assert!(with(&|policy| policy.mr_seam.push_str("00")).is_err());
    assert!(with(&|policy| policy.xfam = policy.xfam.to_uppercase()).is_err());
    assert!(with(&|policy| policy.td_attributes = "zz".repeat(8)).is_err());
    assert!(with(&|policy| policy.minimum_tee_tcb_svn.truncate(30)).is_err());
    assert!(with(&|policy| policy.minimum_tcb_evaluation_data_number = None).is_err());
    assert!(with(&|policy| policy.minimum_tcb_evaluation_data_number = Some(-1)).is_err());
    assert_eq!(
        with(&|policy| policy.minimum_tcb_evaluation_data_number = Some(0)),
        Ok(())
    );
    assert_eq!(
        with(&|policy| policy.minimum_tcb_evaluation_data_number = Some(i64::MAX)),
        Ok(())
    );
}

#[test]
fn a_minimum_that_no_collateral_reaches_rejects_every_quote() {
    let bytes = production_quote();
    let (mut policy, measurement, report_data, config_id) =
        matching(Quote::unauthenticated(&bytes, 0).unwrap().quote());
    // A minimum above 32 bits is kept whole: an edition that equals it
    // modulo 2^32 is far below it.
    policy.minimum_tcb_evaluation_data_number = Some((1 << 32) + 5);
    let expectations = assemble(&policy, &measurement, &report_data, &config_id).unwrap();
    for number in [5, u32::MAX.into(), 1 << 32, (1 << 32) + 4, -1, i64::MIN] {
        let quote = Quote::unauthenticated(&bytes, number).unwrap();
        assert!(expectations.validate(&quote).is_err(), "{number}");
    }
    for number in [(1 << 32) + 5, i64::MAX] {
        let quote = Quote::unauthenticated(&bytes, number).unwrap();
        assert_eq!(expectations.validate(&quote), Ok(()), "{number}");
    }
}

const VALIDATIONS: &str = include_str!("../../../tests/data/quote-tdx/validate_differential.json");

/// Recorded policies and quotes with the outcome that an independent
/// implementation gave: `ok`, a failure to assemble, or a failure to
/// validate. A case states what differs from the defaults of the record.
#[test]
fn recorded_validations_have_their_recorded_outcome() {
    let document = json::parse(VALIDATIONS.as_bytes()).unwrap();
    let mut pool = Pool::new(&document);
    let defaults = member(&document, "defaults");
    let cases = member(&document, "cases").as_array().unwrap();
    let mut outcomes = BTreeMap::<String, usize>::new();
    for case in cases {
        let id = member(case, "id").as_str().unwrap();
        let field = |name: &str| -> &Value {
            case.as_object()
                .unwrap()
                .get(name)
                .unwrap_or_else(|| member(defaults, name))
        };
        let text = |name: &str| field(name).as_str().unwrap().to_string();
        let policy = TdxPolicy {
            qe_vendor_id: text("qe_vendor_id"),
            minimum_tee_tcb_svn: text("minimum_tee_tcb_svn"),
            mr_seam: text("mr_seam"),
            td_attributes: text("td_attributes"),
            xfam: text("xfam"),
            minimum_tcb_evaluation_data_number: field("minimum")
                .as_number()
                .map(|number| number.to_i64().unwrap()),
            platform_measurements: Vec::new(),
        };
        let registers = hex(&text("m"));
        let register = |which: usize| {
            Register::new(registers[which * 48..(which + 1) * 48].try_into().unwrap())
        };
        let measurement = Measurement::Tdx {
            mrtd: register(0),
            rtmr0: register(1),
            rtmr1: register(2),
            rtmr2: register(3),
            rtmr3: register(4),
        };
        let report_data: [u8; 64] = hex(&text("report_data")).try_into().unwrap();
        let config_id: [u8; 48] = hex(&text("config_id")).try_into().unwrap();
        let bytes = pool.get(index(field("quote")));
        let quote = Quote::unauthenticated(&bytes, integer(field("tcb"))).unwrap();

        let outcome = match assemble(&policy, &measurement, &report_data, &config_id) {
            Err(_) => "assemble",
            Ok(expectations) => match expectations.validate(&quote) {
                Err(_) => "validate",
                Ok(()) => "ok",
            },
        };
        assert_eq!(outcome, member(case, "reference").as_str().unwrap(), "{id}");
        *outcomes.entry(outcome.to_string()).or_default() += 1;
    }
    assert!(cases.len() > 200);
    assert!(outcomes.values().all(|count| *count > 30), "{outcomes:?}");
}

#[test]
fn authenticated_collateral_bounds_the_quote_lifetime() {
    for id in [
        "chain/quote-root/reissued-expires-now",
        "pcs/header/tcb-info/chain-root-reissued-expires-now",
        "pcs/header/qe-identity/chain-root-reissued-expires-now",
        "pcs/header/pck-crl/chain-root-reissued-expires-now",
        "pcs/crl/pck-crl/next-update-now",
        "pcs/crl/root-crl/next-update-now",
        "json/tcb-info/next-update-at-now-zero-offset",
        "json/qe-identity/next-update-at-now-zero-offset",
    ] {
        let sample = Recorded::load(id);
        let evidence = || Evidence {
            quote: &sample.quote,
            pcs: &sample.pcs,
        };
        let verified = authenticate(evidence(), sample.now, sample.root.as_deref()).unwrap();
        assert_eq!(verified.expires_at(), sample.now, "{id}");
        let after = sample
            .now
            .checked_add(std::time::Duration::from_nanos(1))
            .unwrap();
        assert!(
            authenticate(evidence(), after, sample.root.as_deref()).is_err(),
            "{id}"
        );
    }
}
