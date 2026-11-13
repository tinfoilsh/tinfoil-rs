//! Replays recorded SEV-SNP evidence through authentication, assembly and
//! validation.
//!
//! `authentication_differential.json` holds reports, VCEK certificates,
//! certificate chains and revocation lists: evidence captured from hardware,
//! evidence of the shared test vectors, and chains minted for these cases so
//! that a changed report or certificate is signed again and reaches the
//! checks behind the signatures. Each case is a change to a named base and
//! records two verdicts: `accepted`, the verdict of this crate, and
//! `reference`, the verdict of a second, independent implementation of the
//! same rules. Where the two differ this crate is the stricter one, and the
//! case names the `class` of the difference.
//!
//! `validation_differential.json` holds minted evidence that authenticates,
//! each case with a policy, and records where the second implementation
//! stops: at assembly, at validation, or not at all.

use std::collections::BTreeMap;

use super::authenticate::{Evidence, Quote, authenticate};
use super::expectations::assemble;
use crate::canonical::encode_lower_hex;
use crate::instant::Instant;
use crate::json::{self, Object, Value};
use crate::measurement::Register;
use crate::policy::{GuestPolicy, SevSnpPolicy, SnpPlatform, Tcb};
use crate::sigstore::testutil::{b64, to_b64};
use crate::x509::der::pem_certificates;

const AUTHENTICATION: &[u8] =
    include_bytes!("../../../tests/data/sev/authentication_differential.json");
const VALIDATION: &[u8] = include_bytes!("../../../tests/data/sev/validation_differential.json");

fn object(value: &Value) -> &Object {
    value.as_object().unwrap()
}

fn text<'a>(fields: &'a Object, name: &str) -> &'a str {
    fields.get(name).and_then(Value::as_str).unwrap()
}

fn integer(value: &Value) -> i64 {
    value.as_number().unwrap().to_i64().unwrap()
}

fn index(value: &Value) -> usize {
    usize::try_from(integer(value)).unwrap()
}

/// Maps `items` on as many threads as the machine offers, keeping their
/// order. Signature checks dominate these tests, and they are independent.
fn in_parallel<T: Sync, R: Send>(items: &[T], map: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    let chunk = items.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        let workers: Vec<_> = items
            .chunks(chunk)
            .map(|chunk| scope.spawn(|| chunk.iter().map(&map).collect::<Vec<R>>()))
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect()
    })
}

/// Applies the edits of a case to a base. An edit is `[at, del, ins]`: `del`
/// units at offset `at` of the base are replaced by `ins`. Offsets refer to
/// the base, so the edits are applied from the end.
fn edited<T: Clone>(base: &[T], edits: Option<&Value>, decode: impl Fn(&str) -> Vec<T>) -> Vec<T> {
    let mut out = base.to_vec();
    let Some(edits) = edits else {
        return out;
    };
    for edit in edits.as_array().unwrap().iter().rev() {
        let [at, del, ins] = edit.as_array().unwrap() else {
            panic!("an edit is [at, del, ins]");
        };
        let at = index(at);
        out.splice(at..at + index(del), decode(ins.as_str().unwrap()));
    }
    out
}

fn edited_bytes(base: &[u8], edits: Option<&Value>) -> Vec<u8> {
    edited(base, edits, b64)
}

fn edited_text(base: &str, edits: Option<&Value>) -> String {
    let edited = edited(base.as_bytes(), edits, |ins| ins.as_bytes().to_vec());
    String::from_utf8(edited).unwrap()
}

/// A certificate as a PEM block with lines of 64 characters.
pub(super) fn pem(der: &[u8]) -> String {
    let encoded = to_b64(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// A pinned certificate of a case: the base's, the base's with its DER
/// edited, or the base's with its text edited.
fn pinned(case: &Object, base: &Object, role: &str) -> String {
    let base_pem = text(base, &format!("{role}_pem"));
    if let Some(edits) = case.get(&format!("{role}_der")) {
        let der = pem_certificates(base_pem.as_bytes()).unwrap().remove(0);
        return pem(&edited_bytes(&der, Some(edits)));
    }
    edited_text(base_pem, case.get(&format!("{role}_pem")))
}

/// The pinned chain as the test harness joins it: the intermediate and then
/// the root. Without both, the embedded chain is used.
fn pinned_chain(ask_pem: &str, ark_pem: &str) -> Option<String> {
    if ask_pem.is_empty() && ark_pem.is_empty() {
        return None;
    }
    assert!(!ask_pem.is_empty() && !ark_pem.is_empty());
    Some(format!("{}\n{}\n", ask_pem.trim(), ark_pem.trim()))
}

/// One authentication case, assembled.
pub(super) struct AuthenticationCase {
    pub name: String,
    pub report: Vec<u8>,
    pub vcek: Vec<u8>,
    pub chain_pem: String,
    pub crl: Vec<u8>,
    pub root_pem: Option<String>,
    pub now: Instant,
    pub accepted: bool,
    pub reference: bool,
    pub class: Option<String>,
    pub measurement: Option<String>,
}

impl AuthenticationCase {
    pub fn authenticate(&self) -> Result<Quote, crate::quote::QuoteError> {
        authenticate(
            Evidence {
                report: &self.report,
                vcek_der: &self.vcek,
                cert_chain_pem: &self.chain_pem,
                crl_der: &self.crl,
            },
            self.now,
            self.root_pem.as_deref().map(str::as_bytes),
        )
    }
}

/// Every recorded authentication case, by name.
pub(super) fn authentication_cases() -> Vec<AuthenticationCase> {
    let fixture = json::parse(AUTHENTICATION).unwrap();
    let bases = object(object(&fixture).get("bases").unwrap());
    let cases = object(&fixture).get("cases").unwrap().as_array().unwrap();
    cases
        .iter()
        .map(|case| {
            let case = object(case);
            let base = object(bases.get(text(case, "base")).unwrap());
            let bytes = |name: &str| edited_bytes(&b64(text(base, name)), case.get(name));
            let now = integer(case.get("now").unwrap_or_else(|| base.get("now").unwrap()));
            AuthenticationCase {
                name: text(case, "name").to_owned(),
                report: bytes("report"),
                vcek: bytes("vcek"),
                chain_pem: edited_text(text(base, "chain_pem"), case.get("chain_pem")),
                crl: bytes("crl"),
                root_pem: pinned_chain(&pinned(case, base, "ask"), &pinned(case, base, "ark")),
                now: Instant::from_unix(now, 0).unwrap(),
                accepted: case.get("accepted").and_then(Value::as_bool).unwrap(),
                reference: case.get("reference").and_then(Value::as_bool).unwrap(),
                class: case
                    .get("class")
                    .map(|class| class.as_str().unwrap().to_owned()),
                measurement: case
                    .get("measurement")
                    .map(|register| register.as_str().unwrap().to_owned()),
            }
        })
        .collect()
}

/// The case called `name` among recorded cases.
pub(super) fn named<'a>(cases: &'a [AuthenticationCase], name: &str) -> &'a AuthenticationCase {
    cases
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("no recorded case {name}"))
}

#[test]
fn recorded_evidence_gets_its_recorded_verdict() {
    let cases = authentication_cases();
    assert!(cases.len() > 1_000);
    let mut accepted = 0;
    let mut stricter: BTreeMap<String, usize> = BTreeMap::new();
    let results = in_parallel(&cases, AuthenticationCase::authenticate);
    for (case, result) in cases.iter().zip(results) {
        let name = &case.name;
        assert_eq!(
            result.is_ok(),
            case.accepted,
            "{name}: verdict differs from the record: {:?}",
            result.as_ref().err()
        );
        assert!(
            case.reference || !case.accepted,
            "{name}: accepted evidence that the other implementation turns down"
        );
        match (&result, &case.class) {
            (Ok(quote), None) => {
                accepted += 1;
                let crate::measurement::Measurement::SevSnp { launch } = quote.measurement() else {
                    panic!("{name}: not an SEV-SNP measurement");
                };
                assert_eq!(Some(launch.to_string()), case.measurement, "{name}");
                assert_eq!(quote.report_bytes(), case.report, "{name}");
                assert_eq!(
                    quote.identity(),
                    encode_lower_hex(&quote.report().chip_id),
                    "{name}"
                );
            }
            (Err(_), Some(class)) => {
                assert!(case.reference, "{name}: a class without a difference");
                *stricter.entry(class.clone()).or_default() += 1;
            }
            (Err(_), None) => assert!(!case.reference, "{name}: an unnamed difference"),
            (Ok(_), Some(_)) => panic!("{name}: a class on accepted evidence"),
        }
    }
    let stricter: Vec<(&str, usize)> = stricter
        .iter()
        .map(|(class, count)| (class.as_str(), *count))
        .collect();
    assert_eq!(accepted, EXPECTED_ACCEPTED);
    assert_eq!(stricter, EXPECTED_STRICTER);
}

/// The recorded cases that authenticate.
const EXPECTED_ACCEPTED: usize = 345;

/// The recorded cases that authenticate elsewhere and not here, by class.
const EXPECTED_STRICTER: [(&str, usize); 10] = [
    ("PEM with text outside blocks, headers or spaces", 9),
    ("VCEK certificate in PEM form", 2),
    ("distribution point URL with an unusual authority", 9),
    ("pinned certificate signature algorithm", 2),
    ("report with an all-zero CHIP_ID", 2),
    ("report with reserved bits set in the CPUID stepping", 14),
    ("revocation list signature algorithm", 2),
    ("revocation list with a critical extension", 2),
    ("revocation list with a negative serial number", 1),
    ("revocation list with trailing data", 3),
];

/// Reads a policy from named values: `lookup` maps a dotted member path,
/// such as `minimum_tcb.bl_spl`, to its value. A missing or null member is
/// an absent one.
pub(super) fn policy_from<'a>(lookup: impl Fn(&str) -> Option<&'a Value>) -> SevSnpPolicy {
    let present = |path: &str| lookup(path).filter(|value| !value.is_null());
    let number = |path: &str| present(path).map(|value| value.as_number().unwrap());
    let level = |path: &str| number(path).map(|level| level.to_u8().unwrap());
    let flag = |path: &str| present(path).is_some_and(|value| value.as_bool().unwrap());
    let string = |path: &str| {
        present(path)
            .map(|value| value.as_str().unwrap().to_owned())
            .unwrap_or_default()
    };
    let tcb = |name: &str| Tcb {
        fmc_spl: level(&format!("{name}.fmc_spl")),
        bl_spl: level(&format!("{name}.bl_spl")),
        tee_spl: level(&format!("{name}.tee_spl")),
        snp_spl: level(&format!("{name}.snp_spl")),
        ucode_spl: level(&format!("{name}.ucode_spl")),
    };
    SevSnpPolicy {
        minimum_build: level("minimum_build"),
        minimum_api_version: string("minimum_api_version"),
        minimum_abi_version: string("minimum_abi_version"),
        minimum_guest_svn: number("minimum_guest_svn").map(|svn| svn.to_u32().unwrap()),
        minimum_tcb: tcb("minimum_tcb"),
        minimum_launch_tcb: tcb("minimum_launch_tcb"),
        guest_policy: GuestPolicy {
            debug: flag("guest_policy.debug"),
            smt: flag("guest_policy.smt"),
            migrate_ma: flag("guest_policy.migrate_ma"),
            single_socket: flag("guest_policy.single_socket"),
            cxl_allowed: flag("guest_policy.cxl_allowed"),
            mem_aes256_xts: flag("guest_policy.mem_aes256_xts"),
            rapl_dis: flag("guest_policy.rapl_dis"),
            ciphertext_hiding_dram: flag("guest_policy.ciphertext_hiding_dram"),
            page_swap_disable: flag("guest_policy.page_swap_disable"),
        },
        platform_info: SnpPlatform {
            smt_enabled: flag("platform_info.smt_enabled"),
            tsme_enabled: flag("platform_info.tsme_enabled"),
            ecc_enabled: flag("platform_info.ecc_enabled"),
            rapl_disabled: flag("platform_info.rapl_disabled"),
            ciphertext_hiding_dram: flag("platform_info.ciphertext_hiding_dram"),
            alias_check_complete: flag("platform_info.alias_check_complete"),
            iommu_write_safe: flag("platform_info.iommu_write_safe"),
            tio_enabled: flag("platform_info.tio_enabled"),
        },
        permit_provisional_firmware: flag("permit_provisional_firmware"),
        vmpl: number("vmpl").map(|vmpl| vmpl.to_i64().unwrap()),
        host_data: string("host_data"),
        image_id: string("image_id"),
        family_id: string("family_id"),
        require_author_key: flag("require_author_key"),
        require_id_block: flag("require_id_block"),
        minimum_launch_mitigation_vector: number("minimum_launch_mitigation_vector")
            .map(|vector| vector.to_u64().unwrap()),
        minimum_current_mitigation_vector: number("minimum_current_mitigation_vector")
            .map(|vector| vector.to_u64().unwrap()),
    }
}

/// Reads a policy from a nested object, such as a `sev_snp` policy block.
pub(super) fn policy_from_object(block: &Object) -> SevSnpPolicy {
    policy_from(|path| {
        let mut parts = path.split('.');
        let mut value = block.get(parts.next()?)?;
        for part in parts {
            value = value.as_object()?.get(part)?;
        }
        Some(value)
    })
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    <[u8; N]>::try_from(bytes).unwrap()
}

#[test]
fn recorded_policies_stop_where_they_are_recorded_to_stop() {
    let fixture = json::parse(VALIDATION).unwrap();
    let bases = object(object(&fixture).get("bases").unwrap());
    let cases = object(&fixture).get("cases").unwrap().as_array().unwrap();
    assert!(cases.len() > 1_000);
    // Many cases change the policy alone, so each distinct report and
    // certificate is authenticated once.
    let evidence = |case: &Object| {
        let base = object(bases.get(text(case, "base")).unwrap());
        let bytes = |name: &str| edited_bytes(&b64(text(base, name)), case.get(name));
        (
            text(case, "base").to_owned(),
            bytes("report"),
            bytes("vcek"),
        )
    };
    let distinct: Vec<_> = cases
        .iter()
        .map(|case| evidence(object(case)))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let quotes = in_parallel(&distinct, |(base, report, vcek)| {
        let base = object(bases.get(base).unwrap());
        authenticate(
            Evidence {
                report,
                vcek_der: vcek,
                cert_chain_pem: text(base, "chain_pem"),
                crl_der: &b64(text(base, "crl")),
            },
            Instant::from_unix(integer(base.get("now").unwrap()), 0).unwrap(),
            Some(text(base, "root_pem").as_bytes()),
        )
        .map_err(|error| error.to_string())
    });
    let quotes: BTreeMap<_, _> = distinct.into_iter().zip(quotes).collect();

    let mut stops: BTreeMap<&str, usize> = BTreeMap::new();
    for case in cases {
        let case = object(case);
        let name = text(case, "name");
        let base = object(bases.get(text(case, "base")).unwrap());
        let bytes = |name: &str| edited_bytes(&b64(text(base, name)), case.get(name));
        let quote = quotes.get(&evidence(case)).unwrap().as_ref();
        // The only evidence of this record that does not authenticate is a
        // report without a chip identity.
        let quote = match quote {
            Ok(quote) => Some(quote),
            Err(message) => {
                assert!(
                    message.contains("CHIP_ID is all zeros"),
                    "{name}: {message}"
                );
                None
            }
        };
        let base_policy = object(base.get("policy").unwrap());
        let changes = case.get("policy").map(object);
        let policy = policy_from(|path| {
            changes
                .and_then(|changes| changes.get(path))
                .or_else(|| base_policy.get(path))
        });
        let launch = Register::new(array(&bytes("launch")));
        let report_data: [u8; 64] = array(&bytes("report_data"));
        let stop = match quote {
            None => "authenticate",
            Some(quote) => match assemble(&policy, quote, launch, &report_data) {
                Err(_) => "assemble",
                Ok(expectations) => match expectations.validate(quote) {
                    Err(_) => "validate",
                    Ok(()) => "accept",
                },
            },
        };
        // A case stops where the record says, unless it names an earlier
        // stop of its own; that is only ever for evidence that the record
        // lets through.
        let here = case.get("here").and_then(Value::as_str);
        if here.is_some() {
            assert_eq!(text(case, "reference"), "accept", "{name}");
        }
        assert_eq!(stop, here.unwrap_or(text(case, "reference")), "{name}");
        *stops.entry(stop).or_default() += 1;
    }
    let stops: Vec<(&str, usize)> = stops.into_iter().collect();
    assert_eq!(
        stops,
        [
            ("accept", 369),
            ("assemble", 193),
            ("authenticate", 6),
            ("validate", 714)
        ]
    );
}
