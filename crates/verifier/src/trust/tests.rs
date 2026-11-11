use sha2::{Digest, Sha256};

use super::*;
use crate::canonical::encode_lower_hex;
use crate::json;
use crate::quote::sev::lib::kds::parse_product_cert_chain;
use crate::quote::sev::lib::verify::check_amd_name;
use crate::sigstore::statement::key_hint;
use crate::sigstore::trusted_root::TRUSTED_ROOT_MEDIA_TYPE;
use crate::x509::der::pem_certificates;
use crate::x509::{Certificate, KeyAlgorithm, NameField, PublicKey};

/// Each generated module with the anchor that it embeds and the hash that
/// it records.
const ANCHORS: [(&str, &[u8], &str); 5] = [
    (
        include_str!("sigstore_root.rs"),
        SIGSTORE_TRUSTED_ROOT_JSON,
        SIGSTORE_TRUSTED_ROOT_JSON_SHA256,
    ),
    (
        include_str!("amd_genoa.rs"),
        AMD_GENOA_CERT_CHAIN_PEM,
        AMD_GENOA_CERT_CHAIN_PEM_SHA256,
    ),
    (
        include_str!("amd_turin.rs"),
        AMD_TURIN_CERT_CHAIN_PEM,
        AMD_TURIN_CERT_CHAIN_PEM_SHA256,
    ),
    (
        include_str!("intel_sgx_root.rs"),
        INTEL_SGX_ROOT_CA_PEM,
        INTEL_SGX_ROOT_CA_PEM_SHA256,
    ),
    (
        include_str!("signing_keys.rs"),
        TINFOIL_SIGNING_KEY_PEM,
        TINFOIL_SIGNING_KEY_PEM_SHA256,
    ),
];

#[test]
fn every_anchor_has_the_hash_that_its_module_records() {
    for (module, anchor, recorded) in ANCHORS {
        let digest = encode_lower_hex(&Sha256::digest(anchor));
        assert_eq!(digest, recorded);
        let header = module
            .lines()
            .find_map(|line| line.strip_prefix("// SHA-256: "))
            .expect("the module header records a hash");
        assert_eq!(header, digest);
        assert!(
            module
                .lines()
                .any(|line| line.starts_with("// Source: ") && line.len() > "// Source: ".len()),
            "the module header records a source"
        );
    }
}

#[test]
fn the_sigstore_trusted_root_is_strict_json_with_every_authority_kind() {
    let root = json::parse(SIGSTORE_TRUSTED_ROOT_JSON).unwrap();
    let root = root.as_object().unwrap();
    assert_eq!(
        root.get("mediaType").unwrap().as_str(),
        Some(TRUSTED_ROOT_MEDIA_TYPE)
    );
    for list in [
        "tlogs",
        "ctlogs",
        "certificateAuthorities",
        "timestampAuthorities",
    ] {
        let entries = root.get(list).unwrap().as_array().unwrap();
        assert!(!entries.is_empty(), "{list}");
    }
}

fn certificate_with_base64(member: &json::Value) -> Certificate {
    use base64::Engine as _;
    let raw = member
        .as_object()
        .unwrap()
        .get("rawBytes")
        .unwrap()
        .as_str()
        .unwrap();
    let der = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .unwrap();
    Certificate::from_der(&der).unwrap()
}

#[test]
fn every_authority_chain_of_the_trusted_root_parses_and_chains() {
    let root = json::parse(SIGSTORE_TRUSTED_ROOT_JSON).unwrap();
    let root = root.as_object().unwrap();
    let mut chains = 0;
    for list in ["certificateAuthorities", "timestampAuthorities"] {
        for authority in root.get(list).unwrap().as_array().unwrap() {
            let chain: Vec<Certificate> = authority
                .as_object()
                .unwrap()
                .get("certChain")
                .unwrap()
                .as_object()
                .unwrap()
                .get("certificates")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(certificate_with_base64)
                .collect();
            assert!(!chain.is_empty());
            for pair in chain.windows(2) {
                assert_eq!(pair[0].issuer_der(), pair[1].subject_der());
                pair[0]
                    .verify_signed_by(&pair[1].public_key().unwrap())
                    .unwrap();
            }
            let last = chain.last().unwrap();
            assert_eq!(last.issuer_der(), last.subject_der());
            last.verify_signed_by(&last.public_key().unwrap()).unwrap();
            chains += 1;
        }
    }
    assert!(chains >= 2);
}

#[test]
fn every_log_key_of_the_trusted_root_parses() {
    use base64::Engine as _;
    let root = json::parse(SIGSTORE_TRUSTED_ROOT_JSON).unwrap();
    let root = root.as_object().unwrap();
    for list in ["tlogs", "ctlogs"] {
        for log in root.get(list).unwrap().as_array().unwrap() {
            let key = log.as_object().unwrap().get("publicKey").unwrap();
            let raw = key.as_object().unwrap().get("rawBytes").unwrap();
            let der = base64::engine::general_purpose::STANDARD
                .decode(raw.as_str().unwrap())
                .unwrap();
            let key = PublicKey::from_spki_der(&der).unwrap();
            assert!(matches!(
                key.algorithm(),
                KeyAlgorithm::EcdsaP256 | KeyAlgorithm::Ed25519
            ));
        }
    }
}

fn amd_chain(pem: &[u8], product: &str) {
    let (ask, ark) = parse_product_cert_chain(pem).unwrap();
    let ask = Certificate::from_der(&ask).unwrap();
    let ark = Certificate::from_der(&ark).unwrap();
    let ark_key = ark.public_key().unwrap();
    assert_eq!(ark_key.algorithm(), KeyAlgorithm::Rsa);

    check_amd_name(&ark, NameField::Subject, &format!("ARK-{product}")).unwrap();
    check_amd_name(&ark, NameField::Issuer, &format!("ARK-{product}")).unwrap();
    ark.verify_signed_by(&ark_key).unwrap();

    check_amd_name(&ask, NameField::Subject, &format!("SEV-{product}")).unwrap();
    check_amd_name(&ask, NameField::Issuer, &format!("ARK-{product}")).unwrap();
    assert_eq!(ask.issuer_der(), ark.subject_der());
    ask.verify_signed_by(&ark_key).unwrap();
    assert!(ask.verify_signed_by(&ask.public_key().unwrap()).is_err());
}

#[test]
fn the_amd_genoa_chain_is_the_ask_signed_by_a_self_signed_ark() {
    amd_chain(AMD_GENOA_CERT_CHAIN_PEM, "Genoa");
}

#[test]
fn the_amd_turin_chain_is_the_ask_signed_by_a_self_signed_ark() {
    amd_chain(AMD_TURIN_CERT_CHAIN_PEM, "Turin");
}

#[test]
fn the_amd_chains_belong_to_different_product_lines() {
    assert_ne!(AMD_GENOA_CERT_CHAIN_PEM, AMD_TURIN_CERT_CHAIN_PEM);
}

#[test]
fn the_intel_root_is_one_self_signed_certificate() {
    const OID_COMMON_NAME: ::der::asn1::ObjectIdentifier =
        ::der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    let mut certificates = pem_certificates(INTEL_SGX_ROOT_CA_PEM).unwrap();
    assert_eq!(certificates.len(), 1);
    let root = Certificate::from_der(&certificates.remove(0)).unwrap();
    assert_eq!(root.issuer_der(), root.subject_der());
    let key = root.public_key().unwrap();
    assert_eq!(key.algorithm(), KeyAlgorithm::EcdsaP256);
    root.verify_signed_by(&key).unwrap();
    assert_eq!(
        root.name_attribute(NameField::Subject, OID_COMMON_NAME)
            .unwrap(),
        ["Intel SGX Root CA"]
    );
}

#[test]
fn the_signing_key_is_an_ecdsa_p256_key_with_a_hint() {
    let key = PublicKey::from_pem(std::str::from_utf8(TINFOIL_SIGNING_KEY_PEM).unwrap()).unwrap();
    assert_eq!(key.algorithm(), KeyAlgorithm::EcdsaP256);
    assert_eq!(key_hint(&key).unwrap().len(), 44);
}

#[test]
fn a_captured_turin_vcek_chains_to_the_embedded_turin_ask() {
    let (ask, _) = parse_product_cert_chain(AMD_TURIN_CERT_CHAIN_PEM).unwrap();
    let ask = Certificate::from_der(&ask).unwrap();
    let vcek =
        Certificate::from_der(crate::quote::sev::lib::abi::testdata::TURIN_VCEK_DER).unwrap();
    assert_eq!(vcek.issuer_der(), ask.subject_der());
    vcek.verify_signed_by(&ask.public_key().unwrap()).unwrap();

    let (genoa_ask, _) = parse_product_cert_chain(AMD_GENOA_CERT_CHAIN_PEM).unwrap();
    let genoa_ask = Certificate::from_der(&genoa_ask).unwrap();
    assert!(
        vcek.verify_signed_by(&genoa_ask.public_key().unwrap())
            .is_err()
    );
}
