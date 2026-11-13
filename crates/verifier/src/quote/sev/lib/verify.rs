//! Verification of an SEV-SNP attestation: the VCEK certificate's profile
//! and chain to the pinned AMD roots, revocation, and the report signature.

use ::der::asn1::ObjectIdentifier;

use super::abi::{ProductLine, Report, SigningKey, verify_report_signature};
use super::kds::{Extensions, TcbLayout, parse_product_cert_chain, vcek_extensions};
use crate::instant::Instant;
use crate::quote::QuoteError;
use crate::x509::{Certificate, Crl, KeyAlgorithm, KeyPurpose, NameField, verify_chain};

const OID_COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_LOCALITY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const OID_STATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// `id-RSASSA-PSS`.
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// The common name of every VCEK certificate.
pub const VCEK_COMMON_NAME: &str = "SEV-VCEK";

/// The start of the common name of a certificate that issues VLEKs. Such a
/// certificate does not issue VCEKs.
const VLEK_ISSUER_COMMON_NAME_PREFIX: &str = "SEV-VLEK";

fn error(message: impl Into<String>) -> QuoteError {
    QuoteError::new(message)
}

/// The pinned AMD certificates of one product line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdRoots {
    /// The product line that the certificates belong to.
    pub product_line: ProductLine,
    /// The AMD SEV signing key certificate, which issues VCEKs.
    pub ask: Certificate,
    /// The AMD root key certificate, which issues the ASK and signs the
    /// revocation list.
    pub ark: Certificate,
}

impl AmdRoots {
    /// Parses a pinned chain for a product line: exactly the ASK and then
    /// the ARK ([`parse_product_cert_chain`]), each a certificate that
    /// parses. A first certificate whose common name marks it as an issuer
    /// of VLEKs is not an ASK and is an error.
    ///
    /// The certificates are trusted as pinned. Nothing else about them is
    /// judged here: their names, that the ARK signed the ASK, and that the
    /// ARK signed itself are not checked, and their validity and authority
    /// are judged when a VCEK is chained to them
    /// ([`verify_attestation`]).
    pub fn from_pem(product_line: ProductLine, pem: &[u8]) -> Result<Self, QuoteError> {
        let (ask_der, ark_der) = parse_product_cert_chain(pem)?;
        let ask = Certificate::from_der(&ask_der)
            .map_err(|cause| error(format!("pinned ASK certificate: {cause}")))?;
        let ark = Certificate::from_der(&ark_der)
            .map_err(|cause| error(format!("pinned ARK certificate: {cause}")))?;
        let issues_vleks = ask
            .name_attribute(NameField::Subject, OID_COMMON_NAME)?
            .last()
            .is_some_and(|name| name.starts_with(VLEK_ISSUER_COMMON_NAME_PREFIX));
        if issues_vleks {
            return Err(error(
                "pinned intermediate certificate issues VLEKs, not VCEKs",
            ));
        }
        Ok(Self {
            product_line,
            ask,
            ark,
        })
    }
}

/// The certificates that a document carries for an attestation report.
#[derive(Debug, Clone, Copy)]
pub struct DocumentChain<'a> {
    /// The VCEK certificate, DER.
    pub vcek_der: &'a [u8],
    /// The ASK certificate, DER.
    pub ask_der: &'a [u8],
    /// The ARK certificate, DER.
    pub ark_der: &'a [u8],
}

/// What a verified attestation establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// The report, decoded from the bytes whose signature was verified.
    pub report: Report,
    /// The VCEK certificate that signed the report.
    pub vcek: Certificate,
    /// The VCEK's AMD extensions.
    pub extensions: Extensions,
}

/// Checks that a name has AMD's fixed attributes and the given common
/// name: exactly one country `US`, one locality `Santa Clara`, one state
/// `CA`, one organization `Advanced Micro Devices` and one organizational
/// unit `Engineering`; and the last common name of the name is
/// `common_name`.
pub fn check_amd_name(
    certificate: &Certificate,
    field: NameField,
    common_name: &str,
) -> Result<(), QuoteError> {
    let role = match field {
        NameField::Subject => "subject",
        NameField::Issuer => "issuer",
    };
    let attributes = [
        (OID_COUNTRY, "country", "US"),
        (OID_LOCALITY, "locality", "Santa Clara"),
        (OID_STATE, "state", "CA"),
        (OID_ORGANIZATION, "organization", "Advanced Micro Devices"),
        (
            OID_ORGANIZATIONAL_UNIT,
            "organizational unit",
            "Engineering",
        ),
    ];
    for (oid, label, expected) in attributes {
        let values = certificate.name_attribute(field, oid)?;
        let [value] = values.as_slice() else {
            return Err(error(format!(
                "certificate {role} has {} {label} attributes, want 1",
                values.len()
            )));
        };
        if value != expected {
            return Err(error(format!(
                "certificate {role} {label} is {value:?}, want {expected:?}"
            )));
        }
    }
    let names = certificate.name_attribute(field, OID_COMMON_NAME)?;
    let name = names.last().map(String::as_str).unwrap_or_default();
    if name != common_name {
        return Err(error(format!(
            "certificate {role} common name is {name:?}, want {common_name:?}"
        )));
    }
    Ok(())
}

/// Decodes the percent escapes of a URL component. An escape that is not
/// `%` and two hexadecimal digits is an error.
fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        let digit = |byte: Option<u8>| byte.and_then(|byte| char::from(byte).to_digit(16));
        let (high, low) = (digit(bytes.next())?, digit(bytes.next())?);
        out.push(u8::try_from(high.checked_mul(16)?.checked_add(low)?).ok()?);
    }
    Some(out)
}

/// Splits a URL reference into its scheme, which may be empty, and the
/// rest. A reference that starts with a colon is an error.
fn split_scheme(reference: &str) -> Option<(&str, &str)> {
    for (index, byte) in reference.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if index > 0 => {}
            b':' if index > 0 => {
                return reference
                    .split_at_checked(index)
                    .map(|(scheme, rest)| (scheme, rest.get(1..).unwrap_or_default()));
            }
            b':' => return None,
            _ => break,
        }
    }
    Some(("", reference))
}

/// The path of a URL reference, with its percent escapes decoded; `None`
/// for a reference that is not recognized.
///
/// The reference is printable ASCII: an optional scheme, an optional
/// `//` authority, a path, an optional query and an optional fragment. A
/// reference with a scheme and no leading slash has no path. The
/// authority is recognized in one form only, a host name of letters,
/// digits, dots and hyphens with an optional numeric port; a user part, a
/// bracketed address or an escape in it makes the reference unrecognized.
fn url_path(reference: &str) -> Option<Vec<u8>> {
    if !reference.bytes().all(|byte| (0x20..0x7f).contains(&byte)) {
        return None;
    }
    let (front, fragment) = reference.split_once('#').unwrap_or((reference, ""));
    percent_decode(fragment)?;
    let (scheme, rest) = split_scheme(front)?;
    let rest = match rest.strip_suffix('?') {
        Some(stripped) if !stripped.contains('?') => stripped,
        _ => rest.split_once('?').map_or(rest, |(path, _)| path),
    };
    if !rest.starts_with('/') {
        if !scheme.is_empty() {
            return Some(Vec::new());
        }
        if rest
            .split('/')
            .next()
            .is_some_and(|segment| segment.contains(':'))
        {
            return None;
        }
    }
    let after_slashes = rest
        .strip_prefix("//")
        .filter(|_| !scheme.is_empty() || !rest.starts_with("///"));
    let path = match after_slashes {
        Some(after) => {
            let (authority, path) = after
                .find('/')
                .and_then(|slash| after.split_at_checked(slash))
                .unwrap_or((after, ""));
            let (host, port) = authority
                .split_once(':')
                .map_or((authority, ""), |(host, port)| (host, port));
            let host_ok = host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-.".contains(&byte));
            if !host_ok || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            path
        }
        None => rest,
    };
    percent_decode(path)
}

/// Whether a CRL distribution point is one that the revocation list of a
/// product line is published at: a URL reference whose path
/// ([`url_path`]) ends in `/crl`.
fn is_crl_location(uri: &str) -> bool {
    url_path(uri).is_some_and(|path| path.ends_with(b"/crl"))
}

/// Verifies an attestation report against pinned AMD certificates.
///
/// The ASK and ARK of `chain` are transport only: they must be present,
/// and nothing in them is parsed, trusted or compared; the pinned `roots`
/// decide. Certificate validity is judged at `now`. Whether the
/// revocation list is current is the caller's check
/// ([`Crl::check_validity`]). In order:
///
/// 1. the report decodes from `report_bytes` ([`Report::parse`]). No
///    separately decoded report is taken: the report in the result is the
///    one whose bytes are verified below. Its CPUID field names the product
///    line of `roots` ([`ProductLine::from_report`]), and its signer field
///    names the VCEK as the signing key; a report signed by any other key
///    is unsupported;
/// 2. the VCEK certificate parses and has the AMD profile: X.509 version
///    3; signed with RSASSA-PSS; an ECDSA P-384 key; a subject with AMD's
///    fixed attributes and the common name [`VCEK_COMMON_NAME`]
///    ([`check_amd_name`]); valid AMD extensions ([`vcek_extensions`]); and
///    the TCB layout of its extensions is that of the report's product
///    line;
/// 3. the VCEK's issuer has AMD's fixed attributes and the common name
///    `SEV-<product line>`;
/// 4. the VCEK chains to the pinned ARK, through the pinned ASK or
///    directly, at `now` ([`verify_chain`] for the server authentication
///    purpose, which a certificate without an extended key usage
///    permits). That checks the RSASSA-PSS parameters too: SHA-384, MGF1
///    with SHA-384 and a salt of 48 bytes;
/// 5. the pinned ASK names a distribution point for the revocation list, a
///    URL whose path ends in `/crl`; the list is signed by the pinned ARK
///    ([`Crl::verify_signed_by`]; the list's issuer name is not compared);
///    and the list does not revoke the pinned ASK. The VCEK's own serial
///    number is not looked up: AMD supersedes VCEKs through TCB versions;
/// 6. the signature of `report_bytes` verifies under the VCEK's key
///    ([`verify_report_signature`]), which also judges the report's
///    version.
pub fn verify_attestation(
    report_bytes: &[u8],
    chain: &DocumentChain<'_>,
    crl: &Crl,
    roots: &AmdRoots,
    now: Instant,
) -> Result<VerifiedAttestation, QuoteError> {
    let report = Report::parse(report_bytes)?;
    let product_line = ProductLine::from_report(&report)?;
    if product_line != roots.product_line {
        return Err(error(format!(
            "report is from a {} chip, and the pinned certificates are for {}",
            product_line.name(),
            roots.product_line.name()
        )));
    }
    if chain.ask_der.is_empty() || chain.ark_der.is_empty() {
        return Err(error("the ASK or ARK certificate is missing"));
    }
    match report.signer_info.signing_key {
        SigningKey::Vcek => {}
        SigningKey::Vlek => {
            return Err(error(
                "report is signed with a VLEK; only VCEK-signed reports are supported",
            ));
        }
        SigningKey::None => return Err(error("report is not signed")),
    }

    if chain.vcek_der.is_empty() {
        return Err(error("missing VCEK certificate"));
    }
    let vcek = Certificate::from_der(chain.vcek_der)
        .map_err(|cause| error(format!("VCEK certificate: {cause}")))?;
    if vcek.version() != 3 {
        return Err(error(format!(
            "VCEK certificate version is {}, want 3",
            vcek.version()
        )));
    }
    if vcek.signature_algorithm() != OID_RSASSA_PSS {
        return Err(error(
            "VCEK certificate is not signed with RSASSA-PSS and SHA-384",
        ));
    }
    let vcek_key = vcek
        .public_key()
        .map_err(|cause| error(format!("VCEK certificate key: {cause}")))?;
    if vcek_key.algorithm() != KeyAlgorithm::EcdsaP384 {
        return Err(error("VCEK certificate key is not ECDSA P-384"));
    }
    check_amd_name(&vcek, NameField::Subject, VCEK_COMMON_NAME)?;
    let extensions = vcek_extensions(&vcek)?;
    if extensions.tcb.layout != TcbLayout::of(product_line) {
        return Err(error(format!(
            "product line {} and the VCEK certificate use different TCB layouts",
            product_line.name()
        )));
    }

    check_amd_name(
        &vcek,
        NameField::Issuer,
        &format!("SEV-{}", product_line.name()),
    )?;
    verify_chain(
        &vcek,
        std::slice::from_ref(&roots.ask),
        std::slice::from_ref(&roots.ark),
        now,
        KeyPurpose::ServerAuth,
    )
    .map_err(|cause| error(format!("verifying the VCEK certificate: {cause}")))?;

    let published = roots
        .ask
        .crl_distribution_uris()?
        .iter()
        .any(|uri| is_crl_location(uri));
    if !published {
        return Err(error(
            "the pinned ASK names no distribution point for the product revocation list",
        ));
    }
    crl.verify_signed_by(&roots.ark)
        .map_err(|cause| error(format!("revocation list is not signed by the ARK: {cause}")))?;
    if crl.is_revoked(roots.ask.serial()) {
        return Err(error("the ASK certificate is revoked"));
    }

    verify_report_signature(report_bytes, &vcek_key)?;
    Ok(VerifiedAttestation {
        report,
        vcek,
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::sev::authenticate::embedded_cert_chain_pem;
    use crate::quote::sev::lib::abi::testdata::{
        TURIN_CRL_DER, TURIN_NOW_UNIX, TURIN_REPORT, TURIN_VCEK_DER,
    };

    fn roots(product_line: ProductLine) -> AmdRoots {
        AmdRoots::from_pem(product_line, embedded_cert_chain_pem(product_line)).unwrap()
    }

    fn turin_chain() -> DocumentChain<'static> {
        DocumentChain {
            vcek_der: TURIN_VCEK_DER,
            ask_der: b"unread",
            ark_der: b"unread",
        }
    }

    fn at(seconds: i64) -> Instant {
        Instant::from_unix(seconds, 0).unwrap()
    }

    fn verify(report: &[u8], chain: &DocumentChain<'_>, now: Instant) -> Result<(), String> {
        let crl = Crl::from_der(TURIN_CRL_DER).unwrap();
        verify_attestation(report, chain, &crl, &roots(ProductLine::Turin), now)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    #[test]
    fn a_captured_vcek_has_amd_names() {
        let vcek = Certificate::from_der(TURIN_VCEK_DER).unwrap();
        check_amd_name(&vcek, NameField::Subject, VCEK_COMMON_NAME).unwrap();
        check_amd_name(&vcek, NameField::Issuer, "SEV-Turin").unwrap();
    }

    #[test]
    fn another_common_name_is_rejected() {
        let vcek = Certificate::from_der(TURIN_VCEK_DER).unwrap();
        let error = check_amd_name(&vcek, NameField::Issuer, "SEV-Genoa").unwrap_err();
        assert!(error.to_string().contains("common name"), "{error}");
        assert!(check_amd_name(&vcek, NameField::Subject, "SEV-VLEK").is_err());
    }

    #[test]
    fn a_name_without_amd_attributes_is_rejected() {
        let leaf = crate::x509::certificate::testdata::certificate(
            crate::x509::certificate::testdata::FULCIO_INTERMEDIATE_PEM,
        );
        let error = check_amd_name(&leaf, NameField::Subject, "sigstore-intermediate").unwrap_err();
        assert!(error.to_string().contains("country"), "{error}");
    }

    #[test]
    fn the_embedded_chains_are_an_ask_and_an_ark_with_amd_names() {
        for product_line in [ProductLine::Genoa, ProductLine::Turin] {
            let roots = roots(product_line);
            assert_eq!(roots.product_line, product_line);
            let name = product_line.name();
            check_amd_name(&roots.ask, NameField::Subject, &format!("SEV-{name}")).unwrap();
            check_amd_name(&roots.ask, NameField::Issuer, &format!("ARK-{name}")).unwrap();
            check_amd_name(&roots.ark, NameField::Subject, &format!("ARK-{name}")).unwrap();
            let published = roots.ask.crl_distribution_uris().unwrap();
            assert_eq!(
                published,
                [format!("https://kdsintf.amd.com/vcek/v1/{name}/crl")]
            );
            assert!(is_crl_location(&published[0]));
        }
    }

    #[test]
    fn a_pinned_chain_is_exactly_two_certificates() {
        let pem = String::from_utf8(embedded_cert_chain_pem(ProductLine::Turin).to_vec()).unwrap();
        let end = "-----END CERTIFICATE-----";
        let (ask, ark) = pem.split_at(pem.find(end).unwrap() + end.len());
        let ark = ark.trim_start();
        for chain in [
            String::new(),
            ask.to_owned(),
            format!("{ask}\n{ark}{ark}"),
            format!("{ask}\n{ark}\n"),
            format!("{ask}\n{ark}trailing"),
            "not PEM".to_owned(),
        ] {
            assert!(AmdRoots::from_pem(ProductLine::Turin, chain.as_bytes()).is_err());
        }
        // Certificates that do not parse.
        let garbage = crate::quote::sev::differential_tests::pem(b"not a certificate");
        assert!(
            AmdRoots::from_pem(ProductLine::Turin, format!("{garbage}{garbage}").as_bytes())
                .is_err()
        );
        // The order is not judged here: a chain in the other order parses,
        // and no VCEK chains to it.
        let swapped = format!("{ark}{ask}\n");
        AmdRoots::from_pem(ProductLine::Turin, swapped.as_bytes()).unwrap();
    }

    #[test]
    fn revocation_list_locations_are_urls_whose_path_ends_in_crl() {
        let cases = [
            ("https://kdsintf.amd.com/vcek/v1/Genoa/crl", true),
            ("http://example.com/a/b/crl", true),
            ("https://example.com:8443/crl", true),
            ("https://example.com/crl?x=1", true),
            ("https://example.com/crl?", true),
            ("https://example.com/crl#frag", true),
            ("https://example.com/%63rl", true),
            ("https://example.com/a%2Fcrl", true),
            ("https://example.com/a b/crl", true),
            ("https://example.com//crl", true),
            ("https:///crl", true),
            ("https:/crl", true),
            ("//example.com/crl", true),
            ("/crl", true),
            ("x/crl", true),
            ("///crl", true),
            ("HTTPS://EXAMPLE.COM/crl", true),
            ("https://example.com/crl/", false),
            ("https://example.com/crl.pem", false),
            ("https://example.com/CRL", false),
            ("https://example.com/acrl", false),
            ("https://crl", false),
            ("https://example.com", false),
            ("https://example.com/list?x=/crl", false),
            ("https://example.com/list#/crl", false),
            ("https://example.com/crl%", false),
            ("https://example.com/crl#%zz", false),
            ("https:crl", false),
            ("crl", false),
            (":/crl", false),
            ("a:b/crl", false),
            ("1https://example.com/crl", false),
            ("https://example.com:port/crl", false),
            ("https://exa mple.com/crl", false),
            ("https://example.com/crl\u{7f}", false),
            ("https://example.com/cr\nl", false),
            ("", false),
            // Forms that are not recognized, whatever their path.
            ("https://user@example.com/crl", false),
            ("https://[::1]/crl", false),
            ("https://example.com/\u{e9}/crl", false),
            ("https://h_x/crl", false),
        ];
        for (uri, located) in cases {
            assert_eq!(is_crl_location(uri), located, "{uri:?}");
        }
    }

    #[test]
    fn a_captured_attestation_verifies_against_the_embedded_chain() {
        let crl = Crl::from_der(TURIN_CRL_DER).unwrap();
        let verified = verify_attestation(
            TURIN_REPORT,
            &turin_chain(),
            &crl,
            &roots(ProductLine::Turin),
            at(TURIN_NOW_UNIX),
        )
        .unwrap();
        assert_eq!(verified.report, Report::parse(TURIN_REPORT).unwrap());
        assert_eq!(verified.vcek.der(), TURIN_VCEK_DER);
        assert_eq!(
            verified.extensions.tcb_version().unwrap(),
            verified.report.reported_tcb
        );
    }

    #[test]
    fn whether_the_revocation_list_is_current_is_not_judged_here() {
        let crl = Crl::from_der(TURIN_CRL_DER).unwrap();
        // 18 August 2026: after the VCEK was issued, before the list was.
        let before_the_list = at(1_787_011_200);
        assert!(crl.check_validity(before_the_list).is_err());
        verify(TURIN_REPORT, &turin_chain(), before_the_list).unwrap();
    }

    #[test]
    fn certificates_are_judged_at_the_given_instant() {
        let vcek = Certificate::from_der(TURIN_VCEK_DER).unwrap();
        let (start, end) = (
            vcek.not_before().unix_seconds(),
            vcek.not_after().unix_seconds(),
        );
        for inside in [start, end] {
            verify(TURIN_REPORT, &turin_chain(), at(inside)).unwrap();
        }
        for outside in [start - 1, end + 1] {
            let error = verify(TURIN_REPORT, &turin_chain(), at(outside)).unwrap_err();
            assert!(error.contains("verifying the VCEK certificate"), "{error}");
        }
    }

    #[test]
    fn the_pinned_certificates_decide() {
        let crl = Crl::from_der(TURIN_CRL_DER).unwrap();
        let now = at(TURIN_NOW_UNIX);
        // Certificates of another product line.
        let error = verify_attestation(
            TURIN_REPORT,
            &turin_chain(),
            &crl,
            &roots(ProductLine::Genoa),
            now,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("pinned certificates are for Genoa"),
            "{error}"
        );
        // The same certificates under another product line's name.
        let mislabeled = AmdRoots {
            product_line: ProductLine::Turin,
            ..roots(ProductLine::Genoa)
        };
        let error =
            verify_attestation(TURIN_REPORT, &turin_chain(), &crl, &mislabeled, now).unwrap_err();
        assert!(
            error.to_string().contains("verifying the VCEK certificate"),
            "{error}"
        );
        // A document chain with a missing certificate.
        for chain in [
            DocumentChain {
                ask_der: b"",
                ..turin_chain()
            },
            DocumentChain {
                ark_der: b"",
                ..turin_chain()
            },
            DocumentChain {
                vcek_der: b"",
                ..turin_chain()
            },
        ] {
            let error = verify(TURIN_REPORT, &chain, now).unwrap_err();
            assert!(error.contains("missing"), "{error}");
        }
    }

    #[test]
    fn a_report_that_names_another_signing_key_is_unsupported() {
        let now = at(TURIN_NOW_UNIX);
        for (signer_info, want) in [(1u8 << 2, "VLEK"), (7 << 2, "not signed")] {
            let mut report = TURIN_REPORT.to_vec();
            report[0x48] = signer_info;
            let error = verify(&report, &turin_chain(), now).unwrap_err();
            assert!(error.contains(want), "{error}");
        }
        let mut changed = TURIN_REPORT.to_vec();
        changed[0x50] ^= 1;
        let error = verify(&changed, &turin_chain(), now).unwrap_err();
        assert!(error.contains("report signature"), "{error}");
    }
}
