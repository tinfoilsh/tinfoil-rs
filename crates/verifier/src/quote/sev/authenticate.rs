//! Authentication of an SEV-SNP attestation report.

use super::identity::identity;
use super::lib::abi::{ProductLine, Report};
use super::lib::kds::Extensions;
use super::lib::verify::{AmdRoots, DocumentChain, verify_attestation};
use crate::instant::Instant;
use crate::measurement::{Measurement, Register};
use crate::quote::QuoteError;
use crate::x509::der::pem_certificates;
use crate::x509::{Certificate, Crl};

/// An SEV-SNP attestation report with the endorsement collateral that
/// authenticates it, all decoded from the document.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// The raw attestation report.
    pub report: &'a [u8],
    /// The chip's VCEK certificate, DER.
    pub vcek_der: &'a [u8],
    /// The ASK and then the ARK certificate that the VCEK chains through,
    /// PEM. It is transport only: the pinned chain is what is trusted.
    pub cert_chain_pem: &'a str,
    /// The AMD revocation list for the product line, DER.
    pub crl_der: &'a [u8],
}

/// A signature-verified SEV-SNP report, not yet compared against any
/// expected value.
#[derive(Debug, Clone)]
pub struct Quote {
    identity: String,
    launch: Register,
    report: Report,
    report_bytes: Vec<u8>,
    product_line: ProductLine,
    vcek: Certificate,
    vcek_extensions: Extensions,
}

impl Quote {
    /// The authenticated machine identifier: the CHIP_ID in lowercase hex.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The authenticated launch measurement.
    pub fn measurement(&self) -> Measurement {
        Measurement::SevSnp {
            launch: self.launch,
        }
    }

    /// The decoded report.
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// The report bytes that were authenticated, as the document carries
    /// them.
    pub fn report_bytes(&self) -> &[u8] {
        &self.report_bytes
    }

    /// The product line of the chip, from the report's CPUID field.
    pub fn product_line(&self) -> ProductLine {
        self.product_line
    }

    /// The VCEK certificate that signed the report.
    pub fn vcek(&self) -> &Certificate {
        &self.vcek
    }

    /// The AMD extensions of the VCEK certificate.
    pub fn vcek_extensions(&self) -> &Extensions {
        &self.vcek_extensions
    }
}

/// The AMD certificate chain embedded in the crate for a product line: the
/// ASK and then the ARK, PEM.
pub fn embedded_cert_chain_pem(product_line: ProductLine) -> &'static [u8] {
    match product_line {
        ProductLine::Genoa => crate::trust::AMD_GENOA_CERT_CHAIN_PEM,
        ProductLine::Turin => crate::trust::AMD_TURIN_CERT_CHAIN_PEM,
    }
}

/// Verifies a report's signature chain up to the pinned AMD root, and the
/// chain against the supplied revocation list.
///
/// `root_pem` replaces the embedded chain of the report's product line
/// (ASK then ARK, PEM) when given; only a conformance build can give one
/// ([`VendorRoots`](crate::quote::VendorRoots)). Everything is judged at
/// `now`. In order:
///
/// 1. the VCEK is not empty; the document's chain is exactly two
///    non-empty `CERTIFICATE` blocks with nothing else around them
///    ([`pem_certificates`]); the revocation list is not empty. The two
///    certificates of the document's chain are transport only: they are
///    not parsed, and they are not compared with the pinned chain;
/// 2. the revocation list parses ([`Crl::from_der`]) and `now` is within
///    its validity, both ends included ([`Crl::check_validity`]);
/// 3. the report is exactly [`REPORT_SIZE`](super::lib::abi::REPORT_SIZE)
///    bytes and decodes ([`Report::parse`]);
/// 4. the report's CPUID field names a supported product line: Genoa or
///    Turin ([`ProductLine::from_report`]). A report without the field
///    (version 2) is an error;
/// 5. the trust anchor is the embedded chain of that product line
///    ([`embedded_cert_chain_pem`]), or `root_pem`: exactly two
///    certificates, ASK then ARK ([`AmdRoots::from_pem`]);
/// 6. the attestation verifies ([`verify_attestation`]): the report is
///    signed by a VCEK; the VCEK has the AMD profile and chains to the
///    pinned ASK and ARK at `now`; the revocation list is signed by the
///    ARK and does not revoke the ASK; the report's signature verifies
///    under the VCEK; and the report's version is supported;
/// 7. the report does not mask its CHIP_ID: a masked platform identity is
///    unsupported;
/// 8. the identity is the CHIP_ID ([`identity`]) and the measurement is
///    the report's launch measurement.
///
/// Whether the report's TCB matches the VCEK and whether the CHIP_ID is the
/// VCEK's hardware identifier are checked at validation
/// ([`Expectations::validate`](super::Expectations::validate)), not here.
pub fn authenticate(
    evidence: Evidence<'_>,
    now: Instant,
    root_pem: Option<&[u8]>,
) -> Result<Quote, QuoteError> {
    if evidence.vcek_der.is_empty() {
        return Err(QuoteError::new("amd-vcek collateral carries an empty VCEK"));
    }
    let chain = pem_certificates(evidence.cert_chain_pem.as_bytes())
        .map_err(|cause| QuoteError::new(format!("amd-vcek collateral: {cause}")))?;
    let [ask_der, ark_der] = chain.as_slice() else {
        return Err(QuoteError::new(format!(
            "amd-vcek collateral: cert_chain_pem must carry exactly the ASK and ARK certificates, got {} blocks",
            chain.len()
        )));
    };
    if evidence.crl_der.is_empty() {
        return Err(QuoteError::new("amd-crl collateral carries an empty CRL"));
    }
    let crl = Crl::from_der(evidence.crl_der)
        .map_err(|cause| QuoteError::new(format!("parsing amd-crl collateral: {cause}")))?;
    crl.check_validity(now)
        .map_err(|cause| QuoteError::new(format!("amd-crl collateral: {cause}")))?;

    let product_line = ProductLine::from_report(&Report::parse(evidence.report)?)?;
    let roots = AmdRoots::from_pem(
        product_line,
        root_pem.unwrap_or_else(|| embedded_cert_chain_pem(product_line)),
    )
    .map_err(|cause| {
        cause.within(format!(
            "parsing AMD {} root certificates",
            product_line.name()
        ))
    })?;
    let verified = verify_attestation(
        evidence.report,
        &DocumentChain {
            vcek_der: evidence.vcek_der,
            ask_der,
            ark_der,
        },
        &crl,
        &roots,
        now,
    )?;
    let report = verified.report;
    if report.signer_info.mask_chip_key {
        return Err(QuoteError::new(
            "report masks CHIP_ID; masked platform identities are unsupported",
        ));
    }
    Ok(Quote {
        identity: identity(&report.chip_id)?,
        launch: Register::new(report.measurement),
        report,
        report_bytes: evidence.report.to_vec(),
        product_line,
        vcek: verified.vcek,
        vcek_extensions: verified.extensions,
    })
}

#[cfg(test)]
impl Quote {
    /// A quote from a report and a VCEK certificate that are taken as
    /// authentic, for tests of what follows authentication.
    pub(crate) fn unauthenticated(report: &[u8], vcek_der: &[u8]) -> Self {
        use super::lib::kds::vcek_extensions;
        let parsed = Report::parse(report).unwrap();
        let vcek = Certificate::from_der(vcek_der).unwrap();
        Quote {
            identity: identity(&parsed.chip_id).unwrap(),
            launch: Register::new(parsed.measurement),
            product_line: ProductLine::from_report(&parsed).unwrap(),
            report: parsed,
            report_bytes: report.to_vec(),
            vcek_extensions: vcek_extensions(&vcek).unwrap(),
            vcek,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::sev::differential_tests::{authentication_cases, named, pem};
    use crate::quote::sev::lib::abi::testdata::{
        TURIN_CHIP_ID, TURIN_CRL_DER, TURIN_NOW_UNIX, TURIN_REPORT, TURIN_VCEK_DER,
    };

    fn turin_chain() -> String {
        String::from_utf8(embedded_cert_chain_pem(ProductLine::Turin).to_vec()).unwrap()
    }

    fn turin<'a>(chain: &'a str) -> Evidence<'a> {
        Evidence {
            report: TURIN_REPORT,
            vcek_der: TURIN_VCEK_DER,
            cert_chain_pem: chain,
            crl_der: TURIN_CRL_DER,
        }
    }

    fn at(seconds: i64) -> Instant {
        Instant::from_unix(seconds, 0).unwrap()
    }

    fn rejected(evidence: Evidence<'_>, now: Instant) -> String {
        authenticate(evidence, now, None).unwrap_err().to_string()
    }

    #[test]
    fn a_captured_report_authenticates_against_the_embedded_chain() {
        let chain = turin_chain();
        let quote = authenticate(turin(&chain), at(TURIN_NOW_UNIX), None).unwrap();
        assert_eq!(quote.identity(), TURIN_CHIP_ID);
        assert_eq!(quote.product_line(), ProductLine::Turin);
        assert_eq!(quote.report_bytes(), TURIN_REPORT);
        assert_eq!(quote.report().version, 5);
        assert_eq!(quote.vcek().der(), TURIN_VCEK_DER);
        assert_eq!(quote.vcek_extensions().hwid, TURIN_REPORT[0x1A0..0x1A8]);
        let Measurement::SevSnp { launch } = quote.measurement() else {
            panic!("not an SEV-SNP measurement");
        };
        assert_eq!(launch.as_bytes(), &TURIN_REPORT[0x90..0xC0]);
    }

    #[test]
    fn the_revocation_list_is_current_on_both_bounds() {
        let chain = turin_chain();
        let crl = Crl::from_der(TURIN_CRL_DER).unwrap();
        let (start, end) = (
            crl.this_update().unix_seconds(),
            crl.next_update().unix_seconds(),
        );
        for inside in [start, end] {
            authenticate(turin(&chain), at(inside), None).unwrap();
        }
        for outside in [start - 1, end + 1] {
            let error = rejected(turin(&chain), at(outside));
            assert!(error.contains("amd-crl collateral"), "{error}");
        }
    }

    #[test]
    fn the_document_chain_is_two_certificate_blocks_that_are_not_read() {
        let now = at(TURIN_NOW_UNIX);
        let garbage = pem(b"not a certificate");
        // The pinned chain decides; the document's is transport only.
        authenticate(turin(&format!("{garbage}{garbage}")), now, None).unwrap();
        let genoa =
            String::from_utf8(embedded_cert_chain_pem(ProductLine::Genoa).to_vec()).unwrap();
        authenticate(turin(&genoa), now, None).unwrap();

        for (chain, want) in [
            (String::new(), "got 0 blocks"),
            (garbage.clone(), "got 1 blocks"),
            (format!("{garbage}{garbage}{garbage}"), "got 3 blocks"),
            (format!("{garbage}{garbage}trailing"), "outside a block"),
            (
                "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n".repeat(2),
                "empty CERTIFICATE block",
            ),
            (
                garbage.replace("CERTIFICATE", "PUBLIC KEY").repeat(2),
                "want CERTIFICATE",
            ),
        ] {
            let error = rejected(turin(&chain), now);
            assert!(error.contains(want), "{error}");
        }
    }

    #[test]
    fn empty_collateral_is_rejected_before_anything_is_parsed() {
        let chain = turin_chain();
        let now = at(TURIN_NOW_UNIX);
        let error = rejected(
            Evidence {
                vcek_der: &[],
                cert_chain_pem: "",
                crl_der: &[],
                ..turin(&chain)
            },
            now,
        );
        assert!(error.contains("empty VCEK"), "{error}");
        let error = rejected(
            Evidence {
                crl_der: &[],
                ..turin(&chain)
            },
            now,
        );
        assert!(error.contains("empty CRL"), "{error}");
        let error = rejected(
            Evidence {
                crl_der: &[0x30, 0x00],
                ..turin(&chain)
            },
            now,
        );
        assert!(error.contains("parsing amd-crl collateral"), "{error}");
    }

    #[test]
    fn a_report_of_another_size_is_rejected() {
        let chain = turin_chain();
        let mut long = TURIN_REPORT.to_vec();
        long.push(0);
        for report in [&TURIN_REPORT[..TURIN_REPORT.len() - 1], &long, &[]] {
            let error = rejected(
                Evidence {
                    report,
                    ..turin(&chain)
                },
                at(TURIN_NOW_UNIX),
            );
            assert!(error.contains("must be exactly 1184 bytes"), "{error}");
        }
    }

    #[test]
    fn a_changed_report_or_certificate_is_rejected() {
        let chain = turin_chain();
        let now = at(TURIN_NOW_UNIX);
        let mut report = TURIN_REPORT.to_vec();
        report[0x90] ^= 1;
        let error = rejected(
            Evidence {
                report: &report,
                ..turin(&chain)
            },
            now,
        );
        assert!(error.contains("report signature"), "{error}");
        let mut vcek = TURIN_VCEK_DER.to_vec();
        *vcek.last_mut().unwrap() ^= 1;
        let error = rejected(
            Evidence {
                vcek_der: &vcek,
                ..turin(&chain)
            },
            now,
        );
        assert!(error.contains("verifying the VCEK certificate"), "{error}");
    }

    #[test]
    fn a_pinned_chain_of_another_product_line_does_not_authenticate() {
        let chain = turin_chain();
        let genoa = embedded_cert_chain_pem(ProductLine::Genoa);
        let error = authenticate(turin(&chain), at(TURIN_NOW_UNIX), Some(genoa))
            .unwrap_err()
            .to_string();
        assert!(error.contains("verifying the VCEK certificate"), "{error}");
        // A replacement that is not a chain of two certificates.
        let error = authenticate(turin(&chain), at(TURIN_NOW_UNIX), Some(b"".as_slice()))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("parsing AMD Turin root certificates"),
            "{error}"
        );
    }

    /// The rules of authentication, each on recorded evidence that is
    /// signed under a minted chain: the case named on the left has the
    /// verdict on the right.
    #[test]
    fn each_rule_has_recorded_evidence() {
        let rules = [
            // The report's version is 2 to 5, and a product line needs the
            // CPUID field that version 2 lacks.
            ("report-version-1", false),
            ("report-version-2", false),
            ("report-version-2-without-cpuid", false),
            ("report-version-3", true),
            ("report-version-5", true),
            ("report-version-6", false),
            ("report-cpuid-19-01-01", false),
            ("report-cpuid-00-00-00", false),
            // Only a VCEK-signed report with an unmasked CHIP_ID.
            ("report-signer-info-0x0", true),
            ("report-signer-info-0x1", true),
            ("report-signer-info-0x2", false),
            ("report-signer-info-0x4", false),
            ("report-signer-info-0x1c", false),
            ("report-signer-info-0x8", false),
            ("report-signer-info-0x20", false),
            // Every byte of the signature field counts.
            ("report-signature-padding-48-set", false),
            ("report-signature-padding-143-set", false),
            ("report-signature-tail-0x330", false),
            ("report-signature-high-s", true),
            ("report-signed-by-another-key", false),
            // Reserved ranges are zero.
            ("report-reserved-0x4c-signed", false),
            ("report-reserved-0x208-signed", false),
            ("report-policy-bit-17-flipped", false),
            ("report-policy-bit-26-flipped", false),
            // The validity of each certificate includes both ends.
            ("vcek-not-before-1", false),
            ("vcek-not-before+0", true),
            ("vcek-not-after+0", true),
            ("vcek-not-after+1", false),
            ("ask-not-before-1", false),
            ("ask-not-before+0", true),
            ("ask-not-after+0", true),
            ("ask-not-after+1", false),
            ("ark-not-before-1", false),
            ("ark-not-before+0", true),
            ("ark-not-after+0", true),
            ("ark-not-after+1", false),
            // So does the validity of the revocation list.
            ("crl-this-update-1", false),
            ("crl-this-update+0", true),
            ("crl-next-update+0", true),
            ("crl-next-update+1", false),
            // The list is signed by the ARK and must not revoke the ASK;
            // no other serial number is looked up, and its issuer name is
            // not compared.
            ("crl-revokes-the-ask", false),
            ("crl-revokes-the-ask-among-others", false),
            ("crl-revokes-the-vcek", true),
            ("crl-revokes-the-ark", true),
            ("crl-signed-by-the-ask", false),
            ("crl-of-another-chain", false),
            ("crl-issuer-name-other", true),
            ("pinned-ask-without-distribution-point", false),
            ("pinned-ark-key-usage-cert-sign-only", false),
            // The VCEK profile.
            ("vcek-signed-with-pkcs1", false),
            ("vcek-key-p256", false),
            ("vcek-subject-common-name-\"SEV-VLEK\"", false),
            ("vcek-subject-country-other", false),
            ("vcek-subject-common-name-then-another", false),
            ("vcek-subject-another-common-name-first", true),
            ("vcek-extension-hwid-missing", false),
            ("vcek-extension-csp-id", false),
            ("vcek-extension-unknown-extension", false),
            ("vcek-extension-authority-key-identifier", true),
            ("vcek-extension-struct-version-value-2", false),
            ("vcek-extension-set-of-the-other-layout", false),
            ("vcek-extension-bl-value-128", false),
            ("vcek-extension-ucode-value-255", true),
            // The chain: issuer name, issuer authority, and the pinned
            // certificates as they are, self-signed or not.
            ("vcek-issuer-not-the-ask", false),
            ("vcek-signed-by-another-ask", false),
            ("pinned-ask-not-a-ca", false),
            ("pinned-ask-key-usage-crl-sign-only", false),
            ("pinned-ask-eku-client-auth", false),
            ("pinned-ark-path-length-0", false),
            ("pinned-ark-not-self-signed", true),
            ("pinned-ask-issues-vleks", false),
            ("pinned-chain-swapped", false),
            ("pinned-chain-three", false),
            // What authentication leaves to validation.
            ("report-tcb-differs-from-certificate", true),
            ("report-chip-id-other", true),
            ("report-chip-id-zero", true),
            ("vcek-extension-hwid-value-other-chip", true),
            // The document's chain is not compared with the pinned one.
            ("document-chain-swapped", true),
            ("document-chain-of-another-chain", true),
            ("document-chain-three", false),
            ("document-chain-ask-only", false),
        ];
        let cases = authentication_cases();
        for (name, accepted) in rules {
            let case = named(&cases, &format!("minted-genoa/{name}"));
            assert_eq!(case.accepted, case.reference, "{name}");
            let result = case.authenticate();
            assert_eq!(result.is_ok(), accepted, "{name}: {:?}", result.err());
        }
    }

    #[test]
    fn evidence_of_either_product_line_authenticates_under_its_own_chain_only() {
        let cases = authentication_cases();
        for (name, accepted) in [
            ("minted-genoa/unchanged", true),
            ("minted-turin/unchanged", true),
            ("real-genoa/unchanged", true),
            ("minted-genoa/report-of-the-other-product-line", false),
            ("minted-genoa/roots-of-the-other-product-line", false),
            ("minted-turin/report-cpuid-of-the-other-product-line", false),
            ("minted-turin/vcek-extension-set-of-the-other-layout", false),
            // The replacement chain serves every product line.
            ("minted-genoa/everything-of-the-other-product-line", true),
        ] {
            let result = named(&cases, name).authenticate();
            assert_eq!(result.is_ok(), accepted, "{name}: {:?}", result.err());
        }
        let genoa = named(&cases, "real-genoa/unchanged");
        assert!(genoa.root_pem.is_none());
        assert_eq!(
            genoa.authenticate().unwrap().product_line(),
            ProductLine::Genoa
        );
    }
}
