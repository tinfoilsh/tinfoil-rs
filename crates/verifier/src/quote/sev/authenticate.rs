//! Authentication of an SEV-SNP attestation report.

use super::lib::abi::{ProductLine, Report};
use super::lib::kds::Extensions;
use crate::instant::Instant;
use crate::measurement::{Measurement, Register};
use crate::quote::QuoteError;
use crate::stub::pending;
use crate::x509::Certificate;

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

    /// The report as it was authenticated.
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

/// Verifies a report's signature chain up to the pinned AMD root, and the
/// chain against the supplied revocation list.
///
/// `root_pem` replaces the embedded chain of the report's product line
/// (ASK then ARK, PEM) when given; only a conformance build can give one
/// ([`VendorRoots`](crate::quote::VendorRoots)). Everything is judged at
/// `now`. In order:
///
/// 1. the VCEK is not empty; the document's chain is exactly two
///    `CERTIFICATE` blocks with nothing else around them
///    ([`pem_certificates`](crate::x509::der::pem_certificates)); the
///    revocation list is not empty;
/// 2. the revocation list parses ([`Crl::from_der`](crate::x509::Crl::from_der))
///    and `now` is within its validity;
/// 3. the report is exactly [`REPORT_SIZE`](super::lib::abi::REPORT_SIZE)
///    bytes and decodes ([`Report::parse`]);
/// 4. the report's CPUID field names a supported product line: Genoa or
///    Turin ([`ProductLine::from_report`]). A report without the field
///    (version 2) is an error;
/// 5. the trust anchor is the embedded chain of that product line, or
///    `root_pem`: exactly two certificates, ASK then ARK
///    ([`parse_product_cert_chain`](super::lib::kds::parse_product_cert_chain));
/// 6. the attestation verifies
///    ([`verify_attestation`](super::lib::verify::verify_attestation)):
///    the VCEK has the AMD profile and chains to the pinned ASK and ARK at
///    `now`, the revocation list is signed by the ARK and does not revoke
///    the ASK, and the report's signature verifies under the VCEK;
/// 7. the report does not mask its CHIP_ID: a masked platform identity is
///    unsupported;
/// 8. the identity is the CHIP_ID ([`identity`](super::identity())) and the
///    measurement is the report's launch measurement.
///
/// Whether the report's TCB matches the VCEK and whether the CHIP_ID is the
/// VCEK's hardware identifier are checked at validation
/// ([`Expectations::validate`](super::Expectations::validate)), not here.
pub fn authenticate(
    evidence: Evidence<'_>,
    now: Instant,
    root_pem: Option<&[u8]>,
) -> Result<Quote, QuoteError> {
    pending("quote::sev::authenticate")
}
