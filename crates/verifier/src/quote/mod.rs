//! Verification of a document's CPU evidence, in three phases:
//!
//! 1. **Authenticate** ([`authenticate`]): verify the quote's signature
//!    chain up to the pinned vendor root, from the collateral that the
//!    document carries. The result is authentic but not yet appraised.
//! 2. **Assemble** ([`assemble`]): resolve the complete policy, every value
//!    that the quote must attest, as one object. Entries differ only in the
//!    verified source that resolves them (policy artifact, code provenance,
//!    document); assembly fails if any entry cannot be resolved.
//! 3. **Validate** ([`AssembledPolicy::validate`]): one comparison of the
//!    quote against the assembled policy.
//!
//! Nothing here fetches collateral or reads a clock: revocation lists and
//! vendor collateral come from the document, and validity is judged at the
//! instant that the caller passes.

pub mod config;
pub mod legacy;
pub mod resolve;
pub mod sev;
pub mod tdx;

use crate::document::collateral::CpuEndorsements;
use crate::document::{CpuEvidence, Document, REPORT_DATA_SIZE};
use crate::instant::Instant;
use crate::measurement::{Expected, Measurement};
use crate::stub::{message_error, pending};

pub use config::ConfigReferenceValues;
pub use legacy::LegacyReferenceValues;

message_error! {
    /// CPU evidence that is not authentic: a quote that does not parse,
    /// does not chain to the vendor root, is revoked, or rests on stale
    /// collateral.
    pub struct QuoteError;
}

message_error! {
    /// A policy that cannot be assembled for a quote, or an authentic quote
    /// that does not satisfy its assembled policy.
    pub struct AssemblyError;
}

impl From<crate::x509::X509Error> for QuoteError {
    fn from(error: crate::x509::X509Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<crate::policy::PolicyError> for AssemblyError {
    fn from(error: crate::policy::PolicyError) -> Self {
        Self::new(error.to_string())
    }
}

/// The vendor trust anchors that quotes are authenticated against.
///
/// The default, and the only value that an ordinary build can construct,
/// selects the anchors embedded in the crate. A replacement anchor destroys
/// the guarantee that evidence chains to AMD or Intel, so the constructor
/// that takes one exists only in conformance builds.
#[derive(Debug, Clone, Default)]
pub struct VendorRoots {
    amd_cert_chain_pem: Option<Vec<u8>>,
    intel_root_pem: Option<Vec<u8>>,
}

impl VendorRoots {
    /// The anchors embedded in the crate.
    pub fn embedded() -> Self {
        Self::default()
    }

    /// Anchors supplied by the conformance harness, so that it can
    /// authenticate synthetic evidence: an AMD certificate chain (ASK then
    /// ARK, PEM) that replaces the embedded chain of every product line,
    /// and an Intel SGX root certificate (PEM). `None` keeps the embedded
    /// anchor of that vendor.
    #[cfg(tinfoil_conformance)]
    pub fn dangerous_test_only(
        amd_cert_chain_pem: Option<Vec<u8>>,
        intel_root_pem: Option<Vec<u8>>,
    ) -> Self {
        Self {
            amd_cert_chain_pem,
            intel_root_pem,
        }
    }

    /// The replacement AMD chain, if one was supplied.
    fn amd(&self) -> Option<&[u8]> {
        self.amd_cert_chain_pem.as_deref()
    }

    /// The replacement Intel root, if one was supplied.
    fn intel(&self) -> Option<&[u8]> {
        self.intel_root_pem.as_deref()
    }
}

/// A signature-verified quote, not yet compared against any expected
/// value.
#[derive(Debug, Clone)]
pub enum Authenticated {
    /// An AMD SEV-SNP attestation report.
    SevSnp(Box<sev::Quote>),
    /// An Intel TDX quote.
    Tdx(Box<tdx::Quote>),
}

impl Authenticated {
    /// The platform label of the quote:
    /// [`PLATFORM_SEV_SNP`](crate::policy::PLATFORM_SEV_SNP) or
    /// [`PLATFORM_TDX`](crate::policy::PLATFORM_TDX).
    pub fn platform(&self) -> &'static str {
        match self {
            Authenticated::SevSnp(_) => crate::policy::PLATFORM_SEV_SNP,
            Authenticated::Tdx(_) => crate::policy::PLATFORM_TDX,
        }
    }

    /// The authenticated machine identifier in lowercase hex: the CHIP_ID
    /// of an SEV-SNP report, the PPID of a TDX quote's PCK certificate.
    pub fn identity(&self) -> &str {
        match self {
            Authenticated::SevSnp(quote) => quote.identity(),
            Authenticated::Tdx(quote) => quote.identity(),
        }
    }

    /// The authenticated registers.
    pub fn measurement(&self) -> Measurement {
        match self {
            Authenticated::SevSnp(quote) => quote.measurement(),
            Authenticated::Tdx(quote) => quote.measurement(),
        }
    }

    /// Whether this quote was authenticated from exactly this evidence: the
    /// same format and the same report bytes.
    pub fn is_evidence(&self, evidence: &CpuEvidence) -> bool {
        match self {
            Authenticated::SevSnp(quote) => {
                evidence.format == crate::document::SEV_SNP_REPORT_V1_FORMAT
                    && evidence.report == quote.report_bytes()
            }
            Authenticated::Tdx(quote) => {
                evidence.format == crate::document::TDX_QUOTE_V1_FORMAT
                    && evidence.report == quote.quote_bytes()
            }
        }
    }
}

/// Verifies the evidence's signature chain up to the pinned vendor root,
/// from the supplied endorsement collateral alone.
///
/// Certificate, revocation list and vendor collateral validity are all
/// judged at `now`. By evidence format:
///
/// - an SEV-SNP report needs the VCEK collateral and the CRL collateral of
///   the CPU; a missing one is an error, never fetched. The report is then
///   authenticated by [`sev::authenticate()`];
/// - a TDX quote needs the recorded Intel PCS responses, and is
///   authenticated by [`tdx::authenticate()`];
/// - any other format is an error.
///
/// The caller must assemble a policy and validate it before trusting the
/// platform.
pub fn authenticate(
    evidence: &CpuEvidence,
    endorsements: &CpuEndorsements,
    now: Instant,
    roots: &VendorRoots,
) -> Result<Authenticated, QuoteError> {
    pending("quote::authenticate")
}

/// Reference values for one verification contract: what resolves the
/// policy and the expected registers of a quote.
#[derive(Debug, Clone)]
pub enum ReferenceValues<'a> {
    /// The repository-release contract: registers from code provenance,
    /// platform registers from the policy artifact.
    Legacy(LegacyReferenceValues<'a>),
    /// The endorsed-config contract: registers from the runtime manifest,
    /// the config's hash bound into the quote.
    Config(ConfigReferenceValues<'a>),
}

/// The complete expected state of one quote, resolved before validation
/// runs. It borrows the quote that it was assembled for, so it cannot be
/// applied to any other.
#[derive(Debug)]
pub enum AssembledPolicy<'q> {
    /// The expected state of an SEV-SNP report.
    SevSnp {
        /// The quote that the policy was assembled for.
        quote: &'q sev::Quote,
        /// The translated expectations.
        expectations: Box<sev::Expectations>,
        /// What was resolved.
        resolution: Resolution,
    },
    /// The expected state of a TDX quote.
    Tdx {
        /// The quote that the policy was assembled for.
        quote: &'q tdx::Quote,
        /// The translated expectations.
        expectations: Box<tdx::Expectations>,
        /// What was resolved.
        resolution: Resolution,
    },
}

/// What assembly resolved, for the verification record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The registers that the release fixes on the quote's platform.
    pub code_measurement: Expected,
    /// The name of the matched policy.
    pub policy_name: String,
    /// The name of the resolved TDX platform measurement; `None` for
    /// SEV-SNP and for the endorsed-config contract.
    pub platform_measurement_name: Option<String>,
}

impl AssembledPolicy<'_> {
    /// What assembly resolved.
    pub fn resolution(&self) -> &Resolution {
        match self {
            AssembledPolicy::SevSnp { resolution, .. }
            | AssembledPolicy::Tdx { resolution, .. } => resolution,
        }
    }

    /// The registers that the release fixes on the quote's platform.
    pub fn code_measurement(&self) -> &Expected {
        &self.resolution().code_measurement
    }

    /// Compares the quote against the assembled policy:
    /// [`sev::Expectations::validate`] or [`tdx::Expectations::validate`].
    /// No lookup and no translation happens here.
    pub fn validate(&self) -> Result<(), AssemblyError> {
        match self {
            AssembledPolicy::SevSnp {
                quote,
                expectations,
                ..
            } => expectations.validate(quote),
            AssembledPolicy::Tdx {
                quote,
                expectations,
                ..
            } => expectations.validate(quote),
        }
    }
}

/// Assembles the policy for a quote from a parsed document.
///
/// Both checks below bind the quote to the caller's challenge: the document
/// carries the report data that was recomputed from the caller's nonce
/// ([`Document::expected_report_data`]; a document that was decoded
/// without a nonce has none and is an error), and `quote` was authenticated
/// from this document's own CPU evidence
/// ([`Authenticated::is_evidence`]). Then as
/// [`assemble_with_report_data`].
pub fn assemble<'q>(
    document: &Document,
    references: &ReferenceValues<'_>,
    pins: Option<&Expected>,
    quote: &'q Authenticated,
) -> Result<AssembledPolicy<'q>, AssemblyError> {
    pending("quote::assemble")
}

/// Assembles the policy for a quote against an explicit report data value.
///
/// In order:
///
/// 1. the reference values resolve the policy and the expected registers
///    for the quote ([`LegacyReferenceValues::resolve`] or
///    [`ConfigReferenceValues::resolve`]), with the caller's pins applied
///    ([`resolve::apply_pins`]);
/// 2. every expected register is fixed ([`resolve::complete`]);
/// 3. the expected registers are for the quote's platform;
/// 4. the platform's expectations are assembled: [`sev::assemble`] with
///    the resolved host data in place of the policy's, or
///    [`tdx::assemble`] with the resolved config identifier.
pub fn assemble_with_report_data<'q>(
    references: &ReferenceValues<'_>,
    pins: Option<&Expected>,
    report_data: &[u8; REPORT_DATA_SIZE],
    quote: &'q Authenticated,
) -> Result<AssembledPolicy<'q>, AssemblyError> {
    pending("quote::assemble_with_report_data")
}
