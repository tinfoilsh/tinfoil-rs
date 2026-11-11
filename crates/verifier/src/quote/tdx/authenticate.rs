//! Authentication of a TDX quote.

use std::collections::BTreeMap;

use super::lib::abi::QuoteV4;
use crate::document::collateral::PcsResponse;
use crate::instant::Instant;
use crate::measurement::{Measurement, Register};
use crate::quote::QuoteError;
use crate::stub::pending;

/// A TDX quote with the Intel PCS responses that were recorded to
/// authenticate it.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// The raw quote.
    pub quote: &'a [u8],
    /// The recorded Intel PCS responses, replayed instead of fetched.
    pub pcs: &'a [PcsResponse],
}

/// A signature-verified TDX quote, not yet compared against any expected
/// value.
#[derive(Debug, Clone)]
pub struct Quote {
    identity: String,
    mrtd: Register,
    rtmrs: [Register; 4],
    /// The lower of the `tcbEvaluationDataNumber` values of the TCB info
    /// and the QE identity that verified the quote.
    tcb_evaluation_data_number: u32,
    quote: QuoteV4,
    quote_bytes: Vec<u8>,
}

impl Quote {
    /// The authenticated machine identifier: the PPID in lowercase hex.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The authenticated MRTD and four RTMRs.
    pub fn measurement(&self) -> Measurement {
        let [rtmr0, rtmr1, rtmr2, rtmr3] = self.rtmrs;
        Measurement::Tdx {
            mrtd: self.mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        }
    }

    /// The MRTD and RTMR0 of the quote in lowercase hex: what a platform
    /// measurement is resolved by.
    pub fn platform_measurements(&self) -> (String, String) {
        let [rtmr0, ..] = self.rtmrs;
        (self.mrtd.to_string(), rtmr0.to_string())
    }

    /// The lower of the `tcbEvaluationDataNumber` values of the Intel
    /// collateral that verified the quote.
    pub fn tcb_evaluation_data_number(&self) -> u32 {
        self.tcb_evaluation_data_number
    }

    /// The decoded quote.
    pub fn quote(&self) -> &QuoteV4 {
        &self.quote
    }

    /// The quote as it was authenticated.
    pub fn quote_bytes(&self) -> &[u8] {
        &self.quote_bytes
    }
}

/// One recorded Intel PCS response, as served to quote verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedResponse<'a> {
    /// The response headers, with names in canonical MIME form
    /// (`Tcb-Info-Issuer-Chain`).
    pub headers: BTreeMap<String, Vec<String>>,
    /// The response body.
    pub body: &'a [u8],
}

/// Serves the document's recorded Intel PCS responses in place of the
/// network.
#[derive(Debug, Clone)]
pub struct PcsReplay<'a> {
    /// The recorded responses by lookup key.
    responses: BTreeMap<String, &'a PcsResponse>,
    now: Instant,
}

impl<'a> PcsReplay<'a> {
    /// Indexes recorded responses by lookup key ([`PcsReplay::key`]). When
    /// two responses have the same key, the later one is served. A URL
    /// that does not parse is an error.
    pub fn new(responses: &'a [PcsResponse], now: Instant) -> Result<Self, QuoteError> {
        pending("quote::tdx::PcsReplay::new")
    }

    /// The lookup key of a PCS URL: the URL without its
    /// `tcbEvaluationDataNumber` query parameter, with the remaining
    /// parameters in sorted order and percent-encoded, in lowercase.
    ///
    /// The parameter selects which edition of the collateral Intel serves,
    /// so a response recorded with it answers the request without it.
    pub fn key(url: &str) -> Result<String, QuoteError> {
        pending("quote::tdx::PcsReplay::key")
    }

    /// The recorded response for a request URL.
    ///
    /// A URL without a recorded response is an error. A body that parses
    /// as a revocation list ([`Crl::from_der`](crate::x509::Crl::from_der))
    /// must be within its validity at the replay's instant, whatever the
    /// URL; a body that does not parse as one is an error when the lookup
    /// key contains `crl`.
    pub fn get(&self, url: &str) -> Result<ReplayedResponse<'a>, QuoteError> {
        pending("quote::tdx::PcsReplay::get")
    }
}

/// Verifies a quote's signature chain up to the pinned Intel SGX root,
/// replaying the recorded Intel collateral.
///
/// `root_pem` replaces the embedded Intel SGX root (one certificate, PEM)
/// when given; only a conformance build can give one
/// ([`VendorRoots`](crate::quote::VendorRoots)). Everything is judged at
/// `now`. In order:
///
/// 1. the trust anchor parses: the first PEM block of the root, a
///    certificate;
/// 2. the quote decodes as a version 4 quote ([`QuoteV4::parse`]);
/// 3. the reserved header bytes 8 to 11 are zero, and every byte after the
///    signed data is zero: trailing bytes may only be the padding of the
///    buffer that the quote was read from;
/// 4. the quote verifies against the replayed collateral
///    ([`verify_quote`](super::lib::verify::verify_quote)) with revocation
///    checking on;
/// 5. the TCB info and the QE identity that verification used both state
///    an issue date, and `now` is not before either;
/// 6. the identity is the PPID ([`identity`](super::identity()));
/// 7. both collateral documents state a `tcbEvaluationDataNumber`; the
///    quote records the lower of the two;
/// 8. the measurement is the quote's MRTD and four RTMRs.
pub fn authenticate(
    evidence: Evidence<'_>,
    now: Instant,
    root_pem: Option<&[u8]>,
) -> Result<Quote, QuoteError> {
    pending("quote::tdx::authenticate")
}
