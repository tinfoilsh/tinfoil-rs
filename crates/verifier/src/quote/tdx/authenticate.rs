//! Authentication of a TDX quote.

use std::collections::BTreeMap;

use super::identity::identity;
use super::lib::abi::QuoteV4;
use super::lib::pcs::{Observed, observe};
use super::lib::verify::verify_quote;
use crate::document::collateral::PcsResponse;
use crate::instant::Instant;
use crate::measurement::{Measurement, Register};
use crate::quote::QuoteError;
use crate::x509::{Certificate, Crl, pem_blocks};

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
    tcb_evaluation_data_number: i64,
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
    /// collateral that verified the quote, as the collateral states them:
    /// any 64-bit integer.
    pub fn tcb_evaluation_data_number(&self) -> i64 {
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

    /// A quote that was not authenticated, for tests of what follows
    /// authentication.
    #[cfg(test)]
    pub(crate) fn unauthenticated(
        quote_bytes: &[u8],
        tcb_evaluation_data_number: i64,
    ) -> Result<Self, QuoteError> {
        let quote = QuoteV4::parse(quote_bytes)?;
        let [rtmr0, rtmr1, rtmr2, rtmr3] = quote.body.rtmrs;
        Ok(Quote {
            identity: String::new(),
            mrtd: Register::new(quote.body.mr_td),
            rtmrs: [
                Register::new(rtmr0),
                Register::new(rtmr1),
                Register::new(rtmr2),
                Register::new(rtmr3),
            ],
            tcb_evaluation_data_number,
            quote,
            quote_bytes: quote_bytes.to_vec(),
        })
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

/// A PCS URL in the plain form that the replay understands, taken apart.
struct PlainUrl<'a> {
    /// The scheme, the host and the path, as written.
    front: &'a str,
    /// The path, as written: empty or starting with `/`.
    path: &'a str,
    /// The query, when the URL has a `?`.
    query: Option<&'a str>,
}

/// The query parameter that selects an edition of Intel's collateral.
const EDITION_PARAMETER: &str = "tcbEvaluationDataNumber";

impl<'a> PlainUrl<'a> {
    /// Takes a URL apart, or `None` when it is outside the plain form:
    ///
    /// ```text
    /// scheme "://" host [ ":" digits ] [ "/" path ] [ "?" query ]
    /// ```
    ///
    /// with a scheme of an ASCII letter followed by letters, digits, `+`,
    /// `-` and `.`; a host of letters, digits, `.` and `-`; a path of
    /// letters, digits, `.`, `_`, `~`, `-` and `/`; and a query of
    /// letters, digits, `.`, `_`, `~`, `-`, `=` and `&`. The form has no
    /// user information, no percent escapes, no `+` in the query and no
    /// fragment, so that a URL has exactly one reading.
    fn parse(url: &'a str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let mut scheme_bytes = scheme.bytes();
        if !scheme_bytes.next()?.is_ascii_alphabetic()
            || !scheme_bytes.all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
        {
            return None;
        }
        let (location, query) = match rest.split_once('?') {
            Some((location, query)) => (location, Some(query)),
            None => (rest, None),
        };
        let path_at = location.find('/').unwrap_or(location.len());
        let (authority, path) = location.split_at_checked(path_at)?;
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, port),
            None => (authority, ""),
        };
        let unreserved = |byte: u8| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte);
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || !path.bytes().all(|byte| unreserved(byte) || byte == b'/')
            || !query
                .unwrap_or_default()
                .bytes()
                .all(|byte| unreserved(byte) || b"=&".contains(&byte))
        {
            return None;
        }
        let front_len = url
            .len()
            .checked_sub(rest.len())?
            .checked_add(location.len())?;
        Some(PlainUrl {
            front: url.get(..front_len)?,
            path,
            query,
        })
    }

    /// The lookup key: the URL without its edition parameter, with the
    /// remaining parameters ordered by name, in lowercase.
    fn key(&self) -> String {
        let mut key = self.front.to_string();
        if let Some(query) = self.query {
            let mut parameters: Vec<(&str, &str)> = query
                .split('&')
                .filter(|parameter| !parameter.is_empty())
                .map(|parameter| parameter.split_once('=').unwrap_or((parameter, "")))
                .filter(|(name, _)| *name != EDITION_PARAMETER)
                .collect();
            // Parameters of one name keep their order.
            parameters.sort_by(|a, b| a.0.cmp(b.0));
            // A `=` inside a value is written as its percent escape.
            let encoded = parameters
                .iter()
                .map(|(name, value)| format!("{name}={}", value.replace('=', "%3D")))
                .collect::<Vec<_>>()
                .join("&");
            // A URL that ends in a bare `?` keeps it.
            if query.is_empty() || !encoded.is_empty() {
                key.push('?');
                key.push_str(&encoded);
            }
        }
        key.to_ascii_lowercase()
    }
}

/// Whether `byte` may appear in an HTTP header name.
fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// The canonical MIME form of a header name: the first letter and every
/// letter after a `-` in uppercase, all others in lowercase. A name with a
/// byte that header names do not allow is left as it is.
pub fn canonical_header_name(name: &str) -> String {
    if !name.bytes().all(is_header_name_byte) {
        return name.to_string();
    }
    let mut upper = true;
    name.chars()
        .map(|character| {
            let mapped = if upper {
                character.to_ascii_uppercase()
            } else {
                character.to_ascii_lowercase()
            };
            upper = character == '-';
            mapped
        })
        .collect()
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
    /// that has no lookup key is an error.
    pub fn new(responses: &'a [PcsResponse], now: Instant) -> Result<Self, QuoteError> {
        let mut index = BTreeMap::new();
        for response in responses {
            index.insert(Self::key(&response.url)?, response);
        }
        Ok(Self {
            responses: index,
            now,
        })
    }

    /// The lookup key of a PCS URL: the URL without its
    /// `tcbEvaluationDataNumber` query parameter, with the remaining
    /// parameters ordered by name, in lowercase.
    ///
    /// The parameter selects which edition of the collateral Intel serves,
    /// so a response recorded with it answers the request without it.
    ///
    /// Only a URL in a plain form has a key: a scheme, a host with an
    /// optional numeric port, a path and a query, all of unreserved
    /// characters. User information, percent escapes, a `+` in the query
    /// and a fragment are errors, because such a URL can be read in more
    /// than one way.
    pub fn key(url: &str) -> Result<String, QuoteError> {
        PlainUrl::parse(url)
            .map(|url| url.key())
            .ok_or_else(|| QuoteError::new(format!("PCS URL {url:?} is not in the plain form")))
    }

    /// The recorded response for a request URL.
    ///
    /// A URL without a recorded response is an error. A body that parses
    /// as a revocation list ([`Crl::from_der`]) must be within its
    /// validity at the replay's instant, whatever the URL; a body that
    /// does not parse as one is an error when the lookup key contains
    /// `crl`. Header names are served in canonical MIME form
    /// ([`canonical_header_name`]); two recorded names with the same
    /// canonical form and different values are an error.
    pub fn get(&self, url: &str) -> Result<ReplayedResponse<'a>, QuoteError> {
        let key = Self::key(url)?;
        let response = self.responses.get(&key).ok_or_else(|| {
            QuoteError::new(format!(
                "intel-pcs collateral has no recorded response for {url}"
            ))
        })?;
        match Crl::from_der(&response.body) {
            Ok(crl) => crl.check_validity(self.now).map_err(|error| {
                QuoteError::new(format!("recorded revocation list for {url}: {error}"))
            })?,
            Err(error) if key.contains("crl") => {
                return Err(QuoteError::new(format!(
                    "parsing recorded revocation list for {url}: {error}"
                )));
            }
            Err(_) => {}
        }
        let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, values) in &response.headers {
            let canonical = canonical_header_name(name);
            match headers.get(&canonical) {
                Some(present) if present != values => {
                    return Err(QuoteError::new(format!(
                        "recorded response for {url} states the header {canonical} twice"
                    )));
                }
                Some(_) => {}
                None => {
                    headers.insert(canonical, values.clone());
                }
            }
        }
        Ok(ReplayedResponse {
            headers,
            body: &response.body,
        })
    }
}

/// The edition and issue time that one kind of collateral was observed to
/// state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Edition {
    /// No response of this kind stated a `tcbEvaluationDataNumber`.
    #[default]
    Unseen,
    /// The last response of this kind that stated a number.
    Seen {
        number: i64,
        issued: Option<Instant>,
    },
    /// A response of this kind stated a number with an issue time that
    /// cannot be read.
    Unreadable,
}

/// Serves replayed collateral to quote verification and notes, for every
/// response that it serves, the `tcbEvaluationDataNumber` and `issueDate`
/// that the response states.
///
/// What is noted goes by the path of the request: a path that ends in
/// `/tcb` is TCB info, one that ends in `/qe/identity` is the QE identity.
/// A later response of a kind replaces what an earlier one stated.
#[derive(Debug, Clone)]
pub struct CollateralRecorder<'a> {
    replay: PcsReplay<'a>,
    tcb_info: Edition,
    qe_identity: Edition,
}

impl<'a> CollateralRecorder<'a> {
    /// A recorder over a replay, with nothing noted yet.
    pub fn new(replay: PcsReplay<'a>) -> Self {
        Self {
            replay,
            tcb_info: Edition::Unseen,
            qe_identity: Edition::Unseen,
        }
    }

    /// The recorded response for a request URL ([`PcsReplay::get`]), noted
    /// as described on the type.
    pub fn get(&mut self, url: &str) -> Result<ReplayedResponse<'a>, QuoteError> {
        let response = self.replay.get(url)?;
        let path = PlainUrl::parse(url).map_or("", |url| url.path);
        let noted = if path.ends_with("/tcb") {
            Some((&mut self.tcb_info, "tcbInfo"))
        } else if path.ends_with("/qe/identity") {
            Some((&mut self.qe_identity, "enclaveIdentity"))
        } else {
            None
        };
        if let Some((edition, member)) = noted {
            match observe(response.body, member) {
                Observed::Nothing => {}
                Observed::Edition { number, issued } => {
                    *edition = Edition::Seen { number, issued };
                }
                Observed::Unreadable => *edition = Edition::Unreadable,
            }
        }
        Ok(response)
    }

    /// Checks that both kinds of collateral stated an issue time and that
    /// `now` is not before either.
    pub fn check_issue_dates(&self, now: Instant) -> Result<(), QuoteError> {
        let (
            Edition::Seen {
                issued: Some(tcb_info),
                ..
            },
            Edition::Seen {
                issued: Some(qe_identity),
                ..
            },
        ) = (self.tcb_info, self.qe_identity)
        else {
            return Err(QuoteError::new(
                "collateral issueDate was not observed during quote verification",
            ));
        };
        if now < tcb_info {
            return Err(QuoteError::new("TCB info is not yet valid"));
        }
        if now < qe_identity {
            return Err(QuoteError::new("QE identity is not yet valid"));
        }
        Ok(())
    }

    /// The lower of the two `tcbEvaluationDataNumber` values that were
    /// stated; an error unless both kinds of collateral stated one.
    pub fn minimum(&self) -> Result<i64, QuoteError> {
        match (self.tcb_info, self.qe_identity) {
            (
                Edition::Seen {
                    number: tcb_info, ..
                },
                Edition::Seen {
                    number: qe_identity,
                    ..
                },
            ) => Ok(tcb_info.min(qe_identity)),
            _ => Err(QuoteError::new(
                "collateral tcbEvaluationDataNumber was not observed during quote verification",
            )),
        }
    }
}

/// The Intel SGX root certificate embedded in the crate, PEM.
pub fn embedded_root_pem() -> &'static [u8] {
    crate::trust::INTEL_SGX_ROOT_CA_PEM
}

/// The trust anchor: the first block of a PEM file, a certificate.
fn trust_anchor(pem: &[u8]) -> Result<Certificate, QuoteError> {
    let blocks =
        pem_blocks(pem).map_err(|error| QuoteError::new(format!("Intel SGX root PEM: {error}")))?;
    let block = blocks
        .first()
        .ok_or_else(|| QuoteError::new("Intel SGX root PEM carries no certificate"))?;
    Certificate::from_der(&block.contents)
        .map_err(|error| QuoteError::new(format!("parsing Intel SGX root certificate: {error}")))
}

/// Verifies a quote's signature chain up to the pinned Intel SGX root,
/// replaying the recorded Intel collateral.
///
/// `root_pem` replaces the embedded Intel SGX root (one certificate, PEM)
/// when given; only a conformance build can give one
/// ([`VendorRoots`](crate::quote::VendorRoots)). Everything is judged at
/// `now`. In order:
///
/// 1. the trust anchor parses: the first PEM block of the embedded root
///    ([`embedded_root_pem`]) or of `root_pem`, a certificate;
/// 2. the quote decodes as a version 4 quote ([`QuoteV4::parse`]);
/// 3. the reserved header bytes 8 to 11 are zero, and every byte after the
///    signed data is zero: trailing bytes may only be the padding of the
///    buffer that the quote was read from;
/// 4. every recorded response has a lookup key ([`PcsReplay::new`]);
/// 5. the quote verifies against the replayed collateral
///    ([`verify_quote`]) with revocation checking on;
/// 6. the TCB info and the QE identity that were served both state an
///    issue date, and `now` is not before either
///    ([`CollateralRecorder::check_issue_dates`]);
/// 7. the identity is the PPID ([`identity`](super::identity()));
/// 8. both collateral documents state a `tcbEvaluationDataNumber`; the
///    quote records the lower of the two;
/// 9. the measurement is the quote's MRTD and four RTMRs.
pub fn authenticate(
    evidence: Evidence<'_>,
    now: Instant,
    root_pem: Option<&[u8]>,
) -> Result<Quote, QuoteError> {
    let trusted_root = trust_anchor(match root_pem {
        Some(pem) => pem,
        None => embedded_root_pem(),
    })?;
    let quote =
        QuoteV4::parse(evidence.quote).map_err(|error| error.within("parsing TDX quote"))?;
    if quote.header.qe_svn != [0, 0] || quote.header.pce_svn != [0, 0] {
        return Err(QuoteError::new(
            "TDX quote header carries non-zero reserved bytes",
        ));
    }
    if quote.extra_bytes.iter().any(|byte| *byte != 0) {
        return Err(QuoteError::new(
            "TDX quote carries non-zero bytes after the signed data",
        ));
    }

    let mut collateral = CollateralRecorder::new(PcsReplay::new(evidence.pcs, now)?);
    verify_quote(&quote, &mut collateral, &trusted_root, now)
        .map_err(|error| error.within("verifying TDX quote"))?;
    collateral.check_issue_dates(now)?;

    let identity = identity(&quote)?;
    let tcb_evaluation_data_number = collateral.minimum()?;

    let [rtmr0, rtmr1, rtmr2, rtmr3] = quote.body.rtmrs;
    Ok(Quote {
        identity,
        mrtd: Register::new(quote.body.mr_td),
        rtmrs: [
            Register::new(rtmr0),
            Register::new(rtmr1),
            Register::new(rtmr2),
            Register::new(rtmr3),
        ],
        tcb_evaluation_data_number,
        quote,
        quote_bytes: evidence.quote.to_vec(),
    })
}
