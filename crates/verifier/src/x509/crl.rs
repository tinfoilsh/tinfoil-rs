//! Certificate revocation lists.

use super::{Certificate, X509Error};
use crate::instant::Instant;
use crate::stub::pending;

/// A parsed certificate revocation list. Parsing establishes its form only;
/// [`Crl::verify_issued_by`] establishes who issued it and
/// [`Crl::check_validity`] that it is current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crl {
    der: Vec<u8>,
    tbs: Vec<u8>,
    issuer_der: Vec<u8>,
    this_update: Instant,
    next_update: Instant,
    revoked_serials: Vec<Vec<u8>>,
}

impl Crl {
    /// Parses a DER `CertificateList`.
    ///
    /// Rules, each an error when broken:
    ///
    /// - canonical DER with nothing after it;
    /// - version 2;
    /// - the inner and outer signature algorithms are identical;
    /// - `nextUpdate` is present, and `thisUpdate` is not after it; both
    ///   are UTCTime or GeneralizedTime in the forms of
    ///   [`parse_utc_time`](super::der::parse_utc_time) and
    ///   [`parse_generalized_time`](super::der::parse_generalized_time)
    ///   without a fraction;
    /// - no critical list extension other than the authority key identifier
    ///   and the CRL number; in particular a delta CRL indicator or an
    ///   issuing distribution point rejects, because such a list does not
    ///   speak for every certificate of its issuer;
    /// - no critical entry extension: a certificate issuer entry extension
    ///   would mean that the list covers other issuers' certificates;
    /// - the signature bit string has no unused bits.
    pub fn from_der(der: &[u8]) -> Result<Self, X509Error> {
        pending("x509::crl::Crl::from_der")
    }

    /// The DER that the list was parsed from.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The encoded issuer name.
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer_der
    }

    /// The start of the list's validity.
    pub fn this_update(&self) -> Instant {
        self.this_update
    }

    /// The end of the list's validity.
    pub fn next_update(&self) -> Instant {
        self.next_update
    }

    /// Checks that `at` is within the list's validity: not before
    /// `thisUpdate` and not after `nextUpdate`.
    pub fn check_validity(&self, at: Instant) -> Result<(), X509Error> {
        pending("x509::crl::Crl::check_validity")
    }

    /// Checks that the list was issued by `issuer`: the list's issuer name
    /// equals the certificate's subject name byte for byte, the certificate
    /// permits CRL signing when it carries a key usage extension, and the
    /// signature verifies under the certificate's key over the encoded
    /// `tbsCertList` as it appears in the list.
    pub fn verify_issued_by(&self, issuer: &Certificate) -> Result<(), X509Error> {
        pending("x509::crl::Crl::verify_issued_by")
    }

    /// Whether the list revokes the certificate with this serial number.
    /// `serial` is the content of the serial number INTEGER, as
    /// [`Certificate::serial`] returns it.
    ///
    /// A list answers only for certificates of its own issuer; the caller
    /// has checked that with [`Crl::verify_issued_by`] against the
    /// certificate's issuer.
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked_serials.iter().any(|revoked| revoked == serial)
    }
}
