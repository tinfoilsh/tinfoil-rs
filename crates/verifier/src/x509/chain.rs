//! Certificate path verification against explicit trust anchors at a
//! supplied time.

use ::der::asn1::ObjectIdentifier;

use super::extension::{self, is_processed};
use super::{Certificate, X509Error};
use crate::instant::Instant;

/// The most certificates in a path, the leaf and the root included.
pub const MAX_PATH_LENGTH: usize = 8;

/// The most signature checks that one path search performs.
pub const MAX_SIGNATURE_CHECKS: usize = 100;

/// `anyExtendedKeyUsage`.
const OID_ANY_PURPOSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");
/// `id-kp-serverAuth`.
const OID_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
/// `id-kp-codeSigning`.
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
/// `id-kp-timeStamping`.
const OID_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// What a certificate path is used for, as an extended key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// No extended key usage is required of the path.
    Any,
    /// `id-kp-serverAuth`: the purpose of a path that states none, such as
    /// the Intel provisioning certificate chain.
    ServerAuth,
    /// `id-kp-codeSigning`: Sigstore signing certificates and registry
    /// signing certificates.
    CodeSigning,
    /// `id-kp-timeStamping`: RFC 3161 timestamp authorities.
    TimeStamping,
}

impl KeyPurpose {
    fn oid(self) -> Option<ObjectIdentifier> {
        match self {
            KeyPurpose::Any => None,
            KeyPurpose::ServerAuth => Some(OID_SERVER_AUTH),
            KeyPurpose::CodeSigning => Some(OID_CODE_SIGNING),
            KeyPurpose::TimeStamping => Some(OID_TIME_STAMPING),
        }
    }
}

/// Verifies that `leaf` chains to one of `roots` at the instant `at`, and
/// returns the path from the leaf to the root, both included.
///
/// A path is built from `leaf` through any of `intermediates` to a
/// certificate in `roots`; the first path that satisfies every rule wins.
/// Certificates in `intermediates` that are not needed are ignored. At most
/// [`MAX_PATH_LENGTH`] certificates form a path, and a search gives up
/// after [`MAX_SIGNATURE_CHECKS`] signature checks. The rules:
///
/// 1. each certificate's issuer name equals its issuer's subject name, byte
///    for byte, and its signature verifies under the issuer's key over the
///    encoded `tbsCertificate` as it appears in the certificate;
/// 2. `at` lies within the validity of every certificate on the path, the
///    root included; both ends of a validity period are inside it;
/// 3. every certificate that issues another permits it: an intermediate
///    has basic constraints with `cA` set; a root has them too unless it is
///    a version 1 or 2 certificate without the extension; a key usage
///    extension with any bit set includes certificate signing; and a path
///    length constraint is not exceeded;
/// 4. no certificate on the path has a critical extension that this module
///    does not process. Processed: basic constraints, key usage, extended
///    key usage, certificate policies, CRL distribution points, and a
///    subject alternative name that holds at least one URI, DNS name,
///    e-mail address or IP address. Certificates with name constraints or
///    policy constraints never parse, so no path contains one;
/// 5. with a `purpose` other than [`KeyPurpose::Any`], every certificate on
///    the path, the root included, either lists no extended key usage or
///    lists the purpose or `anyExtendedKeyUsage`.
///
/// A root is trusted as given: its own signature is not checked. When
/// `leaf` is, byte for byte, one of `roots`, the path is the leaf alone and
/// only rules 2, 4 and 5 apply to it.
///
/// The profile of the leaf (its key type, names, whether it must carry an
/// extended key usage, whether it may be a CA) is the caller's to check.
/// Revocation is not consulted here; see [`Crl`](super::Crl).
pub fn verify_chain<'a>(
    leaf: &'a Certificate,
    intermediates: &'a [Certificate],
    roots: &'a [Certificate],
    at: Instant,
    purpose: KeyPurpose,
) -> Result<Vec<&'a Certificate>, X509Error> {
    check_on_path(leaf, at)?;
    if roots.iter().any(|root| root.der() == leaf.der()) {
        let path = vec![leaf];
        if !permits(&path, purpose)? {
            return Err(X509Error::new(
                "certificate is not permitted for the required purpose",
            ));
        }
        return Ok(path);
    }
    let mut search = Search {
        intermediates,
        roots,
        at,
        purpose,
        signature_checks: 0,
        first_failure: None,
        wrong_purpose: false,
    };
    let mut path = vec![leaf];
    if search.extend(&mut path)? {
        return Ok(path);
    }
    if search.wrong_purpose {
        return Err(X509Error::new(
            "certificate path is not permitted for the required purpose",
        ));
    }
    Err(match search.first_failure {
        Some(cause) => cause.within("certificate does not chain to a trusted root"),
        None => X509Error::new("certificate is signed by an unknown authority"),
    })
}

struct Search<'a> {
    intermediates: &'a [Certificate],
    roots: &'a [Certificate],
    at: Instant,
    purpose: KeyPurpose,
    signature_checks: usize,
    first_failure: Option<X509Error>,
    wrong_purpose: bool,
}

impl<'a> Search<'a> {
    /// Extends `path` to a root. Returns whether a complete path that
    /// satisfies every rule was found; `path` then holds it. The depth of
    /// the recursion is bounded by [`MAX_PATH_LENGTH`].
    fn extend(&mut self, path: &mut Vec<&'a Certificate>) -> Result<bool, X509Error> {
        let Some(child) = path.last().copied() else {
            return Ok(false);
        };
        let (roots, intermediates) = (self.roots, self.intermediates);
        for root in roots {
            if !self.is_candidate(child, root, path)? {
                continue;
            }
            if let Err(cause) = check_issuer(root, path.len(), false, self.at) {
                self.note(cause);
                continue;
            }
            path.push(root);
            if permits(path, self.purpose)? {
                return Ok(true);
            }
            self.wrong_purpose = true;
            path.pop();
        }
        if path.len().saturating_add(1) >= MAX_PATH_LENGTH {
            return Ok(false);
        }
        for intermediate in intermediates {
            if !self.is_candidate(child, intermediate, path)? {
                continue;
            }
            if let Err(cause) = check_issuer(intermediate, path.len(), true, self.at) {
                self.note(cause);
                continue;
            }
            path.push(intermediate);
            if self.extend(path)? {
                return Ok(true);
            }
            path.pop();
        }
        Ok(false)
    }

    /// Whether `candidate` issued `child`: the names match, the candidate
    /// is not already on the path, it may sign certificates, and the
    /// child's signature verifies under its key.
    fn is_candidate(
        &mut self,
        child: &Certificate,
        candidate: &'a Certificate,
        path: &[&'a Certificate],
    ) -> Result<bool, X509Error> {
        if child.issuer_der() != candidate.subject_der() {
            return Ok(false);
        }
        self.signature_checks = self.signature_checks.saturating_add(1);
        if self.signature_checks > MAX_SIGNATURE_CHECKS {
            return Err(X509Error::new(
                "too many signature checks while building a certificate path",
            ));
        }
        if path.iter().any(|on_path| same_entity(on_path, candidate)) {
            return Ok(false);
        }
        if let Err(cause) = check_signed_by(child, candidate) {
            self.note(cause);
            return Ok(false);
        }
        Ok(true)
    }

    fn note(&mut self, cause: X509Error) {
        if self.first_failure.is_none() {
            self.first_failure = Some(cause);
        }
    }
}

/// Whether two certificates are the same entity for the purpose of loop
/// detection: the same subject, key and subject alternative name.
fn same_entity(a: &Certificate, b: &Certificate) -> bool {
    fn names(certificate: &Certificate) -> Option<&[u8]> {
        certificate
            .extension(extension::OID_SUBJECT_ALT_NAME)
            .map(|found| found.value)
    }
    let key = |certificate: &Certificate| certificate.spki_der().ok();
    a.subject_der() == b.subject_der() && key(a) == key(b) && names(a) == names(b)
}

/// Checks that `issuer` may have signed `child` and that it did: the rules
/// that apply to any signer of a certificate, whatever its place on a
/// path.
///
/// A version 3 issuer has basic constraints, and an issuer with basic
/// constraints has `cA` set; a key usage extension with any bit set
/// includes certificate signing; the signature verifies. Names are not
/// compared.
pub fn check_signed_by(child: &Certificate, issuer: &Certificate) -> Result<(), X509Error> {
    check_may_sign(issuer)?;
    if issuer
        .key_usage()?
        .is_some_and(|usage| !usage.is_empty() && !usage.key_cert_sign)
    {
        return Err(X509Error::new(
            "issuer's key usage does not permit certificate signing",
        ));
    }
    child.verify_signed_by(&issuer.public_key()?)
}

/// The basic-constraints rule for a certificate whose key signs other
/// objects as an authority.
pub(super) fn check_may_sign(issuer: &Certificate) -> Result<(), X509Error> {
    let not_an_authority = || X509Error::new("issuer is not a certificate authority");
    match issuer.basic_constraints()? {
        Some(constraints) if !constraints.ca => Err(not_an_authority()),
        None if issuer.version() == 3 => Err(not_an_authority()),
        _ => Ok(()),
    }
}

/// The rules for a certificate at any place on a path: its critical
/// extensions are processed, and `at` is within its validity.
fn check_on_path(certificate: &Certificate, at: Instant) -> Result<(), X509Error> {
    let names = certificate.alternative_names()?;
    for (oid, found) in certificate.extensions() {
        if found.critical && !is_processed(oid, names.as_ref()) {
            return Err(X509Error::new(format!(
                "certificate has an unprocessed critical extension {oid}"
            )));
        }
    }
    if at < certificate.not_before() {
        return Err(X509Error::new(format!(
            "certificate is not valid until {}",
            certificate.not_before().to_rfc3339()
        )));
    }
    if at > certificate.not_after() {
        return Err(X509Error::new(format!(
            "certificate expired at {}",
            certificate.not_after().to_rfc3339()
        )));
    }
    Ok(())
}

/// The rules for a certificate that is appended to a path of `below`
/// certificates as their issuer.
fn check_issuer(
    issuer: &Certificate,
    below: usize,
    intermediate: bool,
    at: Instant,
) -> Result<(), X509Error> {
    check_on_path(issuer, at)?;
    let constraints = issuer.basic_constraints()?;
    if intermediate && !constraints.is_some_and(|constraints| constraints.ca) {
        return Err(X509Error::new(
            "intermediate certificate is not a certificate authority",
        ));
    }
    if let Some(path_len) = constraints.and_then(|constraints| constraints.path_len) {
        // The certificates between this issuer and the leaf.
        let intermediates_below = below.saturating_sub(1);
        if intermediates_below > usize::from(path_len) {
            return Err(X509Error::new(
                "certificate path exceeds a path length constraint",
            ));
        }
    }
    Ok(())
}

/// Whether every certificate of `path` permits `purpose`: it lists no
/// extended key usage, or lists the purpose or the any-purpose identifier.
fn permits(path: &[&Certificate], purpose: KeyPurpose) -> Result<bool, X509Error> {
    let Some(wanted) = purpose.oid() else {
        return Ok(true);
    };
    for certificate in path {
        let Some(purposes) = certificate.extended_key_usage()? else {
            continue;
        };
        if purposes.is_empty() {
            continue;
        }
        if !purposes.contains(&OID_ANY_PURPOSE) && !purposes.contains(&wanted) {
            return Ok(false);
        }
    }
    Ok(true)
}
