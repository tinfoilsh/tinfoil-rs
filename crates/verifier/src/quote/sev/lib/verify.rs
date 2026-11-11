//! Verification of an SEV-SNP attestation: the VCEK certificate's profile
//! and chain to the pinned AMD roots, revocation, and the report signature.

use ::der::asn1::ObjectIdentifier;

use super::abi::{ProductLine, Report};
use super::kds::Extensions;
use crate::instant::Instant;
use crate::quote::QuoteError;
use crate::stub::pending;
use crate::x509::{Certificate, Crl, NameField};

const OID_COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_LOCALITY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const OID_STATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// The common name of every VCEK certificate.
pub const VCEK_COMMON_NAME: &str = "SEV-VCEK";

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
    /// the ARK ([`parse_product_cert_chain`](super::kds::parse_product_cert_chain)),
    /// each a certificate that parses. The certificates are trusted as
    /// pinned; they are not verified against each other here.
    pub fn from_pem(product_line: ProductLine, pem: &[u8]) -> Result<Self, QuoteError> {
        pending("quote::sev::lib::verify::AmdRoots::from_pem")
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

/// What a verified attestation establishes about its certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// The VCEK certificate that signed the report.
    pub vcek: Certificate,
    /// The VCEK's AMD extensions.
    pub extensions: Extensions,
}

/// Checks that a name has AMD's fixed attributes and the given common
/// name: exactly one country `US`, one locality `Santa Clara`, one state
/// `CA`, one organization `Advanced Micro Devices`, one organizational unit
/// `Engineering`, and one common name `common_name`.
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
        (OID_COMMON_NAME, "common name", common_name),
    ];
    for (oid, label, expected) in attributes {
        let values = certificate.name_attribute(field, oid)?;
        let [value] = values.as_slice() else {
            return Err(QuoteError::new(format!(
                "certificate {role} has {} {label} attributes, want 1",
                values.len()
            )));
        };
        if value != expected {
            return Err(QuoteError::new(format!(
                "certificate {role} {label} is {value:?}, want {expected:?}"
            )));
        }
    }
    Ok(())
}

/// Verifies an attestation report against pinned AMD certificates.
///
/// The ASK and ARK of `chain` are transport only: they must be present,
/// and nothing in them is trusted or compared; the pinned `roots` decide.
/// Everything is judged at `now`. In order:
///
/// 1. the report's signer field names the VCEK as the signing key; a
///    report signed by any other key is unsupported;
/// 2. the VCEK certificate parses and has the AMD profile: X.509 version
///    3; signed with RSASSA-PSS and SHA-384; an ECDSA P-384 key; a subject
///    with AMD's fixed attributes and the common name [`VCEK_COMMON_NAME`]
///    ([`check_amd_name`]); valid AMD extensions
///    ([`vcek_extensions`](super::kds::vcek_extensions)); and the TCB
///    layout of its extensions is that of the report's product line;
/// 3. the VCEK's issuer has AMD's fixed attributes and the common name
///    `SEV-<product line>`;
/// 4. the VCEK chains to the pinned ARK through the pinned ASK at `now`
///    ([`verify_chain`](crate::x509::verify_chain), with no purpose
///    requirement);
/// 5. the revocation list is signed by the pinned ARK
///    ([`Crl::verify_issued_by`]) and does not revoke the pinned ASK. The
///    pinned ASK must name a distribution point for the list, a URL whose
///    path ends in `/crl`;
/// 6. the report's signature verifies under the VCEK's key
///    ([`verify_report_signature`](super::abi::verify_report_signature)).
pub fn verify_attestation(
    report: &Report,
    report_bytes: &[u8],
    chain: &DocumentChain<'_>,
    crl: &Crl,
    roots: &AmdRoots,
    now: Instant,
) -> Result<VerifiedAttestation, QuoteError> {
    pending("quote::sev::lib::verify::verify_attestation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::sev::lib::abi::testdata::TURIN_VCEK_DER;

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
}
