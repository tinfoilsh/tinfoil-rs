// Adapted from sigstore-rs (Apache 2.0 License)
// https://github.com/sigstore/sigstore-rs/blob/main/src/crypto/certificate.rs
//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Certificate validation for Sigstore/Fulcio certificates.
//!
//! Adapted from sigstore-rs to use typed extension parsing via x509-cert
//! instead of manual byte manipulation.

use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;
use x509_cert::{
    ext::pkix::{ExtendedKeyUsage, KeyUsage},
    Certificate,
};

use crate::error::{Error, Result};

/// Verification certificate info extracted from bundle
#[derive(Debug)]
pub struct CertificateInfo {
    pub issuer: String,
    pub subject_workflow: String,
    pub repository: String,
}

/// Fulcio OIDC extension OIDs
/// See: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
mod fulcio_oids {
    /// OIDC Issuer V1 (1.3.6.1.4.1.57264.1.1)
    pub const OIDC_ISSUER_V1: &str = "1.3.6.1.4.1.57264.1.1";
    /// OIDC Issuer V2 (1.3.6.1.4.1.57264.1.8)
    pub const OIDC_ISSUER_V2: &str = "1.3.6.1.4.1.57264.1.8";
    /// GitHub Workflow Repository V1 (1.3.6.1.4.1.57264.1.5)
    pub const GITHUB_WORKFLOW_REPOSITORY: &str = "1.3.6.1.4.1.57264.1.5";
    /// Build Signer URI (1.3.6.1.4.1.57264.1.9)
    pub const BUILD_SIGNER_URI: &str = "1.3.6.1.4.1.57264.1.9";
    /// Source Repository URI (1.3.6.1.4.1.57264.1.12)
    pub const SOURCE_REPOSITORY_URI: &str = "1.3.6.1.4.1.57264.1.12";
}

/// Validate certificate extensions for Fulcio code signing requirements.
///
/// Per Sigstore specification, a valid Fulcio certificate must have:
/// 1. KeyUsage extension with digitalSignature bit set
/// 2. ExtendedKeyUsage extension containing codeSigning OID (1.3.6.1.5.5.7.3.3)
///
/// This implementation uses typed extension parsing from x509-cert,
/// following sigstore-rs's approach.
pub fn validate_certificate_extensions(cert: &Certificate) -> Result<()> {
    let tbs = &cert.tbs_certificate;

    // Check KeyUsage extension for digitalSignature
    let key_usage = tbs
        .get::<KeyUsage>()
        .map_err(|e| {
            Error::SigstoreVerification(format!("Failed to parse KeyUsage extension: {}", e))
        })?
        .ok_or_else(|| {
            Error::SigstoreVerification("Certificate missing KeyUsage extension".into())
        })?;

    if !key_usage.1.digital_signature() {
        return Err(Error::SigstoreVerification(
            "Certificate KeyUsage does not include digitalSignature".into(),
        ));
    }

    // Check ExtendedKeyUsage extension for codeSigning
    let ext_key_usage = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|e| {
            Error::SigstoreVerification(format!(
                "Failed to parse ExtendedKeyUsage extension: {}",
                e
            ))
        })?
        .ok_or_else(|| {
            Error::SigstoreVerification("Certificate missing ExtendedKeyUsage extension".into())
        })?;

    if !ext_key_usage.1 .0.contains(&ID_KP_CODE_SIGNING) {
        return Err(Error::SigstoreVerification(
            "Certificate ExtendedKeyUsage does not include codeSigning".into(),
        ));
    }

    Ok(())
}

/// Decode an ASN.1 string from extension value bytes.
/// Fulcio uses UTF8String (tag 0x0C) for these extensions, but IA5String
/// and PrintableString are also accepted.
fn decode_asn1_string(bytes: &[u8]) -> Option<String> {
    use der::Decode;
    // Try UTF8String first (most common for Fulcio V2 extensions)
    if let Ok(s) = der::asn1::Utf8StringRef::from_der(bytes) {
        return Some(s.to_string());
    }
    // IA5String (used by some V1 extensions)
    if let Ok(s) = der::asn1::Ia5StringRef::from_der(bytes) {
        return Some(s.to_string());
    }
    // PrintableString (fallback)
    if let Ok(s) = der::asn1::PrintableStringRef::from_der(bytes) {
        return Some(s.to_string());
    }
    // Fallback: older Fulcio V1 certificates stored the OIDC issuer as raw
    // UTF-8 bytes without an ASN.1 tag wrapper.
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

/// Extract certificate info (OIDC issuer, workflow, repository) from a Fulcio certificate.
pub fn extract_certificate_info(cert: &Certificate) -> Result<CertificateInfo> {
    let mut issuer = String::new();
    let mut repository = String::new();
    let mut subject_workflow = String::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            let oid_str = ext.extn_id.to_string();
            let raw_bytes = ext.extn_value.as_bytes();

            let Some(value) = decode_asn1_string(raw_bytes) else {
                continue;
            };

            match oid_str.as_str() {
                fulcio_oids::OIDC_ISSUER_V2 => {
                    // V2 takes priority over V1
                    issuer = value;
                }
                fulcio_oids::OIDC_ISSUER_V1 if issuer.is_empty() => {
                    // V1 is used only if V2 was not found
                    issuer = value;
                }
                fulcio_oids::BUILD_SIGNER_URI => {
                    subject_workflow = value;
                }
                fulcio_oids::GITHUB_WORKFLOW_REPOSITORY => {
                    repository = value;
                }
                fulcio_oids::SOURCE_REPOSITORY_URI if repository.is_empty() => {
                    // V2 fallback: extract repo name from URI
                    // SOURCE_REPOSITORY_URI is "https://github.com/owner/repo"
                    // GITHUB_WORKFLOW_REPOSITORY (V1) is "owner/repo"
                    repository = value
                        .strip_prefix("https://github.com/")
                        .unwrap_or(&value)
                        .to_string();
                }
                _ => {}
            }
        }
    }

    if issuer.is_empty() {
        return Err(Error::SigstoreVerification(
            "Certificate missing required OIDC issuer extension".into(),
        ));
    }
    if repository.is_empty() {
        return Err(Error::SigstoreVerification(
            "Certificate missing required repository extension".into(),
        ));
    }
    if subject_workflow.is_empty() {
        return Err(Error::SigstoreVerification(
            "Certificate missing required workflow extension".into(),
        ));
    }

    Ok(CertificateInfo {
        issuer,
        subject_workflow,
        repository,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    #[test]
    fn test_decode_asn1_string_utf8() {
        // UTF8String with "test"
        let bytes = [0x0C, 0x04, b't', b'e', b's', b't'];
        assert_eq!(decode_asn1_string(&bytes), Some("test".to_string()));
    }

    #[test]
    fn test_decode_asn1_string_ia5() {
        // IA5String with "test"
        let bytes = [0x16, 0x04, b't', b'e', b's', b't'];
        assert_eq!(decode_asn1_string(&bytes), Some("test".to_string()));
    }

    #[test]
    fn test_decode_asn1_string_raw_utf8_fallback() {
        // Raw UTF-8 bytes without ASN.1 tag (as used by older Fulcio V1 certs)
        let url = b"https://github.com/login/oauth";
        assert_eq!(
            decode_asn1_string(url),
            Some("https://github.com/login/oauth".to_string())
        );
    }

    #[test]
    fn test_decode_asn1_string_invalid_utf8() {
        // Invalid UTF-8 bytes
        let bytes = [0xFF, 0xFE, 0x00, 0x01];
        assert_eq!(decode_asn1_string(&bytes), None);
    }

    #[test]
    fn test_validate_fulcio_certificate() {
        // Real Fulcio certificate from sigstore test data
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICzDCCAlGgAwIBAgIUF96OLbM9/tDVHKCJliXLTFvnfjAwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMxMjEzMDU1MDU1WhcNMjMxMjEzMDYwMDU1WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEmir+Lah2291zCsLkmREQNLzf99z571BNB+fa
rerSLGzcwLFK7GRLTGYcO0oStxCYavxRQPMo3JvB8vGtZbn/76OCAXAwggFsMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU8U9M
t9GMrRm8+gifPtc63nlP3OIwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wGwYDVR0RAQH/BBEwD4ENYXNjQHRldHN1by5zaDAsBgorBgEEAYO/MAEBBB5o
dHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwLgYKKwYBBAGDvzABCAQgDB5o
dHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwgYkGCisGAQQB1nkCBAIEewR5
AHcAdQDdPTBqxscRMmMZHhyZZzcCokpeuN48rf+HinKALynujgAAAYxhumYsAAAE
AwBGMEQCIHRRe20lRrNM4xd07mpjTtgaE6FGS3jjF++zW8ZMnth3AiAd6LVAAeVW
hSW4T0XJRw9lGU6/EK9+ELZpEjrY03dJ1zAKBggqhkjOPQQDAwNpADBmAjEAiHqK
W9PQ/5h7VROVIWPaxUo3LhrL2sZanw4bzTDBDY0dRR19ZFzjtAph1RzpQqppAjEA
plAvxwkAIR2jurboJZ4Zm9rNAx8KvA+A5yQFzNkGgKDLjTJrKmSKoIcWV3j7WfdL
-----END CERTIFICATE-----"#;

        // Parse PEM to DER
        let pem = pem::parse(cert_pem).unwrap();
        let cert = Certificate::from_der(pem.contents()).unwrap();

        // Should pass validation
        assert!(validate_certificate_extensions(&cert).is_ok());

        // This test cert has an OIDC issuer but lacks the GitHub-specific
        // repository and workflow extensions, so extraction should fail.
        let err = extract_certificate_info(&cert).unwrap_err();
        assert!(
            err.to_string().contains("missing required"),
            "Expected missing-field error, got: {}",
            err
        );
    }

    fn parse_test_cert() -> Certificate {
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICzDCCAlGgAwIBAgIUF96OLbM9/tDVHKCJliXLTFvnfjAwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMxMjEzMDU1MDU1WhcNMjMxMjEzMDYwMDU1WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEmir+Lah2291zCsLkmREQNLzf99z571BNB+fa
rerSLGzcwLFK7GRLTGYcO0oStxCYavxRQPMo3JvB8vGtZbn/76OCAXAwggFsMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU8U9M
t9GMrRm8+gifPtc63nlP3OIwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wGwYDVR0RAQH/BBEwD4ENYXNjQHRldHN1by5zaDAsBgorBgEEAYO/MAEBBB5o
dHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwLgYKKwYBBAGDvzABCAQgDB5o
dHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwgYkGCisGAQQB1nkCBAIEewR5
AHcAdQDdPTBqxscRMmMZHhyZZzcCokpeuN48rf+HinKALynujgAAAYxhumYsAAAE
AwBGMEQCIHRRe20lRrNM4xd07mpjTtgaE6FGS3jjF++zW8ZMnth3AiAd6LVAAeVW
hSW4T0XJRw9lGU6/EK9+ELZpEjrY03dJ1zAKBggqhkjOPQQDAwNpADBmAjEAiHqK
W9PQ/5h7VROVIWPaxUo3LhrL2sZanw4bzTDBDY0dRR19ZFzjtAph1RzpQqppAjEA
plAvxwkAIR2jurboJZ4Zm9rNAx8KvA+A5yQFzNkGgKDLjTJrKmSKoIcWV3j7WfdL
-----END CERTIFICATE-----"#;
        let pem = pem::parse(cert_pem).unwrap();
        Certificate::from_der(pem.contents()).unwrap()
    }

    /// OID for KeyUsage: 2.5.29.15
    const KEY_USAGE_OID: &str = "2.5.29.15";
    /// OID for ExtendedKeyUsage: 2.5.29.37
    const EXT_KEY_USAGE_OID: &str = "2.5.29.37";

    fn cert_without_extension(oid_to_remove: &str) -> Certificate {
        let cert = parse_test_cert();
        let mut tbs = cert.tbs_certificate.clone();
        tbs.extensions = tbs.extensions.map(|exts| {
            exts.iter()
                .filter(|ext| ext.extn_id.to_string() != oid_to_remove)
                .cloned()
                .collect()
        });
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: cert.signature_algorithm.clone(),
            signature: cert.signature.clone(),
        }
    }

    #[test]
    fn test_validate_missing_key_usage() {
        let cert = cert_without_extension(KEY_USAGE_OID);
        let err = validate_certificate_extensions(&cert).unwrap_err();
        assert!(
            err.to_string().contains("KeyUsage"),
            "Expected KeyUsage error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_missing_ext_key_usage() {
        let cert = cert_without_extension(EXT_KEY_USAGE_OID);
        let err = validate_certificate_extensions(&cert).unwrap_err();
        assert!(
            err.to_string().contains("ExtendedKeyUsage"),
            "Expected ExtendedKeyUsage error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_no_digital_signature() {
        use der::Encode;

        let cert = parse_test_cert();
        let mut tbs = cert.tbs_certificate.clone();

        // Replace KeyUsage extension with one that has no digitalSignature bit
        // KeyUsage is a BIT STRING; 0x00 = no bits set
        let ku_oid: der::asn1::ObjectIdentifier = KEY_USAGE_OID.parse().unwrap();
        let empty_ku_value = der::asn1::BitString::from_bytes(&[0x00]).unwrap();
        let empty_ku_der = empty_ku_value.to_der().unwrap();

        tbs.extensions = tbs.extensions.map(|exts| {
            exts.iter()
                .map(|ext| {
                    if ext.extn_id == ku_oid {
                        x509_cert::ext::Extension {
                            extn_id: ext.extn_id.clone(),
                            critical: ext.critical,
                            extn_value: der::asn1::OctetString::new(empty_ku_der.clone()).unwrap(),
                        }
                    } else {
                        ext.clone()
                    }
                })
                .collect()
        });

        let modified = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: cert.signature_algorithm.clone(),
            signature: cert.signature.clone(),
        };

        let err = validate_certificate_extensions(&modified).unwrap_err();
        assert!(
            err.to_string().contains("digitalSignature"),
            "Expected digitalSignature error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_no_code_signing() {
        use der::Encode;

        let cert = parse_test_cert();
        let mut tbs = cert.tbs_certificate.clone();

        // Replace ExtendedKeyUsage with one that only has serverAuth (not codeSigning)
        let eku_oid: der::asn1::ObjectIdentifier = EXT_KEY_USAGE_OID.parse().unwrap();
        let server_auth_oid: der::asn1::ObjectIdentifier = "1.3.6.1.5.5.7.3.1".parse().unwrap();
        let eku = ExtendedKeyUsage(vec![server_auth_oid]);
        let eku_der = eku.to_der().unwrap();

        tbs.extensions = tbs.extensions.map(|exts| {
            exts.iter()
                .map(|ext| {
                    if ext.extn_id == eku_oid {
                        x509_cert::ext::Extension {
                            extn_id: ext.extn_id.clone(),
                            critical: ext.critical,
                            extn_value: der::asn1::OctetString::new(eku_der.clone()).unwrap(),
                        }
                    } else {
                        ext.clone()
                    }
                })
                .collect()
        });

        let modified = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: cert.signature_algorithm.clone(),
            signature: cert.signature.clone(),
        };

        let err = validate_certificate_extensions(&modified).unwrap_err();
        assert!(
            err.to_string().contains("codeSigning"),
            "Expected codeSigning error, got: {}",
            err
        );
    }
}
