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
    Certificate,
    ext::pkix::{ExtendedKeyUsage, KeyUsage},
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
mod fulcio_oids {
    /// OIDC Issuer (1.3.6.1.4.1.57264.1.1)
    pub const OIDC_ISSUER: &str = "1.3.6.1.4.1.57264.1.1";
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
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse KeyUsage extension: {}", e)))?
        .ok_or_else(|| Error::SigstoreVerification("Certificate missing KeyUsage extension".into()))?;

    if !key_usage.1.digital_signature() {
        return Err(Error::SigstoreVerification(
            "Certificate KeyUsage does not include digitalSignature".into()
        ));
    }

    // Check ExtendedKeyUsage extension for codeSigning
    let ext_key_usage = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse ExtendedKeyUsage extension: {}", e)))?
        .ok_or_else(|| Error::SigstoreVerification("Certificate missing ExtendedKeyUsage extension".into()))?;

    if !ext_key_usage.1.0.contains(&ID_KP_CODE_SIGNING) {
        return Err(Error::SigstoreVerification(
            "Certificate ExtendedKeyUsage does not include codeSigning".into()
        ));
    }

    Ok(())
}

/// Decode an ASN.1 string from extension value bytes.
/// Fulcio uses UTF8String (tag 0x0C) for these extensions.
fn decode_asn1_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    // Check for UTF8String (0x0C) or IA5String (0x16) or PrintableString (0x13)
    let tag = bytes[0];
    if tag != 0x0C && tag != 0x16 && tag != 0x13 {
        return None;
    }

    // Parse length - handle both short and long form
    let length_byte = bytes[1];
    let (len, header_len) = if length_byte & 0x80 == 0 {
        // Short form: length < 128, single byte
        (length_byte as usize, 2)
    } else {
        // Long form: first byte indicates number of length bytes
        let num_length_bytes = (length_byte & 0x7F) as usize;
        if num_length_bytes == 0 || num_length_bytes > 4 || bytes.len() < 2 + num_length_bytes {
            return None;
        }

        let mut len: usize = 0;
        for i in 0..num_length_bytes {
            len = (len << 8) | (bytes[2 + i] as usize);
        }
        (len, 2 + num_length_bytes)
    };

    let total_len = header_len.checked_add(len)?;
    if bytes.len() < total_len {
        return None;
    }

    String::from_utf8(bytes[header_len..total_len].to_vec()).ok()
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

            // Decode as ASN.1 string, fall back to raw UTF-8 if that fails
            let value = decode_asn1_string(raw_bytes)
                .unwrap_or_else(|| String::from_utf8_lossy(raw_bytes).to_string());

            match oid_str.as_str() {
                fulcio_oids::OIDC_ISSUER => {
                    issuer = value;
                }
                fulcio_oids::BUILD_SIGNER_URI => {
                    subject_workflow = value;
                }
                fulcio_oids::SOURCE_REPOSITORY_URI => {
                    repository = value;
                }
                _ => {}
            }
        }
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
    fn test_decode_asn1_string_invalid_tag() {
        // Invalid tag
        let bytes = [0x30, 0x04, b't', b'e', b's', b't'];
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

        // Should extract certificate info
        let info = extract_certificate_info(&cert).unwrap();
        assert!(info.issuer.contains("github.com"));
    }
}
