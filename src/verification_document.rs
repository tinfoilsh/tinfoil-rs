//! Verification Center-compatible verification document types.

use serde::{Deserialize, Serialize};

use crate::verifier::{GroundTruth, Measurement, SoftwareIdentity};

pub const VERIFICATION_DOCUMENT_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationStepState {
    pub status: VerificationStepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStepStatus {
    Pending,
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationSteps {
    pub fetch_digest: VerificationStepState,
    pub verify_code: VerificationStepState,
    pub verify_enclave: VerificationStepState,
    pub compare_measurements: VerificationStepState,
    pub verify_certificate: VerificationStepState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentEnclaveMeasurement {
    pub measurement: Measurement,
    pub tls_public_key_fingerprint: String,
    pub hpke_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationDocument {
    pub schema_version: u8,
    pub config_repo: String,
    pub enclave_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_tag: Option<String>,
    pub release_digest: String,
    pub code_measurement: Measurement,
    pub enclave_measurement: DocumentEnclaveMeasurement,
    pub tls_public_key: String,
    pub hpke_public_key: String,
    pub code_fingerprint: String,
    pub enclave_fingerprint: String,
    pub selected_router_endpoint: String,
    pub security_verified: bool,
    pub verifier: SoftwareIdentity,
    pub verified_at: String,
    pub steps: VerificationSteps,
}

impl VerificationDocument {
    pub(crate) fn from_ground_truth(
        ground_truth: GroundTruth,
        enclave_host: String,
        tls_public_key: String,
        hpke_public_key: String,
    ) -> Self {
        let pinned = ground_truth.digest == crate::constants::PINNED_NO_DIGEST;
        let successful = VerificationStepState {
            status: VerificationStepStatus::Success,
            error: None,
        };
        let skipped = VerificationStepState {
            status: VerificationStepStatus::Skipped,
            error: None,
        };

        Self {
            schema_version: VERIFICATION_DOCUMENT_SCHEMA_VERSION,
            config_repo: ground_truth.config_repo,
            enclave_host: enclave_host.clone(),
            release_tag: ground_truth.release_tag,
            release_digest: ground_truth.digest,
            code_measurement: ground_truth.code_measurement,
            enclave_measurement: DocumentEnclaveMeasurement {
                measurement: ground_truth.enclave_measurement,
                tls_public_key_fingerprint: tls_public_key.clone(),
                hpke_public_key: hpke_public_key.clone(),
            },
            tls_public_key,
            hpke_public_key,
            code_fingerprint: ground_truth.code_fingerprint,
            enclave_fingerprint: ground_truth.enclave_fingerprint,
            selected_router_endpoint: enclave_host,
            security_verified: true,
            verifier: ground_truth.verifier,
            verified_at: ground_truth.verified_at,
            steps: VerificationSteps {
                fetch_digest: if pinned {
                    skipped.clone()
                } else {
                    successful.clone()
                },
                verify_code: if pinned { skipped } else { successful.clone() },
                verify_enclave: successful.clone(),
                compare_measurements: successful.clone(),
                verify_certificate: successful,
            },
        }
    }
}
