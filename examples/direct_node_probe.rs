//! Explicit, credential-free qualification of an operator-selected node.
//! Nothing runs as part of the default test suite. No router discovery.
use serde::Deserialize;
use std::path::Path;
use tinfoil::{ApprovedRelease, DirectPolicy, Measurement, PinnedRelease};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    repo: String,
    tag: String,
    digest: String,
    measurement: Measurement,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    approved: Vec<Entry>,
}

impl PolicyFile {
    fn policy(&self) -> Result<DirectPolicy, tinfoil::Error> {
        DirectPolicy::new(
            self.approved
                .iter()
                .map(|p| ApprovedRelease {
                    release: PinnedRelease {
                        repo: p.repo.clone(),
                        tag: p.tag.clone(),
                        digest: p.digest.clone(),
                    },
                    measurement: p.measurement.clone(),
                })
                .collect(),
        )
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        return Err(
            "usage: direct_node_probe offline POLICY DOCUMENT NONCE_HEX | live POLICY HOST".into(),
        );
    }
    let input: PolicyFile = serde_json::from_slice(&std::fs::read(Path::new(&args[2]))?)?;
    let policy = input.policy()?;
    if args[1] == "offline" {
        if args.len() != 5 {
            return Err("offline requires policy, captured document and original nonce".into());
        }
        let raw = std::fs::read(&args[3])?;
        let nonce = hex::decode(&args[4])?;
        let result = tinfoil::verifier::v3::verify_document(&raw, &nonce, &policy)?;
        let mut wrong_nonce = nonce.clone();
        wrong_nonce[0] ^= 1;
        let rejected_nonce =
            tinfoil::verifier::v3::verify_document(&raw, &wrong_nonce, &policy).is_err();
        let mut wrong = input.clone();
        for entry in &mut wrong.approved {
            entry.measurement.registers[0] = "0".repeat(96);
        }
        let rejected_measurement =
            tinfoil::verifier::v3::verify_document(&raw, &nonce, &wrong.policy()?).is_err();
        let mut document: serde_json::Value = serde_json::from_slice(&raw)?;
        use base64::Engine;
        let b64 = &base64::engine::general_purpose::STANDARD;
        let report = document["cpu_evidence"]["report_base64"]
            .as_str()
            .ok_or("missing CPU report")?;
        let mut report = b64.decode(report)?;
        report[0x2a0] ^= 1;
        document["cpu_evidence"]["report_base64"] = b64.encode(report).into();
        let rejected_signature = tinfoil::verifier::v3::verify_document(
            &serde_json::to_vec(&document)?,
            &nonce,
            &policy,
        )
        .is_err();
        assert!(rejected_nonce && rejected_measurement && rejected_signature);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mode":"offline", "verified":true, "ground_truth":result.ground_truth,
                "freshness_expires_unix":result.freshness_expires_at.duration_since(std::time::UNIX_EPOCH)?.as_secs(),
                "negative_checks":{"wrong_nonce":rejected_nonce,"wrong_measurement":rejected_measurement,"tampered_cpu_signature":rejected_signature}
            }))?
        );
    } else if args[1] == "live" {
        if args.len() != 4 {
            return Err("live requires policy and one explicit hostname".into());
        }
        let host = &args[3];
        let client = tinfoil::Client::new_direct(host, "", policy).await?;
        let raw = client.http_client()?;
        let mut endpoints = Vec::new();
        for path in ["/health", "/v1/models"] {
            let response = raw.get(format!("https://{host}{path}")).send().await?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("credential-free {path} returned {status}").into());
            }
            let body = response.bytes().await?;
            endpoints.push(serde_json::json!({"path":path,"status":status.as_u16(),"response_bytes":body.len()}));
        }
        let plaintext_rejected = raw
            .get(format!("http://{host}/health"))
            .send()
            .await
            .is_err();
        let alternate_port_rejected = raw
            .get(format!("https://{host}:444/health"))
            .send()
            .await
            .is_err();
        let wrong_pin_rejected = tinfoil::verifier::tls::create_pinned_client(&"0".repeat(64))?
            .get(format!("https://{host}/health"))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .is_err();
        assert!(plaintext_rejected && alternate_port_rejected && wrong_pin_rejected);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mode":"live","host":host,"credentials_used":false,"verified":client.secure_client().is_verified(),
            "ground_truth":client.secure_client().ground_truth(),"requests":endpoints,
            "freshness_expires_unix":client.freshness_expires_at().ok_or("missing direct expiry")?.duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            "negative_checks":{"plaintext_rejected_before_dispatch":plaintext_rejected,"alternate_port_rejected_before_dispatch":alternate_port_rejected,"wrong_tls_pin_rejected":wrong_pin_rejected}
            }))?
        );
    } else {
        return Err("mode must be offline or live".into());
    }
    Ok(())
}
