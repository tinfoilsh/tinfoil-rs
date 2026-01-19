//! Debug TLS fingerprint computation

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use der::Encode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = "inference.tinfoil.sh";
    
    // Connect
    let addr = format!("{}:443", host);
    let stream = TcpStream::connect(&addr).await?;
    
    // TLS
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name: ServerName<'_> = host.to_string().try_into()?;
    
    let tls_stream = connector.connect(server_name, stream).await?;
    
    // Get cert
    let (_, conn) = tls_stream.get_ref();
    let certs = conn.peer_certificates().unwrap();
    
    println!("Cert count: {}", certs.len());
    
    // Compute fingerprint using our function
    let fp = tinfoil::verifier::tls::cert_pubkey_fingerprint(&certs[0])?;
    println!("Our fingerprint:      {}", fp);
    
    // Also compute using raw bytes
    use sha2::{Sha256, Digest};
    use x509_cert::Certificate;
    use der::Decode;
    
    let cert = Certificate::from_der(certs[0].as_ref())?;
    
    // Raw public key bytes
    let pubkey_bytes = cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let hash = Sha256::digest(pubkey_bytes);
    println!("Raw pubkey hash:      {}", hex::encode(hash));
    
    // Try hashing the full SPKI 
    let spki_bytes = cert.tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let hash2 = Sha256::digest(&spki_bytes);
    println!("SPKI DER hash:        {}", hex::encode(hash2));
    
    // Expected from attestation
    println!("Expected (attestation): 2b70a37cba08a1b15fddb7ba71dec4cb0970a94e584096992661d1e5af1b22cc");
    
    Ok(())
}
