//! What the tests of the transport modes share when they need a local TLS
//! server: certificates made when the tests run, and a server that speaks
//! HTTP/2 and HTTP/1.1 and records what it saw.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{HandshakeKind, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

use crate::internal::BoxFuture;

/// The certificates of these tests, made when the tests run: a
/// certificate authority that only these tests trust, two server keys, and
/// server certificates for them. The keys are fixed numbers, good for
/// nothing but telling two keys apart.
pub(crate) mod made {
    use std::str::FromStr;
    use std::sync::LazyLock;

    use der::asn1::{BitString, GeneralizedTime, Ia5String, OctetString, UtcTime};
    use der::oid::{AssociatedOid, ObjectIdentifier};
    use der::{Decode, Encode};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{BasicConstraints, SubjectAltName};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, TbsCertificate, Version};

    const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    /// Seconds since the Unix epoch.
    const YEAR_2020: u64 = 1_577_836_800;
    const YEAR_2100: u64 = 4_102_444_800;
    const DAY: u64 = 86_400;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn time(unix: u64) -> Time {
        let since_epoch = std::time::Duration::from_secs(unix);
        // Dates from 2050 on must use the long form.
        match UtcTime::from_unix_duration(since_epoch) {
            Ok(utc) => Time::UtcTime(utc),
            Err(_) => Time::GeneralTime(GeneralizedTime::from_unix_duration(since_epoch).unwrap()),
        }
    }

    fn extension<T: AssociatedOid + Encode>(critical: bool, value: &T) -> Extension {
        Extension {
            extn_id: T::OID,
            critical,
            extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
        }
    }

    /// A certificate for `subject_key`, signed by `issuer_key`.
    fn certificate(
        subject: &str,
        subject_key: &SigningKey,
        issuer: &str,
        issuer_key: &SigningKey,
        (not_before, not_after): (u64, u64),
        extensions: Vec<Extension>,
    ) -> Vec<u8> {
        let algorithm = AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        };
        let public_key = subject_key.verifying_key().to_public_key_der().unwrap();
        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::from(7u32),
            signature: algorithm.clone(),
            issuer: Name::from_str(issuer).unwrap(),
            validity: Validity {
                not_before: time(not_before),
                not_after: time(not_after),
            },
            subject: Name::from_str(subject).unwrap(),
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(public_key.as_bytes())
                .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let signature: DerSignature = issuer_key.sign(&tbs_certificate.to_der().unwrap());
        Certificate {
            tbs_certificate,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(signature.as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    fn authority(name: &str, key: &SigningKey) -> Vec<u8> {
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        certificate(
            name,
            key,
            name,
            key,
            (YEAR_2020, YEAR_2100),
            vec![extension(true, &constraints)],
        )
    }

    fn leaf(
        key: &SigningKey,
        issuer: &str,
        issuer_key: &SigningKey,
        names: Vec<GeneralName>,
        validity: (u64, u64),
    ) -> Vec<u8> {
        let constraints = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        };
        certificate(
            "CN=test server",
            key,
            issuer,
            issuer_key,
            validity,
            vec![
                extension(true, &constraints),
                extension(false, &SubjectAltName(names)),
            ],
        )
    }

    /// The names of the local server: its address, `localhost`, and the
    /// name that the tests reach it by through a proxy.
    fn local() -> Vec<GeneralName> {
        vec![
            GeneralName::IpAddress(OctetString::new([127, 0, 0, 1]).unwrap()),
            GeneralName::DnsName(Ia5String::new("localhost").unwrap()),
            GeneralName::DnsName(Ia5String::new("enclave.test").unwrap()),
        ]
    }

    const TRUSTED: &str = "CN=Test CA";
    const UNTRUSTED: &str = "CN=Another Test CA";
    static TRUSTED_KEY: LazyLock<SigningKey> = LazyLock::new(|| key(1));
    static UNTRUSTED_KEY: LazyLock<SigningKey> = LazyLock::new(|| key(2));
    static SERVER_KEY_A: LazyLock<SigningKey> = LazyLock::new(|| key(3));
    static SERVER_KEY_B: LazyLock<SigningKey> = LazyLock::new(|| key(4));
    const LONG: (u64, u64) = (YEAR_2020, YEAR_2100);

    /// The authority that the tests trust.
    pub(crate) static CA: LazyLock<Vec<u8>> = LazyLock::new(|| authority(TRUSTED, &TRUSTED_KEY));
    /// Key A, in the form that a TLS server loads.
    pub(crate) static KEY_A: LazyLock<Vec<u8>> =
        LazyLock::new(|| SERVER_KEY_A.to_pkcs8_der().unwrap().as_bytes().to_vec());
    /// Key B, in the form that a TLS server loads.
    pub(crate) static KEY_B: LazyLock<Vec<u8>> =
        LazyLock::new(|| SERVER_KEY_B.to_pkcs8_der().unwrap().as_bytes().to_vec());
    /// Key A, for 127.0.0.1, under the trusted authority.
    pub(crate) static LEAF_A: LazyLock<Vec<u8>> =
        LazyLock::new(|| leaf(&SERVER_KEY_A, TRUSTED, &TRUSTED_KEY, local(), LONG));
    /// Key B, for 127.0.0.1, under the trusted authority.
    pub(crate) static LEAF_B: LazyLock<Vec<u8>> =
        LazyLock::new(|| leaf(&SERVER_KEY_B, TRUSTED, &TRUSTED_KEY, local(), LONG));
    /// Key A, for 127.0.0.1, under an authority that nothing trusts.
    pub(crate) static LEAF_A_OTHER_CA: LazyLock<Vec<u8>> =
        LazyLock::new(|| leaf(&SERVER_KEY_A, UNTRUSTED, &UNTRUSTED_KEY, local(), LONG));
    /// Key A, under the trusted authority, for another name.
    pub(crate) static LEAF_A_WRONG_NAME: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let other = GeneralName::DnsName(Ia5String::new("other.example").unwrap());
        leaf(&SERVER_KEY_A, TRUSTED, &TRUSTED_KEY, vec![other], LONG)
    });
    /// Key A, for 127.0.0.1, under the trusted authority, expired in 2020.
    pub(crate) static LEAF_A_EXPIRED: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let one_day = (YEAR_2020, YEAR_2020 + DAY);
        leaf(&SERVER_KEY_A, TRUSTED, &TRUSTED_KEY, local(), one_day)
    });
}

/// A certificate from its DER bytes.
pub(crate) fn certificate(der: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(der.to_vec())
}

/// Root certificates that hold only the tests' own authority.
pub(crate) fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate(&made::CA)).unwrap();
    roots
}

/// The body of a response from the local server.
pub(crate) type Body = BoxBody<Bytes, Infallible>;

/// A body that holds `bytes`.
pub(crate) fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).boxed()
}

/// One request as the local server received it, with its body read to
/// the end.
#[derive(Clone, Debug)]
pub(crate) struct Seen {
    /// The number of the connection that carried it, from zero.
    pub(crate) connection: usize,
    pub(crate) method: String,
    /// The path, with the query if there is one.
    pub(crate) target: String,
    pub(crate) version: http::Version,
    /// The host that the client asked for: the `:authority` of an HTTP/2
    /// request, the `Host` header of an HTTP/1.1 request.
    pub(crate) authority: Option<String>,
    pub(crate) headers: http::HeaderMap,
    pub(crate) body: Bytes,
}

/// What the local server does with a request.
pub(crate) type Handler =
    Arc<dyn Fn(Seen) -> BoxFuture<hyper::Response<Body>> + Send + Sync + 'static>;

/// The protocols that the local server accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Protocols {
    /// HTTP/2 and HTTP/1.1, HTTP/2 preferred.
    Both,
    /// HTTP/1.1 only.
    Http1Only,
}

/// A local TLS server and what it saw.
#[derive(Default)]
pub(crate) struct Server {
    pub(crate) port: u16,
    /// TCP connections accepted.
    accepted: AtomicUsize,
    /// The protocols that each client offered, one entry for each
    /// connection that got as far as a TLS hello.
    offered: Mutex<Vec<Vec<String>>>,
    /// The kind of each completed handshake and the protocol that it
    /// settled on.
    handshakes: Mutex<Vec<(Option<HandshakeKind>, Option<String>)>>,
    seen: Mutex<Vec<Seen>>,
    /// Connections that have ended.
    closed: AtomicUsize,
}

impl Server {
    pub(crate) fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
    pub(crate) fn closed(&self) -> usize {
        self.closed.load(Ordering::SeqCst)
    }
    pub(crate) fn offered(&self) -> Vec<Vec<String>> {
        self.offered.lock().unwrap().clone()
    }
    pub(crate) fn handshakes(&self) -> Vec<(Option<HandshakeKind>, Option<String>)> {
        self.handshakes.lock().unwrap().clone()
    }
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    /// The method and target of each request received.
    pub(crate) fn requests(&self) -> Vec<String> {
        self.seen()
            .iter()
            .map(|seen| format!("{} {}", seen.method, seen.target))
            .collect()
    }
}

/// A server that presents `leaf` with `key`, accepts `protocols`, and
/// answers each request with what `handler` returns for it.
pub(crate) async fn serve(
    leaf: &[u8],
    key: &[u8],
    protocols: Protocols,
    handler: Handler,
) -> Arc<Server> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate(leaf)],
            PrivateKeyDer::Pkcs8(key.to_vec().into()),
        )
        .unwrap();
    config.alpn_protocols = match protocols {
        Protocols::Both => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        Protocols::Http1Only => vec![b"http/1.1".to_vec()],
    };
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Arc::new(Server {
        port: listener.local_addr().unwrap().port(),
        ..Server::default()
    });
    let state = Arc::clone(&server);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let connection = state.accepted.fetch_add(1, Ordering::SeqCst);
            let (state, config, handler) = (
                Arc::clone(&state),
                Arc::clone(&config),
                Arc::clone(&handler),
            );
            tokio::spawn(async move {
                let acceptor = LazyConfigAcceptor::new(Default::default(), socket);
                let Ok(start) = acceptor.await else {
                    return;
                };
                let offered = start
                    .client_hello()
                    .alpn()
                    .map(|names| {
                        names
                            .map(|name| String::from_utf8_lossy(name).into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                state.offered.lock().unwrap().push(offered);
                let Ok(stream) = start.into_stream(config).await else {
                    return;
                };
                let session = stream.get_ref().1;
                state.handshakes.lock().unwrap().push((
                    session.handshake_kind(),
                    session
                        .alpn_protocol()
                        .map(|name| String::from_utf8_lossy(name).into_owned()),
                ));
                let service = {
                    let state = Arc::clone(&state);
                    service_fn(move |request: hyper::Request<Incoming>| {
                        let (state, handler) = (Arc::clone(&state), Arc::clone(&handler));
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body
                                .collect()
                                .await
                                .map(|collected| collected.to_bytes())
                                .unwrap_or_default();
                            let authority = parts
                                .uri
                                .authority()
                                .map(|authority| authority.to_string())
                                .or_else(|| {
                                    let host = parts.headers.get(http::header::HOST)?;
                                    Some(host.to_str().ok()?.to_owned())
                                });
                            let seen = Seen {
                                connection,
                                method: parts.method.to_string(),
                                target: parts
                                    .uri
                                    .path_and_query()
                                    .map(|target| target.to_string())
                                    .unwrap_or_default(),
                                version: parts.version,
                                authority,
                                headers: parts.headers,
                                body,
                            };
                            state.seen.lock().unwrap().push(seen.clone());
                            Ok::<_, Infallible>(handler(seen).await)
                        }
                    })
                };
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                state.closed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    server
}
