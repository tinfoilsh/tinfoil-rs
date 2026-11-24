//! Tests of the fetcher options and the relays.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::internal::{router as discovery, system_clock};
use crate::{EnclaveHttpClient, RouterHttpClient, Transport, Trust};

/// Runs a test under paused time with a limit, so that a test that can
/// make no progress fails instead of hanging.
async fn unstuck<T>(test: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(1_000 * 86_400), test)
        .await
        .expect("the test can make no progress")
}

/// A nonce drawn at random, as a client draws each one.
fn nonce() -> [u8; NONCE_SIZE] {
    crate::verifier::random_nonce().unwrap()
}

#[test]
fn a_relay_url_joins_the_request_path_under_its_own_path() {
    let nonce = nonce();
    let cases = [
        (
            "https://app.example/tinfoil",
            "https://app.example/tinfoil/",
        ),
        (
            "https://app.example/tinfoil/",
            "https://app.example/tinfoil/",
        ),
        ("https://app.example", "https://app.example/"),
        ("https://app.example/", "https://app.example/"),
        (
            "https://app.example:8443/a/b",
            "https://app.example:8443/a/b/",
        ),
        (
            "http://localhost:8080/tinfoil",
            "http://localhost:8080/tinfoil/",
        ),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
        ("http://[::1]:8080/r", "http://[::1]:8080/r/"),
    ];
    for (relay, root) in cases {
        let attestation = AttestationRelay::new(relay).unwrap();
        let url = attestation
            .document_url("enclave.example.com", &nonce)
            .unwrap();
        assert_eq!(
            url.as_str(),
            format!(
                "{root}.well-known/tinfoil-attestation?nonce={}&enclave=enclave.example.com",
                fetch::lower_hex(&nonce)
            )
        );
        let list = RouterListRelay::new(relay).unwrap();
        assert_eq!(list.list_url().as_str(), format!("{root}routers"));
    }
}

#[test]
fn the_enclave_host_is_encoded_as_a_query_value_with_its_port() {
    let nonce = nonce();
    let relay = AttestationRelay::new("https://app.example/tinfoil").unwrap();
    let url = relay.document_url("enclave.example:8443", &nonce).unwrap();
    assert_eq!(
        url.query(),
        Some(
            format!(
                "nonce={}&enclave=enclave.example%3A8443",
                fetch::lower_hex(&nonce)
            )
            .as_str()
        )
    );
    let url = relay.document_url("[::1]:8443", &nonce).unwrap();
    assert!(
        url.as_str().ends_with("&enclave=%5B%3A%3A1%5D%3A8443"),
        "{url}"
    );
    // A host that is no host is refused before anything is sent.
    for host in ["", "https://enclave.example", "enclave.example/x", "a&b=c"] {
        let error = relay.document_url(host, &nonce).expect_err(host);
        assert_eq!(error.kind(), ErrorKind::Configuration, "{host:?}");
    }
}

#[test]
fn a_relay_url_that_breaks_the_proxy_url_rules_is_refused() {
    let refused = [
        ("", "empty"),
        ("app.example/tinfoil", "absolute URL"),
        ("/tinfoil", "absolute URL"),
        ("ftp://app.example/", "absolute URL"),
        ("wss://app.example/", "absolute URL"),
        ("http://app.example/tinfoil", "HTTP is allowed only"),
        ("https://user@app.example/", "user name"),
        ("https://user:hunter2@app.example/", "user name"),
        ("https://app.example/?", "query string or a fragment"),
        ("https://app.example/?x=1", "query string or a fragment"),
        ("https://app.example/#", "query string or a fragment"),
        ("https://app.example/#top", "query string or a fragment"),
    ];
    for (url, reason) in refused {
        for (error, name) in [
            (
                AttestationRelay::new(url).expect_err(url),
                "attestation relay URL",
            ),
            (
                RouterListRelay::new(url).expect_err(url),
                "router list relay URL",
            ),
        ] {
            assert_eq!(error.kind(), ErrorKind::Configuration, "{url:?}");
            let message = error.to_string();
            assert!(message.contains(name), "{message}");
            assert!(message.contains(reason), "{url:?}: {message}");
            assert!(!message.contains("hunter2"), "{message}");
        }
    }
    AttestationRelay::new("http://localhost:8080/tinfoil").unwrap();
    RouterListRelay::new("http://localhost:8080/tinfoil").unwrap();
}

#[test]
fn a_fetchers_error_is_a_network_error_unless_it_is_this_crates() {
    let plain = from_fetcher("the relay is down".into());
    assert_eq!(plain.kind(), ErrorKind::Network);
    let source = std::error::Error::source(&plain).expect("the fetcher's error");
    assert_eq!(source.to_string(), "the relay is down");

    for error in [
        Error::configuration("misconfigured"),
        Error::attestation("rejected"),
        Error::network("down"),
    ] {
        let kept = from_fetcher(Box::new(error.clone()));
        assert_eq!(kept.kind(), error.kind());
        assert_eq!(kept.to_string(), error.to_string());
    }
}

#[tokio::test(start_paused = true)]
async fn a_fetcher_that_does_not_answer_is_dropped_after_the_bound_of_a_direct_fetch() {
    unstuck(async {
        let fetcher = |_: String, _: [u8; NONCE_SIZE]| std::future::pending();
        let fetch = attestation_fetch(Some(Arc::new(fetcher)));
        let nonce = nonce();
        let started = tokio::time::Instant::now();
        let error = fetch("enclave.example".into(), nonce)
            .await
            .expect_err("no document");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(error.is_timeout(), "{error}");
        assert_eq!(started.elapsed(), fetch::FETCH_TIMEOUT);
    })
    .await
}

/// One call of a fetcher: the host and the nonce.
type Call = (String, [u8; NONCE_SIZE]);

/// What a fetcher saw: each call.
#[derive(Clone, Default)]
struct Calls(Arc<Mutex<Vec<Call>>>);

impl Calls {
    /// A fetcher that records each call and returns `document`.
    fn fetcher(&self, document: &'static [u8]) -> impl AttestationFetcher {
        let calls = self.clone();
        move |host: String, nonce: [u8; NONCE_SIZE]| {
            calls.0.lock().unwrap().push((host, nonce));
            async move { Ok::<_, BoxError>(document.to_vec()) }
        }
    }

    fn hosts(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(h, _)| h.clone())
            .collect()
    }

    fn nonces(&self) -> Vec<[u8; NONCE_SIZE]> {
        self.0.lock().unwrap().iter().map(|(_, n)| *n).collect()
    }
}

#[tokio::test(start_paused = true)]
async fn an_enclave_client_fetches_every_document_with_the_callers_fetcher() {
    unstuck(async {
        let calls = Calls::default();
        let error = EnclaveHttpClient::builder("enclave.example.com:8443", Trust::repo("o/n"))
            .fetch_attestation(calls.fetcher(b"not an attestation document"))
            .connect()
            .await
            .expect_err("the document fails verification");
        // A document that fails verification is an attestation error, as a
        // fetched one is, and it is tried once more.
        assert_eq!(error.kind(), ErrorKind::Attestation, "{error}");
        assert_eq!(
            calls.hosts(),
            ["enclave.example.com:8443", "enclave.example.com:8443"]
        );
        let nonces = calls.nonces();
        assert_ne!(nonces[0], nonces[1], "each attempt has a fresh nonce");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_fetchers_configuration_error_is_kept_and_not_tried_again() {
    unstuck(async {
        let calls = Arc::new(Mutex::new(0));
        let count = Arc::clone(&calls);
        let fetcher = move |_: String, _: [u8; NONCE_SIZE]| {
            *count.lock().unwrap() += 1;
            async { Err::<Vec<u8>, BoxError>(Box::new(Error::configuration("bad relay"))) }
        };
        let error = EnclaveHttpClient::builder("enclave.example.com", Trust::repo("o/n"))
            .fetch_attestation(fetcher)
            .connect()
            .await
            .expect_err("refused");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        assert_eq!(*calls.lock().unwrap(), 1);

        // Any other error is a network error, and is tried once more.
        let calls = Calls::default();
        let failing = {
            let calls = calls.clone();
            move |host: String, nonce: [u8; NONCE_SIZE]| {
                calls.0.lock().unwrap().push((host, nonce));
                async { Err::<Vec<u8>, BoxError>("unreachable".into()) }
            }
        };
        let error = EnclaveHttpClient::builder("enclave.example.com", Trust::repo("o/n"))
            .fetch_attestation(failing)
            .connect()
            .await
            .expect_err("refused");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(calls.hosts().len(), 2);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_router_client_fetches_the_list_and_every_document_with_the_callers_fetchers() {
    unstuck(async {
        let calls = Calls::default();
        let listed = Arc::new(Mutex::new(0));
        let count = Arc::clone(&listed);
        let list = move || {
            *count.lock().unwrap() += 1;
            async { Ok::<_, BoxError>(vec!["a.example".to_owned(), "b.example".to_owned()]) }
        };
        let error = RouterHttpClient::builder()
            .transport(Transport::Ehbp {
                proxy_url: Some("https://proxy.example/".into()),
            })
            .fetch_attestation(calls.fetcher(b"not an attestation document"))
            .fetch_router_list(list)
            .connect()
            .await
            .expect_err("no router passes");
        assert_eq!(error.kind(), ErrorKind::Attestation, "{error}");
        assert_eq!(*listed.lock().unwrap(), 1);
        // Discovery still runs with a proxy: each listed router once, then
        // the fallback with its retry. Nothing is fetched directly.
        assert_eq!(
            calls.hosts(),
            [
                "a.example",
                "b.example",
                discovery::FALLBACK_ROUTER,
                discovery::FALLBACK_ROUTER
            ]
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_failing_router_list_fetcher_is_an_empty_list() {
    unstuck(async {
        let calls = Calls::default();
        let list = || async { Err::<Vec<String>, BoxError>("down".into()) };
        let error = RouterHttpClient::builder()
            .fetch_attestation(calls.fetcher(b"{}"))
            .fetch_router_list(list)
            .connect()
            .await
            .expect_err("the fallback fails too");
        assert_eq!(error.kind(), ErrorKind::Attestation, "{error}");
        assert_eq!(
            calls.hosts(),
            [discovery::FALLBACK_ROUTER, discovery::FALLBACK_ROUTER]
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_verification_after_the_first_uses_the_fetcher_too() {
    unstuck(async {
        let calls = Calls::default();
        let checked = crate::internal::enclave::Config {
            host: "enclave.example.com".into(),
            pin: crate::verifier::Pin::repo("o/n"),
            verifier: None,
            verification_check: None,
            on_verification: None,
        }
        .check()
        .unwrap();
        let enclave = crate::internal::enclave::Enclave::from_checked(
            checked,
            system_clock(),
            attestation_fetch(Some(Arc::new(calls.fetcher(b"{}")))),
        );
        for _ in 0..2 {
            let error = enclave.verify(|_| ()).await.expect_err("rejected");
            assert_eq!(error.kind(), ErrorKind::Attestation);
        }
        assert_eq!(calls.hosts().len(), 4);
    })
    .await
}

#[test]
fn routers_are_shuffled_uniformly_and_the_callers_list_is_left_alone() {
    let mut seen_first = std::collections::BTreeSet::new();
    for _ in 0..200 {
        let mut routers: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
        discovery::shuffle(&mut routers);
        let mut sorted = routers.clone();
        sorted.sort();
        assert_eq!(sorted, ["a", "b", "c", "d"]);
        seen_first.insert(routers[0].clone());
    }
    assert_eq!(
        seen_first.len(),
        4,
        "every router comes first some of the time"
    );
}

#[tokio::test(start_paused = true)]
async fn discovery_tries_the_routers_in_the_shuffled_order_of_a_copy() {
    unstuck(async {
        discovery::TEST_ORDER.set(Some(|routers: &mut [String]| routers.reverse()));
        let calls = Calls::default();
        let callers = Arc::new(vec![
            "a.example".to_owned(),
            "b.example".to_owned(),
            "c.example".to_owned(),
        ]);
        let list = {
            let callers = Arc::clone(&callers);
            move || {
                let callers = Arc::clone(&callers);
                async move { Ok::<_, BoxError>(callers.to_vec()) }
            }
        };
        let _ = RouterHttpClient::builder()
            .fetch_attestation(calls.fetcher(b"{}"))
            .fetch_router_list(list)
            .connect()
            .await;
        discovery::TEST_ORDER.set(None);
        assert_eq!(calls.hosts()[..3], ["c.example", "b.example", "a.example"]);
        assert_eq!(*callers, ["a.example", "b.example", "c.example"]);
    })
    .await
}

/// A local server that answers one request with `answer` and returns the
/// request's head.
async fn serve_once(answer: &'static [u8]) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buffer = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let read = socket.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            head.extend_from_slice(&buffer[..read]);
        }
        socket.write_all(answer).await.unwrap();
        socket.shutdown().await.ok();
        String::from_utf8(head).unwrap()
    });
    (format!("http://127.0.0.1:{port}/tinfoil"), handle)
}

#[tokio::test]
async fn a_relayed_document_is_requested_with_the_sdk_headers_and_returned_as_it_is() {
    let nonce = nonce();
    let (relay, request) =
        serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\ndocument").await;
    let relay = AttestationRelay::new(relay).unwrap();
    let document = relay
        .fetch_attestation("enclave.example:8443".into(), nonce)
        .await
        .unwrap();
    assert_eq!(document, b"document");
    let head = request.await.unwrap().to_ascii_lowercase();
    let line = head.lines().next().unwrap();
    assert_eq!(
        line,
        format!(
            "get /tinfoil/.well-known/tinfoil-attestation?nonce={}&enclave=enclave.example%3a8443 http/1.1",
            fetch::lower_hex(&nonce)
        )
    );
    assert!(head.contains("\r\ntinfoil-sdk: "), "{head}");
    assert!(head.contains("\r\ntinfoil-sdk-version: "), "{head}");
    assert!(!head.contains("authorization"), "{head}");
}

#[tokio::test]
async fn a_relay_failure_is_a_network_error() {
    let nonce = nonce();
    for answer in [
        &b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\r\ncontent-length: 99999999999\r\n\r\n",
    ] {
        let (relay, _) = serve_once(answer).await;
        let error = AttestationRelay::new(relay)
            .unwrap()
            .fetch_attestation("enclave.example".into(), nonce)
            .await
            .expect_err("a failure");
        let error = from_fetcher(error);
        assert_eq!(error.kind(), ErrorKind::Network, "{error}");
    }
    // Nothing listens on the port of a listener that was dropped.
    let unreachable = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let error = AttestationRelay::new(format!("http://127.0.0.1:{unreachable}/"))
        .unwrap()
        .fetch_attestation("enclave.example".into(), nonce)
        .await
        .expect_err("unreachable");
    assert_eq!(from_fetcher(error).kind(), ErrorKind::Network);
}

#[tokio::test]
async fn a_relayed_router_list_is_read_as_tinfoils_list() {
    let (relay, request) = serve_once(
        b"HTTP/1.1 200 OK\r\ncontent-length: 39\r\n\r\n[\"a.example\",null,\"https://x\",\"b:8443\"]",
    )
    .await;
    let list = RouterListRelay::new(relay)
        .unwrap()
        .fetch_router_list()
        .await
        .unwrap();
    assert_eq!(list, ["a.example", "b:8443"]);
    let head = request.await.unwrap().to_ascii_lowercase();
    assert!(
        head.starts_with("get /tinfoil/routers http/1.1\r\n"),
        "{head}"
    );

    for answer in [
        &b"HTTP/1.1 200 OK\r\ncontent-length: 13\r\n\r\n{\"a\":\"b.com\"}"[..],
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n[1,2]",
        b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\ncontent-length: 99999999999\r\n\r\n",
    ] {
        let (relay, _) = serve_once(answer).await;
        let relay = RouterListRelay::new(relay).unwrap();
        let error = relay.fetch_router_list().await.expect_err("no list");
        assert_eq!(from_fetcher(error).kind(), ErrorKind::Network);
        // To discovery, it is an empty list.
        assert!(router_list(Arc::new(relay)).await.is_empty());
    }
}

#[test]
fn the_relays_print_their_url_and_the_builders_print_no_fetcher() {
    let relay = AttestationRelay::new("https://app.example/tinfoil").unwrap();
    assert_eq!(relay.url().as_str(), "https://app.example/tinfoil/");
    assert!(format!("{relay:?}").contains("https://app.example/tinfoil/"));
    let builder = RouterHttpClient::builder()
        .fetch_attestation(relay)
        .fetch_router_list(RouterListRelay::new("https://app.example/").unwrap());
    let printed = format!("{builder:?}");
    assert!(printed.contains("router_list_fetcher: true"), "{printed}");
}

/// What an observer of the public options was told: the host, and for a
/// failure the error with the layer of the report that it carries.
type Seen = Arc<
    Mutex<
        Vec<(
            String,
            Result<(), (ErrorKind, Option<crate::verifier::Layer>)>,
        )>,
    >,
>;

fn seeing() -> (
    Seen,
    impl Fn(&str, Result<&crate::verifier::VerificationReport, &Error>) + Send + Sync + 'static,
) {
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let observe =
        move |host: &str, outcome: Result<&crate::verifier::VerificationReport, &Error>| {
            let outcome = outcome.map(|_| ()).map_err(|error| {
                let layer = crate::internal::testing::rejected_report(error)
                    .and_then(|report| report.failed_step())
                    .map(|step| step.layer);
                (error.kind(), layer)
            });
            log.lock().unwrap().push((host.to_owned(), outcome));
        };
    (seen, observe)
}

#[tokio::test(start_paused = true)]
async fn a_rejected_document_reaches_the_caller_and_the_observer_with_its_report() {
    unstuck(async {
        let calls = Calls::default();
        let checked = Arc::new(Mutex::new(0));
        let (seen, observe) = seeing();
        let count = Arc::clone(&checked);
        let error = EnclaveHttpClient::builder("enclave.example.com", Trust::repo("o/n"))
            .fetch_attestation(calls.fetcher(b"{}"))
            .verification_check(move |_| {
                *count.lock().unwrap() += 1;
                Ok(())
            })
            .on_verification(observe)
            .connect()
            .await
            .expect_err("the document fails verification");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        // The verifier's error and its report are reachable from the
        // client's error, through its source.
        let report = crate::internal::testing::rejected_report(&error).expect("a report");
        assert_eq!(
            report.failed_step().map(|step| step.layer),
            Some(crate::verifier::Layer::Envelope)
        );
        assert!(report.verified_facts().is_none());
        // Both attempts are told, each with its own report; the check sees
        // no verification that failed.
        let rejected = Err((
            ErrorKind::Attestation,
            Some(crate::verifier::Layer::Envelope),
        ));
        assert_eq!(
            *seen.lock().unwrap(),
            [
                ("enclave.example.com".to_owned(), rejected),
                ("enclave.example.com".to_owned(), rejected),
            ]
        );
        assert_eq!(*checked.lock().unwrap(), 0);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_failed_fetch_is_told_without_a_report() {
    unstuck(async {
        let (seen, observe) = seeing();
        let failing = |_: String, _: [u8; NONCE_SIZE]| async {
            Err::<Vec<u8>, BoxError>("unreachable".into())
        };
        let error = EnclaveHttpClient::builder("enclave.example.com", Trust::repo("o/n"))
            .fetch_attestation(failing)
            .on_verification(observe)
            .connect()
            .await
            .expect_err("the fetch fails");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(crate::internal::testing::rejected_report(&error).is_none());
        let failed = Err((ErrorKind::Network, None));
        assert_eq!(
            *seen.lock().unwrap(),
            [
                ("enclave.example.com".to_owned(), failed),
                ("enclave.example.com".to_owned(), failed),
            ]
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn discovery_tells_each_router_that_it_tries_with_its_own_host() {
    unstuck(async {
        let calls = Calls::default();
        let (seen, observe) = seeing();
        let list =
            || async { Ok::<_, BoxError>(vec!["a.example".to_owned(), "b.example".to_owned()]) };
        let _ = RouterHttpClient::builder()
            .fetch_attestation(calls.fetcher(b"{}"))
            .fetch_router_list(list)
            .on_verification(observe)
            .connect()
            .await
            .expect_err("no router passes");
        let hosts: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|(host, _)| host.clone())
            .collect();
        let mut tried = hosts[..2].to_vec();
        tried.sort();
        assert_eq!(tried, ["a.example", "b.example"]);
        // The fallback, with its retry.
        assert_eq!(
            hosts[2..],
            [discovery::FALLBACK_ROUTER, discovery::FALLBACK_ROUTER]
        );
        assert!(seen.lock().unwrap().iter().all(|(_, outcome)| {
            *outcome
                == Err((
                    ErrorKind::Attestation,
                    Some(crate::verifier::Layer::Envelope),
                ))
        }));
    })
    .await
}
