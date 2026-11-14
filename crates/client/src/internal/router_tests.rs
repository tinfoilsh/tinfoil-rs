//! Router discovery: the list parser, the list fetch against a local
//! server, and the choice of a router on scripted evidence under Tokio's
//! paused time.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::{Method, Request, Response, Url};
use tokio::sync::Notify;

use super::*;
use crate::error::ErrorKind;
use crate::internal::BoxFuture;
use crate::internal::testing::{Record, Script, Step, record, tokio_clock};
use crate::internal::transport::{Failure, RoundTrip};
use crate::options::TransportMode;
use crate::request::{Execute, RequestBuilder, into_url};

const HOUR: Duration = Duration::from_secs(3600);

/// Runs a test under paused time with a limit: when nothing in the test
/// can make progress any more, Tokio moves its clock to this limit, and
/// the test fails instead of hanging.
async fn unstuck<T>(test: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(1_000 * 86_400), test)
        .await
        .expect("the test can make no progress")
}

// The parser.

fn parsed(body: &str) -> Option<Vec<String>> {
    parse_router_list(body.as_bytes())
}

#[test]
fn a_list_is_one_json_array_of_strings_and_anything_else_is_no_list() {
    for body in [
        "",
        "null x",
        "{}",
        r#"{"routers":["a.example"]}"#,
        r#""a.example""#,
        "42",
        r#"["a.example""#,
        r#"["a.example"] ["b.example"]"#,
        r#"["a.example"],"#,
        "not json",
        // One entry of another type refuses the whole list.
        r#"["a.example", 1]"#,
        r#"["a.example", true]"#,
        r#"["a.example", ["b.example"]]"#,
        r#"["a.example", {"host":"b.example"}]"#,
        r#"[1, "a.example"]"#,
    ] {
        assert_eq!(parsed(body), None, "{body:?}");
    }
    assert_eq!(parse_router_list(b"[\"a\xff.example\"]"), None);
}

#[test]
fn hosts_are_kept_in_order_as_written_and_repeated_entries_stay() {
    assert_eq!(parsed("[]"), Some(vec![]));
    assert_eq!(parsed(" [ ] \n"), Some(vec![]));
    assert_eq!(
        parsed(r#"["c.example","a.example","b.example"]"#).unwrap(),
        ["c.example", "a.example", "b.example"]
    );
    assert_eq!(
        parsed(r#"["a.example","b.example","a.example"]"#).unwrap(),
        ["a.example", "b.example", "a.example"]
    );
    assert_eq!(
        parsed(
            r#"["Router.Example.COM","a.example:8443","[::1]:443","127.0.0.1","bücher.example","xn--bcher-kva.example"]"#
        )
        .unwrap(),
        [
            "Router.Example.COM",
            "a.example:8443",
            "[::1]:443",
            "127.0.0.1",
            "b\u{fc}cher.example",
            "xn--bcher-kva.example"
        ]
    );
}

#[test]
fn an_entry_that_is_not_a_host_is_left_out_and_the_others_stay() {
    for entry in [
        r#""""#,
        "null",
        r#"" a.example""#,
        r#""a.example ""#,
        r#""a.example\n""#,
        r#""https://a.example""#,
        r#""a.example/path""#,
        r#""a.example?x=1""#,
        r#""a.example#f""#,
        r#""user@a.example""#,
        r#""user:pass@a.example""#,
        r#""a.example:notaport""#,
        r#""a.example:99999""#,
        r#""127.1""#,
        r#""a b.example""#,
        r#""a.example,b.example""#,
    ] {
        let body = format!(r#"["first.example",{entry},"last.example"]"#);
        assert_eq!(
            parsed(&body).unwrap(),
            ["first.example", "last.example"],
            "{entry}"
        );
    }
}

#[test]
fn the_constants_are_the_published_ones() {
    assert_eq!(ROUTER_LIST_URL, "https://atc.tinfoil.sh/routers");
    assert_eq!(FALLBACK_ROUTER, "inference.tinfoil.sh");
    assert_eq!(ROUTER_NAME, "tinfoilsh/confidential-model-router");
    assert_eq!(
        router_pin(),
        Pin::repo(ROUTER_NAME).with_project(ROUTER_NAME)
    );
    assert_eq!(DISCOVERY_BUDGET, Duration::from_secs(30));
    assert_eq!(LIST_FETCH_TIMEOUT, Duration::from_secs(30));
    assert_eq!(MAX_ROUTER_LIST_BYTES, 32 * 1024 * 1024);
    assert!(authority_url(FALLBACK_ROUTER).is_ok());
    assert!(Url::parse(ROUTER_LIST_URL).is_ok());
}

// The list fetch, against a local server.

mod fetching {
    use super::*;
    use crate::internal::transport::tls::testing::made::{KEY_A, LEAF_A};
    use crate::internal::transport::tls::testing::{
        Handler, Protocols, Seen, Server, full, roots, serve,
    };

    /// Bounds a wait on the local server, so that a hang fails the test.
    const PATIENCE: Duration = Duration::from_secs(20);

    /// A client that trusts the local server and uses no proxy.
    fn client() -> Client {
        fetch::tls_builder_with(roots())
            .unwrap()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    async fn server(handler: Handler) -> Arc<Server> {
        serve(&LEAF_A, &KEY_A, Protocols::Both, handler).await
    }

    fn answering(status: u16, body: &'static str) -> Handler {
        Arc::new(move |_: Seen| {
            Box::pin(async move {
                hyper::Response::builder()
                    .status(status)
                    .body(full(body))
                    .unwrap()
            })
        })
    }

    async fn list(server: &Server, limit: usize, timeout: Duration) -> Vec<String> {
        let url = Url::parse(&format!("https://127.0.0.1:{}/routers", server.port)).unwrap();
        tokio::time::timeout(PATIENCE, list_through(&client(), url, limit, timeout))
            .await
            .expect("the fetch neither succeeded nor failed in time")
    }

    const LIST: &str = r#"["a.example","not a host","b.example:8443"]"#;

    #[tokio::test]
    async fn a_list_is_fetched_with_a_get_that_carries_no_credential() {
        let server = server(answering(200, LIST)).await;
        let hosts = list(&server, 1024, PATIENCE).await;
        assert_eq!(hosts, ["a.example", "b.example:8443"]);
        let seen = server.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].method.as_str(), seen[0].target.as_str()),
            ("GET", "/routers")
        );
        for name in ["authorization", "cookie"] {
            assert!(!seen[0].headers.contains_key(name), "{name}");
        }
        assert!(seen[0].body.is_empty());
    }

    #[tokio::test]
    async fn any_2xx_is_a_list_and_every_other_status_is_an_empty_list() {
        for status in [200, 203, 299] {
            let server = server(answering(status, LIST)).await;
            assert_eq!(list(&server, 1024, PATIENCE).await.len(), 2, "{status}");
        }
        for status in [301, 302, 400, 404, 500, 503] {
            let server = server(answering(status, LIST)).await;
            assert!(list(&server, 1024, PATIENCE).await.is_empty(), "{status}");
        }
    }

    #[tokio::test]
    async fn a_body_over_the_limit_or_one_that_is_no_list_is_an_empty_list() {
        let server = server(answering(200, LIST)).await;
        assert_eq!(list(&server, LIST.len(), PATIENCE).await.len(), 2);
        assert!(list(&server, LIST.len() - 1, PATIENCE).await.is_empty());

        let server = self::server(answering(200, r#"["a.example", 7]"#)).await;
        assert!(list(&server, 1024, PATIENCE).await.is_empty());
    }

    #[tokio::test]
    async fn a_list_that_does_not_arrive_in_time_is_an_empty_list() {
        let gate = Arc::new(Notify::new());
        let hold = Arc::clone(&gate);
        let server = server(Arc::new(move |_: Seen| {
            let hold = Arc::clone(&hold);
            Box::pin(async move {
                hold.notified().await;
                hyper::Response::new(full(LIST))
            })
        }))
        .await;
        let started = std::time::Instant::now();
        assert!(
            list(&server, 1024, Duration::from_millis(300))
                .await
                .is_empty()
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        gate.notify_one();
    }

    #[tokio::test]
    async fn a_server_that_cannot_be_reached_is_an_empty_list() {
        // A port that nothing listens on.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = Url::parse(&format!("https://127.0.0.1:{port}/routers")).unwrap();
        let hosts = tokio::time::timeout(PATIENCE, list_through(&client(), url, 1024, PATIENCE))
            .await
            .expect("in time");
        assert!(hosts.is_empty());
    }
}

// Choosing a router.

/// A mode that binds evidence with a TLS key and records each request's
/// body with the name of the evidence that it was sent under.
#[derive(Default)]
struct Recording {
    sent: Arc<Mutex<Vec<(&'static str, String)>>>,
}

impl Mode<Record> for Recording {
    fn validate_request(&self, _: &Request) -> Result<(), Error> {
        Ok(())
    }

    fn bind(&self, evidence: &Record) -> Result<Arc<dyn RoundTrip>, Error> {
        if evidence.tls.is_none() {
            return Err(Error::attestation("the evidence endorses no key"));
        }
        Ok(Arc::new(Bound(evidence.name, Arc::clone(&self.sent))))
    }
}

struct Bound(&'static str, Arc<Mutex<Vec<(&'static str, String)>>>);

impl RoundTrip for Bound {
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>> {
        let body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map(|body| String::from_utf8_lossy(body).into_owned())
            .unwrap_or_default();
        self.1.lock().unwrap().push((self.0, body));
        Box::pin(async { Ok(Response::from(http::Response::new("ok"))) })
    }
}

/// The routers of a test: what each host's verifications yield, and which
/// hosts were asked for an enclave, in order.
#[derive(Default)]
struct World {
    scripts: Mutex<HashMap<String, Arc<Script>>>,
    asked: Mutex<Vec<String>>,
}

impl World {
    fn new(hosts: Vec<(&str, Vec<Step>)>) -> Arc<Self> {
        let world = Self::default();
        for (host, steps) in hosts {
            world
                .scripts
                .lock()
                .unwrap()
                .insert(host.to_owned(), Script::new(steps));
        }
        Arc::new(world)
    }

    /// The enclave of `host`, as discovery asks for it. A host that the
    /// test did not describe cannot be verified; a host that is not a host
    /// is refused.
    fn enclave_for(self: &Arc<Self>) -> impl Fn(&str) -> Result<Enclave<Record>, Error> + use<> {
        let world = Arc::clone(self);
        move |host: &str| {
            world.asked.lock().unwrap().push(host.to_owned());
            authority_url(host)?;
            let script = world
                .scripts
                .lock()
                .unwrap()
                .entry(host.to_owned())
                .or_insert_with(|| Script::new([]))
                .clone();
            Ok(Enclave::from_source(
                host,
                script.source(),
                None,
                tokio_clock(),
            ))
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }

    /// How many verifications of `host` have started.
    fn attempts(&self, host: &str) -> usize {
        self.scripts
            .lock()
            .unwrap()
            .get(host)
            .map_or(0, |script| script.calls())
    }
}

fn good(name: &'static str) -> Step {
    Step::Ready(Ok(record(name, &tokio_clock(), HOUR)))
}

fn bad(kind: ErrorKind, message: &'static str) -> Step {
    Step::Ready(Err(match kind {
        ErrorKind::Network => Error::network(message),
        ErrorKind::Attestation => Error::attestation(message),
        _ => Error::configuration(message),
    }))
}

fn hosts(list: &[&str]) -> std::future::Ready<Vec<String>> {
    std::future::ready(list.iter().map(|host| (*host).to_owned()).collect())
}

async fn discovered(
    world: &Arc<World>,
    list: impl Future<Output = Vec<String>>,
) -> Result<Transport<Record>, Error> {
    discover(list, world.enclave_for(), Arc::new(Recording::default())).await
}

#[tokio::test(start_paused = true)]
async fn the_first_router_of_the_list_that_verifies_is_chosen_and_no_other_is_tried() {
    unstuck(async {
        let world = World::new(vec![
            ("a.example", vec![good("a")]),
            ("b.example", vec![good("b")]),
        ]);
        let transport = discovered(&world, hosts(&["a.example", "b.example"]))
            .await
            .unwrap();
        assert_eq!(transport.enclave().host(), "a.example");
        assert_eq!(transport.current().name, "a");
        assert_eq!(world.asked(), ["a.example"]);
        // The verification of the probe is the client's: no second one.
        assert_eq!(world.attempts("a.example"), 1);
        transport.ensure_verified().await.unwrap();
        assert_eq!(world.attempts("a.example"), 1);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn the_list_is_tried_in_its_own_order() {
    unstuck(async {
        let world = World::new(vec![
            ("a.example", vec![good("a")]),
            ("z.example", vec![good("z")]),
        ]);
        let transport = discovered(&world, hosts(&["z.example", "a.example"]))
            .await
            .unwrap();
        assert_eq!(transport.enclave().host(), "z.example");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_router_that_fails_for_any_reason_is_skipped_without_a_retry() {
    unstuck(async {
        let world = World::new(vec![
            ("down.example", vec![bad(ErrorKind::Network, "refused")]),
            (
                "forged.example",
                vec![bad(ErrorKind::Attestation, "rejected")],
            ),
            (
                "odd.example",
                vec![bad(ErrorKind::Configuration, "unusable")],
            ),
            // A document that endorses no key for the mode.
            (
                "keyless.example",
                vec![Step::Ready(Ok(Record {
                    tls: None,
                    ..record("keyless", &tokio_clock(), HOUR)
                }))],
            ),
            ("good.example", vec![good("good")]),
        ]);
        let started = tokio::time::Instant::now();
        let transport = discovered(
            &world,
            hosts(&[
                "down.example",
                "forged.example",
                "odd.example",
                "keyless.example",
                "good.example",
            ]),
        )
        .await
        .unwrap();
        assert_eq!(transport.enclave().host(), "good.example");
        for host in [
            "down.example",
            "forged.example",
            "odd.example",
            "keyless.example",
        ] {
            assert_eq!(world.attempts(host), 1, "{host}");
        }
        // No pause for a retry was taken on the way.
        assert_eq!(started.elapsed(), Duration::ZERO);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_host_that_is_refused_is_skipped_and_a_repeated_host_is_tried_again() {
    unstuck(async {
        let world = World::new(vec![
            (
                "flaky.example",
                vec![bad(ErrorKind::Network, "reset"), good("second try")],
            ),
            ("never.example", vec![good("never")]),
        ]);
        let transport = discovered(
            &world,
            hosts(&[
                "https://not-a-host.example/",
                "flaky.example",
                "flaky.example",
                "never.example",
            ]),
        )
        .await
        .unwrap();
        assert_eq!(transport.current().name, "second try");
        assert_eq!(
            world.asked(),
            [
                "https://not-a-host.example/",
                "flaky.example",
                "flaky.example"
            ]
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn with_no_router_from_the_list_the_fallback_is_verified_with_its_retry() {
    unstuck(async {
        // An empty list.
        let world = World::new(vec![(FALLBACK_ROUTER, vec![good("fallback")])]);
        let transport = discovered(&world, hosts(&[])).await.unwrap();
        assert_eq!(transport.enclave().host(), FALLBACK_ROUTER);
        assert_eq!(world.asked(), [FALLBACK_ROUTER]);

        // A list of which nothing verifies; the fallback needs its retry.
        let world = World::new(vec![
            ("a.example", vec![bad(ErrorKind::Network, "a down")]),
            (
                FALLBACK_ROUTER,
                vec![bad(ErrorKind::Network, "blip"), good("fallback")],
            ),
        ]);
        let started = tokio::time::Instant::now();
        let transport = discovered(&world, hosts(&["a.example", "b.example"]))
            .await
            .unwrap();
        assert_eq!(transport.current().name, "fallback");
        assert_eq!(world.asked(), ["a.example", "b.example", FALLBACK_ROUTER]);
        assert_eq!(world.attempts(FALLBACK_ROUTER), 2);
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_fallback_that_fails_is_the_error_and_the_routers_failures_are_not() {
    unstuck(async {
        let world = World::new(vec![
            ("a.example", vec![bad(ErrorKind::Network, "a down")]),
            (
                FALLBACK_ROUTER,
                vec![
                    bad(ErrorKind::Network, "fallback unreachable"),
                    bad(ErrorKind::Attestation, "fallback rejected"),
                ],
            ),
        ]);
        let error = discovered(&world, hosts(&["a.example"]))
            .await
            .expect_err("nothing verifies");
        assert_eq!(error.to_string(), "attestation error: fallback rejected");
        let first = error.earlier_attempt().expect("the first attempt");
        assert_eq!(first.to_string(), "network error: fallback unreachable");
        assert!(first.earlier_attempt().is_none());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn the_list_and_the_probes_share_thirty_seconds_and_the_fallback_is_outside_them() {
    unstuck(async {
        let slow = |name, seconds| {
            Step::After(
                Duration::from_secs(seconds),
                Ok(record(name, &tokio_clock(), HOUR)),
            )
        };
        // The list takes 10 seconds, the first probe fails after 15 more,
        // and the second would need 10: it is dropped after 5.
        let world = World::new(vec![
            (
                "a.example",
                vec![Step::After(
                    Duration::from_secs(15),
                    Err(Error::network("slow failure")),
                )],
            ),
            ("b.example", vec![slow("b", 10)]),
            ("c.example", vec![good("c")]),
            (FALLBACK_ROUTER, vec![slow("fallback", 20)]),
        ]);
        let list = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            ["a.example", "b.example", "c.example"]
                .map(str::to_owned)
                .to_vec()
        };
        let started = tokio::time::Instant::now();
        let transport = discovered(&world, list).await.unwrap();
        assert_eq!(transport.current().name, "fallback");
        // No router is tried once the budget is spent.
        assert_eq!(world.asked(), ["a.example", "b.example", FALLBACK_ROUTER]);
        assert_eq!(started.elapsed(), Duration::from_secs(30 + 20));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_router_that_would_answer_at_once_is_not_tried_after_the_budget() {
    unstuck(async {
        // The first probe fails at the very instant that the budget ends.
        let world = World::new(vec![
            (
                "a.example",
                vec![Step::After(
                    DISCOVERY_BUDGET,
                    Err(Error::network("slow failure")),
                )],
            ),
            ("b.example", vec![good("b")]),
            (FALLBACK_ROUTER, vec![good("fallback")]),
        ]);
        let transport = discovered(&world, hosts(&["a.example", "b.example"]))
            .await
            .unwrap();
        assert_eq!(transport.current().name, "fallback");
        assert_eq!(world.asked(), ["a.example", FALLBACK_ROUTER]);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_list_that_takes_the_whole_budget_leaves_only_the_fallback() {
    unstuck(async {
        let world = World::new(vec![
            ("a.example", vec![good("a")]),
            (FALLBACK_ROUTER, vec![good("fallback")]),
        ]);
        // A list that never arrives.
        let started = tokio::time::Instant::now();
        let transport = discovered(&world, std::future::pending()).await.unwrap();
        assert_eq!(transport.current().name, "fallback");
        assert_eq!(started.elapsed(), DISCOVERY_BUDGET);
        assert_eq!(world.asked(), [FALLBACK_ROUTER]);

        // A list that arrives at the very end of the budget.
        let world = World::new(vec![
            ("a.example", vec![good("a")]),
            (FALLBACK_ROUTER, vec![good("fallback")]),
        ]);
        let list = async {
            tokio::time::sleep(DISCOVERY_BUDGET - Duration::from_millis(1)).await;
            vec!["a.example".to_owned()]
        };
        let transport = discovered(&world, list).await.unwrap();
        assert_eq!(transport.current().name, "a");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn dropping_discovery_keeps_nothing_and_the_next_one_starts_over() {
    unstuck(async {
        let gate = Arc::new(Notify::new());
        let world = World::new(vec![(
            "a.example",
            vec![
                Step::Gated(Arc::clone(&gate), Ok(record("a", &tokio_clock(), HOUR))),
                good("again"),
            ],
        )]);
        {
            let discovery = discovered(&world, hosts(&["a.example"]));
            tokio::pin!(discovery);
            let waited = tokio::time::timeout(Duration::from_secs(1), &mut discovery).await;
            assert!(waited.is_err());
        }
        let transport = discovered(&world, hosts(&["a.example"])).await.unwrap();
        assert_eq!(transport.current().name, "again");
    })
    .await
}

// The client.

fn settings(timeout: Option<Duration>) -> Settings {
    Settings {
        mode: TransportMode::Tls,
        base_url: None,
        secret: None,
        timeout,
    }
}

#[tokio::test(start_paused = true)]
async fn the_client_is_bound_to_the_router_that_discovery_chose() {
    unstuck(async {
        let world = World::new(vec![
            ("a.example", vec![bad(ErrorKind::Network, "down")]),
            ("b.example:8443", vec![good("b")]),
        ]);
        let client = connect(
            hosts(&["a.example", "b.example:8443"]),
            world.enclave_for(),
            Arc::new(Recording::default()),
            settings(None),
            |secret| secret,
        )
        .await
        .unwrap();
        assert_eq!(client.enclave(), "b.example:8443");
        assert_eq!(client.base_url().as_str(), "https://b.example:8443/");
        assert_eq!(client.openai_url().as_str(), "https://b.example:8443/v1/");
        assert_eq!(client.current().name, "b");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn through_a_proxy_the_requests_name_the_router_that_was_chosen() {
    unstuck(async {
        let world = World::new(vec![("b.example", vec![good("b")])]);
        let proxy = Url::parse("https://proxy.example.com/").unwrap();
        let client = connect(
            hosts(&["b.example"]),
            world.enclave_for(),
            Arc::new(Recording::default()),
            Settings {
                mode: TransportMode::Ehbp,
                base_url: Some(proxy.clone()),
                ..settings(None)
            },
            |secret| secret,
        )
        .await
        .unwrap();
        assert_eq!(client.enclave(), "b.example");
        assert_eq!(client.base_url(), &proxy);
        assert_eq!(client.openai_url(), &proxy);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn the_cache_secret_is_resolved_once_after_discovery_and_reaches_the_request_body() {
    unstuck(async {
        let world = World::new(vec![("a.example", vec![good("a")])]);
        let mode = Recording::default();
        let sent = Arc::clone(&mode.sent);
        let resolved = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&resolved);
        let chosen = Arc::clone(&world);
        let client = connect(
            hosts(&["a.example"]),
            world.enclave_for(),
            Arc::new(mode),
            settings(None),
            move |option| {
                // Discovery is over by now.
                log.lock()
                    .unwrap()
                    .push((option, chosen.attempts("a.example")));
                Some(Secret::new("resolved-scope"))
            },
        )
        .await
        .unwrap();
        assert_eq!(*resolved.lock().unwrap(), [(None, 1)]);

        let executor: Arc<dyn Execute> = Arc::new(client);
        let request = |path: &str| {
            RequestBuilder::new(
                Arc::clone(&executor),
                Method::POST,
                into_url(format!("https://a.example{path}")),
            )
            .body(r#"{"model":"m"}"#)
        };
        request("/v1/chat/completions").send().await.unwrap();
        request("/v1/embeddings").send().await.unwrap();
        assert_eq!(
            *sent.lock().unwrap(),
            [
                (
                    "a",
                    r#"{"model":"m","user_cache_secret":"resolved-scope"}"#.to_owned()
                ),
                ("a", r#"{"model":"m"}"#.to_owned()),
            ]
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn no_secret_is_resolved_for_a_client_that_cannot_be_created() {
    unstuck(async {
        let world = World::new(vec![]);
        let resolved = Arc::new(Mutex::new(0));
        let count = Arc::clone(&resolved);
        let error = connect(
            hosts(&["a.example"]),
            world.enclave_for(),
            Arc::new(Recording::default()),
            settings(None),
            move |secret| {
                *count.lock().unwrap() += 1;
                secret
            },
        )
        .await
        .err()
        .expect("nothing verifies");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(*resolved.lock().unwrap(), 0);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn the_timeout_bounds_discovery_and_the_fallback_together() {
    unstuck(async {
        let world = World::new(vec![(
            FALLBACK_ROUTER,
            vec![Step::After(
                Duration::from_secs(20),
                Ok(record("fallback", &tokio_clock(), HOUR)),
            )],
        )]);
        // Discovery spends its 30 seconds, and the fallback would take 20.
        let started = tokio::time::Instant::now();
        let error = connect(
            std::future::pending(),
            world.enclave_for(),
            Arc::new(Recording::default()),
            settings(Some(Duration::from_secs(40))),
            |secret| secret,
        )
        .await
        .err()
        .expect("out of time");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(error.is_timeout());
        assert_eq!(started.elapsed(), Duration::from_secs(40));
    })
    .await
}

// The options and the secret of the router client.

mod options {
    use super::*;
    use crate::RouterHttpClient;
    use crate::internal::cachesecret;
    use crate::verifier::Verifier;

    #[test]
    fn options_that_pass_every_check_describe_the_fallback_router_and_the_client() {
        let (fallback, settings) = RouterHttpClient::builder().prepare().unwrap();
        assert_eq!(fallback.host(), FALLBACK_ROUTER);
        assert_eq!(settings.mode, TransportMode::Tls);
        assert!(settings.base_url.is_none() && settings.secret.is_none());
        assert!(settings.timeout.is_none());

        let verifier = Arc::new(Verifier::new());
        let (fallback, settings) = RouterHttpClient::builder()
            .transport_mode(TransportMode::Ehbp)
            .base_url("https://proxy.example.com/tinfoil")
            .verifier(Arc::clone(&verifier))
            .verification_check(|_| Ok(()))
            .user_cache_secret("opaque")
            .timeout(Duration::from_secs(5))
            .prepare()
            .unwrap();
        // The verifier of the fallback is the one for every router.
        assert!(Arc::ptr_eq(fallback.verifier(), &verifier));
        assert!(fallback.verification_check().is_some());
        assert_eq!(settings.mode, TransportMode::Ehbp);
        assert_eq!(
            settings.base_url.as_ref().map(Url::as_str),
            Some("https://proxy.example.com/tinfoil/")
        );
        assert_eq!(settings.secret.as_ref().map(Secret::expose), Some("opaque"));
        assert_eq!(settings.timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn the_checks_run_in_the_documented_order() {
        let authorizing = || {
            let verifier = Verifier::builder().config_authorizer(|_| Ok(())).build();
            Arc::new(verifier.expect("a verifier"))
        };
        let refusal = |builder: crate::RouterHttpClientBuilder| {
            let error = builder.prepare().err().expect("refused");
            assert_eq!(error.kind(), ErrorKind::Configuration);
            error.to_string()
        };
        let all_wrong = || {
            RouterHttpClient::builder()
                .verifier(authorizing())
                .timeout(Duration::ZERO)
        };
        let message = refusal(all_wrong().base_url("ftp://proxy.example/"));
        assert!(message.contains("invalid base URL"), "{message}");
        let message = refusal(all_wrong().base_url("https://proxy.example/"));
        assert!(message.contains("TransportMode::Ehbp"), "{message}");
        let message = refusal(all_wrong());
        assert!(message.contains("timeout is zero"), "{message}");
        let message = refusal(RouterHttpClient::builder().verifier(authorizing()));
        assert!(message.contains("explicit enclave"), "{message}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_fails_after_discovery_resolves_no_secret() {
        unstuck(async {
            let world = World::new(vec![("a.example", vec![good("a")])]);
            let resolved = Arc::new(Mutex::new(0));
            let count = Arc::clone(&resolved);
            // A pinned client cannot take a base URL on another origin:
            // the client is refused once its router is known.
            let error = connect(
                hosts(&["a.example"]),
                world.enclave_for(),
                Arc::new(Recording::default()),
                Settings {
                    base_url: Some(Url::parse("https://proxy.example.com/").unwrap()),
                    ..settings(None)
                },
                move |option| {
                    *count.lock().unwrap() += 1;
                    cachesecret::resolve(option)
                },
            )
            .await
            .err()
            .expect("no client");
            assert_eq!(error.kind(), ErrorKind::Configuration);
            // The router was discovered and verified, and no secret was
            // resolved.
            assert_eq!(world.attempts("a.example"), 1);
            assert_eq!(*resolved.lock().unwrap(), 0);
        })
        .await
    }

    /// A router client made with the crate's resolver and `option`, and
    /// the body that it sent for `body`.
    async fn sent_by_a_router_client(option: Option<&str>, body: &str) -> String {
        let world = World::new(vec![("a.example", vec![good("a")])]);
        let mode = Recording::default();
        let sent = Arc::clone(&mode.sent);
        let client = connect(
            hosts(&["a.example"]),
            world.enclave_for(),
            Arc::new(mode),
            Settings {
                secret: option.map(Secret::new),
                ..settings(None)
            },
            cachesecret::resolve,
        )
        .await
        .unwrap();
        let executor: Arc<dyn Execute> = Arc::new(client);
        let url = "https://a.example/v1/chat/completions";
        RequestBuilder::new(executor, Method::POST, into_url(url))
            .body(body.to_owned())
            .send()
            .await
            .unwrap();
        sent.lock().unwrap()[0].1.clone()
    }

    #[tokio::test(start_paused = true)]
    async fn router_clients_without_the_option_share_the_secret_of_the_process() {
        unstuck(async {
            let body = r#"{"model":"m","n":1}"#;
            let first = sent_by_a_router_client(None, body).await;
            let second = sent_by_a_router_client(None, body).await;
            // The messages never print the generated secret.
            assert!(first == second, "two router clients sent different secrets");
            let secret = cachesecret::resolve(None).unwrap();
            let expected = format!(
                r#"{{"model":"m","n":1,"user_cache_secret":"{}"}}"#,
                secret.expose()
            );
            assert!(
                first == expected,
                "the body is not the original with the process secret appended"
            );
            assert_eq!(secret.expose().len(), 64);
        })
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn the_option_and_then_the_body_win_over_the_secret_of_the_process() {
        unstuck(async {
            let from_option = sent_by_a_router_client(Some("from-option"), "{}").await;
            assert_eq!(from_option, r#"{"user_cache_secret":"from-option"}"#);

            // A non-empty string in the body wins over the option and over
            // the secret of the process, and the body is sent as it is.
            let body = r#"{ "user_cache_secret" : "from-body", "model":"m" }"#;
            for option in [Some("from-option"), None] {
                assert_eq!(sent_by_a_router_client(option, body).await, body);
            }
            // A body that repeats the member is sent as it is.
            let repeated = r#"{"user_cache_secret":"","user_cache_secret":""}"#;
            assert_eq!(sent_by_a_router_client(None, repeated).await, repeated);
        })
        .await
    }
}
