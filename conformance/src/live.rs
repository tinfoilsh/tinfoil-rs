//! `live-verify`: verifies a running enclave as an application does.
//!
//! The command reads `{"host": "...", "repo": "..."}` on stdin and connects
//! the client's [`EnclaveHttpClient`] to the host with the repository as
//! its pin. The client fetches a document under a fresh nonce and verifies
//! it with the default verifier: the embedded roots, the current time, no
//! test seam. One request is then sent through the client, whose TLS
//! handshake succeeds only if the server's certificate carries the public
//! key of the verified fingerprint. The facts that are reported are those
//! of the verification that the connection was pinned to, with
//! `channel_binding` set to [`CHANNEL_BINDING`].
//!
//! The command needs no conformance seam, so it is available in every
//! build of the adapter.

use std::error::Error as StdError;
use std::time::Duration;

use serde::Deserialize;
use tinfoil::verifier::{Error as VerifierError, Layer};
use tinfoil::{EnclaveHttpClient, ErrorKind, TransportMode};

use crate::{
    CODE_ENVELOPE_REJECTED, CODE_POLICY_REJECTED, EXIT_ACCEPTED, EXIT_INTERNAL, EXIT_REJECTED,
    Output, Rejection, facts, malformed,
};

/// The name of the command, and the stage that its output reports.
pub const COMMAND: &str = "live-verify";

/// The channel check that the command performs: the public key of the TLS
/// connection's certificate against the verified fingerprint.
pub const CHANNEL_BINDING: &str = "tls-spki";

/// The deadline for fetching and verifying the enclave's document, which
/// leaves room for the one retry that the client makes.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(70);
/// The deadline for the request that exercises the pinned connection.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The stdin JSON of the command. Members other than these are ignored.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Request {
    /// The enclave's host, with an optional port.
    pub host: String,
    /// The repository that the enclave's code must come from.
    pub repo: String,
}

impl Request {
    /// Decodes the request. `None` unless the input is one JSON object
    /// that names a host and a repository.
    pub fn parse(stdin: &[u8]) -> Option<Self> {
        if !crate::is_object(stdin) {
            return None;
        }
        let request: Self = serde_json::from_slice(stdin).ok()?;
        (!request.host.is_empty() && !request.repo.is_empty()).then_some(request)
    }
}

/// The result of one run of the command.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    /// What goes to stdout. `None` for a run without a verdict, which
    /// prints nothing there.
    pub output: Option<Output>,
    /// The process exit code.
    pub code: i32,
    /// What goes to stderr: why the run did not accept.
    pub diagnostic: Option<String>,
}

impl Outcome {
    fn accepted(outputs: crate::AcceptOutputs) -> Self {
        let output = Output {
            stage: COMMAND.to_owned(),
            accepted: true,
            outputs: Some(outputs),
            rejection: None,
        };
        Self {
            output: Some(output),
            code: EXIT_ACCEPTED,
            diagnostic: None,
        }
    }

    fn of(verdict: Verdict, diagnostic: String) -> Self {
        let (output, code) = match verdict {
            Verdict::Malformed => {
                let (output, code) = malformed(COMMAND);
                (Some(output), code)
            }
            Verdict::Rejected(code) => {
                let output = Output {
                    stage: COMMAND.to_owned(),
                    accepted: false,
                    outputs: None,
                    rejection: Some(Rejection {
                        code: code.to_owned(),
                    }),
                };
                (Some(output), EXIT_REJECTED)
            }
            Verdict::Internal => (None, EXIT_INTERNAL),
        };
        Self {
            output,
            code,
            diagnostic: Some(diagnostic),
        }
    }
}

/// How a run that did not accept ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The request cannot be acted on.
    Malformed,
    /// The enclave must not be trusted, for the reason of this code.
    Rejected(&'static str),
    /// The enclave could not be judged.
    Internal,
}

/// The verdict for a verification that failed, from the kind of the
/// client's error and the verifier layer that rejected the document, if
/// one did.
///
/// A host or a repository that the client cannot use is malformed input,
/// and an enclave that could not be reached gives no verdict. A document
/// that the verifier rejected carries the code of the layer. One that the
/// verifier accepted and the client still refused has no key that a
/// connection can be bound to, which is the envelope's code.
fn verification_verdict(kind: ErrorKind, layer: Option<Layer>) -> Verdict {
    match (kind, layer) {
        (ErrorKind::Configuration, _) => Verdict::Malformed,
        (ErrorKind::Attestation, Some(layer)) => {
            facts::layer_code(layer).map_or(Verdict::Internal, Verdict::Rejected)
        }
        (ErrorKind::Attestation, None) => Verdict::Rejected(CODE_ENVELOPE_REJECTED),
        _ => Verdict::Internal,
    }
}

/// The verdict for a failed request over the pinned connection. An
/// attestation error there is the pin: the server does not present the
/// verified key, which the policy layer's code reports. Any other failure
/// says nothing about the enclave.
fn channel_verdict(kind: ErrorKind) -> Verdict {
    match kind {
        ErrorKind::Attestation => Verdict::Rejected(CODE_POLICY_REJECTED),
        _ => Verdict::Internal,
    }
}

/// The verifier layer that rejected the document, when `error` or one of
/// its sources is a rejection by the verifier.
fn rejecting_layer(error: &(dyn StdError + 'static)) -> Option<Layer> {
    let mut next = Some(error);
    while let Some(error) = next {
        if let Some(VerifierError::Verification(rejected)) = error.downcast_ref::<VerifierError>() {
            return Some(rejected.layer());
        }
        next = error.source();
    }
    None
}

/// Runs the command over the raw stdin bytes.
pub fn run(stdin: &[u8]) -> Outcome {
    let Some(request) = Request::parse(stdin) else {
        let diagnostic = "the input must be a JSON object with a host and a repo".to_owned();
        return Outcome::of(Verdict::Malformed, diagnostic);
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    match runtime {
        Ok(runtime) => runtime.block_on(verify(&request)),
        Err(error) => Outcome::of(Verdict::Internal, format!("starting the runtime: {error}")),
    }
}

async fn verify(request: &Request) -> Outcome {
    let host = &request.host;
    let connected = EnclaveHttpClient::builder(host.as_str(), Some(&request.repo))
        .transport_mode(TransportMode::Tls)
        .timeout(VERIFY_TIMEOUT)
        .connect()
        .await;
    let client = match connected {
        Ok(client) => client,
        Err(error) => {
            let verdict = verification_verdict(error.kind(), rejecting_layer(&error));
            return Outcome::of(verdict, format!("verifying {host}: {error}"));
        }
    };
    // Any response will do: the handshake behind it is what compares the
    // server's key with the verified fingerprint.
    let response = client
        .head(client.base_url().clone())
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await;
    if let Err(error) = response {
        let verdict = channel_verdict(error.kind());
        return Outcome::of(verdict, format!("channel binding to {host}: {error}"));
    }
    // The verification that the connection was pinned to.
    let verification = client.current();
    match facts::verified(&verification) {
        Some(outputs) => Outcome::accepted(crate::AcceptOutputs {
            channel_binding: CHANNEL_BINDING.to_owned(),
            ..outputs
        }),
        None => Outcome::of(
            Verdict::Rejected(CODE_ENVELOPE_REJECTED),
            format!("the document of {host} endorses no usable TLS or HPKE key"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use tinfoil::verifier::Verifier;

    use super::*;
    use crate::{
        CODE_MALFORMED_INPUT, CODE_PROVENANCE_REJECTED, CODE_QUOTE_REJECTED, EXIT_MALFORMED,
    };

    #[test]
    fn a_request_names_a_host_and_a_repository() {
        let request = Request::parse(br#" {"host":"enclave.example","repo":"owner/name"} "#);
        assert_eq!(
            request,
            Some(Request {
                host: "enclave.example".to_owned(),
                repo: "owner/name".to_owned(),
            })
        );
        // A member that the command does not know is ignored.
        let extended = br#"{"host":"h","repo":"o/r","note":1}"#;
        assert!(Request::parse(extended).is_some());
    }

    #[test]
    fn a_request_that_is_not_one_complete_object_is_refused() {
        let cases = [
            ("empty", ""),
            ("truncated", "{"),
            ("no host", r#"{"repo":"o/r"}"#),
            ("no repository", r#"{"host":"h"}"#),
            ("empty host", r#"{"host":"","repo":"o/r"}"#),
            ("empty repository", r#"{"host":"h","repo":""}"#),
            ("null host", r#"{"host":null,"repo":"o/r"}"#),
            ("numeric host", r#"{"host":1,"repo":"o/r"}"#),
            ("members by position", r#"["h","o/r"]"#),
            ("string", r#""h""#),
            ("trailing data", r#"{"host":"h","repo":"o/r"} {}"#),
            ("repeated member", r#"{"host":"h","host":"i","repo":"o/r"}"#),
        ];
        for (name, input) in cases {
            assert_eq!(Request::parse(input.as_bytes()), None, "{name}");
        }
    }

    #[test]
    fn a_refused_request_is_malformed_input_and_contacts_nothing() {
        let outcome = run(b"{}");
        assert_eq!(outcome.code, EXIT_MALFORMED);
        let json = serde_json::to_string(&outcome.output).unwrap();
        assert_eq!(
            json,
            r#"{"stage":"live-verify","accepted":false,"rejection":{"code":"MALFORMED_INPUT"}}"#
        );
        assert!(outcome.diagnostic.is_some());
    }

    #[test]
    fn a_host_or_repository_that_the_client_refuses_is_malformed_input() {
        // The client checks both before it opens a connection.
        for input in [
            r#"{"host":"https://enclave.example","repo":"owner/name"}"#,
            r#"{"host":"enclave.example/path","repo":"owner/name"}"#,
            r#"{"host":"enclave.example","repo":"not a repository"}"#,
        ] {
            let outcome = run(input.as_bytes());
            assert_eq!(outcome.code, EXIT_MALFORMED, "{input}");
            let rejection = outcome.output.and_then(|output| output.rejection);
            assert_eq!(
                rejection.map(|rejection| rejection.code).as_deref(),
                Some(CODE_MALFORMED_INPUT),
                "{input}"
            );
        }
    }

    #[test]
    fn a_failed_verification_ends_as_its_cause_says() {
        use ErrorKind::{Attestation, Configuration, Network};
        let cases = [
            (Configuration, None, Verdict::Malformed),
            (Configuration, Some(Layer::Envelope), Verdict::Malformed),
            (Network, None, Verdict::Internal),
            (Network, Some(Layer::Quote), Verdict::Internal),
            (
                Attestation,
                Some(Layer::Envelope),
                Verdict::Rejected(CODE_ENVELOPE_REJECTED),
            ),
            (
                Attestation,
                Some(Layer::Provenance),
                Verdict::Rejected(CODE_PROVENANCE_REJECTED),
            ),
            (
                Attestation,
                Some(Layer::Quote),
                Verdict::Rejected(CODE_QUOTE_REJECTED),
            ),
            (
                Attestation,
                Some(Layer::Policy),
                Verdict::Rejected(CODE_POLICY_REJECTED),
            ),
            (Attestation, None, Verdict::Rejected(CODE_ENVELOPE_REJECTED)),
        ];
        for (kind, layer, want) in cases {
            assert_eq!(verification_verdict(kind, layer), want, "{kind} {layer:?}");
        }
    }

    #[test]
    fn only_a_refused_pin_rejects_the_channel() {
        assert_eq!(
            channel_verdict(ErrorKind::Attestation),
            Verdict::Rejected(CODE_POLICY_REJECTED)
        );
        assert_eq!(channel_verdict(ErrorKind::Network), Verdict::Internal);
        assert_eq!(channel_verdict(ErrorKind::Configuration), Verdict::Internal);
    }

    /// An error that only passes on its source.
    #[derive(Debug)]
    struct Wrapper(Box<dyn StdError + 'static>);

    impl fmt::Display for Wrapper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("wrapper")
        }
    }

    impl StdError for Wrapper {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[test]
    fn the_rejecting_layer_is_found_among_the_sources() {
        // Not a document at all: the envelope layer rejects it.
        let rejection = Verifier::new()
            .verify_v3(b"{}", &[0; 32], Some("owner/name"))
            .unwrap_err();
        assert!(matches!(rejection, VerifierError::Verification(_)));
        let wrapped = Wrapper(Box::new(Wrapper(Box::new(rejection))));
        assert_eq!(rejecting_layer(&wrapped), Some(Layer::Envelope));

        // A usage error is not a rejection, and neither is another error.
        let usage = Verifier::new()
            .verify_v3(b"{}", &[0; 32], Some(""))
            .unwrap_err();
        assert!(matches!(usage, VerifierError::Usage(_)));
        assert_eq!(rejecting_layer(&Wrapper(Box::new(usage))), None);
        assert_eq!(rejecting_layer(&fmt::Error), None);
    }

    #[test]
    fn outcomes_have_the_shape_of_their_verdict() {
        let rejected = Outcome::of(Verdict::Rejected(CODE_POLICY_REJECTED), "why".to_owned());
        assert_eq!(rejected.code, EXIT_REJECTED);
        assert_eq!(
            serde_json::to_string(&rejected.output).unwrap(),
            r#"{"stage":"live-verify","accepted":false,"rejection":{"code":"POLICY_REJECTED"}}"#
        );

        let internal = Outcome::of(Verdict::Internal, "why".to_owned());
        assert_eq!(internal.code, EXIT_INTERNAL);
        assert_eq!(internal.output, None);
        assert_eq!(internal.diagnostic.as_deref(), Some("why"));

        let accepted = Outcome::accepted(crate::AcceptOutputs {
            code_digest: "digest".to_owned(),
            tls_public_key_fp: "fingerprint".to_owned(),
            hpke_public_key: "key".to_owned(),
            channel_binding: CHANNEL_BINDING.to_owned(),
            ..crate::AcceptOutputs::default()
        });
        assert_eq!(accepted.code, EXIT_ACCEPTED);
        assert_eq!(accepted.diagnostic, None);
        assert_eq!(
            serde_json::to_string(&accepted.output).unwrap(),
            concat!(
                r#"{"stage":"live-verify","accepted":true,"outputs":{"code_digest":"digest","#,
                r#""tls_public_key_fp":"fingerprint","hpke_public_key":"key","#,
                r#""channel_binding":"tls-spki"}}"#
            )
        );
    }
}
