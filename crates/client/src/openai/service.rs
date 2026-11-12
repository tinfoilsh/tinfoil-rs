//! Installs an attested HTTP client under an `async_openai` client.

use std::sync::Arc;
use std::task::{Context, Poll};

use async_openai::config::OpenAIConfig;
use async_openai::error::OpenAIError;
use async_openai::middleware::HttpRequestFactory;
use async_openai::middleware::retry::{OpenAIRetry, OpenAIRetryLayer};
use reqwest::header::CONTENT_LENGTH;
use reqwest::{Request, Response, Url};
use tower_layer::Layer;
use tower_service::Service;

use crate::error::{Error, ErrorKind};
use crate::internal::{BoxFuture, fetch};
use crate::options::TransportMode;
use crate::request::Execute;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

/// How often `async_openai` sends a call again after the first attempt.
pub(crate) const MAX_RETRIES: usize = 2;

/// An `async_openai` client that sends through `http`, and the service
/// that it sends through.
///
/// - **Configuration.** `config` is taken as the caller built it (the API
///   key, the organization, the project and any extra headers), and then
///   its API base is set to `api_base` without the trailing `/`, which is
///   the form that `async_openai` appends its paths to. Whatever base the
///   caller's configuration named, or `OPENAI_BASE_URL` supplied, is
///   replaced: every URL that `async_openai` builds starts with
///   `api_base`. The client's origin restriction stands behind that.
/// - **The hook.** `async_openai` hands each call, of every API family,
///   streaming and multipart calls included, to one executor: a
///   `tower::Service` over its `HttpRequestFactory`, which builds the
///   `reqwest::Request` anew for each attempt. The service installed here
///   builds the request and sends it through `http`, and nothing else
///   sends. The `reqwest::Client` that `async_openai` keeps for building
///   requests never sends one.
/// - **Retries.** The service sits inside `async_openai`'s retry layer,
///   limited to [`MAX_RETRIES`] retries: a response with status `429`
///   (unless its error is `insufficient_quota`) or `5xx` is tried again
///   after a backoff, or after the response's `Retry-After`. An error of
///   `http` is never tried again by that layer, whatever its kind, so a
///   refused verification or a refused request is reported once.
/// - **Uploads after a key rejection.** A multipart body is a stream, which
///   `http` cannot send again after the enclave rejected its keys. The
///   request can be built again here, so it is, once, and goes out under
///   the new verification. If that attempt fails too, its error is
///   returned with the rejection attached.
/// - **Lengths.** `reqwest` declares the length of a multipart body in a
///   `Content-Length` header. In [`TransportMode::Ehbp`] the body that is
///   sent is the sealed one, whose length the transport declares, and the
///   mode refuses a request that sets the header; so there the header is
///   removed from the request that `async_openai` built.
/// - **Errors.** An error of `http` is returned boxed, which
///   `async_openai` reports as `OpenAIError::Boxed`;
///   [`Error::from_openai`] finds it there. A failed read of a response
///   body is `OpenAIError::Reqwest`, and is found there too.
pub(crate) fn openai_client(
    config: OpenAIConfig,
    api_base: &Url,
    http: Arc<dyn Execute>,
    mode: TransportMode,
) -> Result<(async_openai::Client<OpenAIConfig>, Sender), Error> {
    let config = config.with_api_base(api_base.as_str().trim_end_matches('/'));
    // Only collects the parts of each request.
    let parts = fetch::tls_builder()?
        .build()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?;
    let service = OpenAIRetryLayer::new(MAX_RETRIES).layer(Attested { http, mode });
    let sender = Sender {
        service: service.clone(),
    };
    let openai = async_openai::Client::build(parts, config).with_http_service(service);
    Ok((openai, sender))
}

/// What `async_openai` sends through, for the calls that this crate makes
/// by itself: the same service, with the same retries.
#[derive(Clone)]
pub(crate) struct Sender {
    service: OpenAIRetry<Attested>,
}

impl Sender {
    /// Sends the request that `factory` builds, as a call of
    /// `async_openai` is sent, and returns the response whatever its
    /// status once no retry is due.
    pub(crate) async fn send(&self, factory: HttpRequestFactory) -> Result<Response, OpenAIError> {
        self.service.clone().call(factory).await
    }
}

/// The service that sends `async_openai`'s requests through the attested
/// client.
#[derive(Clone)]
struct Attested {
    http: Arc<dyn Execute>,
    mode: TransportMode,
}

impl Attested {
    /// The request that `factory` builds, as the client takes it.
    async fn build(&self, factory: &HttpRequestFactory) -> Result<Request, OpenAIError> {
        let mut request = factory.build().await?;
        if self.mode == TransportMode::Ehbp {
            request.headers_mut().remove(CONTENT_LENGTH);
        }
        Ok(request)
    }
}

impl Service<HttpRequestFactory> for Attested {
    type Response = Response;
    type Error = OpenAIError;
    type Future = BoxFuture<Result<Response, OpenAIError>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, factory: HttpRequestFactory) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let http = &this.http;
            let request = this.build(&factory).await?;
            let unsent = match http.execute(request).await {
                Ok(response) => return Ok(response),
                Err(error) if error.is_unsent_after_rejection() => error,
                Err(error) => return Err(boxed(error)),
            };
            // The keys were rejected and the body was a stream. The
            // rejection has invalidated the verification, so a request
            // built anew goes out under a new one.
            let request = this.build(&factory).await?;
            http.execute(request).await.map_err(|error| {
                boxed(match unsent.earlier_attempt() {
                    Some(rejection) => error.after_all(rejection.clone()),
                    None => error,
                })
            })
        })
    }
}

/// A client error as `async_openai` carries it.
fn boxed(error: Error) -> OpenAIError {
    OpenAIError::Boxed(Box::new(error))
}
