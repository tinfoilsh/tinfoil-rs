//! Installs an attested HTTP client under an `async_openai` client.

use std::sync::Arc;
use std::task::{Context, Poll};

use async_openai::config::OpenAIConfig;
use async_openai::error::{ApiErrorResponse, OpenAIError, WrappedError};
use async_openai::middleware::HttpRequestFactory;
use reqwest::header::CONTENT_LENGTH;
use reqwest::{Request, Response, StatusCode, Url};
use tower_service::Service;

use crate::error::{Error, ErrorKind};
use crate::internal::{BoxFuture, fetch};
use crate::openai::retry::{MAX_RETRIES, Waits};
use crate::options::TransportMode;
use crate::request::Execute;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

/// The `type` of the error in a `429` response that waiting cannot cure.
const INSUFFICIENT_QUOTA: &str = "insufficient_quota";

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
/// - **Retries.** The service sends a call again itself, at most
///   [`MAX_RETRIES`] times: after a response with status `429` (unless its
///   error is `insufficient_quota`) or `5xx`, and after the wait that
///   [`Waits`] decides. A response that asks for a longer wait than
///   `waits` allows is the call's result at once. An error of `http` is
///   never tried again here, whatever its kind, so a refused verification
///   or a refused request is reported once.
/// - **Deadlines.** The client's `timeout` option bounds each request
///   that `http` sends, from its start until its response body has been
///   read, and each wait between two attempts; it is not one deadline for
///   the whole call.
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
///   body that `async_openai` reads whole is `OpenAIError::Reqwest`, and
///   is found there too. A failed read of a body that `async_openai`
///   reads as a stream of events is `OpenAIError::StreamError`, which
///   keeps the message of the failure and nothing else: the stream ends
///   with that error, and no client error is found in it.
pub(crate) fn openai_client(
    config: OpenAIConfig,
    api_base: &Url,
    http: Arc<dyn Execute>,
    mode: TransportMode,
    waits: Waits,
) -> Result<(async_openai::Client<OpenAIConfig>, Sender), Error> {
    let config = config.with_api_base(api_base.as_str().trim_end_matches('/'));
    // Only collects the parts of each request.
    let parts = fetch::tls_builder()?
        .build()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?;
    let service = Attested { http, mode, waits };
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
    service: Attested,
}

impl Sender {
    /// Sends the request that `factory` builds, as a call of
    /// `async_openai` is sent, and returns the response whatever its
    /// status once no retry is due.
    pub(crate) async fn send(&self, factory: HttpRequestFactory) -> Result<Response, OpenAIError> {
        self.service.send(&factory).await
    }
}

/// The service that sends `async_openai`'s requests through the attested
/// client, and sends them again.
#[derive(Clone)]
struct Attested {
    http: Arc<dyn Execute>,
    mode: TransportMode,
    waits: Waits,
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

impl Attested {
    /// Sends the request that `factory` builds until a response is final:
    /// one whose status is not tried again, the response of the last
    /// attempt, or one that asks for too long a wait.
    ///
    /// A `5xx` response that is final is returned as a response. A `429`
    /// response is read here, to tell a rate limit from a spent quota, so
    /// a final one is returned as the API's error.
    async fn send(&self, factory: &HttpRequestFactory) -> Result<Response, OpenAIError> {
        let mut retries = 0_u32;
        loop {
            let response = self.attempt(factory).await?;
            let status = response.status();
            let limited = status == StatusCode::TOO_MANY_REQUESTS;
            if !limited && !status.is_server_error() {
                return Ok(response);
            }
            let wait = if retries < MAX_RETRIES {
                self.waits.before_retry(response.headers(), retries)
            } else {
                None
            };
            let last = if limited {
                Err(rate_limit(response).await?)
            } else {
                Ok(response)
            };
            let Some(wait) = wait else { return last };
            // The response is closed before the wait, not held through it.
            drop(last);
            tokio::time::sleep(wait).await;
            retries = retries.saturating_add(1);
        }
    }

    /// One attempt: the request is built and sent, and built and sent once
    /// more if the enclave rejected its keys and its body was a stream.
    async fn attempt(&self, factory: &HttpRequestFactory) -> Result<Response, OpenAIError> {
        let http = &self.http;
        let request = self.build(factory).await?;
        let unsent = match http.execute(request).await {
            Ok(response) => return Ok(response),
            Err(error) if error.is_unsent_after_rejection() => error,
            Err(error) => return Err(boxed(error)),
        };
        // The keys were rejected and the body was a stream. The rejection
        // has invalidated the verification, so a request built anew goes
        // out under a new one.
        let request = self.build(factory).await?;
        http.execute(request).await.map_err(|error| {
            boxed(match unsent.earlier_attempt() {
                Some(rejection) => error.after_all(rejection.clone()),
                None => error,
            })
        })
    }
}

/// The API's error in a `429` response, to be tried again; or, as `Err`,
/// what ends the call: the error of a spent quota, a body that could not
/// be read, or one that is not the API's error object.
async fn rate_limit(response: Response) -> Result<OpenAIError, OpenAIError> {
    let status_code = response.status();
    let bytes = response.bytes().await.map_err(OpenAIError::Reqwest)?;
    let wrapped = serde_json::from_slice::<WrappedError>(&bytes).map_err(|error| {
        OpenAIError::JSONDeserialize(error, String::from_utf8_lossy(&bytes).into_owned())
    })?;
    let spent = wrapped.error.r#type.as_deref() == Some(INSUFFICIENT_QUOTA);
    let error = OpenAIError::ApiError(ApiErrorResponse {
        status_code,
        api_error: wrapped.error,
    });
    if spent { Err(error) } else { Ok(error) }
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
        Box::pin(async move { this.send(&factory).await })
    }
}

/// A client error as `async_openai` carries it.
fn boxed(error: Error) -> OpenAIError {
    OpenAIError::Boxed(Box::new(error))
}
