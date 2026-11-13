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
use crate::internal::{BoxFuture, body, fetch};
use crate::openai::retry::{MAX_RETRIES, Waits};
use crate::options::TransportMode;
use crate::request::Execute;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

/// The `type` of the error in a `429` response that waiting cannot cure.
const INSUFFICIENT_QUOTA: &str = "insufficient_quota";

/// The largest body of an error response that this crate reads into
/// memory by itself. An error of the API is a small JSON object; in
/// [`TransportMode::Ehbp`] an error response can come from a proxy and is
/// not authenticated, so its size is not left to whoever sent it.
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 1 << 20;

/// The largest body of a successful response that is read into memory on
/// the caller's behalf: by `async_openai` for a typed call, streamed or
/// not, and by this crate for a relaxed call that is not streamed. It
/// leaves room for a large batch of embeddings or a response that holds
/// audio or images.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 << 20;

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
///   [`Waits`] decides. The status decides: a `429` whose body is not the
///   API's error object, is larger than [`MAX_ERROR_BODY_BYTES`] or
///   cannot be read is tried again like any other, and is the call's
///   error if the last attempt ends that way. A response that asks for a longer wait than
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
/// - **Sizes.** `async_openai` reads response bodies into memory, so the
///   responses that it is handed are bounded ([`bounded`]): an error
///   response at [`MAX_ERROR_BODY_BYTES`], a successful one, streamed or
///   not, at [`MAX_RESPONSE_BYTES`]. A longer body fails where it is
///   read, with the client's network error.
/// - **Errors.** An error of `http` is returned boxed, which
///   `async_openai` reports as `OpenAIError::Boxed`;
///   [`Error::from_openai`] finds it there. A failed read of a response
///   body that `async_openai` reads whole is `OpenAIError::Reqwest`, and
///   is found there too. A failed read of a body that `async_openai`
///   reads as a stream of events is `OpenAIError::StreamError`, which
///   keeps a message and not the error: the stream ends with that error,
///   and no client error is found in it.
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
    /// a final one is returned as an error: the API's, or the one for a
    /// body that could not be read as the API's error.
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
                let (error, spent) = rate_limit(response).await;
                if spent {
                    return Err(error);
                }
                Err(error)
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

/// The error of a `429` response, and whether it is that of a spent
/// quota, which waiting cannot cure. The error is the API's when the body
/// holds it; otherwise it says what was wrong with the body: it could not
/// be read, is larger than [`MAX_ERROR_BODY_BYTES`], or is not the API's
/// error object. Only a body that could be read can report a spent quota.
async fn rate_limit(response: Response) -> (OpenAIError, bool) {
    let status_code = response.status();
    let bytes = match read_within(response, MAX_ERROR_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => return (error, false),
    };
    match serde_json::from_slice::<WrappedError>(&bytes) {
        Ok(wrapped) => {
            let spent = wrapped.error.r#type.as_deref() == Some(INSUFFICIENT_QUOTA);
            let error = OpenAIError::ApiError(ApiErrorResponse {
                status_code,
                api_error: wrapped.error,
            });
            (error, spent)
        }
        Err(error) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            (OpenAIError::JSONDeserialize(error, text), false)
        }
    }
}

/// The whole body of `response`, if it is at most `limit` bytes long. The
/// read stops at the first byte beyond the limit, and the error is then a
/// network error of the client: nothing of a longer body is returned, and
/// no more of it is held than the limit. A read that fails is
/// `OpenAIError::Reqwest`.
pub(crate) async fn read_within(
    mut response: Response,
    limit: usize,
) -> Result<Vec<u8>, OpenAIError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(OpenAIError::Reqwest)? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(boxed(body::too_large(limit)));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
        Box::pin(async move { this.send(&factory).await.map(bounded) })
    }
}

/// `response`, as it is handed to `async_openai`, which reads the body of
/// every response into memory: whole when the call is not streamed and
/// when the status is an error, and event by event, ahead of the caller,
/// when it is streamed. The body fails once it exceeds
/// [`MAX_RESPONSE_BYTES`], or [`MAX_ERROR_BODY_BYTES`] when the status is
/// not a success ([`body::limit`]).
fn bounded(response: Response) -> Response {
    let limit = if response.status().is_success() {
        MAX_RESPONSE_BYTES
    } else {
        MAX_ERROR_BODY_BYTES
    };
    body::limit(response, limit)
}

/// A client error as `async_openai` carries it.
fn boxed(error: Error) -> OpenAIError {
    OpenAIError::Boxed(Box::new(error))
}
