//! Installs an attested HTTP client under an `async_openai` client.

use std::sync::Arc;

use async_openai::config::OpenAIConfig;
use reqwest::Url;

use crate::error::Error;
use crate::request::Execute;

/// An `async_openai` client that sends through `http`.
///
/// - `config` is taken as the caller built it, and then its API base is set
///   to `api_base` without the trailing `/`, which is the form that
///   `async_openai` appends its paths to.
/// - `async_openai` hands each call to a `tower::Service` over its
///   `HttpRequestFactory`, which builds the `reqwest::Request` again for
///   each attempt. The service installed here builds the request and sends
///   it through `http`, inside `async_openai`'s own retry layer with its
///   default policy, so that a retry builds, checks and seals a new
///   request.
/// - An error of `http` is returned boxed, which `async_openai` reports as
///   `OpenAIError::Boxed`; [`Error::from_openai`] finds it there.
/// - The `reqwest::Client` that `async_openai` keeps for building requests
///   never sends one.
pub(crate) fn openai_client(
    config: OpenAIConfig,
    api_base: &Url,
    http: Arc<dyn Execute>,
) -> Result<async_openai::Client<OpenAIConfig>, Error> {
    Err(Error::not_implemented("the OpenAI client"))
}
