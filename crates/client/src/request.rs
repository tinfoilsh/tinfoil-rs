//! Requests through an attested client: the request builder, the response
//! future, and the request methods that every HTTP client has.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Body, Method, Request, Response};
use serde::Serialize;

use crate::error::{Error, ErrorKind};

/// What a request builder sends through: the attested chain of one client.
pub(crate) trait Execute: Send + Sync + 'static {
    /// Sends `request` through the client's chain.
    fn execute(&self, request: Request) -> ResponseFuture;

    /// A `reqwest` builder for `method` and `url`. It only collects the
    /// parts of a request; nothing is ever sent through it.
    fn start(&self, method: Method, url: reqwest::Url) -> reqwest::RequestBuilder;
}

/// The future of a response from an attested client. Dropping it cancels
/// the request.
#[must_use = "futures do nothing unless polled"]
pub(crate) struct ResponseFuture {
    inner: Pin<Box<dyn Future<Output = Result<Response, Error>> + Send + 'static>>,
}

impl ResponseFuture {
    pub(crate) fn new(
        future: impl Future<Output = Result<Response, Error>> + Send + 'static,
    ) -> Self {
        Self {
            inner: Box::pin(future),
        }
    }
}

impl Future for ResponseFuture {
    type Output = Result<Response, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

impl fmt::Debug for ResponseFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture").finish_non_exhaustive()
    }
}

/// A request to an attested client, built with `reqwest`'s method names.
///
/// It is created by a client's `get`, `post`, `put`, `patch`, `delete`,
/// `head` or `request`, and [`send`](RequestBuilder::send) sends it through
/// that client: the request is checked against the client's origin, the
/// enclave is verified again if its verification expired, and the request
/// then goes out under the keys of the current verification.
///
/// The `Host` header belongs to the client, and so do the headers of the
/// sealed-body protocol in [`TransportMode::Ehbp`](crate::TransportMode::Ehbp);
/// a request that sets one of them is refused with a configuration error.
///
/// Its `Debug` output names no header value, because a header can hold a
/// credential.
#[must_use = "a request does nothing until it is sent"]
pub struct RequestBuilder {
    executor: Arc<dyn Execute>,
    // An invalid URL is kept here and reported when the request is built.
    inner: Result<reqwest::RequestBuilder, Error>,
}

impl RequestBuilder {
    pub(crate) fn new(
        executor: Arc<dyn Execute>,
        method: Method,
        url: Result<reqwest::Url, Error>,
    ) -> Self {
        let inner = url.map(|url| executor.start(method, url));
        Self { executor, inner }
    }

    fn map(mut self, set: impl FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder) -> Self {
        self.inner = self.inner.map(set);
        self
    }

    /// Adds a header.
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.map(|inner| inner.header(key, value))
    }

    /// Merges `headers` into the request's headers.
    pub fn headers(self, headers: HeaderMap) -> Self {
        self.map(|inner| inner.headers(headers))
    }

    /// Sets `Authorization: Bearer <token>`. In
    /// [`TransportMode::Ehbp`](crate::TransportMode::Ehbp) a proxy sees this
    /// header.
    pub fn bearer_auth(self, token: impl fmt::Display) -> Self {
        self.map(|inner| inner.bearer_auth(token))
    }

    /// Sets the body. A body made from bytes or a string can be sent again
    /// after the enclave rotates its key; a streaming body cannot, and such
    /// a request then fails instead of being replayed.
    pub fn body(self, body: impl Into<Body>) -> Self {
        self.map(|inner| inner.body(body))
    }

    /// Sets the body to `json`, serialized, and the content type to JSON.
    /// A value that fails to serialize is reported by
    /// [`send`](RequestBuilder::send).
    pub fn json<T: Serialize + ?Sized>(self, json: &T) -> Self {
        self.map(|inner| inner.json(json))
    }

    /// Appends `query`, serialized, to the URL's query string.
    pub fn query<T: Serialize + ?Sized>(self, query: &T) -> Self {
        self.map(|inner| inner.query(query))
    }

    /// A deadline for this request, from [`send`](RequestBuilder::send)
    /// until the response body has been read. It replaces the client's
    /// `timeout` option for this request, and covers the wait for a
    /// verification that the request needs.
    pub fn timeout(self, timeout: Duration) -> Self {
        self.map(|inner| inner.timeout(timeout))
    }

    /// A copy of the builder, or `None` when the body is a stream.
    pub fn try_clone(&self) -> Option<Self> {
        let inner = match &self.inner {
            Ok(inner) => Ok(inner.try_clone()?),
            Err(error) => Err(error.clone()),
        };
        Some(Self {
            executor: Arc::clone(&self.executor),
            inner,
        })
    }

    /// The request as built, for a client's `execute`. An invalid URL,
    /// header or body is a configuration error.
    pub fn build(self) -> Result<Request, Error> {
        self.inner?
            .build()
            .map_err(|error| Error::wrap(ErrorKind::Configuration, error))
    }

    /// Sends the request through the client that created the builder. See
    /// the client's `execute` for the checks, the errors and what dropping
    /// the future leaves behind.
    pub async fn send(self) -> Result<Response, Error> {
        let executor = Arc::clone(&self.executor);
        let request = self.build()?;
        executor.execute(request).await
    }
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestBuilder").finish_non_exhaustive()
    }
}

/// Parses `url` as `reqwest` does, into this crate's error.
pub(crate) fn into_url(url: impl reqwest::IntoUrl) -> Result<reqwest::Url, Error> {
    url.into_url()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))
}

/// The request methods of an HTTP client whose `inner` field is an `Arc` of
/// a type that implements [`Execute`].
macro_rules! http_request_methods {
    ($client:ident) => {
        impl $client {
            /// Starts a `GET` request to `url`, an absolute URL on the
            /// client's origin.
            pub fn get(&self, url: impl reqwest::IntoUrl) -> $crate::RequestBuilder {
                self.request(reqwest::Method::GET, url)
            }

            /// Starts a `POST` request to `url`, an absolute URL on the
            /// client's origin.
            pub fn post(&self, url: impl reqwest::IntoUrl) -> $crate::RequestBuilder {
                self.request(reqwest::Method::POST, url)
            }

            /// Starts a `PUT` request to `url`, an absolute URL on the
            /// client's origin.
            pub fn put(&self, url: impl reqwest::IntoUrl) -> $crate::RequestBuilder {
                self.request(reqwest::Method::PUT, url)
            }

            /// Starts a `PATCH` request to `url`, an absolute URL on the
            /// client's origin.
            pub fn patch(&self, url: impl reqwest::IntoUrl) -> $crate::RequestBuilder {
                self.request(reqwest::Method::PATCH, url)
            }

            /// Starts a `DELETE` request to `url`, an absolute URL on the
            /// client's origin.
            pub fn delete(&self, url: impl reqwest::IntoUrl) -> $crate::RequestBuilder {
                self.request(reqwest::Method::DELETE, url)
            }

            /// Starts a `HEAD` request to `url`, an absolute URL on the
            /// client's origin.
            pub fn head(&self, url: impl reqwest::IntoUrl) -> $crate::RequestBuilder {
                self.request(reqwest::Method::HEAD, url)
            }

            /// Starts a request with `method` to `url`.
            ///
            /// The URL must be absolute; build it from
            /// [`base_url`](Self::base_url) so that it follows the client's
            /// route. A URL that does not parse is reported when the request
            /// is sent. Nothing is checked or sent until then.
            pub fn request(
                &self,
                method: reqwest::Method,
                url: impl reqwest::IntoUrl,
            ) -> $crate::RequestBuilder {
                let executor: std::sync::Arc<dyn $crate::request::Execute> = self.inner.clone();
                $crate::RequestBuilder::new(executor, method, $crate::request::into_url(url))
            }

            /// Sends `request` through the client and returns the response,
            /// whatever its status: a `4xx` or `5xx` is a response, not an
            /// error, and so is a `3xx`, because redirects are not followed.
            ///
            /// In order, and before anything is sent:
            ///
            /// 1. A request to any origin other than the client's own is
            ///    refused, so that its headers are never disclosed to
            ///    another host. A request that the transport mode cannot
            ///    protect is refused too: plaintext `http://` in
            ///    [`TransportMode::Tls`](crate::TransportMode::Tls); a
            ///    protocol upgrade or `CONNECT` wherever bodies are sealed.
            ///    A `Host` header, or a header that the sealed-body protocol
            ///    owns, is refused. These are configuration errors, and they
            ///    never start a verification.
            /// 2. If the current verification has expired or was rejected,
            ///    the enclave is verified again first, as
            ///    [`ensure_verified`](Self::ensure_verified) does. A failure
            ///    is the request's error, and nothing is sent.
            /// 3. The request goes out under the keys of that verification.
            ///    If the enclave no longer holds them (the certificate check
            ///    fails in the handshake, or the enclave refuses the sealed
            ///    body's key), the verification is discarded, the enclave is
            ///    verified again, and the request is sent once more. A body
            ///    that is a stream cannot be sent again; the request then
            ///    fails with the rejection.
            ///
            /// A failure to connect, or a connection that breaks, is a
            /// network error with the `reqwest` error as its source.
            ///
            /// # Deadline
            ///
            /// The request's own timeout, or else the client's `timeout`
            /// option, is one deadline counted from the first poll of the
            /// returned future. It covers a verification that the request
            /// waits for, the request, its replay, and the read of the
            /// response body. When it passes before the response arrives,
            /// the error is a network error whose
            /// [`is_timeout`]($crate::Error::is_timeout) is `true`.
            ///
            /// # Reading the body
            ///
            /// The body is read with `reqwest`'s methods, and a failed
            /// read is a `reqwest::Error`.
            /// [`Error::from_reqwest`]($crate::Error::from_reqwest) returns
            /// the client's error inside it: an attestation error when a
            /// sealed body stops authenticating, a network error when the
            /// connection breaks or the deadline passes. After a failed
            /// read nothing more of the body is delivered.
            ///
            /// # Cancel safety
            ///
            /// Dropping the future cancels the request. The enclave may or
            /// may not have received it, and its connection is closed
            /// rather than reused. A verification that the request was
            /// waiting for continues for the other requests that wait for
            /// it, and is abandoned if there are none; the client's current
            /// verification is replaced only by a complete new one, so the
            /// client stays usable either way. No replay is sent after the
            /// drop.
            pub async fn execute(
                &self,
                request: reqwest::Request,
            ) -> Result<reqwest::Response, $crate::Error> {
                $crate::request::Execute::execute(&*self.inner, request).await
            }
        }
    };
}

pub(crate) use http_request_methods;
