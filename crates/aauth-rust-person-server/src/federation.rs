use http::{Request, Response};

/// Host could not resolve an admitted AS endpoint or complete a bounded exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Access Server endpoint or bounded HTTPS exchange is unavailable")]
pub struct FederationError;

/// Host-owned AS discovery and HTTPS transport. Implementations must admit the
/// verified AS identifier before discovery/network access, verify metadata issuer,
/// require a safe HTTPS endpoint, bound collection, set deadlines and enforce DNS/
/// egress policy. Do not follow credential-bearing redirects. The PS checks
/// endpoint syntax and every returned Auth token; it cannot enforce host I/O policy.
pub trait Federation: Send + Sync {
    /// Resolve/admit an AS's auth_token_endpoint from trusted configuration or
    /// issuer-checked aauth-access.json metadata. No arbitrary issuer auto-trust.
    fn endpoint(&self, access_server: &str) -> Result<String, FederationError>;
    /// Send exactly these already signed bytes/target, with bounded response and
    /// verified HTTPS. No URI, body, covered-header rewrite, redirect or retry.
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError>;
}
/// Captured host federation adapter for application state.
pub type BoxedFederation = Box<dyn Federation>;
impl<T: Federation + ?Sized> Federation for Box<T> {
    fn endpoint(&self, issuer: &str) -> Result<String, FederationError> {
        (**self).endpoint(issuer)
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        (**self).send(request)
    }
}

/// Local explanation of a failed PS-to-AS exchange. This value lives only in
/// `http::Response::extensions`; it is never serialized into the Agent response.
/// Inspect it before handing the response to a framework or network transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationFailure {
    /// Verified AS identity selected by the Resource challenge.
    pub access_server: String,
    /// Actual AS HTTP status, or None when no response was obtained.
    pub status: Option<http::StatusCode>,
    /// Exchange phase or terminal AS error; remote text is bounded but untrusted.
    pub reason: FederationFailureReason,
}

/// Distinguishes a terminal AS refusal from discovery, transport and delivery
/// failures. No automatic retry, polling, payment or direct-signing fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FederationFailureReason {
    /// Host could not discover/admit the configured AS endpoint.
    EndpointUnavailable,
    /// Discovered endpoint was not an acceptable HTTPS token target.
    InvalidEndpoint,
    /// Host could not complete its bounded authenticated exchange.
    TransportUnavailable,
    /// Buffered AS body exceeded the library bound; host must also bound collection.
    ResponseTooLarge,
    /// Response framing/content was unusable; explanation is a fixed local string.
    MalformedResponse(&'static str),
    /// AS requested an unsupported deferred/payment exchange or returned a redirect.
    UnsupportedResponse,
    /// Well-formed terminal AS error, relayed using its status/error in the PS's
    /// own problem body. Other fields below remain host-private diagnostics.
    TerminalError {
        /// Validated AS problem error identifier, at most 128 ASCII bytes.
        error: String,
        /// AS's Signature-Error field, at most 1024 bytes; refers to the PS proof,
        /// never to the Agent proof presented to this Person Server.
        signature_error: Option<String>,
        /// AS's problem detail, at most 4096 bytes. The host chooses whether/how
        /// to log this untrusted remote text; it is never forwarded automatically.
        detail: Option<String>,
    },
    /// Returned Auth JWT failed parsing, issuer/key trust or signature verification.
    TokenVerification(aauth_rust_core::TokenError),
    /// Verified grant did not match requested identity, audience, scope or lifetimes.
    InvalidGrant,
    /// Grant expired before the PS could release it after retention.
    ExpiredBeforeRelease,
}
