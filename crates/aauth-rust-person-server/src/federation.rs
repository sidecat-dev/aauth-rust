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
