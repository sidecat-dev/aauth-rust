use crate::{Binding, TokenRecord};
use aauth_rust_core::{VerifiedAgentToken, VerifiedResourceToken};
use serde_json::Value;

/// Host-authenticated accountable person and a Resource-directed public identity.
#[derive(Clone, Debug)]
pub struct Person {
    /// Stable internal person ID; never publish this identifier in protocol JWTs.
    pub id: String,
    /// Stable opaque subject for this person at the requested Resource.
    pub subject: String,
    /// Current organization context, distinct from the person's identifier.
    pub tenant: Option<String>,
}

/// Verified original caller credential recovered from exact retained issuance.
#[derive(Clone, Debug)]
pub struct UpstreamContext {
    /// Complete retained upstream issuance and original accountable Agent.
    pub record: TokenRecord,
    /// Upstream authorization scopes, or None for an identity-only Person token.
    pub scope: Option<String>,
}

/// Verified context passed to person binding or explicit downstream policy.
pub struct PersonRequest {
    /// Authenticated requesting Agent, whose HTTP proof also verified.
    pub agent: VerifiedAgentToken,
    /// Canonical Resource audience requested in the signed JSON.
    pub resource: String,
    /// Existing direct binding; upstream requests do not use intermediary bindings.
    pub binding: Option<Binding>,
    /// Original caller context on an explicitly chained request.
    pub upstream: Option<UpstreamContext>,
    /// Signed request parameters, including untrusted display/login hints.
    pub parameters: Value,
}

/// Complete verified exchange context, before any Auth credential is released.
pub struct AuthorizationRequest {
    /// Authenticated requesting Agent and verified HTTP proof holder.
    pub agent: VerifiedAgentToken,
    /// Authenticated Resource challenge with matched presented-token lineage.
    pub resource: VerifiedResourceToken,
    /// Exact retained presented issuance, including internal accountable person.
    pub presented: TokenRecord,
    /// Requested Core scopes, validated as nonempty distinct scope values.
    pub scopes: Vec<String>,
    /// Original caller context on an explicitly chained request.
    pub upstream: Option<UpstreamContext>,
    /// Signed JSON parameters; display values remain Agent assertions.
    pub parameters: Value,
}

/// Host grant, constrained by requested scope and all verified parent lifetimes.
#[derive(Clone, Debug)]
pub struct Grant {
    /// Nonempty distinct subset of the Resource's requested scopes.
    pub scopes: Vec<String>,
    /// Desired positive lifetime in Unix seconds, at most 3600.
    pub lifetime: i64,
}

/// Intentional refusal is separate from an operational policy failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// Authenticated person or authorization policy refused this request.
    Denied,
    /// A required host policy service is unavailable.
    Unavailable,
    /// The host needs user interaction but has no implemented interaction channel.
    UserUnreachable,
}

/// Host authentication, directed identity and authorization decisions.
/// Never treat login_hint or tenant parameters alone as person authentication.
pub trait Policy: Send + Sync {
    /// Authenticate/resolve the direct Agent's person and directed subject.
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError>;
    /// Authorize a verified direct exchange, returning only requested scopes.
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError>;
    /// Explicitly permit a downstream identity for the original caller's person.
    /// Default refusal prevents existing direct policies from granting delegation.
    fn bind_upstream(&self, _request: &PersonRequest) -> Result<Person, PolicyError> {
        Err(PolicyError::Denied)
    }
    /// Explicitly authorize a downstream operation using verified upstream context.
    /// Downstream scope need not be a syntactic subset of upstream scope.
    fn authorize_upstream(&self, _request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}
