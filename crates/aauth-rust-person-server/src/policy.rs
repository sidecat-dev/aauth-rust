use crate::{Binding, TokenRecord};
use aauth_rust_core::{VerifiedAgentToken, VerifiedResourceToken};
use serde_json::Value;

/// Named host policy for PersonServer values stored in application state.
pub type BoxedPolicy = Box<dyn Policy>;

/// Captured trusted clock returning current Unix seconds; safe to share in state.
pub type BoxedClock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Captured fresh issuance-ID source; safe to share in state. Host owns uniqueness.
pub type BoxedTokenIds = Box<dyn Fn() -> String + Send + Sync>;

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
    /// Verified active host-approved mission, never a raw Agent assertion.
    pub mission: Option<crate::MissionRecord>,
    /// Authenticated requesting Agent, whose HTTP proof also verified.
    pub agent: VerifiedAgentToken,
    /// Verified child receiving the credential; the parent in agent owns consent.
    pub subagent: Option<VerifiedAgentToken>,
    /// Canonical Resource audience requested in the signed JSON.
    pub resource: String,
    /// Existing direct binding; upstream requests do not use intermediary bindings.
    pub binding: Option<Binding>,
    /// Original caller context on an explicitly chained request.
    pub upstream: Option<UpstreamContext>,
    /// Signed request parameters, including untrusted display/login hints.
    pub parameters: Value,
}

impl PersonRequest {
    /// Whether this request would bind the agent to a person for the first
    /// time (`draft-hardt-oauth-aauth-protocol`, Agent-Person Binding). The
    /// consent screen should then present it as a new-agent enrollment,
    /// showing the agent provider's `name` and `logo_uri`, read from its
    /// metadata with [`aauth_rust_core::MetadataDisplay::from_metadata`],
    /// beside the agent-asserted `platform` and `device` in
    /// [`Self::parameters`]. A chained request never enrolls.
    pub fn enrolls_agent(&self) -> bool {
        self.binding.is_none() && self.upstream.is_none()
    }
}

/// Complete verified exchange context, before any Auth credential is released.
pub struct AuthorizationRequest {
    /// Verified active host-approved mission, matched to presented context.
    pub mission: Option<crate::MissionRecord>,
    /// Authenticated requesting Agent and verified HTTP proof holder.
    pub agent: VerifiedAgentToken,
    /// Verified child holder, independently bound to Resource and presented token.
    pub subagent: Option<VerifiedAgentToken>,
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
    /// Consent to an already verified four-party exchange before the PS contacts
    /// the AS. Default denial keeps existing direct policies closed to federation.
    fn consent(&self, _request: &AuthorizationRequest) -> Result<(), PolicyError> {
        Err(PolicyError::Denied)
    }
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

impl<P: Policy + ?Sized> Policy for Box<P> {
    fn consent(&self, request: &AuthorizationRequest) -> Result<(), PolicyError> {
        (**self).consent(request)
    }
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        (**self).bind_person(request)
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        (**self).authorize(request)
    }
    fn bind_upstream(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        (**self).bind_upstream(request)
    }
    fn authorize_upstream(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        (**self).authorize_upstream(request)
    }
}
