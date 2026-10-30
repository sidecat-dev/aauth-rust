//! Immediate Person-Server authorization with route challenges.
//! Mission context is opt-in through `with_mission_context`.
//! Budgets are opt-in through `with_budgets`.
//! Immediate class R3 is opt-in through `with_r3`.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::budget_gate::{BudgetGate, metadata_units, problem};
use crate::{Decision, Deny, PolicyOutcome, SignatureFailure};
use aauth_rust_budgets::{
    Budget, BudgetHeader, ChargeError, ConsumptionRecord, KeyRole, Ledger, MAX_AMOUNT, Reservation,
    UnitDeclaration, answer_usage, metered_access_mode, parse_budget, parse_usage_query,
    read_granted, sender_field, sign_usage_response, validate_endpoint_url,
};
use aauth_rust_core::interaction::ResourceInteraction;
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthToken, MetadataDisplay, PersonToken, ResourceClaims,
    TokenError, VerifiedAuthToken, mint_resource_token, validate_server_identifier,
};
use aauth_rust_jose::{Jws, SigningKey, strict_json};
use aauth_rust_signature_key::{
    Error, KeyMaterial, PreparedRequest, canonical_authority, required_components,
};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
enum Meter {
    Buffered,
    Reserve,
    Observe,
}

#[path = "resource_revocation.rs"]
mod revocation;

#[path = "r3_call_directory.rs"]
mod r3_call_directory;
#[path = "r3_class.rs"]
mod r3_class;
pub use r3_call_directory::DirectoryCallStore;
#[path = "r3_document_directory.rs"]
mod r3_document_directory;
pub use r3_class::{
    BoxedR3Describe, BoxedR3Display, BoxedR3OperationMapper, BoxedR3Present, BoxedR3Release,
    R3CallDescription, R3CallResult, R3CallStore, R3CallToken, R3Claim, R3Config, R3Definitions,
    R3DocumentRecord, R3DocumentStore, R3Grant, R3HeldRequest, R3HostError, R3PendingHeaders,
    R3PerCallConfig, R3ProposalRecord, R3Release, R3StoreError, R3Vocabulary,
};
pub use r3_document_directory::DirectoryDocumentStore;

/// Named captured-state policy for a PS-authorized Resource in application state.
pub type BoxedAuthPolicy = Box<dyn Fn(&VerifiedAuthToken, &Request<Vec<u8>>) -> bool + Send + Sync>;

/// Named PS Auth policy returning application context to the admitted handler.
pub type BoxedAuthAdmissionPolicy<T> =
    Box<dyn Fn(&VerifiedAuthToken, &Request<Vec<u8>>) -> Result<T, Deny> + Send + Sync>;

/// Host configuration for one origin and one fixed route scope profile.
/// The host router owns which paths use this profile.
pub struct PsAuthorizationConfig {
    /// Canonical published Resource identity, without port or path.
    pub issuer: String,
    /// Actual HTTPS request origin; a configured nondefault port is allowed.
    pub signed_origin: String,
    /// Nonempty JWKS identifier of the Resource signing key.
    pub kid: String,
    /// Caller-owned Resource signing key; secret bytes are never serialized.
    pub signing_key: SigningKey,
    /// Nonempty unique scope values required by every route using this value.
    pub scopes: Vec<String>,
    /// Host-authored Markdown description of each value in `scopes`, published
    /// as `scope_descriptions`. It must name exactly `scopes`: a Resource token
    /// carries only scopes the Resource has defined there.
    pub scope_descriptions: BTreeMap<String, String>,
}

/// Local configuration failure, separate from request authentication failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsConfigurationError {
    /// Published identity is not a canonical HTTPS DNS origin.
    InvalidIssuer,
    /// Signed origin has an invalid authority, path, query or fragment.
    InvalidOrigin,
    /// The signing key identifier is empty.
    InvalidKeyId,
    /// Scope profile is empty, duplicated, malformed, or not described exactly.
    InvalidScopes,
    /// Expected Access Server identifier is malformed.
    InvalidAccessServer,
    /// Budget units, bounds, or `usage_endpoint` are not a usable profile.
    InvalidBudgetProfile,
    /// R3 definitions, registry or composition are not a usable class profile.
    InvalidR3Profile,
}
impl std::fmt::Display for PsConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidAccessServer => {
                "Access Server must be a canonical HTTPS server identifier"
            }
            Self::InvalidIssuer => {
                "Resource issuer must be a canonical HTTPS DNS origin without port or path"
            }
            Self::InvalidOrigin => {
                "signed_origin must be an absolute HTTPS origin without path, query or fragment"
            }
            Self::InvalidKeyId => "Resource kid must name its published signing key",
            Self::InvalidScopes => {
                "Resource scopes must be nonempty unique RFC 6749 scope values, each with a description"
            }
            Self::InvalidBudgetProfile => {
                "budget profile needs declared units, a finite bound, and an HTTPS usage endpoint"
            }
            Self::InvalidR3Profile => {
                "R3 needs registered authoritative definitions; missions compose only with direct class R3"
            }
        })
    }
}
impl std::error::Error for PsConfigurationError {}

/// Verified PS-issued Auth token and application context returned by host policy.
#[derive(Debug)]
pub struct AuthAuthorized<T = ()> {
    token: VerifiedAuthToken,
    admitted: T,
    budget_header: Option<String>,
    admitted_maximum: Option<i64>,
    r3: Option<R3Grant>,
}
impl<T> AuthAuthorized<T> {
    /// Authenticated authorization token whose HTTP holder proof also succeeded.
    pub fn token(&self) -> &VerifiedAuthToken {
        &self.token
    }
    /// Application context produced by the admission policy.
    pub fn admitted(&self) -> &T {
        &self.admitted
    }
    /// Class grant that admitted a mapped R3 route. `None` on a Core route.
    pub fn r3_grant(&self) -> Option<&R3Grant> {
        self.r3.as_ref()
    }
    /// `AAuth-Budget` field value for this admission, when the request was metered.
    pub fn budget_header(&self) -> Option<&str> {
        self.budget_header.as_deref()
    }
    /// Maximum the host may serve for this admission.
    ///
    /// The host supplies the cost bound. A client `AAuth-Max-Cost` can only lower
    /// it. The host must not perform work beyond this figure.
    pub fn admitted_maximum(&self) -> Option<i64> {
        self.admitted_maximum
    }
    /// Move authenticated token and policy context to the application handler.
    pub fn into_parts(self) -> (VerifiedAuthToken, T) {
        (self.token, self.admitted)
    }
}

/// Proof, audience, revocation, and scope succeeded, and the admitted maximum is reserved.
///
/// The reservation is not committed. The host bounds served work to
/// [`Self::admitted_maximum`], then [`PsAuthorizationResource::budget_commit`] or
/// [`PsAuthorizationResource::budget_release`]. Calling [`PsAuthorizationResource::authorize`]
/// on the same request would meter it again. Dropping the hold, including by
/// [`AuthDecision::into_response`] or [`AuthDecision::into_result`], releases the
/// reservation. The grant and `as_of` return to where they were. A commit that
/// already removed the hold is left alone.
pub struct HeldAdmission<T = ()> {
    token: VerifiedAuthToken,
    admitted: T,
    reservation: Reservation,
    admitted_maximum: i64,
    gate: Arc<BudgetGate>,
    r3: Option<R3Grant>,
}
impl<T: std::fmt::Debug> std::fmt::Debug for HeldAdmission<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeldAdmission")
            .field("token", &self.token)
            .field("admitted", &self.admitted)
            .field("reservation", &self.reservation)
            .field("admitted_maximum", &self.admitted_maximum)
            .field("r3", &self.r3)
            .finish()
    }
}
impl<T> Drop for HeldAdmission<T> {
    fn drop(&mut self) {
        self.gate.release(&self.reservation);
    }
}
impl<T> HeldAdmission<T> {
    /// Authenticated authorization token whose HTTP holder proof also succeeded.
    pub fn token(&self) -> &VerifiedAuthToken {
        &self.token
    }
    /// Application context produced by the admission policy.
    pub fn admitted(&self) -> &T {
        &self.admitted
    }
    /// Outstanding reservation. It has not been committed.
    pub fn reservation(&self) -> &Reservation {
        &self.reservation
    }
    /// Maximum the host may serve. The reservation covers this figure.
    pub fn admitted_maximum(&self) -> i64 {
        self.admitted_maximum
    }
    /// Class grant that admitted a mapped R3 route. `None` on a Core route.
    pub fn r3_grant(&self) -> Option<&R3Grant> {
        self.r3.as_ref()
    }
}

/// Proof, audience, revocation, and scope succeeded, and nothing was metered.
///
/// The host meters once with [`PsAuthorizationResource::budget_reserve`] or
/// [`PsAuthorizationResource::budget_complete_held`]. The host must not serve more
/// than [`Self::admitted_maximum`] when that figure is present.
#[derive(Debug)]
pub struct ObservedAdmission<T = ()> {
    token: VerifiedAuthToken,
    admitted: T,
    admitted_maximum: Option<i64>,
    r3: Option<R3Grant>,
}
impl<T> ObservedAdmission<T> {
    /// Class grant that admitted a mapped R3 route. `None` on a Core route.
    pub fn r3_grant(&self) -> Option<&R3Grant> {
        self.r3.as_ref()
    }
    /// Authenticated authorization token whose HTTP holder proof also succeeded.
    pub fn token(&self) -> &VerifiedAuthToken {
        &self.token
    }
    /// Application context produced by the admission policy.
    pub fn admitted(&self) -> &T {
        &self.admitted
    }
    /// Maximum the host may serve, when the token carries a budget.
    pub fn admitted_maximum(&self) -> Option<i64> {
        self.admitted_maximum
    }
}

/// Result of immediate Person-Server Resource authorization.
pub enum AuthDecision<T = ()> {
    /// No Person/Auth credential was verified; obtain a Person token first.
    PersonTokenRequired,
    /// A verified person or auth token is revoked. No resource token is issued.
    Revoked {
        /// The refused credential was an auth token, so the requirement is a person token.
        auth_token: bool,
        /// `AAuth-Budget` when the refused credential is an unexpired budgeted auth token.
        budget_header: Option<String>,
    },
    /// Verified Person identity requires PS authorization before application use.
    AuthTokenRequired {
        /// Resource-signed challenge to exchange with the actual presented token.
        resource_token: String,
        /// `budget-exhausted` or `insufficient-budget` when a grant did not fit.
        budget_reason: Option<String>,
        /// `AAuth-Budget` on the challenge. Absent when this step is not metered.
        budget_header: Option<String>,
    },
    /// JWT or HTTP proof verification failed before host policy.
    SignatureFailure(SignatureFailure),
    /// Verified authorization is insufficient or host policy refused admission.
    Forbidden {
        /// `AAuth-Budget` when a budgeted auth token was refused without metering.
        budget_header: Option<String>,
    },
    /// Held-invocation polling accepts only GET.
    MethodNotAllowed {
        /// `AAuth-Budget` when the request bore a budgeted auth token.
        budget_header: Option<String>,
    },
    /// The pending id is not a stored held invocation.
    Gone {
        /// `AAuth-Budget` when the request bore a budgeted auth token.
        budget_header: Option<String>,
    },
    /// The host still holds this held grant and has not retained a result.
    /// The poll stays pending. The invocation does not run again.
    StillPending {
        /// Pending URL at this Resource's signed origin.
        location: String,
    },
    /// The host still holds this `401` retry grant and has not retained a result.
    /// The same token can be presented again. The invocation does not run again.
    TemporarilyUnavailable,
    /// Host-supplied challenge identifier/time could not produce a valid token.
    InternalError,
    /// Verified Auth token, holder proof, route scopes and host policy admitted it.
    Granted(Box<AuthAuthorized<T>>),
    /// Verified and reserved, not committed. The host finishes metering.
    Held(Box<HeldAdmission<T>>),
    /// Verified without reserving or committing. The host meters once.
    Observed(Box<ObservedAdmission<T>>),
    /// An R3 per-call operation was challenged and its invocation is held
    /// (`202`). The Agent obtains a per-call Auth token and presents it at
    /// `location`; the held call runs once there.
    R3Pending {
        /// Resource token referencing the retained proposal.
        resource_token: String,
        /// Pending URL at this Resource's signed origin. Its last segment is a
        /// fresh random pending id, not the challenge identifier.
        location: String,
    },
    /// The retained result for this exact per-call Auth token: a replay of
    /// the one execution it authorized, or a release-gated result released
    /// now on its first presentation. Nothing runs; the host sends it as is.
    Replayed(Box<Response<Vec<u8>>>),
}
impl<T> std::fmt::Debug for AuthDecision<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PersonTokenRequired => f.write_str("PersonTokenRequired"),
            Self::Revoked { auth_token, .. } => f
                .debug_struct("Revoked")
                .field("auth_token", auth_token)
                .finish_non_exhaustive(),
            Self::AuthTokenRequired { .. } => {
                f.debug_struct("AuthTokenRequired").finish_non_exhaustive()
            }
            Self::SignatureFailure(error) => {
                f.debug_tuple("SignatureFailure").field(error).finish()
            }
            Self::Forbidden { .. } => f.write_str("Forbidden"),
            Self::MethodNotAllowed { .. } => f.write_str("MethodNotAllowed"),
            Self::Gone { .. } => f.write_str("Gone"),
            Self::StillPending { location } => f
                .debug_struct("StillPending")
                .field("location", location)
                .finish(),
            Self::TemporarilyUnavailable => f.write_str("TemporarilyUnavailable"),
            Self::InternalError => f.write_str("InternalError"),
            Self::Granted(value) => f
                .debug_struct("Granted")
                .field("token", &value.token)
                .finish_non_exhaustive(),
            Self::Held(value) => f
                .debug_struct("Held")
                .field("token", &value.token)
                .field("admitted_maximum", &value.admitted_maximum)
                .finish_non_exhaustive(),
            Self::Observed(value) => f
                .debug_struct("Observed")
                .field("token", &value.token)
                .field("admitted_maximum", &value.admitted_maximum)
                .finish_non_exhaustive(),
            Self::R3Pending { location, .. } => f
                .debug_struct("R3Pending")
                .field("location", location)
                .finish_non_exhaustive(),
            Self::Replayed(response) => {
                f.debug_tuple("Replayed").field(&response.status()).finish()
            }
        }
    }
}
impl<T> AuthDecision<T> {
    /// Move authenticated Auth claims and policy context to application handling.
    ///
    /// # Errors
    /// Returns the mapped HTTP challenge, authentication failure or refusal.
    pub fn into_result(self) -> Result<(VerifiedAuthToken, T), Box<Response<Vec<u8>>>> {
        match self {
            Self::Granted(value) => Ok((*value).into_parts()),
            other => Err(Box::new(other.into_response())),
        }
    }
    /// Map challenges/refusals to HTTP. Granted writes the authenticated subject.
    /// Applications normally use into_result and implement their own response.
    pub fn into_response(self) -> Response<Vec<u8>> {
        match self {
            Self::SignatureFailure(failure) => {
                let mut response = Decision::<()>::SignatureFailure(failure).into_response();
                // The shared Agent diagnostics must not advertise Agent-only access.
                response.headers_mut().remove("aauth-requirement");
                response
            }
            Self::Granted(value) => {
                let mut response = Response::new(value.token.claims().sub.as_bytes().to_vec());
                insert_budget(&mut response, value.budget_header);
                response
            }
            Self::PersonTokenRequired => {
                let mut response = refusal(StatusCode::UNAUTHORIZED, "person_token_required");
                response.headers_mut().insert(
                    "aauth-requirement",
                    "requirement=person-token".parse().unwrap(),
                );
                response
            }
            Self::Revoked {
                auth_token,
                budget_header,
            } => {
                let mut response = revoked_jwt();
                if auth_token {
                    response.headers_mut().insert(
                        "aauth-requirement",
                        "requirement=person-token"
                            .parse()
                            .expect("static requirement"),
                    );
                }
                insert_budget(&mut response, budget_header);
                response
            }
            Self::AuthTokenRequired {
                resource_token,
                budget_reason,
                budget_header,
            } => {
                let mut response = refusal(StatusCode::UNAUTHORIZED, "auth_token_required");
                let mut requirement =
                    format!("requirement=auth-token;resource-token=\"{resource_token}\"");
                if let Some(reason) = budget_reason {
                    requirement.push_str(&format!(";reason={reason}"));
                }
                let Ok(value) = requirement.parse() else {
                    return refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
                };
                response.headers_mut().insert("aauth-requirement", value);
                insert_budget(&mut response, budget_header);
                response
            }
            Self::Forbidden { budget_header } => {
                let mut response = refusal(StatusCode::FORBIDDEN, "access_denied");
                insert_budget(&mut response, budget_header);
                response
            }
            Self::MethodNotAllowed { budget_header } => {
                let mut response = refusal(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
                response
                    .headers_mut()
                    .insert("allow", "GET".parse().expect("static allow"));
                insert_budget(&mut response, budget_header);
                response
            }
            Self::Gone { budget_header } => {
                let mut response = refusal(StatusCode::GONE, "gone");
                insert_budget(&mut response, budget_header);
                response
            }
            // The host still holds the grant. This is the same pending answer as
            // the original 202, without a new resource token: the agent already
            // has the auth token and is polling. Dropping the grant without a
            // retained result is `500`, not another 202.
            Self::StillPending { location } => {
                let mut response =
                    Response::new(json!({"status":"pending"}).to_string().into_bytes());
                *response.status_mut() = StatusCode::ACCEPTED;
                let Ok(location) = location.parse() else {
                    return refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
                };
                let headers = response.headers_mut();
                headers.insert("location", location);
                headers.insert("retry-after", "1".parse().expect("static retry"));
                headers.insert("cache-control", "no-store".parse().expect("static cache"));
                headers.insert(
                    "content-type",
                    "application/json".parse().expect("static content type"),
                );
                response
            }
            // The host still holds the 401 retry. Go's retry conflict is 503
            // with Retry-After 1. Dropping the grant without a retained result
            // is 500, not another 503.
            Self::TemporarilyUnavailable => {
                let mut response =
                    refusal(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
                response
                    .headers_mut()
                    .insert("retry-after", "1".parse().expect("static retry"));
                response
            }
            // A hold or an unmetered admission is not an HTTP grant. Mapping it
            // here does not commit the reservation. Dropping the hold releases it.
            Self::Held(_) | Self::Observed(_) => {
                refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
            Self::InternalError => refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            Self::R3Pending {
                resource_token,
                location,
            } => {
                let mut response =
                    Response::new(json!({"status":"pending"}).to_string().into_bytes());
                *response.status_mut() = StatusCode::ACCEPTED;
                let requirement =
                    format!("requirement=auth-token;resource-token=\"{resource_token}\"");
                let (Ok(requirement), Ok(location)) = (requirement.parse(), location.parse())
                else {
                    return refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
                };
                let headers = response.headers_mut();
                headers.insert("aauth-requirement", requirement);
                headers.insert("location", location);
                headers.insert("retry-after", "1".parse().expect("static retry"));
                headers.insert("cache-control", "no-store".parse().expect("static cache"));
                headers.insert(
                    "content-type",
                    "application/json".parse().expect("static content type"),
                );
                response
            }
            Self::Replayed(response) => *response,
        }
    }
}
/// Result of a proactive authorization-endpoint request.
pub enum ProactiveDecision {
    /// The request did not present a verified person token.
    PersonTokenRequired,
    /// The presented person token is revoked. No resource token is issued.
    Revoked,
    /// The person token or HTTP proof failed verification.
    SignatureFailure(SignatureFailure),
    /// `scope` is missing, empty, or not a string.
    InvalidRequest,
    /// `scope` names a value this resource does not publish.
    InvalidScope,
    /// The person token and scope were verified. The resource token carries that scope.
    ResourceToken {
        /// Resource-signed token for the Person Server or Access Server.
        resource_token: String,
    },
    /// The host challenge identifier could not be minted.
    InternalError,
    /// A budget object was present and could not be narrowed.
    InvalidBudget,
    /// The R3 document store conflicted or failed. No resource token is released.
    RetentionFailed,
}
impl ProactiveDecision {
    /// Map the decision to the authorization-endpoint HTTP response.
    pub fn into_response(self) -> Response<Vec<u8>> {
        match self {
            Self::PersonTokenRequired => {
                let mut response = refusal(StatusCode::UNAUTHORIZED, "person_token_required");
                response.headers_mut().insert(
                    "aauth-requirement",
                    "requirement=person-token".parse().unwrap(),
                );
                response
            }
            Self::Revoked => revoked_jwt(),
            Self::SignatureFailure(failure) => {
                let mut response = Decision::<()>::SignatureFailure(failure).into_response();
                response.headers_mut().remove("aauth-requirement");
                response
            }
            Self::InvalidRequest => refusal(StatusCode::BAD_REQUEST, "invalid_request"),
            Self::InvalidScope => refusal(StatusCode::BAD_REQUEST, "invalid_scope"),
            Self::InvalidBudget => refusal(StatusCode::BAD_REQUEST, "invalid_budget"),
            Self::ResourceToken { resource_token } => {
                let mut response = Response::new(
                    json!({ "resource_token": resource_token })
                        .to_string()
                        .into_bytes(),
                );
                *response.status_mut() = StatusCode::OK;
                response.headers_mut().insert(
                    "content-type",
                    "application/json".parse().expect("static content type"),
                );
                response
            }
            Self::InternalError | Self::RetentionFailed => {
                refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
        }
    }
}
fn requested_scope(
    request: &Request<Vec<u8>>,
    allowed: &[String],
) -> Result<String, ProactiveDecision> {
    let Ok(value) = aauth_rust_jose::strict_json(request.body()) else {
        return Err(ProactiveDecision::InvalidRequest);
    };
    let Some(scope) = value.get("scope").and_then(|scope| scope.as_str()) else {
        return Err(ProactiveDecision::InvalidRequest);
    };
    let tokens: Vec<&str> = scope.split(' ').filter(|token| !token.is_empty()).collect();
    if scope.is_empty() || tokens.is_empty() || tokens.len() != scope.split(' ').count() {
        return Err(ProactiveDecision::InvalidRequest);
    }
    if tokens.iter().any(|token| !scope_value(token)) {
        return Err(ProactiveDecision::InvalidRequest);
    }
    if tokens
        .iter()
        .any(|token| !allowed.iter().any(|configured| configured == token))
    {
        return Err(ProactiveDecision::InvalidScope);
    }
    let mut seen = std::collections::BTreeSet::new();
    if tokens.iter().any(|token| !seen.insert(*token)) {
        return Err(ProactiveDecision::InvalidRequest);
    }
    Ok(scope.to_owned())
}
fn refusal(status: StatusCode, code: &str) -> Response<Vec<u8>> {
    typed_refusal(status, code, "about:blank")
}
/// `401 revoked_jwt`. A body sent with `Signature-Error` names that error as its type.
fn revoked_jwt() -> Response<Vec<u8>> {
    let mut response = typed_refusal(
        StatusCode::UNAUTHORIZED,
        "revoked_jwt",
        "urn:ietf:params:sig-error:revoked_jwt",
    );
    response.headers_mut().insert(
        "signature-error",
        "error=revoked_jwt".parse().expect("static signature error"),
    );
    response
}
fn typed_refusal(status: StatusCode, code: &str, kind: &str) -> Response<Vec<u8>> {
    let mut response = Response::new(json!({"type":kind, "title":status.canonical_reason().unwrap_or("Request refused"), "status":status.as_u16(), "error":code}).to_string().into_bytes());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

/// Claims a Resource asked a Person Server to authorize.
///
/// `ps` is that Person Server. A Person token must carry it as `iss` and an
/// Auth token must carry it as `ps`. `sub` and `tenant` are compared only in
/// that namespace, so the same subject string from another server does not
/// match. `sub` is a required field; an empty subject is a host error and
/// authorizes no one. `login_hint` is copied into the resource-token challenge
/// and is not an Auth subject. `account` and `tenant` are exact expectations,
/// including when they are absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationAsk {
    /// Person Server namespace for `sub` and `tenant`.
    pub ps: String,
    /// Hint forwarded unchanged. An empty string is a host error.
    pub login_hint: Option<String>,
    /// Directed subject required on the Person token and the Auth token.
    /// An empty string is a host error, not a wildcard.
    pub sub: String,
    /// Account placed in the challenge and required again on the Auth token.
    pub account: Option<String>,
    /// Tenant required on the Person token and the Auth token, under `ps`.
    pub tenant: Option<String>,
}
impl AuthorizationAsk {
    fn host_error(&self) -> bool {
        validate_server_identifier(&self.ps).is_err()
            || self.sub.is_empty()
            || self.login_hint.as_ref().is_some_and(|hint| hint.is_empty())
            || self
                .account
                .as_ref()
                .is_some_and(|account| account.is_empty())
            || self.tenant.as_ref().is_some_and(|tenant| tenant.is_empty())
    }
    fn person_differs(&self, iss: &str, sub: &str, tenant: Option<&str>) -> bool {
        self.ps != iss || self.sub != sub || self.tenant.as_deref() != tenant
    }
    fn auth_differs(
        &self,
        ps: &str,
        sub: &str,
        account: Option<&str>,
        tenant: Option<&str>,
    ) -> bool {
        self.ps != ps
            || self.sub != sub
            || self.account.as_deref() != account
            || self.tenant.as_deref() != tenant
    }
}

/// PS authorization: credential/holder verification precedes policy.
/// This Resource issues route challenges. [`Self::with_authorization_endpoint`]
/// also publishes a proactive authorization endpoint.
/// The default profile is missionless. [`Self::with_mission_context`] copies a
/// verified Person mission digest into the challenge and admits a PS Auth token
/// that carries one; host policy still decides whether that digest is the mission
/// it asked for. [`PsAuthorizationResource::authorize`] does not ask for a login
/// hint. [`PsAuthorizationResource::authorize_for`] does, and checks the Auth
/// token against that ask. Host keys implement the accepted issuer trust set;
/// host policy owns person-record admission. A Person token is never admitted
/// as authorization.
pub struct PsAuthorizationResource<K, P> {
    config: PsAuthorizationConfig,
    authority: String,
    keys: K,
    policy: P,
    access_server: Option<String>,
    mission_context: bool,
    authorization_endpoint: bool,
    revocation: Option<revocation::Gate>,
    budgets: Option<Arc<BudgetGate>>,
    omit_required: bool,
    r3: Option<Box<r3_class::R3Profile>>,
    /// Proposal URIs whose held execution grant the host still holds.
    executing: Arc<Mutex<BTreeSet<String>>>,
    display: MetadataDisplay,
}
impl<K: AgentKeyResolver, P, O> PsAuthorizationResource<K, P>
where
    P: Fn(&VerifiedAuthToken, &Request<Vec<u8>>) -> O,
    O: PolicyOutcome,
{
    /// Bind a published identity, separately configured signed origin, keys and policy.
    ///
    /// # Errors
    /// Rejects invalid identifiers/origins, empty kid and invalid scope
    /// profiles, including a scope without a nonblank description or a
    /// description for a scope outside the profile.
    pub fn new(
        config: PsAuthorizationConfig,
        keys: K,
        policy: P,
    ) -> Result<Self, PsConfigurationError> {
        validate_server_identifier(&config.issuer)
            .map_err(|_| PsConfigurationError::InvalidIssuer)?;
        let uri: http::Uri = config
            .signed_origin
            .parse()
            .map_err(|_| PsConfigurationError::InvalidOrigin)?;
        if uri.query().is_some()
            || config.signed_origin.contains('#')
            || (!uri.path().is_empty() && uri.path() != "/")
        {
            return Err(PsConfigurationError::InvalidOrigin);
        }
        let authority =
            canonical_authority(&uri).map_err(|_| PsConfigurationError::InvalidOrigin)?;
        if config.kid.is_empty() {
            return Err(PsConfigurationError::InvalidKeyId);
        }
        let mut seen = std::collections::BTreeSet::new();
        if config.scopes.is_empty()
            || config
                .scopes
                .iter()
                .any(|scope| !scope_value(scope) || !seen.insert(scope))
        {
            return Err(PsConfigurationError::InvalidScopes);
        }
        // Every scope a Resource token may carry is defined in the published
        // `scope_descriptions`, and nothing else is described there.
        if config.scope_descriptions.len() != config.scopes.len()
            || config.scopes.iter().any(|scope| {
                config
                    .scope_descriptions
                    .get(scope)
                    .is_none_or(|description| description.trim().is_empty())
            })
        {
            return Err(PsConfigurationError::InvalidScopes);
        }
        Ok(Self {
            config,
            authority,
            keys,
            policy,
            access_server: None,
            mission_context: false,
            authorization_endpoint: false,
            revocation: None,
            budgets: None,
            omit_required: false,
            r3: None,
            executing: Arc::new(Mutex::new(BTreeSet::new())),
            display: MetadataDisplay::new(),
        })
    }
    /// Publish `name`, `description`, `logo_uri` and the other display
    /// members in [`Self::metadata`]. A Person Server presents `name`,
    /// `description` and `logo_uri` at consent as resource-asserted content.
    /// The checked values replace any earlier ones.
    pub fn with_display(mut self, display: MetadataDisplay) -> Self {
        self.display = display;
        self
    }
    /// Construct a Resource that trusts the named AS's policy verdict. Challenges
    /// target this AS; only its aauth-access.json Auth tokens may grant access,
    /// including when PS and AS share one identifier. Existing new remains PS-only.
    ///
    /// # Errors
    /// As for new, also rejects an invalid Access Server identifier.
    pub fn new_federated(
        config: PsAuthorizationConfig,
        access_server: &str,
        keys: K,
        policy: P,
    ) -> Result<Self, PsConfigurationError> {
        validate_server_identifier(access_server)
            .map_err(|_| PsConfigurationError::InvalidAccessServer)?;
        let mut resource = Self::new(config, keys, policy)?;
        resource.access_server = Some(access_server.into());
        Ok(resource)
    }
    /// Accept signed mission context on the direct PS path.
    ///
    /// A Person token's `mission_s256` is copied into the Resource challenge.
    /// A PS Auth token carrying one reaches host policy instead of being refused
    /// as an unknown profile. Federated AS Auth remains missionless. The digest
    /// is not a grant: policy must still compare it with the mission it asked for.
    /// With [`Self::with_r3`], a class document records the mission and admits
    /// only an Auth token for it; per-call proposals stay missionless.
    pub fn with_mission_context(mut self) -> Self {
        self.mission_context = true;
        self
    }
    /// Meter auth-token requests against a declared budget profile.
    ///
    /// `default_bound` is the host's maximum cost of a buffered request. A client
    /// `AAuth-Max-Cost` may only lower that figure, and the admitted maximum is
    /// what the host may serve. `default_offer` is the amount placed on a challenge
    /// when the client does not name one. The first unit is the usage report's
    /// unit. An empty declaration list is rejected: a resource that meters has
    /// published `budget_units`.
    ///
    /// # Errors
    /// Returns [`PsConfigurationError::InvalidBudgetProfile`] when the endpoint
    /// is not HTTPS, a bound is outside the carrier, or the units cannot form an offer.
    pub fn with_budgets(
        self,
        units: Vec<UnitDeclaration>,
        usage_endpoint: impl Into<String>,
        default_bound: i64,
        default_offer: i64,
    ) -> Result<Self, PsConfigurationError> {
        self.with_budget_ledger(
            units,
            usage_endpoint,
            default_bound,
            default_offer,
            Arc::new(Mutex::new(Ledger::new())),
        )
    }
    /// Meter with a host-supplied ledger.
    ///
    /// Two Resources that receive the same ledger continue one spend. A
    /// Resource that does not receive it starts empty. A ledger from
    /// [`aauth_rust_budgets::Ledger::new`] is process memory. Sharing that
    /// object is not an operating-system restart. A ledger from
    /// [`aauth_rust_budgets::Ledger::open_directory`] writes the meter to a
    /// directory. A later process that opens the directory continues the spend.
    ///
    /// # Errors
    /// Returns [`PsConfigurationError::InvalidBudgetProfile`] when the endpoint
    /// is not HTTPS, a bound is outside the carrier, or the units cannot form an offer.
    pub fn with_budget_ledger(
        mut self,
        units: Vec<UnitDeclaration>,
        usage_endpoint: impl Into<String>,
        default_bound: i64,
        default_offer: i64,
        ledger: Arc<Mutex<Ledger>>,
    ) -> Result<Self, PsConfigurationError> {
        metered_access_mode("auth-token")
            .map_err(|_| PsConfigurationError::InvalidBudgetProfile)?;
        let usage_endpoint = usage_endpoint.into();
        validate_endpoint_url(&usage_endpoint)
            .map_err(|_| PsConfigurationError::InvalidBudgetProfile)?;
        if units.is_empty()
            || !(0..=MAX_AMOUNT).contains(&default_bound)
            || !(0..=MAX_AMOUNT).contains(&default_offer)
        {
            return Err(PsConfigurationError::InvalidBudgetProfile);
        }
        let mut seen = std::collections::BTreeSet::new();
        if units
            .iter()
            .any(|unit| !seen.insert(unit.unit().to_owned()))
        {
            return Err(PsConfigurationError::InvalidBudgetProfile);
        }
        aauth_rust_budgets::offer_budget(&units, None, default_offer)
            .map_err(|_| PsConfigurationError::InvalidBudgetProfile)?;
        self.budgets = Some(Arc::new(BudgetGate {
            units: Mutex::new(units),
            usage_endpoint,
            default_bound,
            default_offer,
            omit_required: AtomicBool::new(self.omit_required),
            ledger,
        }));
        Ok(self)
    }
    /// The ledger this Resource meters, when budgets are enabled.
    ///
    /// The host can pass it to [`Self::with_budget_ledger`] on another Resource.
    pub fn budget_ledger(&self) -> Option<Arc<Mutex<Ledger>>> {
        self.budgets.as_ref().map(|gate| Arc::clone(&gate.ledger))
    }
    /// Omit `required` on an `insufficient-budget` refusal.
    ///
    /// The default sends `required`. Call this when the resource will not state
    /// a cost bound. Exhaustion already omits `required` because nothing remains.
    pub fn without_stated_required(mut self) -> Self {
        self.omit_required = true;
        if let Some(gate) = &self.budgets {
            gate.omit_required.store(true, Ordering::Relaxed);
        }
        self
    }
    /// Replace cached `budget_units` after challenges have been issued.
    ///
    /// Later metering still uses the unit and scale on each auth token.
    ///
    /// # Errors
    /// Returns [`PsConfigurationError::InvalidBudgetProfile`] when budgets are
    /// off or the replacement cannot form an offer.
    pub fn replace_budget_units(
        &self,
        units: Vec<UnitDeclaration>,
    ) -> Result<(), PsConfigurationError> {
        let Some(gate) = &self.budgets else {
            return Err(PsConfigurationError::InvalidBudgetProfile);
        };
        if units.is_empty() {
            return Err(PsConfigurationError::InvalidBudgetProfile);
        }
        aauth_rust_budgets::offer_budget(&units, None, gate.default_offer)
            .map_err(|_| PsConfigurationError::InvalidBudgetProfile)?;
        *gate
            .units
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = units;
        Ok(())
    }
    /// Publish `{issuer}/authorize` for a proactive scope request.
    ///
    /// The route still requires a verified person token. Metadata omits
    /// `authorization_endpoint` until this is called.
    pub fn with_authorization_endpoint(mut self) -> Self {
        self.authorization_endpoint = true;
        self
    }
    /// Accurate public metadata; serve at the published Resource well-known path.
    /// `scope_descriptions` is always present and names exactly the configured
    /// scopes. It adds no authorization endpoint; host routing and actual
    /// revision/payload policy must implement the advertised meaning.
    /// `revocation_endpoint` is present only after [`Self::with_revocation`].
    /// `authorization_endpoint` is present only after [`Self::with_authorization_endpoint`].
    /// `r3_vocabularies` is present only after [`Self::with_r3`] and names each
    /// selected definition's discovery endpoint.
    /// AS selection is carried by its signed challenge audience.
    /// Display members are present after [`Self::with_display`].
    ///
    /// # Errors
    /// Returns a serialization error as InvalidJwt.
    pub fn metadata(&self) -> Result<Vec<u8>, TokenError> {
        let mut metadata = json!({"issuer":self.config.issuer,"jwks_uri":format!("{}/.well-known/jwks.json",self.config.issuer),"access_mode":"auth-token","signature_window":60});
        metadata["scope_descriptions"] = json!(self.config.scope_descriptions);
        if self.revocation.is_some() {
            metadata["revocation_endpoint"] = json!(format!("{}/revoke", self.config.issuer));
        }
        if self.authorization_endpoint {
            // Under R3 every endpoint this Resource serves is named at its signed
            // origin, as its document URIs are. Core-only keeps the issuer form.
            let origin = match self.r3_document_origin() {
                Some(origin) => origin,
                None => self.config.issuer.clone(),
            };
            metadata["authorization_endpoint"] = json!(format!("{origin}/authorize"));
        }
        if let Some(gate) = &self.budgets {
            metadata["budget_units"] = metadata_units(&gate.declarations());
            metadata["usage_endpoint"] = json!(gate.usage_endpoint);
        }
        if let Some(vocabularies) = self.r3_metadata() {
            metadata["r3_vocabularies"] = vocabularies;
        }
        for (member, value) in self.display.members() {
            metadata[member] = json!(value);
        }
        serde_json::to_vec(&metadata).map_err(|_| TokenError::InvalidJwt)
    }
    /// Public Resource signing key with its configured kid, without secret bytes.
    ///
    /// # Errors
    /// Returns a serialization error as InvalidJwt.
    pub fn jwks(&self) -> Result<Vec<u8>, TokenError> {
        let mut jwk = serde_json::to_value(self.config.signing_key.public_jwk())
            .map_err(|_| TokenError::InvalidJwt)?;
        jwk["kid"] = json!(self.config.kid);
        serde_json::to_vec(&json!({"keys":[jwk]})).map_err(|_| TokenError::InvalidJwt)
    }
    /// Verify one actual buffered request, then challenge or invoke Auth policy.
    /// Host supplies trusted Unix seconds and a fresh challenge identifier. Proof
    /// coverage/body bounds follow Signature-Key's 1 MiB buffered profile and
    /// 60-second window. Direct mode accepts PS Auth; new_federated accepts only
    /// its configured AS issuer and discovery role. Missions are refused unless
    /// `with_mission_context` is set, and AS missions stay refused either way.
    /// Known companion authority claims are refused by this immediate Core-scope profile.
    pub fn authorize(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
    ) -> AuthDecision<O::Context> {
        let authority = match canonical_authority(request.uri()) {
            Ok(value) => value,
            Err(error) => return AuthDecision::SignatureFailure(SignatureFailure::Proof(error)),
        };
        if authority != self.authority {
            return AuthDecision::SignatureFailure(SignatureFailure::Proof(Error::TargetMismatch));
        }
        if !(0..=(1_i64 << 33) - 1).contains(&now) {
            return AuthDecision::SignatureFailure(SignatureFailure::Proof(Error::InvalidClock));
        }
        if ["signature-key", "signature-input", "signature"]
            .iter()
            .all(|name| !request.headers().contains_key(*name))
        {
            return AuthDecision::PersonTokenRequired;
        }
        match self.authorize_proved(request, now, challenge_jti, None, None, Meter::Buffered) {
            Ok(decision) => decision,
            Err(error) => AuthDecision::SignatureFailure(error),
        }
    }
    /// Verify the request, then reserve the admitted maximum without committing it.
    ///
    /// Proof, audience, revocation, and scope are the same checks as
    /// [`Self::authorize`]. A budgeted token that fits returns [`AuthDecision::Held`].
    /// The host bounds served work to the admitted maximum, then commits or releases.
    /// [`Self::authorize`] on the same request would reserve and commit a second time.
    pub fn authorize_reserved(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
    ) -> AuthDecision<O::Context> {
        self.authorize_with(request, now, challenge_jti, Meter::Reserve, None)
    }
    /// Verify the request and do not meter it.
    ///
    /// Proof, audience, revocation, and scope are the same checks as
    /// [`Self::authorize`]. Nothing is reserved or committed. The host meters once
    /// with [`Self::budget_reserve`] or [`Self::budget_complete_held`], and must
    /// not serve more than the admitted maximum. A later call to [`Self::authorize`]
    /// meters the request as a new buffered admission.
    pub fn authorize_observed(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
    ) -> AuthDecision<O::Context> {
        self.authorize_with(request, now, challenge_jti, Meter::Observe, None)
    }
    /// Verify one request like [`Self::authorize`], and put `interaction` in
    /// a Person-token challenge (`draft-hardt-oauth-aauth-protocol`,
    /// Resource-Initiated Interaction).
    ///
    /// Use it when this Resource needs its own user-facing flow, such as an
    /// OAuth authorization at a third-party service, before the Person Server
    /// can issue. Open the claim with [`ResourceInteraction::open`] for the
    /// Resource's interaction endpoint and keep its code. The Person Server
    /// resolves that flow before its own consent: it sends the person to
    /// `{url}?code={code}&callback={ps_callback_url}`, and the endpoint reads
    /// that query with [`aauth_rust_core::interaction::parse_interaction_query`],
    /// whether an agent or a Person Server sent the person. When the flow
    /// ends, successfully or not, the endpoint redirects to `callback` with
    /// [`aauth_rust_core::interaction::completion_redirect`].
    ///
    /// Only the first challenge of a grant, against a Person token, carries the
    /// claim; an Auth token is judged as by [`Self::authorize`]. A request this
    /// Resource maps to an R3 operation is a host error, as R3 does not carry
    /// the claim here.
    pub fn authorize_with_interaction(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
        interaction: &ResourceInteraction,
    ) -> AuthDecision<O::Context> {
        self.authorize_with(
            request,
            now,
            challenge_jti,
            Meter::Buffered,
            Some(interaction),
        )
    }
    fn authorize_with(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
        meter: Meter,
        interaction: Option<&ResourceInteraction>,
    ) -> AuthDecision<O::Context> {
        let authority = match canonical_authority(request.uri()) {
            Ok(value) => value,
            Err(error) => return AuthDecision::SignatureFailure(SignatureFailure::Proof(error)),
        };
        if authority != self.authority {
            return AuthDecision::SignatureFailure(SignatureFailure::Proof(Error::TargetMismatch));
        }
        if !(0..=(1_i64 << 33) - 1).contains(&now) {
            return AuthDecision::SignatureFailure(SignatureFailure::Proof(Error::InvalidClock));
        }
        if ["signature-key", "signature-input", "signature"]
            .iter()
            .all(|name| !request.headers().contains_key(*name))
        {
            return AuthDecision::PersonTokenRequired;
        }
        match self.authorize_proved(request, now, challenge_jti, None, interaction, meter) {
            Ok(decision) => decision,
            Err(error) => AuthDecision::SignatureFailure(error),
        }
    }
    /// Verify one request, and compare its Auth token with `asked`.
    ///
    /// A Person challenge copies `login_hint` and `account` and still copies
    /// `sub` and `tenant` from the presented Person token. The Person token's
    /// `iss` and the Auth token's `ps` must be the asked Person Server, and
    /// `sub`, `account` and `tenant` must match inside that namespace. A
    /// verified token that differs is `403` `access_denied` with no
    /// `Signature-Error` header and does not reach policy. The hint is not
    /// compared to `sub` and is not shown to policy as an identity. A missing
    /// or empty subject, an empty hint, account or tenant, or a `ps` that is
    /// not a server identifier, is a host error.
    pub fn authorize_for(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
        asked: &AuthorizationAsk,
    ) -> AuthDecision<O::Context> {
        if asked.host_error() {
            return AuthDecision::InternalError;
        }
        let authority = match canonical_authority(request.uri()) {
            Ok(value) => value,
            Err(error) => return AuthDecision::SignatureFailure(SignatureFailure::Proof(error)),
        };
        if authority != self.authority {
            return AuthDecision::SignatureFailure(SignatureFailure::Proof(Error::TargetMismatch));
        }
        if !(0..=(1_i64 << 33) - 1).contains(&now) {
            return AuthDecision::SignatureFailure(SignatureFailure::Proof(Error::InvalidClock));
        }
        if ["signature-key", "signature-input", "signature"]
            .iter()
            .all(|name| !request.headers().contains_key(*name))
        {
            return AuthDecision::PersonTokenRequired;
        }
        match self.authorize_proved(
            request,
            now,
            challenge_jti,
            Some(asked),
            None,
            Meter::Buffered,
        ) {
            Ok(decision) => decision,
            Err(error) => AuthDecision::SignatureFailure(error),
        }
    }
    fn authorize_proved(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
        asked: Option<&AuthorizationAsk>,
        interaction: Option<&ResourceInteraction>,
        meter: Meter,
    ) -> Result<AuthDecision<O::Context>, SignatureFailure> {
        if self.r3_composition_refused() {
            return Ok(AuthDecision::InternalError);
        }
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwt"])
            .map_err(|error| match error {
                Error::ClockSkew => SignatureFailure::ClockSkew { server_time: now },
                Error::InvalidInput => SignatureFailure::Input(required_components(request)),
                other => SignatureFailure::Proof(other),
            })?;
        let KeyMaterial::Jwt(compact) = proof.key() else {
            return Err(SignatureFailure::Proof(Error::UnsupportedScheme));
        };
        let parsed = Jws::parse(compact).map_err(|error| SignatureFailure::Token(error.into()))?;
        match parsed.header().get("typ").and_then(|value| value.as_str()) {
            Some("aa-agent+jwt") => {
                let token = AgentToken::parse(compact)
                    .and_then(|token| token.verify(&self.keys, now))
                    .map_err(SignatureFailure::Token)?;
                proof
                    .verify(&token.claims().cnf.jwk)
                    .map_err(SignatureFailure::Proof)?;
                check_iat(token.claims().iat, now)?;
                Ok(AuthDecision::PersonTokenRequired)
            }
            Some("aa-person+jwt") => {
                let parsed = PersonToken::parse(compact).map_err(SignatureFailure::Token)?;
                let issuer = parsed.unverified_claims().iss.clone();
                let jti = parsed.unverified_claims().jti.clone();
                let token = match parsed.verify(&self.keys, now) {
                    Ok(token) => token,
                    Err(TokenError::ExpiredJwt) if self.presented_revoked(&issuer, &jti, now) => {
                        proof
                            .verify(&parsed.unverified_claims().cnf.jwk)
                            .map_err(SignatureFailure::Proof)?;
                        check_iat(parsed.unverified_claims().iat, now)?;
                        if parsed.unverified_claims().aud != self.config.issuer {
                            return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                        }
                        return Ok(AuthDecision::Revoked {
                            auth_token: false,
                            budget_header: None,
                        });
                    }
                    Err(error) => return Err(SignatureFailure::Token(error)),
                };
                let claims = token.claims();
                proof
                    .verify(&claims.cnf.jwk)
                    .map_err(SignatureFailure::Proof)?;
                check_iat(claims.iat, now)?;
                if claims.aud != self.config.issuer {
                    return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                }
                if self.presented_revoked(&issuer, &jti, now) {
                    return Ok(AuthDecision::Revoked {
                        auth_token: false,
                        budget_header: None,
                    });
                }
                if self.mission_refused(claims.mission_s256.is_some())
                    || unsupported_companion(&claims.extra, false, false)
                {
                    return Err(SignatureFailure::Token(TokenError::InvalidJwt));
                }
                let (login_hint, account) = if let Some(asked) = asked {
                    if asked.person_differs(&claims.iss, &claims.sub, claims.tenant.as_deref()) {
                        return Ok(AuthDecision::Forbidden {
                            budget_header: None,
                        });
                    }
                    (asked.login_hint.clone(), asked.account.clone())
                } else {
                    (None, None)
                };
                let extra = match self.idle_offer() {
                    Ok(extra) => extra,
                    Err(()) => return Ok(AuthDecision::InternalError),
                };
                let mut challenge = ResourceClaims {
                    iss: self.config.issuer.clone(),
                    dwk: "aauth-resource.json".into(),
                    aud: self
                        .access_server
                        .clone()
                        .unwrap_or_else(|| claims.iss.clone()),
                    ps: claims.iss.clone(),
                    sub: claims.sub.clone(),
                    jti: challenge_jti.into(),
                    presented_jti: claims.jti.clone(),
                    agent_jkt: claims
                        .cnf
                        .jwk
                        .thumbprint()
                        .map_err(|error| SignatureFailure::Token(error.into()))?,
                    iat: now,
                    exp: challenge_exp(
                        now,
                        self.mission_context && claims.mission_s256.is_some(),
                        claims.exp,
                    ),
                    scope: Some(self.config.scopes.join(" ")),
                    account,
                    login_hint,
                    nbf: None,
                    tenant: claims.tenant.clone(),
                    mission_s256: if self.mission_context {
                        claims.mission_s256.clone()
                    } else {
                        None
                    },
                    extra,
                };
                if let Some(interaction) = interaction {
                    if self.maps_r3_operation(request) {
                        return Ok(AuthDecision::InternalError);
                    }
                    interaction.insert_into(&mut challenge);
                }
                if let Some(decision) = self.r3_challenge(request, &challenge) {
                    return Ok(decision);
                }
                match mint_resource_token(&self.config.signing_key, &self.config.kid, &challenge) {
                    Ok(resource_token) => Ok(AuthDecision::AuthTokenRequired {
                        resource_token,
                        budget_reason: None,
                        budget_header: None,
                    }),
                    Err(_) => Ok(AuthDecision::InternalError),
                }
            }
            Some("aa-auth+jwt") => {
                let parsed = AuthToken::parse(compact).map_err(SignatureFailure::Token)?;
                let issuer = parsed.unverified_claims().iss.clone();
                let jti = parsed.unverified_claims().jti.clone();
                let token = match parsed.verify(&self.keys, now) {
                    Ok(token) => token,
                    Err(TokenError::ExpiredJwt) if self.presented_revoked(&issuer, &jti, now) => {
                        proof
                            .verify(&parsed.unverified_claims().cnf.jwk)
                            .map_err(SignatureFailure::Proof)?;
                        check_iat(parsed.unverified_claims().iat, now)?;
                        if parsed.unverified_claims().aud != self.config.issuer {
                            return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                        }
                        // An expired token's budget expired with it.
                        return Ok(AuthDecision::Revoked {
                            auth_token: true,
                            budget_header: None,
                        });
                    }
                    Err(error) => return Err(SignatureFailure::Token(error)),
                };
                let claims = token.claims();
                proof
                    .verify(&claims.cnf.jwk)
                    .map_err(SignatureFailure::Proof)?;
                check_iat(claims.iat, now)?;
                if claims.aud != self.config.issuer {
                    return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                }
                if self.presented_revoked(&issuer, &jti, now) {
                    let grant = read_granted(&claims.extra).ok().flatten();
                    return Ok(AuthDecision::Revoked {
                        auth_token: true,
                        budget_header: self.untouched_budget(&token, grant.as_ref()),
                    });
                }
                let valid_role = match &self.access_server {
                    Some(issuer) => claims.dwk == "aauth-access.json" && &claims.iss == issuer,
                    None => claims.dwk == "aauth-person.json" && claims.iss == claims.ps,
                };
                if !valid_role
                    || self.mission_refused(claims.mission_s256.is_some())
                    || unsupported_companion(
                        &claims.extra,
                        self.budgets.is_some(),
                        self.r3.is_some(),
                    )
                {
                    return Err(SignatureFailure::Token(TokenError::InvalidJwt));
                }
                let grant = read_granted(&claims.extra)
                    .map_err(|_| SignatureFailure::Token(TokenError::InvalidJwt))?;
                if let Some(asked) = asked {
                    // The hint is not a subject. The asked Person Server and
                    // claims authorize; a bare subject from another server does not.
                    if asked.auth_differs(
                        &claims.ps,
                        &claims.sub,
                        claims.account.as_deref(),
                        claims.tenant.as_deref(),
                    ) {
                        return Ok(self.forbidden_budget(&token, grant.as_ref()));
                    }
                }
                let r3 = match self.r3_gate(&token, request, now, challenge_jti) {
                    Ok(r3) => r3,
                    Err(decision) => return Ok(self.with_budget(decision, &token, grant.as_ref())),
                };
                // A Core route always needs the scope profile; an R3 route needs
                // it as well only when the host configured both to be enforced.
                let scope_required = r3.is_none()
                    || self
                        .r3
                        .as_ref()
                        .is_some_and(|profile| profile.require_core_scope);
                let granted: Vec<&str> = claims.scope.as_deref().unwrap_or("").split(' ').collect();
                if scope_required
                    && self
                        .config
                        .scopes
                        .iter()
                        .any(|scope| !granted.contains(&scope.as_str()))
                {
                    return Ok(self.forbidden_budget(&token, grant.as_ref()));
                }
                // A per-call completion is claimed only after every check and
                // host policy admitted it, so a refusal never consumes it.
                // The poll's proof was verified above. Host policy must instead
                // admit the verified held request that the host will execute.
                let policy_request = r3
                    .as_ref()
                    .and_then(R3Grant::held_request)
                    .unwrap_or(request);
                // A refusal after admission reports what is left of a budgeted grant.
                let budgeted = grant.clone().map(|grant| (token.clone(), grant));
                let refused = |decision: AuthDecision<O::Context>| match &budgeted {
                    Some((token, grant)) => self.with_budget(decision, token, Some(grant)),
                    None => decision,
                };
                // Every admission, Core or R3, passes the shared post-callback
                // verification: a revocation completed during host policy fences it.
                match self.admit_auth(token, policy_request, now, challenge_jti, grant, meter)? {
                    AuthDecision::Granted(mut admitted) => {
                        match self.post_callback_admission(r3, &admitted.token, now) {
                            Ok(claimed) => admitted.r3 = claimed,
                            Err(decision) => return Ok(refused(decision)),
                        }
                        Ok(AuthDecision::Granted(admitted))
                    }
                    AuthDecision::Observed(mut admitted) => {
                        match self.post_callback_admission(r3, &admitted.token, now) {
                            Ok(claimed) => admitted.r3 = claimed,
                            Err(decision) => return Ok(refused(decision)),
                        }
                        Ok(AuthDecision::Observed(admitted))
                    }
                    // A class grant stays on the hold. The host commits a cost at
                    // or below the admitted maximum. Dropping the hold releases
                    // an uncommitted reservation.
                    AuthDecision::Held(mut admitted) => {
                        match self.post_callback_admission(r3, &admitted.token, now) {
                            Ok(claimed) => {
                                admitted.r3 = claimed;
                                Ok(AuthDecision::Held(admitted))
                            }
                            Err(decision) => {
                                // Release the hold before reading what is left.
                                drop(admitted);
                                Ok(refused(decision))
                            }
                        }
                    }
                    decision => Ok(decision),
                }
            }
            _ => Err(SignatureFailure::Token(TokenError::UnexpectedTokenType)),
        }
    }
    /// Accept `POST /authorize` when [`Self::with_authorization_endpoint`] is set.
    ///
    /// A missing proof, and a verified agent token, are `requirement=person-token`.
    /// The person token is verified before `scope` is read. A missing or empty
    /// `scope` is `invalid_request`. A scope this resource does not publish is
    /// `invalid_scope`. A recognized scope returns that resource token.
    /// After [`Self::with_r3`], a body carrying `r3_operations` may omit
    /// `scope`; see that method for validation and retention before release.
    pub fn authorize_endpoint(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
    ) -> ProactiveDecision {
        if !self.authorization_endpoint {
            return ProactiveDecision::InvalidRequest;
        }
        let authority = match canonical_authority(request.uri()) {
            Ok(value) => value,
            Err(error) => {
                return ProactiveDecision::SignatureFailure(SignatureFailure::Proof(error));
            }
        };
        if authority != self.authority || request.uri().path() != "/authorize" {
            return ProactiveDecision::SignatureFailure(SignatureFailure::Proof(
                Error::TargetMismatch,
            ));
        }
        if request.method() != http::Method::POST {
            return ProactiveDecision::InvalidRequest;
        }
        if !(0..=(1_i64 << 33) - 1).contains(&now) {
            return ProactiveDecision::SignatureFailure(SignatureFailure::Proof(
                Error::InvalidClock,
            ));
        }
        if ["signature-key", "signature-input", "signature"]
            .iter()
            .all(|name| !request.headers().contains_key(*name))
        {
            return ProactiveDecision::PersonTokenRequired;
        }
        if self.r3_composition_refused() {
            return ProactiveDecision::InternalError;
        }
        match self.proactive_person(request, now, challenge_jti) {
            Ok(decision) => decision,
            Err(error) => ProactiveDecision::SignatureFailure(error),
        }
    }
    fn proactive_person(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
    ) -> Result<ProactiveDecision, SignatureFailure> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwt"])
            .map_err(|error| match error {
                Error::ClockSkew => SignatureFailure::ClockSkew { server_time: now },
                Error::InvalidInput => SignatureFailure::Input(required_components(request)),
                other => SignatureFailure::Proof(other),
            })?;
        let KeyMaterial::Jwt(compact) = proof.key() else {
            return Err(SignatureFailure::Proof(Error::UnsupportedScheme));
        };
        let parsed = Jws::parse(compact).map_err(|error| SignatureFailure::Token(error.into()))?;
        match parsed.header().get("typ").and_then(|value| value.as_str()) {
            Some("aa-agent+jwt") => {
                let token = AgentToken::parse(compact)
                    .and_then(|token| token.verify(&self.keys, now))
                    .map_err(SignatureFailure::Token)?;
                proof
                    .verify(&token.claims().cnf.jwk)
                    .map_err(SignatureFailure::Proof)?;
                check_iat(token.claims().iat, now)?;
                Ok(ProactiveDecision::PersonTokenRequired)
            }
            Some("aa-person+jwt") => {
                let parsed = PersonToken::parse(compact).map_err(SignatureFailure::Token)?;
                let issuer = parsed.unverified_claims().iss.clone();
                let jti = parsed.unverified_claims().jti.clone();
                let token = match parsed.verify(&self.keys, now) {
                    Ok(token) => token,
                    Err(TokenError::ExpiredJwt) if self.presented_revoked(&issuer, &jti, now) => {
                        proof
                            .verify(&parsed.unverified_claims().cnf.jwk)
                            .map_err(SignatureFailure::Proof)?;
                        check_iat(parsed.unverified_claims().iat, now)?;
                        if parsed.unverified_claims().aud != self.config.issuer {
                            return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                        }
                        return Ok(ProactiveDecision::Revoked);
                    }
                    Err(error) => return Err(SignatureFailure::Token(error)),
                };
                let claims = token.claims();
                proof
                    .verify(&claims.cnf.jwk)
                    .map_err(SignatureFailure::Proof)?;
                check_iat(claims.iat, now)?;
                if claims.aud != self.config.issuer {
                    return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                }
                if self.presented_revoked(&issuer, &jti, now) {
                    return Ok(ProactiveDecision::Revoked);
                }
                if self.mission_refused(claims.mission_s256.is_some())
                    || unsupported_companion(&claims.extra, false, false)
                {
                    return Err(SignatureFailure::Token(TokenError::InvalidJwt));
                }
                let mut challenge = ResourceClaims {
                    iss: self.config.issuer.clone(),
                    dwk: "aauth-resource.json".into(),
                    aud: self
                        .access_server
                        .clone()
                        .unwrap_or_else(|| claims.iss.clone()),
                    ps: claims.iss.clone(),
                    sub: claims.sub.clone(),
                    jti: challenge_jti.into(),
                    presented_jti: claims.jti.clone(),
                    agent_jkt: claims
                        .cnf
                        .jwk
                        .thumbprint()
                        .map_err(|error| SignatureFailure::Token(error.into()))?,
                    iat: now,
                    exp: challenge_exp(
                        now,
                        self.mission_context && claims.mission_s256.is_some(),
                        claims.exp,
                    ),
                    scope: None,
                    account: None,
                    login_hint: None,
                    nbf: None,
                    tenant: claims.tenant.clone(),
                    mission_s256: if self.mission_context {
                        claims.mission_s256.clone()
                    } else {
                        None
                    },
                    extra: BTreeMap::new(),
                };
                if let Some(decision) = self.proactive_r3(request, &challenge) {
                    return Ok(decision);
                }
                challenge.scope = match requested_scope(request, &self.config.scopes) {
                    Ok(scope) => Some(scope),
                    Err(decision) => return Ok(decision),
                };
                challenge.extra = match self.proactive_extra(request) {
                    Ok(extra) => extra,
                    Err(decision) => return Ok(decision),
                };
                match mint_resource_token(&self.config.signing_key, &self.config.kid, &challenge) {
                    Ok(resource_token) => Ok(ProactiveDecision::ResourceToken { resource_token }),
                    Err(_) => Ok(ProactiveDecision::InternalError),
                }
            }
            _ => Err(SignatureFailure::Token(TokenError::UnexpectedTokenType)),
        }
    }
    fn mission_refused(&self, present: bool) -> bool {
        present && (!self.mission_context || self.access_server.is_some())
    }
    fn idle_offer(&self) -> Result<BTreeMap<String, Value>, ()> {
        match &self.budgets {
            None => Ok(BTreeMap::new()),
            Some(gate) => gate.challenge_extra(None, None, None).map_err(|_| ()),
        }
    }
    fn proactive_extra(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<BTreeMap<String, Value>, ProactiveDecision> {
        let Some(gate) = &self.budgets else {
            return Ok(BTreeMap::new());
        };
        let value = strict_json(request.body()).map_err(|_| ProactiveDecision::InvalidRequest)?;
        let requested = match value.get("budget") {
            None => None,
            Some(budget) => {
                Some(parse_budget(budget).map_err(|_| ProactiveDecision::InvalidBudget)?)
            }
        };
        gate.challenge_extra(requested.as_ref(), None, None)
            .map_err(|_| ProactiveDecision::InvalidBudget)
    }
    /// `AAuth-Budget` for a budgeted auth token this call refuses without
    /// metering: what is left of its grant.
    fn untouched_budget(
        &self,
        token: &VerifiedAuthToken,
        grant: Option<&Budget>,
    ) -> Option<String> {
        let gate = self.budgets.as_ref()?;
        gate.untouched_header(token, grant?).ok()
    }
    fn forbidden_budget(
        &self,
        token: &VerifiedAuthToken,
        grant: Option<&Budget>,
    ) -> AuthDecision<O::Context> {
        AuthDecision::Forbidden {
            budget_header: self.untouched_budget(token, grant),
        }
    }
    /// Give a refusal of a budgeted auth token that carries no `AAuth-Budget`
    /// the figure its grant has left. Release any hold first. A per-call
    /// challenge, hold or completion never answers a budgeted token: the
    /// class-R3 Budget profile refuses `r3_per_call`, and a per-call token
    /// carries no budget.
    fn with_budget(
        &self,
        decision: AuthDecision<O::Context>,
        token: &VerifiedAuthToken,
        grant: Option<&Budget>,
    ) -> AuthDecision<O::Context> {
        match decision {
            AuthDecision::Forbidden {
                budget_header: None,
            } => self.forbidden_budget(token, grant),
            AuthDecision::Revoked {
                auth_token,
                budget_header: None,
            } => AuthDecision::Revoked {
                auth_token,
                budget_header: self.untouched_budget(token, grant),
            },
            AuthDecision::MethodNotAllowed {
                budget_header: None,
            } => AuthDecision::MethodNotAllowed {
                budget_header: self.untouched_budget(token, grant),
            },
            AuthDecision::Gone {
                budget_header: None,
            } => AuthDecision::Gone {
                budget_header: self.untouched_budget(token, grant),
            },
            other => other,
        }
    }
    fn admit_auth(
        &self,
        token: VerifiedAuthToken,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
        grant: Option<Budget>,
        meter: Meter,
    ) -> Result<AuthDecision<O::Context>, SignatureFailure> {
        let Some(gate) = &self.budgets else {
            return self.finish_admission(token, request, None, meter);
        };
        let Some(grant) = grant else {
            return self.finish_admission(token, request, None, meter);
        };
        let maximum = match gate.admitted_cost(request) {
            Ok(maximum) => maximum,
            Err(()) => return Ok(self.forbidden_budget(&token, Some(&grant))),
        };
        // A client figure of zero is not a free admission of the host's work,
        // and it does not fit a spent grant.
        if maximum == 0 && gate.default_bound > 0 {
            let remaining = match gate.remaining(&token, &grant) {
                Ok(remaining) => remaining,
                Err(_) => return Ok(AuthDecision::InternalError),
            };
            let refusal = if remaining == 0 {
                aauth_rust_budgets::Refusal::Exhausted {
                    remaining,
                    header: match unstated_required(&grant, 0) {
                        Ok(header) => header,
                        Err(()) => return Ok(AuthDecision::InternalError),
                    },
                }
            } else {
                let header = if gate.omit_required.load(Ordering::Relaxed) {
                    match unstated_required(&grant, remaining) {
                        Ok(header) => header,
                        Err(()) => return Ok(AuthDecision::InternalError),
                    }
                } else {
                    match BudgetHeader::refusal(
                        remaining,
                        Some(gate.default_bound),
                        grant.unit(),
                        grant.decimals(),
                    )
                    .and_then(|header| sender_field(&header, false))
                    {
                        Ok(header) => header,
                        Err(_) => return Ok(AuthDecision::InternalError),
                    }
                };
                aauth_rust_budgets::Refusal::Insufficient {
                    remaining,
                    required: gate.default_bound,
                    header,
                }
            };
            return self.budget_refusal(&token, &grant, now, challenge_jti, refusal);
        }
        match meter {
            Meter::Observe => match gate.open_grant(&token) {
                Ok(_) => match (self.policy)(&token, request).into_admission() {
                    Ok(admitted) => Ok(AuthDecision::Observed(Box::new(ObservedAdmission {
                        token,
                        admitted,
                        admitted_maximum: Some(maximum),
                        r3: None,
                    }))),
                    Err(Deny) => Ok(self.forbidden_budget(&token, Some(&grant))),
                },
                Err(_) => Ok(AuthDecision::InternalError),
            },
            Meter::Reserve => match gate.reserve(&token, &grant, maximum) {
                Ok(reservation) => match (self.policy)(&token, request).into_admission() {
                    Ok(admitted) => Ok(AuthDecision::Held(Box::new(HeldAdmission {
                        token,
                        admitted,
                        reservation,
                        admitted_maximum: maximum,
                        gate: Arc::clone(gate),
                        r3: None,
                    }))),
                    Err(Deny) => {
                        gate.release(&reservation);
                        Ok(self.forbidden_budget(&token, Some(&grant)))
                    }
                },
                Err(ChargeError::Refused(refusal)) => {
                    self.budget_refusal(&token, &grant, now, challenge_jti, refusal)
                }
                Err(ChargeError::Protocol(_)) => Ok(AuthDecision::InternalError),
            },
            Meter::Buffered => match gate.reserve(&token, &grant, maximum) {
                Ok(reservation) => match (self.policy)(&token, request).into_admission() {
                    // Post-callback revocation precedes the commit, so a
                    // revoked call never draws down the grant.
                    Ok(_)
                        if self.presented_revoked(
                            &token.claims().iss,
                            &token.claims().jti,
                            now,
                        ) =>
                    {
                        gate.release(&reservation);
                        Ok(AuthDecision::Revoked {
                            auth_token: true,
                            budget_header: self.untouched_budget(&token, Some(&grant)),
                        })
                    }
                    Ok(admitted) => match gate.commit(&reservation, maximum, now) {
                        Ok(header) => Ok(AuthDecision::Granted(Box::new(AuthAuthorized {
                            token,
                            admitted,
                            budget_header: Some(header),
                            admitted_maximum: Some(maximum),
                            r3: None,
                        }))),
                        Err(()) => Ok(AuthDecision::InternalError),
                    },
                    Err(Deny) => {
                        gate.release(&reservation);
                        Ok(self.forbidden_budget(&token, Some(&grant)))
                    }
                },
                Err(ChargeError::Refused(refusal)) => {
                    self.budget_refusal(&token, &grant, now, challenge_jti, refusal)
                }
                Err(ChargeError::Protocol(_)) => Ok(AuthDecision::InternalError),
            },
        }
    }
    fn budget_refusal(
        &self,
        token: &VerifiedAuthToken,
        grant: &Budget,
        now: i64,
        challenge_jti: &str,
        refusal: aauth_rust_budgets::Refusal,
    ) -> Result<AuthDecision<O::Context>, SignatureFailure> {
        let Some(gate) = &self.budgets else {
            return Ok(AuthDecision::InternalError);
        };
        let (reason, header) = match refusal {
            aauth_rust_budgets::Refusal::Exhausted { header, .. } => ("budget-exhausted", header),
            aauth_rust_budgets::Refusal::Insufficient {
                remaining, header, ..
            } => {
                let header = if gate.omit_required.load(Ordering::Relaxed) {
                    match unstated_required(grant, remaining) {
                        Ok(header) => header,
                        Err(()) => return Ok(AuthDecision::InternalError),
                    }
                } else {
                    header
                };
                ("insufficient-budget", header)
            }
        };
        let consumed = gate
            .lock()
            .committed(token.claims().iss.as_str(), token.claims().jti.as_str())
            .unwrap_or(0);
        let record = match ConsumptionRecord::new(token.claims().jti.clone(), consumed) {
            Ok(record) => record,
            Err(_) => return Ok(AuthDecision::InternalError),
        };
        let extra = match gate.challenge_extra(None, Some(&record), Some(grant)) {
            Ok(extra) => extra,
            Err(_) => return Ok(AuthDecision::InternalError),
        };
        match self.mint_step_up(token, now, challenge_jti, extra) {
            Ok(resource_token) => Ok(AuthDecision::AuthTokenRequired {
                resource_token,
                budget_reason: Some(reason.to_owned()),
                budget_header: Some(header),
            }),
            Err(()) => Ok(AuthDecision::InternalError),
        }
    }
    fn finish_admission(
        &self,
        token: VerifiedAuthToken,
        request: &Request<Vec<u8>>,
        budget_header: Option<String>,
        meter: Meter,
    ) -> Result<AuthDecision<O::Context>, SignatureFailure> {
        match (self.policy)(&token, request).into_admission() {
            Ok(admitted) => match meter {
                Meter::Observe | Meter::Reserve => {
                    Ok(AuthDecision::Observed(Box::new(ObservedAdmission {
                        token,
                        admitted,
                        admitted_maximum: None,
                        r3: None,
                    })))
                }
                Meter::Buffered => Ok(AuthDecision::Granted(Box::new(AuthAuthorized {
                    token,
                    admitted,
                    budget_header,
                    admitted_maximum: None,
                    r3: None,
                }))),
            },
            Err(Deny) => Ok(AuthDecision::Forbidden {
                budget_header: None,
            }),
        }
    }
    fn mint_step_up(
        &self,
        token: &VerifiedAuthToken,
        now: i64,
        challenge_jti: &str,
        extra: BTreeMap<String, Value>,
    ) -> Result<String, ()> {
        let claims = token.claims();
        let challenge = ResourceClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-resource.json".into(),
            aud: self
                .access_server
                .clone()
                .unwrap_or_else(|| claims.ps.clone()),
            ps: claims.ps.clone(),
            sub: claims.sub.clone(),
            jti: challenge_jti.into(),
            presented_jti: claims.jti.clone(),
            agent_jkt: claims.cnf.jwk.thumbprint().map_err(|_| ())?,
            iat: now,
            exp: challenge_exp(
                now,
                self.mission_context && claims.mission_s256.is_some(),
                claims.exp,
            ),
            scope: Some(self.config.scopes.join(" ")),
            account: claims.account.clone(),
            login_hint: None,
            nbf: None,
            tenant: claims.tenant.clone(),
            mission_s256: if self.mission_context {
                claims.mission_s256.clone()
            } else {
                None
            },
            extra,
        };
        mint_resource_token(&self.config.signing_key, &self.config.kid, &challenge).map_err(|_| ())
    }
    /// Answer `POST` on the configured usage endpoint.
    ///
    /// The caller proves a person-server or access-server key with `jwks_uri`
    /// and covers `content-type` and `content-digest`. Figures are limited to
    /// tokens whose `iss` or `ps` names the caller. An unrecognized scope key,
    /// including a caller who has not appeared, is `200` with `usage` omitted.
    /// An unrecognized thumbprint is omitted from `jkts`. The response is signed.
    pub fn usage(&self, request: &Request<Vec<u8>>, now: i64) -> Response<Vec<u8>> {
        let Some(gate) = &self.budgets else {
            return problem(StatusCode::NOT_FOUND, "not_found");
        };
        let endpoint: http::Uri = match gate.usage_endpoint.parse() {
            Ok(uri) => uri,
            Err(_) => return problem(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        if request.method() != http::Method::POST || request.uri().path() != endpoint.path() {
            return problem(StatusCode::NOT_FOUND, "not_found");
        }
        let proof =
            match PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"]) {
                Ok(proof) => proof,
                Err(_) => return problem(StatusCode::UNAUTHORIZED, "invalid_signature"),
            };
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return problem(StatusCode::UNAUTHORIZED, "invalid_key");
        };
        let role = match dwk.as_str() {
            "aauth-person.json" => KeyRole::PersonServer,
            "aauth-access.json" => KeyRole::AccessServer,
            _ => return problem(StatusCode::UNAUTHORIZED, "invalid_key"),
        };
        let base = std::str::from_utf8(proof.signature_base()).unwrap_or("");
        if !base
            .lines()
            .any(|line| line.starts_with("\"content-type\":"))
            || !base
                .lines()
                .any(|line| line.starts_with("\"content-digest\":"))
        {
            return problem(StatusCode::UNAUTHORIZED, "invalid_input");
        }
        let key = match self.keys.key(id, dwk, kid) {
            Ok(key) => key,
            Err(_) => return problem(StatusCode::UNAUTHORIZED, "untrusted_issuer"),
        };
        if proof.verify(&key).is_err() {
            return problem(StatusCode::UNAUTHORIZED, "invalid_signature");
        }
        let Ok(body) = strict_json(request.body()) else {
            return problem(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let Ok(query) = parse_usage_query(&body, role) else {
            return problem(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let Some(report) = gate.reporting_budget() else {
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        let caller = aauth_rust_budgets::Caller {
            id: id.clone(),
            role,
            ps: query.ps.clone(),
        };
        let value = {
            let ledger = gate.lock();
            answer_usage(&ledger, &caller, &query, now, &report)
        };
        let Ok(bytes) = serde_json::to_vec(&value.to_value()) else {
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        let authority = canonical_authority(request.uri()).unwrap_or_default();
        let Ok(signed) = sign_usage_response(
            &self.config.signing_key,
            &self.config.issuer,
            &self.config.kid,
            &authority,
            request.uri().path(),
            &bytes,
            now,
        ) else {
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        let mut response = Response::new(signed.body);
        *response.status_mut() = StatusCode::OK;
        let headers = response.headers_mut();
        if let Ok(value) = "application/json".parse() {
            headers.insert("content-type", value);
        }
        if let Ok(value) = signed.content_digest.parse() {
            headers.insert("content-digest", value);
        }
        if let Ok(value) = signed.signature_input.parse() {
            headers.insert("signature-input", value);
        }
        if let Ok(value) = signed.signature.parse() {
            headers.insert("signature", value);
        }
        if let Ok(value) = signed.signature_key.parse() {
            headers.insert("signature-key", value);
        }
        if let Ok(value) = "no-store".parse() {
            headers.insert("cache-control", value);
        }
        response
    }
    /// Reserve `maximum` against a verified auth token without serving the request.
    ///
    /// # Errors
    /// Returns the refusal when the maximum does not fit. A refusal does not draw down.
    pub fn budget_reserve(
        &self,
        token: &VerifiedAuthToken,
        maximum: i64,
    ) -> Result<Reservation, ChargeError> {
        let gate = self
            .budgets
            .as_ref()
            .ok_or(ChargeError::Protocol(aauth_rust_budgets::Error::AccessMode))?;
        let grant = gate.open_grant(token)?;
        gate.reserve(token, &grant, maximum)
    }
    /// Drop a reservation without posting consumption.
    ///
    /// # Errors
    /// Returns a protocol error when budgets are off or the reservation is unknown.
    pub fn budget_release(&self, reservation: &Reservation) -> Result<(), ChargeError> {
        let gate = self
            .budgets
            .as_ref()
            .ok_or(ChargeError::Protocol(aauth_rust_budgets::Error::AccessMode))?;
        gate.lock().release(reservation)
    }
    /// Commit `actual` for a reservation and return the final `AAuth-Budget` field.
    ///
    /// # Errors
    /// Returns a protocol error when the reservation is unknown or `actual` exceeds it.
    pub fn budget_commit(
        &self,
        reservation: &Reservation,
        actual: i64,
        at: i64,
    ) -> Result<String, ChargeError> {
        let gate = self
            .budgets
            .as_ref()
            .ok_or(ChargeError::Protocol(aauth_rust_budgets::Error::AccessMode))?;
        gate.commit(reservation, actual, at)
            .map_err(|_| ChargeError::Protocol(aauth_rust_budgets::Error::Malformed))
    }
    /// Header for a stream that has reserved and does not yet know `cost`.
    ///
    /// # Errors
    /// Returns a protocol error when the reservation is unknown.
    pub fn budget_stream_header(&self, reservation: &Reservation) -> Result<String, ChargeError> {
        let gate = self
            .budgets
            .as_ref()
            .ok_or(ChargeError::Protocol(aauth_rust_budgets::Error::AccessMode))?;
        gate.stream_header(reservation)
    }
    /// `Trailer` header value, field name, and `cost`-only field.
    ///
    /// The first string is `AAuth-Budget`, the value of the HTTP `Trailer`
    /// header. The trailer does not restate the header.
    ///
    /// # Errors
    /// Returns a protocol error when `prior` already carried `cost`.
    pub fn budget_trailer(
        &self,
        prior: &str,
        cost: i64,
    ) -> Result<(String, String, String), ChargeError> {
        let gate = self
            .budgets
            .as_ref()
            .ok_or(ChargeError::Protocol(aauth_rust_budgets::Error::AccessMode))?;
        gate.trailer(prior, cost).map_err(ChargeError::Protocol)
    }
    /// Header for a held invocation. The original token is not reserved.
    ///
    /// # Errors
    /// Returns a protocol error when the token has no budget.
    pub fn budget_held_header(&self, token: &VerifiedAuthToken) -> Result<String, ChargeError> {
        let gate = self
            .budgets
            .as_ref()
            .ok_or(ChargeError::Protocol(aauth_rust_budgets::Error::AccessMode))?;
        gate.held_header(token)
    }
    /// Meter a held invocation once against the completing token.
    ///
    /// A second call reports the stored cost and does not add consumption.
    ///
    /// # Errors
    /// Returns a refusal when the completing token cannot cover `maximum`,
    /// without recording the invocation as metered.
    pub fn budget_complete_held(
        &self,
        pending: &str,
        token: &VerifiedAuthToken,
        maximum: i64,
        actual: i64,
        at: i64,
    ) -> Result<String, ChargeError> {
        let gate = self
            .budgets
            .as_ref()
            .ok_or(ChargeError::Protocol(aauth_rust_budgets::Error::AccessMode))?;
        gate.complete_held(pending, token, maximum, actual, at)
    }
}
fn check_iat(iat: i64, now: i64) -> Result<(), SignatureFailure> {
    if iat > now.saturating_add(60) {
        return Err(SignatureFailure::ClockSkew { server_time: now });
    }
    Ok(())
}
fn scope_value(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}
fn unsupported_companion(
    claims: &BTreeMap<String, Value>,
    allow_budget: bool,
    allow_r3: bool,
) -> bool {
    claims.keys().any(|name| match name.as_str() {
        "r3_uri" | "r3_s256" | "r3_granted" | "r3_per_call" => !allow_r3,
        "budget_consumed" => true,
        "budget" => !allow_budget,
        _ => false,
    })
}
fn unstated_required(grant: &Budget, remaining: i64) -> Result<String, ()> {
    let header =
        BudgetHeader::refusal(remaining, None, grant.unit(), grant.decimals()).map_err(|_| ())?;
    sender_field(&header, false).map_err(|_| ())
}
fn insert_budget(response: &mut Response<Vec<u8>>, header: Option<String>) {
    if let Some(header) = header
        && let Ok(value) = header.parse()
    {
        response.headers_mut().insert("aauth-budget", value);
    }
}

/// A mission-bound Resource token never outlives the token presented with it.
fn challenge_exp(now: i64, mission_bound: bool, presented_exp: i64) -> i64 {
    let exp = now.saturating_add(300);
    if mission_bound {
        exp.min(presented_exp)
    } else {
        exp
    }
}
