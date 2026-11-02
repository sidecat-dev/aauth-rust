//! Agent bootstrap: how an agent comes to hold an Agent token
//! (`draft-hardt-aauth-bootstrap`).
//!
//! A hosted Agent Provider serves [`BootstrapService`]: enrollment of an
//! install's durable key under `hwk`, two-key refresh under `jkt-jwt`,
//! single-key refresh under `hwk`, and sub-agent issuance to a parent that
//! presents its own Agent token under `jwt`. Host policy decides each step
//! through [`BootstrapPolicy`], and state lives in a [`BootstrapStore`].
//!
//! A self-hosted domain is its own Agent Provider. Its token-issuing process
//! calls [`AgentProvider::issue_to`] for each agent, with that agent's own
//! key or, for a single agent, [`AgentProvider::public_jwk`], and
//! [`AgentProvider::issue_subagent_to`] for a sub-agent. Only the provider key
//! is in [`AgentProvider::jwks`]; an agent key appears only in its token.
//!
//! The draft is informational and defines no routes or bodies. The bodies
//! this service reads are documented on [`BootstrapService::handle`]; the
//! readings are in INTERPRETATIONS.md.
use crate::{AgentProvider, IssuanceKeys};
use aauth_rust_core::events::generate_identifier;
use aauth_rust_core::{
    AgentClaims, AgentToken, Confirmation, REFRESH_MARGIN, TokenError, VerifiedAgentToken,
    validate_agent_identifier, validate_server_identifier,
};
use aauth_rust_jose::{JWS_ALGORITHMS, Jwk};
use aauth_rust_signature_key::{
    Error, KeyMaterial, PreparedRequest, canonical_authority, required_components,
    role_signature_alg_header,
};
use http::{Method, Request, Response, StatusCode};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

mod store;
pub use store::{
    BootstrapStore, BootstrapStoreError, Enrollment, EnrollmentState, MemoryBootstrapStore,
    SubagentRecord,
};

/// Accepted distance, in seconds, between a bootstrap request's `created`
/// and the verifier clock.
pub const SIGNATURE_WINDOW: i64 = 60;

/// What a top-level Agent token carries beyond `sub` and `cnf`: the agent's
/// Person Server, the lifetime and any claims the provider attests.
#[derive(Clone, Debug)]
pub struct AgentGrant {
    /// The `ps` claim: the agent's one Person Server, when it has one.
    pub ps: Option<String>,
    /// Seconds from issuance to `exp`. Above [`REFRESH_MARGIN`], at most 86400.
    pub lifetime: i64,
    /// Additional claims, such as an attestation tier. Registered claim
    /// names are refused at issuance.
    pub extra: BTreeMap<String, Value>,
}

impl AgentGrant {
    /// A grant of `lifetime` seconds with no Person Server and no extra claims.
    pub fn new(lifetime: i64) -> Self {
        Self {
            ps: None,
            lifetime,
            extra: BTreeMap::new(),
        }
    }
    /// The same grant naming `ps` as the agent's Person Server.
    pub fn with_ps(mut self, ps: &str) -> Self {
        self.ps = Some(ps.to_owned());
        self
    }
}

/// An Agent token this provider signed, with the claims in it.
#[derive(Clone, Debug)]
pub struct IssuedAgentToken {
    /// Compact `aa-agent+jwt`.
    pub token: String,
    /// The signed claims.
    pub claims: AgentClaims,
}

impl AgentProvider {
    /// The public JWK of this provider's signing key, as [`Self::jwks`]
    /// publishes it without `kid`. A self-hosted domain running one agent
    /// binds that agent's token to it (Bootstrap, Self-Hosted Agents).
    pub fn public_jwk(&self) -> Jwk {
        self.key.public_jwk()
    }

    /// Issue a top-level Agent token for `agent`, bound to `key`, at `now`
    /// in Unix seconds, with a fresh random `jti`. This is the refresh step of
    /// [`BootstrapService`] and a self-hosted domain's issuance for each of
    /// its agents (Bootstrap, Many Agents, One Operator).
    ///
    /// # Errors
    /// `InvalidTokenLifetime` for a lifetime of [`REFRESH_MARGIN`] seconds or
    /// less, which an agent would have to refresh at once (Bootstrap, Refresh
    /// Patterns), or over 86400 seconds. Otherwise the errors of
    /// [`Self::issue`]: an identifier outside this provider's domain or with
    /// a `+`, an invalid Person Server or key, or a signing failure.
    pub fn issue_to(
        &self,
        agent: &str,
        key: &Jwk,
        grant: &AgentGrant,
        now: i64,
    ) -> Result<IssuedAgentToken, TokenError> {
        if grant.lifetime <= REFRESH_MARGIN {
            return Err(TokenError::InvalidTokenLifetime);
        }
        let claims = AgentClaims {
            iss: self.issuer.clone(),
            dwk: "aauth-agent.json".into(),
            sub: agent.to_owned(),
            jti: generate_identifier(),
            iat: now,
            exp: now.saturating_add(grant.lifetime),
            cnf: Confirmation { jwk: key.clone() },
            ps: grant.ps.clone(),
            parent_agent: None,
            nbf: None,
            extra: grant.extra.clone(),
        };
        let token = self.issue(&claims)?;
        Ok(IssuedAgentToken { token, claims })
    }

    /// Issue a sub-agent token under the parent token `parent_compact`, which
    /// this provider must have issued and which must be current at `now`.
    /// The sub-agent's `sub` is the parent's local part, `+` and
    /// `discriminator`; `parent_agent` names the parent; `ps` is copied from
    /// the parent's token; `cnf` is `key`; `exp` is `now + lifetime` or the
    /// parent's `exp`, whichever is earlier (Bootstrap, Sub-Agent Tokens).
    ///
    /// The caller keeps `discriminator` unique among the parent's live
    /// sub-agents; [`BootstrapService`] does so with its store.
    ///
    /// # Errors
    /// The parent token's verification errors (another issuer is
    /// `IssuerMismatch`, an expired one `ExpiredJwt`), `UnsupportedAgentProfile`
    /// when the parent is itself a sub-agent, `InvalidTokenLifetime` for a
    /// nonpositive lifetime, `InvalidAgentIdentifier` for a discriminator that
    /// is empty, holds `+` or other characters an identifier refuses, and
    /// `InvalidJwt` when `key` is the parent's key.
    pub fn issue_subagent_to(
        &self,
        parent_compact: &str,
        key: &Jwk,
        discriminator: &str,
        lifetime: i64,
        now: i64,
    ) -> Result<IssuedAgentToken, TokenError> {
        let parent = AgentToken::parse(parent_compact)?.verify(&IssuanceKeys(self), now)?;
        let parent = parent.claims();
        if parent.parent_agent.is_some() {
            return Err(TokenError::UnsupportedAgentProfile);
        }
        if lifetime <= 0 {
            return Err(TokenError::InvalidTokenLifetime);
        }
        if !valid_discriminator(discriminator) {
            return Err(TokenError::InvalidAgentIdentifier);
        }
        let (local, domain) = split_agent(&parent.sub)?;
        let claims = AgentClaims {
            iss: self.issuer.clone(),
            dwk: "aauth-agent.json".into(),
            sub: format!("aauth:{local}+{discriminator}@{domain}"),
            jti: generate_identifier(),
            iat: now,
            exp: now.saturating_add(lifetime).min(parent.exp),
            cnf: Confirmation { jwk: key.clone() },
            ps: parent.ps.clone(),
            parent_agent: Some(parent.sub.clone()),
            nbf: None,
            extra: BTreeMap::new(),
        };
        let token = self.issue_subagent(&claims, parent_compact, now)?;
        Ok(IssuedAgentToken { token, claims })
    }
}

fn split_agent(agent: &str) -> Result<(&str, &str), TokenError> {
    agent
        .strip_prefix("aauth:")
        .and_then(|rest| rest.rsplit_once('@'))
        .ok_or(TokenError::InvalidAgentIdentifier)
}

// A discriminator is one segment of an identifier's local part (Protocol,
// Agent Identifiers): ASCII letters, digits, `-`, `_` and `.`, never `+`.
fn valid_discriminator(discriminator: &str) -> bool {
    !discriminator.is_empty()
        && discriminator
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

/// A host policy refusal, answered `403 access_denied`. `reason`, when set,
/// is sent as the Problem Details `detail`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Denial {
    /// Text for the requester. It must not reveal more than the host intends.
    pub reason: Option<String>,
}

/// An enrollment the service has authenticated, put to host policy.
#[derive(Debug)]
pub struct EnrollmentRequest<'a> {
    /// The durable key that signed the request under `hwk`.
    pub durable_key: &'a Jwk,
    /// Its RFC 7638 thumbprint.
    pub durable_thumbprint: &'a str,
    /// The body's `evidence` member, or `null`: what the host requires, such
    /// as a platform attestation or a signed-in session (Bootstrap, What
    /// Bootstrapping Is). Its form is the host's.
    pub evidence: &'a Value,
    /// The whole request, for the host's own session or account checks.
    pub request: &'a Request<Vec<u8>>,
}

/// Host approval of an enrollment.
#[derive(Clone, Debug)]
pub struct EnrollmentApproval {
    /// The local part of the agent identifier. It must be stable for the
    /// install, unique at this provider, and without `+` (Bootstrap, Agent
    /// Identifier Strategies). [`thumbprint_local_part`] derives one from the
    /// durable key.
    pub local: String,
    /// The host account that enrolled the install, recorded with it.
    pub account: Option<String>,
}

/// The local part a provider gets by deriving the identifier from the
/// durable key: the base64url thumbprint, which meets the identifier rules
/// as it stands (Bootstrap, Agent Identifier Strategies).
pub fn thumbprint_local_part(request: &EnrollmentRequest<'_>) -> String {
    request.durable_thumbprint.to_owned()
}

/// An authenticated refresh, put to host policy before a token is issued.
#[derive(Debug)]
pub struct RefreshRequest<'a> {
    /// The active enrollment the durable key names.
    pub enrollment: &'a Enrollment,
    /// The key the new token binds: the delegated ephemeral key, or the
    /// durable key itself in a single-key refresh.
    pub key: &'a Jwk,
    /// The refresh was signed by the durable key under `hwk`.
    pub single_key: bool,
    /// The body's `ps` member: the Person Server the agent asks to have named.
    pub ps: Option<&'a str>,
    /// The body's `evidence` member, or `null`.
    pub evidence: &'a Value,
    /// The whole request.
    pub request: &'a Request<Vec<u8>>,
}

/// An authenticated sub-agent request, put to host policy.
#[derive(Debug)]
pub struct SubagentRequest<'a> {
    /// The parent's verified, top-level Agent token.
    pub parent: &'a VerifiedAgentToken,
    /// The sub-agent's public key.
    pub key: &'a Jwk,
    /// The discriminator the parent offered, if any.
    pub discriminator: Option<&'a str>,
    /// The parent's sub-agent tokens that are still live.
    pub live: &'a [SubagentRecord],
    /// The whole request.
    pub request: &'a Request<Vec<u8>>,
}

/// Host decisions at each bootstrap step (Bootstrap, Refresh Patterns step
/// 4 and Sub-Agents Under a Hosted AP step 3).
pub trait BootstrapPolicy: Send + Sync {
    /// Approve an enrollment and assign its agent identifier, or refuse it.
    ///
    /// # Errors
    /// A [`Denial`] is answered `403`.
    fn enroll(&self, request: &EnrollmentRequest<'_>) -> Result<EnrollmentApproval, Denial>;
    /// Re-evaluate the install (device posture, attestation freshness,
    /// account status) and grant the new token's `ps`, lifetime and claims.
    ///
    /// # Errors
    /// A [`Denial`] is answered `403`.
    fn refresh(&self, request: &RefreshRequest<'_>) -> Result<AgentGrant, Denial>;
    /// Decide whether this parent may have another sub-agent, and for how
    /// many seconds. The token never outlives the parent's.
    ///
    /// # Errors
    /// A [`Denial`] is answered `403`.
    fn subagent(&self, request: &SubagentRequest<'_>) -> Result<i64, Denial>;
}

/// The URLs at which a hosted provider serves each bootstrap step. The draft
/// defines none (Bootstrap lines 371 and 410). Each is an absolute HTTPS URL.
#[derive(Clone, Debug)]
pub struct BootstrapEndpoints {
    /// Enrollment of a durable key, signed under `hwk` by that key.
    pub enrollment: String,
    /// Two-key refresh under `jkt-jwt`.
    pub refresh: String,
    /// Single-key refresh under `hwk`, when the provider offers it.
    pub single_key_refresh: Option<String>,
    /// Sub-agent issuance, when the provider offers it.
    pub subagent: Option<String>,
}

/// Bootstrap service configuration failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapConfigurationError {
    /// An endpoint is not an absolute HTTPS URL without query or fragment.
    InvalidEndpoint,
    /// Two steps share one endpoint.
    DuplicateEndpoint,
}

impl std::fmt::Display for BootstrapConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidEndpoint => {
                "each bootstrap endpoint must be an absolute HTTPS URL without query or fragment"
            }
            Self::DuplicateEndpoint => "each bootstrap step needs its own endpoint",
        })
    }
}
impl std::error::Error for BootstrapConfigurationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Enroll,
    Refresh,
    SingleKeyRefresh,
    Subagent,
}

impl Step {
    // Signature-Key scheme each step accepts.
    fn scheme(self) -> &'static str {
        match self {
            Self::Enroll | Self::SingleKeyRefresh => "hwk",
            Self::Refresh => "jkt-jwt",
            Self::Subagent => "jwt",
        }
    }
}

/// A request's proof failed. Answered `401` with `Signature-Error`.
#[derive(Debug)]
pub enum BootstrapFailure {
    /// HTTP proof, key or scheme failure, including the naming JWT's.
    Proof(Error),
    /// The parent's Agent token failed verification.
    Token(TokenError),
    /// Missing coverage, with the complete component list for this request.
    Input(Vec<&'static str>),
    /// Signature `created` or naming JWT `iat` is too far ahead.
    ClockSkew,
    /// The naming JWT's `jti` was already used with this durable key.
    Replay,
}

impl BootstrapFailure {
    /// Stable `Signature-Error` code. A replayed naming JWT is
    /// `invalid_signature`, as a replayed signature is (Signature-Key,
    /// `clock_skew`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Proof(error) => error.code(),
            Self::Token(error) => error.code(),
            Self::Input(_) => "invalid_input",
            Self::ClockSkew => "clock_skew",
            Self::Replay => "invalid_signature",
        }
    }
}

impl std::fmt::Display for BootstrapFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(error) => error.fmt(f),
            Self::Token(error) => error.fmt(f),
            Self::Input(required) => {
                write!(f, "signature coverage is incomplete: cover {required:?}")
            }
            Self::ClockSkew => Error::ClockSkew.fmt(f),
            Self::Replay => f.write_str(
                "this naming JWT was already used: sign each refresh with a new naming JWT and jti",
            ),
        }
    }
}

/// Outcome of one bootstrap request. Convert with [`Self::into_response`].
#[derive(Debug)]
pub enum BootstrapDecision {
    /// The durable key is enrolled: `201`, or `200` when it already was.
    /// Body `{"agent"}`.
    Enrolled {
        /// The enrollment record.
        enrollment: Enrollment,
        /// The record was created by this request.
        created: bool,
    },
    /// A refresh or sub-agent token: `200 {"agent_token"}`.
    Issued(IssuedAgentToken),
    /// No bootstrap step is served at this URL: `404`.
    NotFound,
    /// Each step accepts only POST: `405`.
    MethodNotAllowed,
    /// Proof failure: `401` with `Signature-Error`.
    SignatureFailure {
        /// What failed.
        failure: BootstrapFailure,
        /// The scheme this step accepts, sent as `Accept-Signature-Scheme`
        /// with `unsupported_scheme`.
        scheme: &'static str,
    },
    /// The body is not the JSON object this step reads: `400 invalid_request`.
    InvalidRequest(&'static str),
    /// The durable key is not enrolled: `404 enrollment_not_found`.
    NotEnrolled,
    /// The enrollment is disabled or revoked: `403 enrollment_inactive`.
    EnrollmentInactive,
    /// Host policy refused, or a sub-agent asked for a sub-agent:
    /// `403 access_denied`.
    Denied(Denial),
    /// The agent identifier policy assigned is already enrolled for another
    /// durable key: `409 conflict`.
    Conflict,
    /// The token could not be issued, for example because policy granted a
    /// lifetime outside the profile: `500 server_error`.
    IssuanceFailed(TokenError),
    /// The store failed. Nothing was recorded or released: `503`.
    Unavailable,
}

impl BootstrapDecision {
    /// HTTP response. Successes are JSON with `Cache-Control: no-store`;
    /// failures carry RFC 9457 Problem Details, and only a signature failure
    /// carries `Signature-Error`.
    pub fn into_response(self) -> Response<Vec<u8>> {
        match self {
            Self::Enrolled {
                enrollment,
                created,
            } => success(
                if created {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                &json!({ "agent": enrollment.agent }),
            ),
            Self::Issued(issued) => {
                success(StatusCode::OK, &json!({ "agent_token": issued.token }))
            }
            Self::NotFound => problem(StatusCode::NOT_FOUND, "not_found", None),
            Self::MethodNotAllowed => {
                let mut response = problem(StatusCode::METHOD_NOT_ALLOWED, "invalid_request", None);
                response
                    .headers_mut()
                    .insert("allow", "POST".parse().unwrap());
                response
            }
            Self::SignatureFailure { failure, scheme } => {
                let mut response = problem(
                    StatusCode::UNAUTHORIZED,
                    failure.code(),
                    Some(failure.to_string()),
                );
                let mut error = format!("error={}", failure.code());
                if let BootstrapFailure::Input(required) = &failure {
                    let components = required
                        .iter()
                        .map(|name| format!("\"{name}\""))
                        .collect::<Vec<_>>()
                        .join(" ");
                    error.push_str(&format!(", required_input=({components})"));
                }
                let headers = response.headers_mut();
                headers.insert("signature-error", error.parse().unwrap());
                if matches!(failure, BootstrapFailure::Proof(Error::UnsupportedScheme)) {
                    headers.insert("accept-signature-scheme", scheme.parse().unwrap());
                }
                if matches!(
                    failure,
                    BootstrapFailure::Proof(Error::UnsupportedAlgorithm)
                        | BootstrapFailure::Token(TokenError::UnsupportedAlgorithm)
                ) {
                    headers.insert(
                        "accept-signature-alg",
                        role_signature_alg_header().parse().unwrap(),
                    );
                }
                response
            }
            Self::InvalidRequest(detail) => problem(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(detail.to_owned()),
            ),
            Self::NotEnrolled => problem(StatusCode::NOT_FOUND, "enrollment_not_found", None),
            Self::EnrollmentInactive => problem(StatusCode::FORBIDDEN, "enrollment_inactive", None),
            Self::Denied(denial) => problem(StatusCode::FORBIDDEN, "access_denied", denial.reason),
            Self::Conflict => problem(StatusCode::CONFLICT, "conflict", None),
            Self::IssuanceFailed(_) => {
                problem(StatusCode::INTERNAL_SERVER_ERROR, "server_error", None)
            }
            Self::Unavailable => problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                None,
            ),
        }
    }
}

fn success(status: StatusCode, body: &Value) -> Response<Vec<u8>> {
    let mut response = Response::new(serde_json::to_vec(body).expect("a JSON value serializes"));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    response
}

fn problem(status: StatusCode, code: &str, detail: Option<String>) -> Response<Vec<u8>> {
    let kind = if status == StatusCode::UNAUTHORIZED {
        format!("urn:ietf:params:sig-error:{code}")
    } else {
        "about:blank".to_owned()
    };
    let mut body = json!({
        "type": kind,
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "error": code,
    });
    if let Some(detail) = detail {
        body["detail"] = json!(detail);
    }
    let mut response = Response::new(serde_json::to_vec(&body).expect("a JSON value serializes"));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

/// A hosted Agent Provider's bootstrap endpoints (Bootstrap, Refresh
/// Patterns, Sub-Agents Under a Hosted AP and Per-Platform Enrollment
/// Sketches).
///
/// The service owns the [`AgentProvider`] whose key signs every token it
/// issues; serve [`AgentProvider::metadata`] and [`AgentProvider::jwks`]
/// from [`Self::provider`].
pub struct BootstrapService<S, P> {
    provider: AgentProvider,
    domain: String,
    routes: Vec<(String, String, Step)>,
    store: S,
    policy: P,
}

impl<S: BootstrapStore, P: BootstrapPolicy> BootstrapService<S, P> {
    /// Serve each configured step at its endpoint.
    ///
    /// # Errors
    /// [`BootstrapConfigurationError::InvalidEndpoint`] for an endpoint that
    /// is not an absolute HTTPS URL without query or fragment, and
    /// [`BootstrapConfigurationError::DuplicateEndpoint`] when two steps share
    /// one.
    pub fn new(
        provider: AgentProvider,
        endpoints: BootstrapEndpoints,
        store: S,
        policy: P,
    ) -> Result<Self, BootstrapConfigurationError> {
        let mut routes: Vec<(String, String, Step)> = Vec::new();
        let configured = [
            (Some(endpoints.enrollment), Step::Enroll),
            (Some(endpoints.refresh), Step::Refresh),
            (endpoints.single_key_refresh, Step::SingleKeyRefresh),
            (endpoints.subagent, Step::Subagent),
        ];
        for (endpoint, step) in configured {
            let Some(endpoint) = endpoint else { continue };
            let uri: http::Uri = endpoint
                .parse()
                .map_err(|_| BootstrapConfigurationError::InvalidEndpoint)?;
            let authority = canonical_authority(&uri)
                .map_err(|_| BootstrapConfigurationError::InvalidEndpoint)?;
            if uri.query().is_some() || endpoint.contains('#') {
                return Err(BootstrapConfigurationError::InvalidEndpoint);
            }
            let path = match uri.path() {
                "" => "/".to_owned(),
                path => path.to_owned(),
            };
            if routes.iter().any(|(a, p, _)| *a == authority && *p == path) {
                return Err(BootstrapConfigurationError::DuplicateEndpoint);
            }
            routes.push((authority, path, step));
        }
        let domain = provider
            .issuer
            .strip_prefix("https://")
            .unwrap_or(&provider.issuer)
            .to_owned();
        Ok(Self {
            provider,
            domain,
            routes,
            store,
            policy,
        })
    }

    /// The provider that signs every token this service issues.
    pub fn provider(&self) -> &AgentProvider {
        &self.provider
    }

    /// The store holding enrollments, naming-JWT identifiers and sub-agent
    /// records. Revoke an enrollment with [`BootstrapStore::set_state`].
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Handle one buffered request at `now`, in Unix seconds.
    ///
    /// Every step is a POST signed with label `sig` within
    /// [`SIGNATURE_WINDOW`] seconds and covering `@method`, `@authority`,
    /// `@path` and `signature-key`. A body is a JSON object (an empty body
    /// reads as `{}`), sent as `application/json` with `content-type` and
    /// `content-digest` covered (Bootstrap, Two-Key Refresh). Members a step
    /// does not read are ignored.
    ///
    /// - **Enrollment** (`hwk`, by the durable key; Ed25519 or ES256, since
    ///   the key later signs naming JWTs): body `{"evidence"?}`. Host policy
    ///   approves and assigns the identifier, and the enrollment is recorded.
    ///   An already enrolled active key is answered with its record.
    /// - **Refresh** (`jkt-jwt`): the naming JWT is verified, with a `jti`
    ///   required, then the HTTP signature under its `cnf.jwk`. The durable
    ///   key's enrollment must be active, and the `jti` unused for it. Body
    ///   `{"ps"?, "evidence"?}`. Host policy grants the token, which binds
    ///   the delegated key (Bootstrap, Two-Key Refresh step 4).
    /// - **Single-key refresh** (`hwk`, by the durable key): the same, with
    ///   the token bound to the durable key (Bootstrap, Single-Key Refresh).
    /// - **Sub-agent** (`jwt`, the parent's Agent token from this provider,
    ///   signed by its `cnf` key): body `{"jwk", "discriminator"?}`. A parent
    ///   that is itself a sub-agent is refused. The provider uses the offered
    ///   discriminator unless a live sub-agent of the parent already has it,
    ///   and otherwise chooses a random one. Host policy sets the lifetime,
    ///   and the token is recorded before it is released (Bootstrap,
    ///   Sub-Agents Under a Hosted AP).
    pub fn handle(&self, request: &Request<Vec<u8>>, now: i64) -> BootstrapDecision {
        let Ok(authority) = canonical_authority(request.uri()) else {
            return BootstrapDecision::NotFound;
        };
        let Some(step) = self
            .routes
            .iter()
            .find(|(a, p, _)| *a == authority && p == request.uri().path())
            .map(|(_, _, step)| *step)
        else {
            return BootstrapDecision::NotFound;
        };
        if request.method() != Method::POST {
            return BootstrapDecision::MethodNotAllowed;
        }
        let fail = |failure| BootstrapDecision::SignatureFailure {
            failure,
            scheme: step.scheme(),
        };
        let proof = match PreparedRequest::prepare_with_schemes(
            request,
            "sig",
            now,
            SIGNATURE_WINDOW,
            &[step.scheme()],
        ) {
            Ok(proof) => proof,
            Err(Error::ClockSkew) => return fail(BootstrapFailure::ClockSkew),
            Err(Error::InvalidInput) => {
                return fail(BootstrapFailure::Input(body_components(request)));
            }
            Err(error) => return fail(BootstrapFailure::Proof(error)),
        };
        // A body binds a key or evidence, so its media type is covered too.
        if !request.body().is_empty() && !request.headers().contains_key("content-type") {
            return fail(BootstrapFailure::Input(body_components(request)));
        }
        let body = match read_body(request) {
            Ok(body) => body,
            Err(detail) => return BootstrapDecision::InvalidRequest(detail),
        };
        match step {
            Step::Enroll => self.enroll(&proof, &body, request, now),
            Step::Refresh => self.refresh(&proof, &body, request, now),
            Step::SingleKeyRefresh => self.refresh_single_key(&proof, &body, request, now),
            Step::Subagent => self.subagent(&proof, &body, request, now),
        }
    }

    fn enroll(
        &self,
        proof: &PreparedRequest,
        body: &Map<String, Value>,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> BootstrapDecision {
        let (key, thumbprint) = match durable_key(proof) {
            Ok(found) => found,
            Err(failure) => return signature_failure(failure, Step::Enroll),
        };
        match self.store.enrollment(&thumbprint) {
            Ok(Some(existing)) => return answer_existing(existing),
            Ok(None) => {}
            Err(_) => return BootstrapDecision::Unavailable,
        }
        let evidence = body.get("evidence").unwrap_or(&Value::Null);
        let approval = match self.policy.enroll(&EnrollmentRequest {
            durable_key: &key,
            durable_thumbprint: &thumbprint,
            evidence,
            request,
        }) {
            Ok(approval) => approval,
            Err(denial) => return BootstrapDecision::Denied(denial),
        };
        let agent = format!("aauth:{}@{}", approval.local, self.domain);
        if approval.local.contains('+') || validate_agent_identifier(&agent).is_err() {
            return BootstrapDecision::IssuanceFailed(TokenError::InvalidAgentIdentifier);
        }
        let enrollment = Enrollment {
            durable_thumbprint: thumbprint,
            durable_key: key,
            agent,
            account: approval.account,
            state: EnrollmentState::Active,
            enrolled_at: now,
        };
        match self.store.enroll(&enrollment) {
            Ok(()) => BootstrapDecision::Enrolled {
                enrollment,
                created: true,
            },
            // A concurrent enrollment of the same key wins; answer with it.
            Err(BootstrapStoreError::Conflict) => {
                match self.store.enrollment(&enrollment.durable_thumbprint) {
                    Ok(Some(existing)) => answer_existing(existing),
                    Ok(None) => BootstrapDecision::Conflict,
                    Err(_) => BootstrapDecision::Unavailable,
                }
            }
            Err(_) => BootstrapDecision::Unavailable,
        }
    }

    fn refresh(
        &self,
        proof: &PreparedRequest,
        body: &Map<String, Value>,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> BootstrapDecision {
        let fail = |failure| signature_failure(failure, Step::Refresh);
        let delegation = match proof.verify_jkt_jwt(now) {
            Ok(delegation) => delegation,
            Err(Error::ClockSkew) => return fail(BootstrapFailure::ClockSkew),
            Err(error) => return fail(BootstrapFailure::Proof(error)),
        };
        // The draft's naming JWT carries a jti for replay protection
        // (Bootstrap, Two-Key Refresh).
        let Some(jti) = delegation.jti.as_deref() else {
            return fail(BootstrapFailure::Proof(Error::InvalidJwt));
        };
        let Ok(thumbprint) = delegation.identity.thumbprint() else {
            return fail(BootstrapFailure::Proof(Error::InvalidKey));
        };
        let enrollment = match self.active_enrollment(&thumbprint) {
            Ok(enrollment) => enrollment,
            Err(missing) => return missing.into(),
        };
        match self
            .store
            .use_naming_jti(&thumbprint, jti, delegation.expires_at, now)
        {
            Ok(true) => {}
            Ok(false) => return fail(BootstrapFailure::Replay),
            Err(_) => return BootstrapDecision::Unavailable,
        }
        self.issue_refreshed(
            &enrollment,
            &delegation.confirmation,
            false,
            body,
            request,
            now,
        )
    }

    fn refresh_single_key(
        &self,
        proof: &PreparedRequest,
        body: &Map<String, Value>,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> BootstrapDecision {
        let (key, thumbprint) = match durable_key(proof) {
            Ok(found) => found,
            Err(failure) => return signature_failure(failure, Step::SingleKeyRefresh),
        };
        match self.active_enrollment(&thumbprint) {
            Ok(enrollment) => self.issue_refreshed(&enrollment, &key, true, body, request, now),
            Err(missing) => missing.into(),
        }
    }

    fn active_enrollment(&self, thumbprint: &str) -> Result<Enrollment, NoEnrollment> {
        match self.store.enrollment(thumbprint) {
            Ok(Some(enrollment)) if enrollment.state == EnrollmentState::Active => Ok(enrollment),
            Ok(Some(_)) => Err(NoEnrollment::Inactive),
            Ok(None) => Err(NoEnrollment::Unknown),
            Err(_) => Err(NoEnrollment::Unavailable),
        }
    }

    fn issue_refreshed(
        &self,
        enrollment: &Enrollment,
        key: &Jwk,
        single_key: bool,
        body: &Map<String, Value>,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> BootstrapDecision {
        let ps = match body.get("ps") {
            None | Some(Value::Null) => None,
            Some(Value::String(ps)) if validate_server_identifier(ps).is_ok() => Some(ps.as_str()),
            Some(_) => {
                return BootstrapDecision::InvalidRequest(
                    "ps must be a Person Server identifier: a lowercase https:// origin",
                );
            }
        };
        let grant = match self.policy.refresh(&RefreshRequest {
            enrollment,
            key,
            single_key,
            ps,
            evidence: body.get("evidence").unwrap_or(&Value::Null),
            request,
        }) {
            Ok(grant) => grant,
            Err(denial) => return BootstrapDecision::Denied(denial),
        };
        match self.provider.issue_to(&enrollment.agent, key, &grant, now) {
            Ok(issued) => BootstrapDecision::Issued(issued),
            Err(error) => BootstrapDecision::IssuanceFailed(error),
        }
    }

    fn subagent(
        &self,
        proof: &PreparedRequest,
        body: &Map<String, Value>,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> BootstrapDecision {
        let fail = |failure| signature_failure(failure, Step::Subagent);
        let KeyMaterial::Jwt { jwt, .. } = proof.key() else {
            return fail(BootstrapFailure::Proof(Error::UnsupportedScheme));
        };
        let parent = match AgentToken::parse(jwt)
            .and_then(|token| token.verify(&IssuanceKeys(&self.provider), now))
        {
            Ok(parent) => parent,
            Err(error) => return fail(BootstrapFailure::Token(error)),
        };
        if let Err(error) = proof.verify(&parent.claims().cnf.jwk) {
            return fail(BootstrapFailure::Proof(error));
        }
        if parent.claims().parent_agent.is_some() {
            return BootstrapDecision::Denied(Denial {
                reason: Some("a sub-agent cannot have sub-agents".into()),
            });
        }
        let key = match body_key(body, &parent) {
            Ok(key) => key,
            Err(detail) => return BootstrapDecision::InvalidRequest(detail),
        };
        let offered = match body.get("discriminator") {
            None | Some(Value::Null) => None,
            Some(Value::String(d)) if valid_discriminator(d) && d.len() <= 64 => Some(d.as_str()),
            Some(_) => {
                return BootstrapDecision::InvalidRequest(
                    "discriminator must be 1 to 64 ASCII letters, digits, '-', '_' or '.'",
                );
            }
        };
        let live = match self.store.live_subagents(&parent.claims().sub, now) {
            Ok(live) => live,
            Err(_) => return BootstrapDecision::Unavailable,
        };
        let lifetime = match self.policy.subagent(&SubagentRequest {
            parent: &parent,
            key: &key,
            discriminator: offered,
            live: &live,
            request,
        }) {
            Ok(lifetime) => lifetime,
            Err(denial) => return BootstrapDecision::Denied(denial),
        };
        let parent_local = split_agent(&parent.claims().sub).map_or("", |(local, _)| local);
        let taken = |discriminator: &&str| {
            let sub = format!("aauth:{parent_local}+{discriminator}@{}", self.domain);
            live.iter().any(|record| record.agent == sub)
        };
        // The offered discriminator, unless it collides; then the provider's
        // own (Bootstrap, Sub-Agents Under a Hosted AP step 4). A collision
        // the store finds at record time gets one more random choice.
        let mut discriminator = offered
            .filter(|candidate| !taken(candidate))
            .map_or_else(generate_identifier, str::to_owned);
        for _ in 0..2 {
            let issued =
                match self
                    .provider
                    .issue_subagent_to(jwt, &key, &discriminator, lifetime, now)
                {
                    Ok(issued) => issued,
                    Err(error) => return BootstrapDecision::IssuanceFailed(error),
                };
            let record = SubagentRecord {
                agent: issued.claims.sub.clone(),
                parent: parent.claims().sub.clone(),
                jti: issued.claims.jti.clone(),
                key_thumbprint: key.thumbprint().unwrap_or_default(),
                issued_at: issued.claims.iat,
                expires_at: issued.claims.exp,
            };
            match self.store.record_subagent(&record) {
                Ok(()) => return BootstrapDecision::Issued(issued),
                Err(BootstrapStoreError::Conflict) => discriminator = generate_identifier(),
                Err(_) => return BootstrapDecision::Unavailable,
            }
        }
        BootstrapDecision::Conflict
    }
}

// Why a refresh found no active enrollment.
enum NoEnrollment {
    Unknown,
    Inactive,
    Unavailable,
}

impl From<NoEnrollment> for BootstrapDecision {
    fn from(missing: NoEnrollment) -> Self {
        match missing {
            NoEnrollment::Unknown => Self::NotEnrolled,
            NoEnrollment::Inactive => Self::EnrollmentInactive,
            NoEnrollment::Unavailable => Self::Unavailable,
        }
    }
}

fn signature_failure(failure: BootstrapFailure, step: Step) -> BootstrapDecision {
    BootstrapDecision::SignatureFailure {
        failure,
        scheme: step.scheme(),
    }
}

fn answer_existing(existing: Enrollment) -> BootstrapDecision {
    if existing.state == EnrollmentState::Active {
        BootstrapDecision::Enrolled {
            enrollment: existing,
            created: false,
        }
    } else {
        BootstrapDecision::EnrollmentInactive
    }
}

// The `hwk` key of an enrollment or single-key refresh, verified as the
// request's signer, with its thumbprint. The durable key later signs naming
// JWTs, so it is a compact-JWS key: Ed25519 or ES256.
fn durable_key(proof: &PreparedRequest) -> Result<(Jwk, String), BootstrapFailure> {
    let KeyMaterial::Hwk(key) = proof.key() else {
        return Err(BootstrapFailure::Proof(Error::UnsupportedScheme));
    };
    if !JWS_ALGORITHMS.contains(&key.alg.as_str()) {
        return Err(BootstrapFailure::Proof(Error::UnsupportedAlgorithm));
    }
    proof.verify(key).map_err(BootstrapFailure::Proof)?;
    let thumbprint = key
        .thumbprint()
        .map_err(|_| BootstrapFailure::Proof(Error::InvalidKey))?;
    Ok((key.clone(), thumbprint))
}

// The sub-agent's public key from the body: a valid Ed25519 or ES256 JWK
// other than the parent's.
fn body_key(body: &Map<String, Value>, parent: &VerifiedAgentToken) -> Result<Jwk, &'static str> {
    const DETAIL: &str = "jwk must be the sub-agent's public Ed25519 or ES256 JWK with alg";
    let value = body
        .get("jwk")
        .filter(|value| value.is_object())
        .ok_or(DETAIL)?;
    let key: Jwk = serde_json::from_value(value.clone()).map_err(|_| DETAIL)?;
    if key.validate().is_err() || !JWS_ALGORITHMS.contains(&key.alg.as_str()) {
        return Err(DETAIL);
    }
    if key.thumbprint().ok() == parent.claims().cnf.jwk.thumbprint().ok() {
        return Err("the sub-agent's key must not be the parent's key");
    }
    Ok(key)
}

fn read_body(request: &Request<Vec<u8>>) -> Result<Map<String, Value>, &'static str> {
    if request.body().is_empty() {
        return Ok(Map::new());
    }
    let media_type = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err("the body must be application/json");
    }
    match aauth_rust_jose::strict_json(request.body()) {
        Ok(Value::Object(members)) => Ok(members),
        _ => Err("the body must be one JSON object without duplicate members"),
    }
}

// Components a bootstrap request must cover: the base set, plus
// `content-digest` and `content-type` when it carries a body.
fn body_components(request: &Request<Vec<u8>>) -> Vec<&'static str> {
    let required = required_components(request);
    let mut ordered = vec!["@method", "@authority", "@path", "signature-key"];
    for name in ["@query", "authorization", "content-digest", "content-type"] {
        let needed = required.contains(&name)
            || (!request.body().is_empty() && matches!(name, "content-digest" | "content-type"));
        if needed {
            ordered.push(name);
        }
    }
    ordered
}
