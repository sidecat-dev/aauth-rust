//! Agent-identity and PS-authorization Resources. Verification precedes host policy.
#![deny(missing_docs)]
mod budget_gate;
mod held;
mod ps_authorization;
mod session;
use aauth_rust_core::{AgentKeyResolver, AgentToken, TokenError, VerifiedAgentToken};
use aauth_rust_signature_key::{
    Error, KeyMaterial, PreparedRequest, required_components, role_signature_alg_header,
};
pub use held::{HeldError, HeldInvocations, HeldPoll};
use http::{Request, Response, StatusCode};
pub use ps_authorization::{
    AuthAuthorized, AuthDecision, AuthorizationAsk, BoxedAuthAdmissionPolicy, BoxedAuthPolicy,
    BoxedR3Display, BoxedR3OperationMapper, HeldAdmission, ObservedAdmission, ProactiveDecision,
    PsAuthorizationConfig, PsAuthorizationResource, PsConfigurationError, R3Config,
    R3DocumentRecord, R3DocumentStore, R3Grant, R3HostError, R3StoreError, R3Vocabulary,
};
pub use ps_authorization::{
    BoxedR3Describe, BoxedR3Present, BoxedR3Release, DirectoryCallStore, R3CallDescription,
    R3CallResult, R3CallStore,
    R3CallToken, R3Claim, R3HeldRequest, R3PerCallConfig, R3ProposalRecord, R3Release,
};
pub use session::{SessionAdmit, SessionLedger};

/// Invalid host configuration, separate from a caller's proof or token failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigurationError {
    /// The published Resource issuer is not a canonical HTTPS DNS identifier.
    InvalidIssuer,
}
impl ConfigurationError {
    /// Local configuration code; this is not a `Signature-Error` response code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidIssuer => "invalid_configuration",
        }
    }
}
impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "invalid Resource metadata issuer: configure a lowercase HTTPS DNS origin without port or path; use metadata_for(issuer) when the published identity differs from the request authority",
        )
    }
}
impl std::error::Error for ConfigurationError {}

#[derive(Debug)]
/// Failed proof/token verification or the required coverage needed to retry.
pub enum SignatureFailure {
    /// HTTP proof or target binding failed.
    Proof(Error),
    /// Issuer JWT or trusted discovery failed.
    Token(TokenError),
    /// Missing coverage, with the complete request-specific component list.
    Input(Vec<&'static str>),
    /// Signature or token issuance is too far in the future; retains the verifier clock.
    ClockSkew {
        /// Verifier's trusted Unix seconds, used for the response Date header.
        server_time: i64,
    },
}
impl SignatureFailure {
    /// Machine-readable wire code, separate from local error explanations.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Proof(error) => error.code(),
            Self::Token(error) => error.code(),
            Self::Input(_) => "invalid_input",
            Self::ClockSkew { .. } => "clock_skew",
        }
    }
}
impl std::fmt::Display for SignatureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(e) => e.fmt(f),
            Self::Token(e) => e.fmt(f),
            Self::ClockSkew { .. } => Error::ClockSkew.fmt(f),
            Self::Input(required) => {
                write!(f, "signature coverage is incomplete: cover {required:?}")
            }
        }
    }
}
/// Host policy refused an authenticated request. No signature diagnostics are sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deny;

/// Result of a host policy: booleans carry no extra context; `Result<T, Deny>`
/// carries a verified application value into the handler without checking it twice.
pub trait PolicyOutcome {
    /// Value retained only on successful admission.
    type Context;
    /// Convert a policy result into an allowed value or an opaque policy denial.
    fn into_admission(self) -> Result<Self::Context, Deny>;
}
impl PolicyOutcome for bool {
    type Context = ();
    fn into_admission(self) -> Result<(), Deny> {
        if self { Ok(()) } else { Err(Deny) }
    }
}
impl<T> PolicyOutcome for Result<T, Deny> {
    type Context = T;
    fn into_admission(self) -> Result<T, Deny> {
        self
    }
}

/// Verified caller identity and the value returned by successful host policy.
/// Dereferences to the token for read-only claim/compact-byte inspection.
#[derive(Debug)]
pub struct Authorized<T = ()> {
    token: VerifiedAgentToken,
    admitted: T,
}
impl<T> Authorized<T> {
    /// Authenticated caller token; the HTTP proof and host policy also succeeded.
    pub fn token(&self) -> &VerifiedAgentToken {
        &self.token
    }
    /// Application context produced by policy, such as a verified upstream token.
    pub fn admitted(&self) -> &T {
        &self.admitted
    }
    /// Move both values into an application handler without verifying again.
    pub fn into_parts(self) -> (VerifiedAgentToken, T) {
        (self.token, self.admitted)
    }
}
impl<T> std::ops::Deref for Authorized<T> {
    type Target = VerifiedAgentToken;
    fn deref(&self) -> &VerifiedAgentToken {
        &self.token
    }
}

/// Resource outcome. Convert to HTTP only after inspecting application needs.
#[derive(Debug)]
pub enum Decision<T = ()> {
    /// No proof was supplied: send a 401 Agent-token challenge.
    AgentTokenRequired,
    /// Proof/token verification failed: 401 with a stable Signature-Error code.
    SignatureFailure(SignatureFailure),
    /// Verified identity failed host policy: 403 without signature diagnostics.
    Forbidden,
    /// Proof and issuer token verified and host policy allowed the identity.
    Granted(Box<Authorized<T>>),
}
impl<T> Decision<T> {
    /// Extract caller and admitted context for an application handler, or an HTTP refusal.
    ///
    /// # Errors
    /// Returns the mapped 401/403 response if target, authentication or policy refused.
    pub fn into_result(self) -> Result<(VerifiedAgentToken, T), Box<Response<Vec<u8>>>> {
        match self {
            Self::Granted(value) => Ok((*value).into_parts()),
            other => Err(Box::new(other.into_response())),
        }
    }
    /// HTTP mapping with safe RFC 9457 Problem Details for failures.
    /// Granted writes the authenticated subject as the response body. Match
    /// Granted directly when handing control to an application handler instead.
    pub fn into_response(self) -> Response<Vec<u8>> {
        let mut response = Response::new(Vec::new());
        match self {
            Self::AgentTokenRequired => {
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                response.headers_mut().insert(
                    "aauth-requirement",
                    "requirement=agent-token".parse().unwrap(),
                );
                problem(
                    &mut response,
                    "about:blank",
                    "Agent token required",
                    401,
                    None,
                );
            }
            Self::Forbidden => {
                *response.status_mut() = StatusCode::FORBIDDEN;
                problem(&mut response, "about:blank", "Forbidden", 403, None);
            }
            Self::Granted(token) => {
                *response.body_mut() = token.claims().sub.as_bytes().to_vec();
            }
            Self::SignatureFailure(failure) => {
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                let mut error = format!("error={}", failure.code());
                if let SignatureFailure::Input(required) = &failure {
                    let components = required
                        .iter()
                        .map(|s| format!("\"{s}\""))
                        .collect::<Vec<_>>()
                        .join(" ");
                    error.push_str(&format!(", required_input=({components})"));
                }
                response
                    .headers_mut()
                    .insert("signature-error", error.parse().unwrap());
                if let SignatureFailure::ClockSkew { server_time } = &failure
                    && (0..=(1_i64 << 33) - 1).contains(server_time)
                    && let Some(time) = std::time::UNIX_EPOCH
                        .checked_add(std::time::Duration::from_secs(*server_time as u64))
                {
                    response
                        .headers_mut()
                        .insert("date", httpdate::fmt_http_date(time).parse().unwrap());
                }
                problem(
                    &mut response,
                    &format!("urn:ietf:params:sig-error:{}", failure.code()),
                    if matches!(
                        failure,
                        SignatureFailure::Token(TokenError::AudienceMismatch)
                    ) {
                        "Token audience mismatch"
                    } else {
                        "Request signature rejected"
                    },
                    401,
                    if matches!(
                        failure,
                        SignatureFailure::Token(TokenError::AudienceMismatch)
                    ) {
                        Some(
                            "Token audience does not match this Resource; obtain a token for this Resource before retrying.",
                        )
                    } else {
                        None
                    },
                );
                if matches!(
                    failure,
                    SignatureFailure::Token(TokenError::UnexpectedTokenType)
                ) {
                    response.headers_mut().insert(
                        "aauth-requirement",
                        "requirement=agent-token".parse().unwrap(),
                    );
                }
                if matches!(
                    failure,
                    SignatureFailure::Proof(Error::UnsupportedAlgorithm)
                        | SignatureFailure::Token(TokenError::UnsupportedAlgorithm)
                ) {
                    response.headers_mut().insert(
                        "accept-signature-alg",
                        role_signature_alg_header().parse().unwrap(),
                    );
                }
                if matches!(failure, SignatureFailure::Proof(Error::UnsupportedScheme)) {
                    response
                        .headers_mut()
                        .insert("accept-signature-scheme", "jwt".parse().unwrap());
                }
            }
        }
        response
    }
}

fn problem(
    response: &mut Response<Vec<u8>>,
    kind: &str,
    title: &str,
    status: u16,
    detail: Option<&str>,
) {
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    let code = kind
        .strip_prefix("urn:ietf:params:sig-error:")
        .unwrap_or(if status == 403 {
            "forbidden"
        } else {
            "agent_token_required"
        });
    let mut value = serde_json::json!({"type":kind,"title":title,"status":status,"error":code});
    if let Some(detail) = detail {
        value["detail"] = serde_json::json!(detail);
    }
    *response.body_mut() =
        serde_json::to_vec(&value).expect("fixed Problem Details fields are serializable");
}

/// A named policy type for Resource values stored in application state.
/// A boxed closure can capture application state while remaining Send + Sync.
pub type BoxedPolicy = Box<dyn Fn(&VerifiedAgentToken, &Request<Vec<u8>>) -> bool + Send + Sync>;

/// A named stateful policy carrying application context into a successful handler.
pub type BoxedAdmissionPolicy<T> =
    Box<dyn Fn(&VerifiedAgentToken, &Request<Vec<u8>>) -> Result<T, Deny> + Send + Sync>;

/// Direct Agent identity: trusted issuer token, holder proof, then host policy.
pub struct AgentIdentityResource<K, P> {
    keys: K,
    policy: P,
    authority: String,
    path: Option<String>,
}
impl<K: AgentKeyResolver, P, O> AgentIdentityResource<K, P>
where
    P: Fn(&VerifiedAgentToken, &Request<Vec<u8>>) -> O,
    O: PolicyOutcome,
{
    /// Bind this Resource to one HTTPS endpoint, plus trusted keys and policy.
    /// Configure authority/path from server configuration, never from client Host.
    /// Queries vary per request and are covered by the request signature.
    ///
    /// # Errors
    /// Rejects non-HTTPS/relative targets, userinfo, invalid ports, queries and
    /// fragments. The endpoint authority/path must come from server configuration.
    pub fn new(endpoint: &str, keys: K, policy: P) -> Result<Self, Error> {
        let uri: http::Uri = endpoint.parse().map_err(|_| Error::InvalidUri)?;
        if uri.query().is_some() || endpoint.contains('#') {
            return Err(Error::InvalidUri);
        }
        Ok(Self {
            keys,
            policy,
            authority: aauth_rust_signature_key::canonical_authority(&uri)?,
            path: Some(uri.path().to_owned()),
        })
    }
    /// Bind one Resource to an HTTPS origin across all router paths.
    /// Every request must still be signed over its actual path and use this
    /// configured authority. The host router and policy own route admission;
    /// this constructor is not a path-prefix or route whitelist.
    /// Use [`Self::new`] for an exact endpoint binding instead.
    ///
    /// # Errors
    /// Rejects non-HTTPS/invalid authorities, non-root paths, query or fragment.
    /// A trailing root slash is accepted; queries vary on signed requests only.
    pub fn for_origin(origin: &str, keys: K, policy: P) -> Result<Self, Error> {
        let uri: http::Uri = origin.parse().map_err(|_| Error::InvalidUri)?;
        if !uri.path().is_empty() && uri.path() != "/" {
            return Err(Error::InvalidUri);
        }
        let mut resource = Self::new(origin, keys, policy)?;
        resource.path = None;
        Ok(resource)
    }
    /// Minimal metadata for this verifier, served by the host at
    /// `/.well-known/aauth-resource.json` as application/json over HTTPS.
    /// Advertises Agent-token access and the actual 60-second signature window.
    /// No JWKS or token/authorization endpoint is invented for a verifying role.
    /// Hosts may add branding to an owned copy without changing protocol fields.
    /// Conditional body digest/type requirements are reported by `required_input`;
    /// this document does not declare them unconditional for every empty request.
    ///
    /// # Errors
    /// Returns [`ConfigurationError::InvalidIssuer`] if the configured request
    /// authority cannot also serve as a canonical DNS server identity.
    /// Use [`Self::metadata_for`] to configure publication separately when the
    /// request authority includes a nondefault port or IP address.
    pub fn metadata(&self) -> Result<Vec<u8>, ConfigurationError> {
        self.metadata_for(&format!("https://{}", self.authority))
    }
    /// Metadata with an explicitly configured published HTTPS server identity.
    /// The issuer comes from host configuration, never a request Host header.
    /// This does not change request authority/path binding: a configured port
    /// remains part of the signed authority. The host owns discovery routing,
    /// socket mapping and TLS for the published identity.
    ///
    /// # Errors
    /// Returns [`ConfigurationError::InvalidIssuer`] unless `issuer` is a
    /// canonical lowercase HTTPS DNS origin without port, path or trailing slash.
    pub fn metadata_for(&self, issuer: &str) -> Result<Vec<u8>, ConfigurationError> {
        aauth_rust_core::validate_server_identifier(issuer)
            .map_err(|_| ConfigurationError::InvalidIssuer)?;
        Ok(serde_json::json!({
            "issuer":issuer, "access_mode":"agent-token", "signature_window":60
        })
        .to_string()
        .into_bytes())
    }
    /// Replace admission policy while retaining the configured target and keys.
    pub fn with_policy<Q, R>(self, policy: Q) -> AgentIdentityResource<K, Q>
    where
        Q: Fn(&VerifiedAgentToken, &Request<Vec<u8>>) -> R,
        R: PolicyOutcome,
    {
        AgentIdentityResource {
            keys: self.keys,
            policy,
            authority: self.authority,
            path: self.path,
        }
    }
    /// Check a buffered absolute HTTPS request at `now` in Unix seconds.
    /// The proof window is ±60 seconds. Token expiry has no leeway; future
    /// `iat` beyond 60 seconds is refused. Policy receives token and request only
    /// after verification. Nonempty content requires covered SHA-256 Content-Digest
    /// and covered Content-Type when present; actual content is limited to 1 MiB.
    /// Supply actual bytes before decompression, or reject bodies at transport;
    /// an empty placeholder does not authenticate an unread downstream body.
    ///
    /// ```
    /// use aauth_rust_core::{AgentProviderKeys, VerifiedAgentToken};
    /// use aauth_rust_resource::{AgentIdentityResource, Decision};
    /// use http::Request;
    /// let keys = AgentProviderKeys::from_documents("https://ap.example",
    ///     br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/keys"}"#,
    ///     br#"{"keys":[]}"#)?;
    /// let resource = AgentIdentityResource::new("https://resource.example/", keys, |_: &VerifiedAgentToken, _request: &Request<Vec<u8>>| true)?;
    /// let request = http::Request::builder().uri("https://resource.example/")
    ///     .body(Vec::new())?;
    /// assert!(matches!(resource.authorize(&request, 1000), Decision::AgentTokenRequired));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn authorize(&self, request: &Request<Vec<u8>>, now: i64) -> Decision<O::Context> {
        let authority = match aauth_rust_signature_key::canonical_authority(request.uri()) {
            Ok(authority) => authority,
            Err(error) => return Decision::SignatureFailure(SignatureFailure::Proof(error)),
        };
        if authority != self.authority
            || self
                .path
                .as_deref()
                .is_some_and(|path| request.uri().path() != path)
        {
            return Decision::SignatureFailure(SignatureFailure::Proof(Error::TargetMismatch));
        }
        if ["signature-key", "signature-input", "signature"]
            .iter()
            .all(|h| !request.headers().contains_key(*h))
        {
            return Decision::AgentTokenRequired;
        }
        let proof = match PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwt"]) {
            Ok(v) => v,
            Err(Error::ClockSkew) => {
                return Decision::SignatureFailure(SignatureFailure::ClockSkew {
                    server_time: now,
                });
            }
            Err(Error::InvalidInput) => {
                return Decision::SignatureFailure(SignatureFailure::Input(required_components(
                    request,
                )));
            }
            Err(e) => return Decision::SignatureFailure(SignatureFailure::Proof(e)),
        };
        let KeyMaterial::Jwt(compact) = proof.key() else {
            return Decision::SignatureFailure(SignatureFailure::Proof(Error::UnsupportedScheme));
        };
        let token = match AgentToken::parse(compact).and_then(|t| t.verify(&self.keys, now)) {
            Ok(v) => v,
            Err(e) => return Decision::SignatureFailure(SignatureFailure::Token(e)),
        };
        if token.claims().iat > now.saturating_add(60) {
            return Decision::SignatureFailure(SignatureFailure::ClockSkew { server_time: now });
        }
        if let Err(e) = proof.verify(&token.claims().cnf.jwk) {
            return Decision::SignatureFailure(SignatureFailure::Proof(e));
        }
        match (self.policy)(&token, request).into_admission() {
            Ok(admitted) => Decision::Granted(Box::new(Authorized { token, admitted })),
            Err(Deny) => Decision::Forbidden,
        }
    }

    /// Verify `request` and admit its session token in one call.
    ///
    /// The bound subject is returned only when [`Self::authorize`] grants this
    /// request. A caller-supplied subject is not accepted. An unverified
    /// presentation is [`SessionAdmit::Standalone`] and does not reveal the
    /// wrapped subject.
    pub fn admit_session(
        &self,
        ledger: &SessionLedger,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> SessionAdmit {
        let token = match session::presented_token(request) {
            Ok(token) => token,
            Err(outcome) => return outcome,
        };
        match self.authorize(request, now) {
            Decision::Granted(authorized) => ledger.grant(&token, authorized.claims().sub.as_str()),
            _ => SessionAdmit::Standalone,
        }
    }
}
