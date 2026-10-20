//! Immediate, missionless Person-Server authorization with route challenges.
use crate::{Decision, Deny, PolicyOutcome, SignatureFailure};
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthToken, PersonToken, ResourceClaims, TokenError,
    VerifiedAuthToken, mint_resource_token, validate_server_identifier,
};
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_signature_key::{
    Error, KeyMaterial, PreparedRequest, canonical_authority, required_components,
};
use http::{Request, Response, StatusCode};
use serde_json::json;

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
    /// Scope profile is empty, duplicated or contains malformed values.
    InvalidScopes,
    /// Expected Access Server identifier is malformed.
    InvalidAccessServer,
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
            Self::InvalidScopes => "Resource scopes must be nonempty unique RFC 6749 scope values",
        })
    }
}
impl std::error::Error for PsConfigurationError {}

/// Verified PS-issued Auth token and application context returned by host policy.
#[derive(Debug)]
pub struct AuthAuthorized<T = ()> {
    token: VerifiedAuthToken,
    admitted: T,
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
    /// Move authenticated token and policy context to the application handler.
    pub fn into_parts(self) -> (VerifiedAuthToken, T) {
        (self.token, self.admitted)
    }
}

/// Result of immediate Person-Server Resource authorization.
pub enum AuthDecision<T = ()> {
    /// No Person/Auth credential was verified; obtain a Person token first.
    PersonTokenRequired,
    /// Verified Person identity requires PS authorization before application use.
    AuthTokenRequired {
        /// Resource-signed challenge to exchange with the actual presented token.
        resource_token: String,
    },
    /// JWT or HTTP proof verification failed before host policy.
    SignatureFailure(SignatureFailure),
    /// Verified authorization is insufficient or host policy refused admission.
    Forbidden,
    /// Host-supplied challenge identifier/time could not produce a valid token.
    InternalError,
    /// Verified Auth token, holder proof, route scopes and host policy admitted it.
    Granted(Box<AuthAuthorized<T>>),
}
impl<T> std::fmt::Debug for AuthDecision<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PersonTokenRequired => f.write_str("PersonTokenRequired"),
            Self::AuthTokenRequired { .. } => {
                f.debug_struct("AuthTokenRequired").finish_non_exhaustive()
            }
            Self::SignatureFailure(error) => {
                f.debug_tuple("SignatureFailure").field(error).finish()
            }
            Self::Forbidden => f.write_str("Forbidden"),
            Self::InternalError => f.write_str("InternalError"),
            Self::Granted(value) => f
                .debug_struct("Granted")
                .field("token", &value.token)
                .finish_non_exhaustive(),
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
            Self::Granted(value) => Response::new(value.token.claims().sub.as_bytes().to_vec()),
            Self::PersonTokenRequired => {
                let mut response = refusal(StatusCode::UNAUTHORIZED, "person_token_required");
                response.headers_mut().insert(
                    "aauth-requirement",
                    "requirement=person-token".parse().unwrap(),
                );
                response
            }
            Self::AuthTokenRequired { resource_token } => {
                let mut response = refusal(StatusCode::UNAUTHORIZED, "auth_token_required");
                let requirement =
                    format!("requirement=auth-token;resource-token=\"{resource_token}\"");
                let Ok(value) = requirement.parse() else {
                    return refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
                };
                response.headers_mut().insert("aauth-requirement", value);
                response
            }
            Self::Forbidden => refusal(StatusCode::FORBIDDEN, "access_denied"),
            Self::InternalError => refusal(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        }
    }
}
fn refusal(status: StatusCode, code: &str) -> Response<Vec<u8>> {
    let mut response = Response::new(json!({"type":"about:blank", "title":status.canonical_reason().unwrap_or("Request refused"), "status":status.as_u16(), "error":code}).to_string().into_bytes());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

/// Missionless PS authorization: credential/holder verification precedes policy.
/// This Resource issues route challenges, not an explicit authorization endpoint.
/// Host keys implement the accepted issuer trust set; host policy owns account and
/// person-record admission. A Person token is never admitted as authorization.
pub struct PsAuthorizationResource<K, P> {
    config: PsAuthorizationConfig,
    authority: String,
    keys: K,
    policy: P,
    access_server: Option<String>,
}
impl<K: AgentKeyResolver, P, O> PsAuthorizationResource<K, P>
where
    P: Fn(&VerifiedAuthToken, &Request<Vec<u8>>) -> O,
    O: PolicyOutcome,
{
    /// Bind a published identity, separately configured signed origin, keys and policy.
    ///
    /// # Errors
    /// Rejects invalid identifiers/origins, empty kid and invalid scope profiles.
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
        Ok(Self {
            config,
            authority,
            keys,
            policy,
            access_server: None,
        })
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
    /// Accurate public metadata; serve at the published Resource well-known path.
    /// This profile publishes no AS, revocation or explicit authorization endpoint.
    ///
    /// # Errors
    /// Returns a serialization error as InvalidJwt.
    pub fn metadata(&self) -> Result<Vec<u8>, TokenError> {
        serde_json::to_vec(&json!({"issuer":self.config.issuer,"jwks_uri":format!("{}/.well-known/jwks.json",self.config.issuer),"access_mode":"auth-token","signature_window":60})).map_err(|_| TokenError::InvalidJwt)
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
    /// 60-second window. Missions, AS-issued Auth and known companion authority
    /// claims are refused by this immediate Core profile.
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
        match self.authorize_proved(request, now, challenge_jti) {
            Ok(decision) => decision,
            Err(error) => AuthDecision::SignatureFailure(error),
        }
    }
    fn authorize_proved(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        challenge_jti: &str,
    ) -> Result<AuthDecision<O::Context>, SignatureFailure> {
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
                let token = PersonToken::parse(compact)
                    .and_then(|token| token.verify(&self.keys, now))
                    .map_err(SignatureFailure::Token)?;
                let claims = token.claims();
                proof
                    .verify(&claims.cnf.jwk)
                    .map_err(SignatureFailure::Proof)?;
                check_iat(claims.iat, now)?;
                if claims.aud != self.config.issuer {
                    return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                }
                if claims.mission_s256.is_some() || unsupported_companion(&claims.extra) {
                    return Err(SignatureFailure::Token(TokenError::InvalidJwt));
                }
                let challenge = ResourceClaims {
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
                    exp: now.saturating_add(300),
                    scope: Some(self.config.scopes.join(" ")),
                    account: None,
                    login_hint: None,
                    nbf: None,
                    tenant: claims.tenant.clone(),
                    mission_s256: None,
                    extra: Default::default(),
                };
                match mint_resource_token(&self.config.signing_key, &self.config.kid, &challenge) {
                    Ok(resource_token) => Ok(AuthDecision::AuthTokenRequired { resource_token }),
                    Err(_) => Ok(AuthDecision::InternalError),
                }
            }
            Some("aa-auth+jwt") => {
                let token = AuthToken::parse(compact)
                    .and_then(|token| token.verify(&self.keys, now))
                    .map_err(SignatureFailure::Token)?;
                let claims = token.claims();
                proof
                    .verify(&claims.cnf.jwk)
                    .map_err(SignatureFailure::Proof)?;
                check_iat(claims.iat, now)?;
                if claims.aud != self.config.issuer {
                    return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
                }
                let valid_role = match &self.access_server {
                    Some(issuer) => claims.dwk == "aauth-access.json" && &claims.iss == issuer,
                    None => claims.dwk == "aauth-person.json" && claims.iss == claims.ps,
                };
                if !valid_role
                    || claims.mission_s256.is_some()
                    || unsupported_companion(&claims.extra)
                {
                    return Err(SignatureFailure::Token(TokenError::InvalidJwt));
                }
                let granted: Vec<&str> = claims.scope.as_deref().unwrap_or("").split(' ').collect();
                if self
                    .config
                    .scopes
                    .iter()
                    .any(|scope| !granted.contains(&scope.as_str()))
                {
                    return Ok(AuthDecision::Forbidden);
                }
                match (self.policy)(&token, request).into_admission() {
                    Ok(admitted) => Ok(AuthDecision::Granted(Box::new(AuthAuthorized {
                        token,
                        admitted,
                    }))),
                    Err(Deny) => Ok(AuthDecision::Forbidden),
                }
            }
            _ => Err(SignatureFailure::Token(TokenError::UnexpectedTokenType)),
        }
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
fn unsupported_companion(claims: &std::collections::BTreeMap<String, serde_json::Value>) -> bool {
    [
        "r3_uri",
        "r3_s256",
        "r3_granted",
        "r3_per_call",
        "budget",
        "budget_consumed",
    ]
    .iter()
    .any(|name| claims.contains_key(*name))
}
