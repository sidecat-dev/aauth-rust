mod continuation;
mod federation;
pub use continuation::{AdvanceError, DeferredConfig, FederationInput};
mod lineage;
mod wire;
use wire::{Failure, bytes_response, json_response, token_response};

use crate::{
    AgentIdentity, AuthorizationRequest, Grant, Person, PersonRequest, Policy, PolicyError, Store,
    StoreError, TokenKind, TokenRecord, TokenReference, TokenTie, UpstreamContext,
};
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthClaims, AuthToken, Confirmation, PersonClaims, PersonToken,
    ResourceToken, TokenError, VerifiedAgentToken, VerifiedResourceToken, mint_auth_token,
    mint_person_token, validate_server_identifier,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey, strict_json};
use aauth_rust_signature_key::{
    Error as ProofError, KeyMaterial, PreparedRequest, canonical_authority,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Host-controlled Person Server identity, signing key and lifetime bounds.
pub struct Config {
    /// Published canonical HTTPS Person Server identity.
    pub issuer: String,
    /// Actual HTTPS origin verified on requests; ports are allowed here only.
    pub signed_origin: String,
    /// Identifier of the published signing key.
    pub kid: String,
    /// Host-owned signing key; no secret bytes are exported.
    pub signing_key: SigningKey,
    /// Requested Person token lifetime in seconds, positive and at most 3600.
    pub person_lifetime: i64,
    /// Maximum accepted Resource token lifetime in seconds, positive and at most 3600.
    pub max_resource_lifetime: i64,
}
impl Config {
    /// Prepare configuration with 3600-second Person and 300-second Resource bounds.
    /// PersonServer::new performs validation before requests can be handled.
    pub fn new(issuer: &str, kid: &str, signing_key: SigningKey) -> Self {
        Self {
            issuer: issuer.into(),
            signed_origin: issuer.into(),
            kid: kid.into(),
            signing_key,
            person_lifetime: 3600,
            max_resource_lifetime: 300,
        }
    }
}
/// Invalid local configuration; never a caller's protocol authentication error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid_configuration: use a canonical issuer, HTTPS signed origin, nonempty kid and positive bounded lifetimes"
)]
pub struct ConfigurationError;
impl ConfigurationError {
    /// Stable local diagnostic code, not a Signature-Error code.
    pub fn code(&self) -> &'static str {
        "invalid_configuration"
    }
}

/// Buffered PS authorization with optional host-driven AS continuations. Host supplies trust, atomic storage,
/// authenticated person policy, a trusted clock and fresh token identifiers.
pub struct PersonServer<K, S, P, C, I> {
    config: Config,
    authority: String,
    keys: K,
    store: S,
    policy: P,
    clock: C,
    ids: I,
    federation: Option<crate::BoxedFederation>,
    deferred: Option<DeferredConfig>,
}
struct LocalKeys<'a, K> {
    config: &'a Config,
    host: &'a K,
}
impl<K: AgentKeyResolver> AgentKeyResolver for LocalKeys<'_, K> {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if issuer == self.config.issuer && dwk == "aauth-person.json" {
            if kid != self.config.kid {
                return Err(TokenError::UnknownKey);
            }
            return Ok(self.config.signing_key.public_jwk());
        }
        self.host.key(issuer, dwk, kid)
    }
}
#[derive(Clone)]
struct Presented {
    kind: TokenKind,
    issuer: String,
    jti: String,
    aud: String,
    ps: String,
    sub: String,
    tenant: Option<String>,
    mission: Option<String>,
    jkt: String,
    iat: i64,
    exp: i64,
    scope: Option<String>,
}
struct PreparedAuthorization {
    resource: VerifiedResourceToken,
    presented: Presented,
    retained: TokenRecord,
    context: AuthorizationRequest,
    binding_context: BindingContext,
}
struct Issuance<'a> {
    kind: TokenKind,
    jti: &'a str,
    resource: &'a str,
    subject: &'a str,
    tenant: Option<String>,
    issued_at: i64,
    expires_at: i64,
    presented: Option<TokenTie>,
    upstream: Option<TokenTie>,
}
struct Upstream {
    context: UpstreamContext,
    token: Presented,
}
#[derive(Clone, Copy)]
enum BindingContext {
    NewPerson,
    Presented,
    Upstream,
}
impl BindingContext {
    fn revoked(self) -> Failure {
        match self {
            Self::NewPerson => Failure::status(StatusCode::FORBIDDEN, "denied"),
            Self::Presented => Failure::parameter("revoked_presented_token"),
            Self::Upstream => Failure::parameter("revoked_upstream_token"),
        }
    }
}
impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Validate local identity/origin/lifetimes and retain host-owned dependencies.
    ///
    /// # Errors
    /// Returns invalid_configuration for malformed identities, origin, kid or limits.
    pub fn new(
        config: Config,
        keys: K,
        store: S,
        policy: P,
        clock: C,
        ids: I,
    ) -> Result<Self, ConfigurationError> {
        validate_server_identifier(&config.issuer).map_err(|_| ConfigurationError)?;
        let uri: http::Uri = config
            .signed_origin
            .parse()
            .map_err(|_| ConfigurationError)?;
        if config.signed_origin.contains('#')
            || uri.query().is_some()
            || (!uri.path().is_empty() && uri.path() != "/")
            || config.kid.is_empty()
            || !(1..=3600).contains(&config.person_lifetime)
            || !(1..=3600).contains(&config.max_resource_lifetime)
        {
            return Err(ConfigurationError);
        }
        let authority = canonical_authority(&uri).map_err(|_| ConfigurationError)?;
        Ok(Self {
            config,
            authority,
            keys,
            store,
            policy,
            clock,
            ids,
            federation: None,
            deferred: None,
        })
    }
    /// Enable AS federation for every /token request, including
    /// collocated PS=AS. No direct-issuance fallback; consent defaults denied.
    /// Host adapter owns discovery, safe HTTPS, bounds, deadlines and egress.
    pub fn with_federation(mut self, adapter: impl crate::Federation + 'static) -> Self {
        self.federation = Some(Box::new(adapter));
        self
    }
    /// Public PS metadata; only implemented Person/Auth endpoints are advertised.
    pub fn metadata(&self) -> Vec<u8> {
        json!({"issuer":self.config.issuer,"person_token_endpoint":format!("{}/person",self.config.issuer),"auth_token_endpoint":format!("{}/token",self.config.issuer),"jwks_uri":format!("{}/.well-known/jwks.json",self.config.issuer)}).to_string().into_bytes()
    }
    /// Public signing key and kid, never secret material.
    pub fn jwks(&self) -> Vec<u8> {
        let mut key = serde_json::to_value(self.config.signing_key.public_jwk())
            .expect("public key is serializable");
        key["kid"] = json!(self.config.kid);
        json!({"keys":[key]}).to_string().into_bytes()
    }
    /// Handle actual buffered bytes at configured HTTPS targets. Host transport
    /// must bound collection too. Policy and storage complete before token release;
    /// trusted time is resampled after policy and after durable commit.
    /// Federation failures attach a host-only [`crate::FederationFailure`] in
    /// response extensions. Inspect before framework conversion/serialization;
    /// the wire problem relays terminal AS status/error but excludes private detail.
    pub fn handle(&self, request: &Request<Vec<u8>>) -> Response<Vec<u8>> {
        match self.handle_inner(request) {
            Ok(response) => response,
            Err(error) => error.response(),
        }
    }
    fn resolver(&self) -> LocalKeys<'_, K> {
        LocalKeys {
            config: &self.config,
            host: &self.keys,
        }
    }
    fn handle_inner(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Failure> {
        let now = (self.clock)();
        if canonical_authority(request.uri()).ok().as_deref() != Some(&self.authority) {
            return Err(Failure::proof(ProofError::TargetMismatch, request, now));
        }
        if self.deferred.is_some() && request.uri().path().starts_with("/token/pending/") {
            return self.pending(request, now);
        }
        match (request.method().as_str(), request.uri().path()) {
            ("GET", "/.well-known/aauth-person.json") => {
                return Ok(bytes_response(self.metadata()));
            }
            ("GET", "/.well-known/jwks.json") => return Ok(bytes_response(self.jwks())),
            ("POST", "/person" | "/token") => {}
            _ => {
                return Ok(json_response(
                    StatusCode::NOT_FOUND,
                    json!({"error":"not_found"}),
                ));
            }
        }
        let agent = self.verify_request(request, now)?;
        let body =
            strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))?;
        let parameters = body
            .as_object()
            .ok_or_else(|| Failure::parameter("invalid_request"))?;
        self.validate_parameters(parameters, request.uri().path() == "/person")?;
        if agent.claims().parent_agent.is_some() {
            return Err(Failure::credential(TokenError::InvalidJwt));
        }
        let upstream = if parameters.contains_key("upstream_token") {
            Some(self.verify_upstream(required_string(&body, "upstream_token")?, &agent, now)?)
        } else {
            None
        };
        if request.uri().path() == "/person" {
            if upstream.is_none() && agent.claims().ps.as_deref() != Some(&self.config.issuer) {
                return Err(Failure::credential(TokenError::InvalidJwt));
            }
            self.person(agent, body, upstream)
        } else {
            self.auth(agent, body, now, upstream)
        }
    }
    fn verify_request(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<VerifiedAgentToken, Failure> {
        self.verify_agent(request, now, true)
    }
    fn verify_agent(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        body_required: bool,
    ) -> Result<VerifiedAgentToken, Failure> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwt"])
            .map_err(|error| Failure::proof(error, request, now))?;
        let base = std::str::from_utf8(proof.signature_base())
            .map_err(|_| Failure::proof(ProofError::InvalidInput, request, now))?;
        if body_required
            && (!request.headers().contains_key("content-type")
                || !base
                    .lines()
                    .any(|line| line.starts_with("\"content-type\":"))
                || !base
                    .lines()
                    .any(|line| line.starts_with("\"content-digest\":")))
        {
            return Err(Failure::proof(ProofError::InvalidInput, request, now));
        }
        let KeyMaterial::Jwt(compact) = proof.key() else {
            return Err(Failure::proof(ProofError::UnsupportedScheme, request, now));
        };
        let token = AgentToken::parse(compact)
            .and_then(|token| token.verify(&self.resolver(), now))
            .map_err(Failure::credential)?;
        proof
            .verify(&token.claims().cnf.jwk)
            .map_err(|error| Failure::proof(error, request, now))?;
        if token.claims().iat > now.saturating_add(60) {
            return Err(Failure::proof(ProofError::ClockSkew, request, now));
        }
        if body_required
            && request
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .map(str::trim)
                .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
        {
            return Err(Failure::parameter("invalid_request"));
        }
        Ok(token)
    }
    fn validate_parameters(
        &self,
        parameters: &serde_json::Map<String, Value>,
        person: bool,
    ) -> Result<(), Failure> {
        let common = [
            "upstream_token",
            "justification",
            "login_hint",
            "tenant",
            "domain_hint",
            "prompt",
            "platform",
            "device",
            "capabilities",
        ];
        let specific = if person {
            &["resource"][..]
        } else {
            &["resource_token", "presented_token"][..]
        };
        for (name, value) in parameters {
            if !common.contains(&name.as_str()) && !specific.contains(&name.as_str()) {
                return Err(Failure::parameter("invalid_request"));
            }
            if name == "capabilities" {
                let values = value
                    .as_array()
                    .ok_or_else(|| Failure::parameter("invalid_request"))?;
                let mut seen = std::collections::BTreeSet::new();
                if values.iter().any(|value| {
                    value
                        .as_str()
                        .is_none_or(|value| value.is_empty() || !seen.insert(value))
                }) {
                    return Err(Failure::parameter("invalid_request"));
                }
            } else if !value.is_string() {
                return Err(Failure::parameter("invalid_request"));
            }
            if name == "device"
                && value.as_str().is_some_and(|value| {
                    value.chars().count() > 64 || value.chars().any(char::is_control)
                })
            {
                return Err(Failure::parameter("invalid_request"));
            }
        }
        Ok(())
    }
    fn identity(agent: &VerifiedAgentToken) -> AgentIdentity {
        AgentIdentity {
            issuer: agent.claims().iss.clone(),
            subject: agent.claims().sub.clone(),
        }
    }
    fn binding(
        &self,
        principal: &AgentIdentity,
        context: BindingContext,
    ) -> Result<Option<crate::Binding>, Failure> {
        let binding = self
            .store
            .binding(&self.config.issuer, principal)
            .map_err(|_| Failure::internal())?;
        if binding.as_ref().is_some_and(|binding| binding.revoked) {
            return Err(context.revoked());
        }
        Ok(binding)
    }
    fn verify_upstream(
        &self,
        compact: &str,
        agent: &VerifiedAgentToken,
        now: i64,
    ) -> Result<Upstream, Failure> {
        let token = self.verify_presented(compact, now, "upstream")?;
        if token.ps != self.config.issuer
            || token.issuer != self.config.issuer
            || token.aud != agent.claims().iss
        {
            return Err(Failure::parameter("invalid_upstream_token"));
        }
        let record = self.load_record(&token, compact, now, "upstream")?;
        let binding = self
            .binding(&record.principal, BindingContext::Upstream)?
            .ok_or_else(|| Failure::parameter("invalid_upstream_token"))?;
        if binding.person_id != record.person_id {
            return Err(Failure::parameter("invalid_upstream_token"));
        }
        Ok(Upstream {
            context: UpstreamContext {
                record,
                scope: token.scope.clone(),
            },
            token,
        })
    }
    fn person(
        &self,
        agent: VerifiedAgentToken,
        parameters: Value,
        upstream: Option<Upstream>,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let resource = required_string(&parameters, "resource")?;
        validate_server_identifier(resource).map_err(|_| Failure::parameter("invalid_request"))?;
        let binding_context = if upstream.is_some() {
            BindingContext::Upstream
        } else {
            BindingContext::NewPerson
        };
        let principal = upstream
            .as_ref()
            .map(|up| up.context.record.principal.clone())
            .unwrap_or_else(|| Self::identity(&agent));
        let binding = if upstream.is_some() {
            None
        } else {
            self.binding(&principal, binding_context)?
        };
        let policy_request = PersonRequest {
            agent: agent.clone(),
            resource: resource.into(),
            binding: binding.clone(),
            upstream: upstream.as_ref().map(|up| up.context.clone()),
            parameters,
        };
        let person = if upstream.is_some() {
            self.policy.bind_upstream(&policy_request)
        } else {
            self.policy.bind_person(&policy_request)
        }
        .map_err(Failure::policy)?;
        validate_person(&person)?;
        if binding.is_some_and(|binding| binding.person_id != person.id)
            || upstream
                .as_ref()
                .is_some_and(|up| up.context.record.person_id != person.id)
        {
            return Err(Failure::internal());
        }
        if upstream
            .as_ref()
            .is_some_and(|up| up.token.sub == person.subject)
        {
            return Err(Failure::policy(PolicyError::Denied));
        }
        let now = (self.clock)();
        check_agent_current(&agent, now)?;
        check_upstream_current(upstream.as_ref(), now)?;
        let mut expires_at = now
            .saturating_add(self.config.person_lifetime)
            .min(agent.claims().exp);
        if let Some(up) = &upstream {
            expires_at = expires_at.min(up.token.exp);
        }
        let claims = PersonClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-person.json".into(),
            aud: policy_request.resource,
            sub: person.subject,
            cnf: Confirmation {
                jwk: agent.claims().cnf.jwk.clone(),
            },
            jti: (self.ids)(),
            iat: now,
            exp: expires_at,
            nbf: None,
            mission_s256: None,
            tenant: person.tenant,
            extra: Default::default(),
        };
        let compact = mint_person_token(&self.config.signing_key, &self.config.kid, &claims)
            .map_err(|_| Failure::internal())?;
        let record = self.record(
            &compact,
            &agent,
            &principal,
            &person.id,
            Issuance {
                kind: TokenKind::Person,
                jti: &claims.jti,
                resource: &claims.aud,
                subject: &claims.sub,
                tenant: claims.tenant.clone(),
                issued_at: now,
                expires_at,
                presented: None,
                upstream: upstream.as_ref().map(|up| up.context.record.token.clone()),
            },
        )?;
        self.store
            .commit(record, upstream.is_none())
            .map_err(|error| store_issuance_failure(error, binding_context))?;
        self.binding(&principal, binding_context)?
            .ok_or_else(Failure::internal)?;
        let released_at = (self.clock)();
        check_agent_current(&agent, released_at)?;
        check_upstream_current(upstream.as_ref(), released_at)?;
        if expires_at <= released_at {
            return Err(Failure::internal());
        }
        Ok(token_response(
            "person_token",
            compact,
            expires_at - released_at,
        ))
    }
    fn prepare_authorization(
        &self,
        agent: &VerifiedAgentToken,
        parameters: Value,
        verified_at: i64,
        upstream: Option<&Upstream>,
    ) -> Result<PreparedAuthorization, Failure> {
        let resource_compact = required_string(&parameters, "resource_token")?;
        let presented_compact = required_string(&parameters, "presented_token")?;
        let resource = ResourceToken::parse(resource_compact)
            .and_then(|token| token.verify(&self.resolver(), verified_at))
            .map_err(|error| Failure::token(error, "resource", verified_at))?;
        let r = resource.claims();
        check_parameter_iat(r.iat, verified_at)?;
        if r.ps != self.config.issuer
            || (self.federation.is_none() && r.aud != self.config.issuer)
            || r.exp - r.iat > self.config.max_resource_lifetime
            || r.agent_jkt
                != agent
                    .claims()
                    .cnf
                    .jwk
                    .thumbprint()
                    .map_err(|_| Failure::internal())?
            || r.mission_s256.is_some()
            || unsupported(&r.extra)
        {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        let scopes = parse_scopes(
            r.scope
                .as_deref()
                .ok_or_else(|| Failure::parameter("invalid_resource_token"))?,
        )
        .ok_or_else(|| Failure::parameter("invalid_resource_token"))?;
        let presented = self.verify_presented(presented_compact, verified_at, "presented")?;
        self.match_resource(&presented, r)?;
        let retained = self.load_record(&presented, presented_compact, verified_at, "presented")?;
        if retained.agent != Self::identity(agent) {
            return Err(Failure::parameter("invalid_presented_token"));
        }
        if retained.upstream != upstream.map(|up| up.context.record.token.clone()) {
            return Err(Failure::parameter("invalid_upstream_token"));
        }
        if upstream.is_none() && agent.claims().ps.as_deref() != Some(&self.config.issuer) {
            return Err(Failure::credential(TokenError::InvalidJwt));
        }
        if upstream.is_some_and(|up| {
            up.context.record.person_id != retained.person_id
                || up.context.record.principal != retained.principal
        }) {
            return Err(Failure::parameter("invalid_upstream_token"));
        }
        let binding_context = if upstream.is_some() {
            BindingContext::Upstream
        } else {
            BindingContext::Presented
        };
        let binding = self
            .binding(&retained.principal, binding_context)?
            .ok_or_else(|| Failure::parameter("invalid_presented_token"))?;
        if binding.person_id != retained.person_id {
            return Err(binding_context.revoked());
        }
        if r.login_hint
            .as_deref()
            .is_some_and(|hint| parameters.get("login_hint").and_then(Value::as_str) != Some(hint))
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let context = AuthorizationRequest {
            agent: agent.clone(),
            resource: resource.clone(),
            presented: retained.clone(),
            scopes,
            upstream: upstream.map(|up| up.context.clone()),
            parameters,
        };
        Ok(PreparedAuthorization {
            resource,
            presented,
            retained,
            context,
            binding_context,
        })
    }
    fn auth(
        &self,
        agent: VerifiedAgentToken,
        parameters: Value,
        verified_at: i64,
        upstream: Option<Upstream>,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let prepared =
            self.prepare_authorization(&agent, parameters, verified_at, upstream.as_ref())?;
        if self.federation.is_some() {
            if upstream.is_some() {
                return Err(Failure::parameter("invalid_request"));
            }
            return self.federate(&agent, &prepared);
        }
        let PreparedAuthorization {
            resource,
            presented,
            retained,
            context,
            binding_context,
        } = prepared;
        let r = resource.claims();
        let grant = if upstream.is_some() {
            self.policy.authorize_upstream(&context)
        } else {
            self.policy.authorize(&context)
        }
        .map_err(Failure::policy)?;
        validate_grant(&grant, &context.scopes)?;
        let now = (self.clock)();
        self.inputs_current(&agent, &resource, &presented, now)?;
        check_upstream_current(upstream.as_ref(), now)?;
        let mut expires_at = now
            .saturating_add(grant.lifetime)
            .min(agent.claims().exp)
            .min(presented.exp);
        if let Some(up) = &upstream {
            expires_at = expires_at.min(up.token.exp);
        }
        let claims = AuthClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-person.json".into(),
            aud: r.iss.clone(),
            ps: self.config.issuer.clone(),
            sub: r.sub.clone(),
            cnf: Confirmation {
                jwk: agent.claims().cnf.jwk.clone(),
            },
            jti: (self.ids)(),
            iat: now,
            exp: expires_at,
            scope: Some(grant.scopes.join(" ")),
            account: r.account.clone(),
            nbf: None,
            mission_s256: None,
            tenant: r.tenant.clone(),
            extra: Default::default(),
        };
        let compact = mint_auth_token(&self.config.signing_key, &self.config.kid, &claims)
            .map_err(|_| Failure::internal())?;
        let record = self.record(
            &compact,
            &agent,
            &retained.principal,
            &retained.person_id,
            Issuance {
                kind: TokenKind::Auth,
                jti: &claims.jti,
                resource: &claims.aud,
                subject: &claims.sub,
                tenant: claims.tenant.clone(),
                issued_at: now,
                expires_at,
                presented: Some(retained.token),
                upstream: upstream.as_ref().map(|up| up.context.record.token.clone()),
            },
        )?;
        self.store
            .commit(record, false)
            .map_err(|error| store_issuance_failure(error, binding_context))?;
        self.binding(&retained.principal, binding_context)?
            .ok_or_else(Failure::internal)?;
        let released_at = (self.clock)();
        self.inputs_current(&agent, &resource, &presented, released_at)?;
        check_upstream_current(upstream.as_ref(), released_at)?;
        if expires_at <= released_at {
            return Err(Failure::internal());
        }
        Ok(token_response(
            "auth_token",
            compact,
            expires_at - released_at,
        ))
    }
    fn inputs_current(
        &self,
        agent: &VerifiedAgentToken,
        resource: &VerifiedResourceToken,
        presented: &Presented,
        now: i64,
    ) -> Result<(), Failure> {
        check_agent_current(agent, now)?;
        if resource.claims().exp <= now {
            return Err(Failure::parameter("expired_resource_token"));
        }
        if presented.exp <= now {
            return Err(Failure::parameter("expired_presented_token"));
        }
        Ok(())
    }
}
fn required_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, Failure> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Failure::parameter("invalid_request"))
}
fn validate_person(person: &Person) -> Result<(), Failure> {
    if person.id.is_empty() || person.subject.is_empty() || person.tenant.as_deref() == Some("") {
        return Err(Failure::internal());
    }
    Ok(())
}
fn parse_scopes(scope: &str) -> Option<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let scopes: Vec<String> = scope.split(' ').map(str::to_owned).collect();
    if scopes.iter().any(|scope| {
        scope.is_empty()
            || !scope
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
            || !seen.insert(scope)
    }) {
        None
    } else {
        Some(scopes)
    }
}
fn validate_grant(grant: &Grant, requested: &[String]) -> Result<(), Failure> {
    if !(1..=3600).contains(&grant.lifetime)
        || parse_scopes(&grant.scopes.join(" ")).is_none()
        || grant.scopes.iter().any(|scope| !requested.contains(scope))
    {
        return Err(Failure::internal());
    }
    Ok(())
}
fn check_agent_current(agent: &VerifiedAgentToken, now: i64) -> Result<(), Failure> {
    if !(0..=(1_i64 << 33) - 1).contains(&now) {
        return Err(Failure::internal());
    }
    if agent.claims().exp <= now {
        return Err(Failure::credential(TokenError::ExpiredJwt));
    }
    Ok(())
}
fn check_parameter_iat(iat: i64, now: i64) -> Result<(), Failure> {
    if iat > now.saturating_add(60) {
        Err(Failure::clock(now))
    } else {
        Ok(())
    }
}
fn store_issuance_failure(error: StoreError, context: BindingContext) -> Failure {
    match error {
        StoreError::RevokedBinding => context.revoked(),
        _ => Failure::internal(),
    }
}
fn check_upstream_current(upstream: Option<&Upstream>, now: i64) -> Result<(), Failure> {
    if upstream.is_some_and(|up| up.token.exp <= now) {
        return Err(Failure::parameter("expired_upstream_token"));
    }
    Ok(())
}
fn unsupported(extra: &std::collections::BTreeMap<String, Value>) -> bool {
    [
        "interaction",
        "r3_uri",
        "r3_s256",
        "r3_granted",
        "r3_per_call",
        "budget",
        "budget_consumed",
    ]
    .iter()
    .any(|name| extra.contains_key(*name))
}
fn digest(compact: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(compact.as_bytes()))
}
