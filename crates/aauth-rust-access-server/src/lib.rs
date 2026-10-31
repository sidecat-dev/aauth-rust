//! Core-scope Access Server with host-supplied issuer trust and policy.
//!
//! This buffered role verifies a PS service proof plus Agent, Resource and actual
//! presented credentials before policy. It performs no discovery fetch or HTTP
//! transport. Hosts admit issuers before key resolution and bound request collection.
//! Explicit `with_deferred` adds bounded claims, clarification, interaction,
//! approval and payment continuations. One-level parent-mediated sub-agents use
//! the parent's policy identity and the child's credential key. A passed-through
//! `upstream_token` is verified per Upstream Token Verification before policy and
//! bounds the issued token; a deferred chained request whose upstream token is
//! revoked while it waits ends with the polling error `revoked`. Full R3 and missions remain outside this profile and
//! are refused.
//! A complete configuration that publishes metadata and refuses grants until
//! application trust and resource policy are supplied:
//!
//! ```
//! use aauth_rust_access_server::{AccessServer, AuthorizationRequest, Config, PolicyError};
//! use aauth_rust_core::{AgentKeyResolver, TokenError};
//! use aauth_rust_jose::{Jwk, SigningKey};
//! use http::Request;
//! struct AdmittedKeys;
//! impl AgentKeyResolver for AdmittedKeys {
//!     fn key(&self, _: &str, _: &str, _: &str) -> Result<Jwk, TokenError> {
//!         Err(TokenError::UntrustedIssuer)
//!     }
//! }
//! let server = AccessServer::new(
//!     Config::new("https://as.example", "as-1", SigningKey::generate()),
//!     AdmittedKeys,
//!     |_: &AuthorizationRequest| Err(PolicyError::Denied),
//!     || 1_792_526_400, // Host trusted clock: Unix seconds.
//!     || "unique-host-generated-token-id".to_owned(),
//! )?;
//! let request = Request::builder()
//!     .uri("https://as.example/.well-known/aauth-access.json")
//!     .body(Vec::new())?;
//! assert_eq!(server.handle(&request).status(), 200);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![deny(missing_docs)]
mod continuation;
mod revocation;
mod usage;
mod wire;
use aauth_rust_budgets::{
    Budget, IssuerPolicy, MAX_AMOUNT, check_declared, issue_auth_budget, parse_budget,
    parse_resource_claims,
};
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthClaims, AuthToken, Confirmation, MetadataDisplay,
    PersonToken, ResourceClaims, ResourceToken, TokenError, VerifiedAgentToken, VerifiedAuthToken,
    VerifiedPersonToken, VerifiedResourceToken, mint_auth_token, validate_server_identifier,
    verify_subagent,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey, strict_json};
use aauth_rust_signature_key::{
    Error as ProofError, KeyMaterial, PreparedRequest, canonical_authority,
};
pub use continuation::{DeferredConfig, DeferredContext};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use wire::{Failure, bytes_response, token_response};

/// Local identity, request target and signing credentials; validated by new.
pub struct Config {
    /// Published canonical HTTPS Access Server identifier, without port or path.
    pub issuer: String,
    /// Actual HTTPS listener origin, independently configurable with a port.
    pub signed_origin: String,
    /// Nonempty identifier of the signing key published in this role's JWKS.
    pub kid: String,
    /// Host-owned signing key; private material is never returned.
    pub signing_key: SigningKey,
    /// Maximum Resource challenge lifetime in seconds, 1..=3600; default 300.
    pub max_resource_lifetime: i64,
}
impl Config {
    /// Prepare a configuration with a 300-second Resource challenge ceiling.
    pub fn new(issuer: &str, kid: &str, signing_key: SigningKey) -> Self {
        Self {
            issuer: issuer.into(),
            signed_origin: issuer.into(),
            kid: kid.into(),
            signing_key,
            max_resource_lifetime: 300,
        }
    }
}
/// Local configuration failure, separate from caller authentication errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid_configuration: use a canonical issuer, HTTPS origin, nonempty kid and bounded Resource lifetime"
)]
pub struct ConfigurationError;
impl ConfigurationError {
    /// Stable local diagnostic; never a Signature-Error code.
    pub fn code(&self) -> &'static str {
        "invalid_configuration"
    }
}
/// Fully verified context passed to the Access Server's resource policy.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    /// Person Server whose admitted key authenticated the signed POST.
    pub person_server: String,
    /// Parent/top-level Agent identity and posture authenticated by its provider.
    pub agent: VerifiedAgentToken,
    /// Independently verified one-level child, when authorization is parent-mediated.
    /// Policy evaluates the parent; issued credentials belong to this child's key.
    pub subagent: Option<VerifiedAgentToken>,
    /// Verified Resource challenge, matched to the actual presented credential.
    pub resource: VerifiedResourceToken,
    /// Nonempty distinct requested Core scope values.
    pub scopes: Vec<String>,
    /// Budget the person server asked to grant. `None` means issue no budget claim.
    pub budget: Option<Budget>,
    /// Verified `upstream_token` when an intermediary chains this request. It
    /// names the person the intermediary acts for and grants nothing by itself.
    /// The issued Auth token ends no later than it.
    pub upstream: Option<UpstreamToken>,
}
/// `upstream_token` verified per Upstream Token Verification: signature, `exp`
/// and revocation; a person token's `iss` or an auth token's `ps` is the signing
/// Person Server; `aud` is the `iss` of the intermediary's Agent token. Its
/// confirmation key is the calling Agent's and is not compared with any key here.
#[derive(Clone, Debug)]
pub enum UpstreamToken {
    /// `aa-person+jwt` issued by the signing Person Server.
    Person(VerifiedPersonToken),
    /// `aa-auth+jwt` whose `ps` is the signing Person Server.
    Auth(VerifiedAuthToken),
}
impl UpstreamToken {
    /// Person Server that issued the person token or that the auth token names.
    pub fn person_server(&self) -> &str {
        match self {
            Self::Person(token) => &token.claims().iss,
            Self::Auth(token) => &token.claims().ps,
        }
    }
    /// The intermediary the calling Agent presented this token to.
    pub fn audience(&self) -> &str {
        match self {
            Self::Person(token) => &token.claims().aud,
            Self::Auth(token) => &token.claims().aud,
        }
    }
    /// Expiry in Unix seconds.
    pub fn expires_at(&self) -> i64 {
        match self {
            Self::Person(token) => token.claims().exp,
            Self::Auth(token) => token.claims().exp,
        }
    }
    fn issued_at(&self) -> i64 {
        match self {
            Self::Person(token) => token.claims().iat,
            Self::Auth(token) => token.claims().iat,
        }
    }
}
/// Resource-policy grant; scopes must be a nonempty subset of the request.
#[derive(Clone, Debug)]
pub struct Decision {
    /// Nonempty unique subset of requested Core scopes.
    pub scopes: Vec<String>,
    /// Desired positive lifetime in seconds, at most 3600; parents cap it.
    pub lifetime: i64,
}
/// Intentional denial versus operational policy failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// Resource policy refused authorization; mapped to 403 access_denied.
    Denied,
    /// A policy dependency failed; mapped to 500 server_error.
    Unavailable,
}
/// Named captured policy for use in application state.
pub type BoxedPolicy =
    Box<dyn Fn(&AuthorizationRequest) -> Result<Decision, PolicyError> + Send + Sync>;
/// Named trusted clock, returning Unix seconds.
pub type BoxedClock = Box<dyn Fn() -> i64 + Send + Sync>;
/// Named fresh token-ID source; host owns uniqueness.
pub type BoxedTokenIds = Box<dyn Fn() -> String + Send + Sync>;

/// Immediate four-party Core-scope authorization. Construction is explicit even
/// when this AS is collocated with a PS. Keys must implement prior issuer/role
/// admission; unfamiliar asserted identities must never trigger unconstrained fetches.
pub struct AccessServer<K, P, C, I> {
    config: Config,
    authority: String,
    keys: K,
    policy: P,
    clock: C,
    ids: I,
    deferred: Option<continuation::Deferred>,
    revocation: Option<revocation::Gate>,
    budgets: Option<IssuerPolicy>,
    display: MetadataDisplay,
}
struct Resolver<'a, K> {
    config: &'a Config,
    host: &'a K,
}
impl<K: AgentKeyResolver> AgentKeyResolver for Resolver<'_, K> {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if issuer == self.config.issuer && dwk == "aauth-access.json" {
            if kid != self.config.kid {
                return Err(TokenError::UnknownKey);
            }
            Ok(self.config.signing_key.public_jwk())
        } else {
            self.host.key(issuer, dwk, kid)
        }
    }
}
impl<
    K: AgentKeyResolver,
    P: Fn(&AuthorizationRequest) -> Result<Decision, PolicyError>,
    C: Fn() -> i64,
    I: Fn() -> String,
> AccessServer<K, P, C, I>
{
    /// Validate configuration and retain host trust, policy, clock and IDs.
    ///
    /// # Errors
    /// Returns invalid_configuration for malformed identities/origins, empty kid
    /// or a Resource lifetime outside 1..=3600 seconds.
    pub fn new(
        config: Config,
        keys: K,
        policy: P,
        clock: C,
        ids: I,
    ) -> Result<Self, ConfigurationError> {
        validate_server_identifier(&config.issuer).map_err(|_| ConfigurationError)?;
        let uri: http::Uri = config
            .signed_origin
            .parse()
            .map_err(|_| ConfigurationError)?;
        let authority = canonical_authority(&uri).map_err(|_| ConfigurationError)?;
        if config.signed_origin != format!("https://{}", uri.authority().ok_or(ConfigurationError)?)
            || config.kid.is_empty()
            || !(1..=3600).contains(&config.max_resource_lifetime)
        {
            return Err(ConfigurationError);
        }
        Ok(Self {
            config,
            authority,
            keys,
            policy,
            clock,
            ids,
            deferred: None,
            revocation: None,
            budgets: None,
            display: MetadataDisplay::new(),
        })
    }
    /// Publish `name`, `description`, `logo_uri` and the other display
    /// members in [`Self::metadata`]. The checked values replace any earlier ones.
    pub fn with_display(mut self, display: MetadataDisplay) -> Self {
        self.display = display;
        self
    }
    /// Cap issued budgets. An empty unit cache accepts the signed scale.
    ///
    /// # Errors
    /// Returns [`ConfigurationError`] when `cap` is outside the carrier.
    pub fn with_budgets(mut self, policy: IssuerPolicy) -> Result<Self, ConfigurationError> {
        if policy
            .cap
            .is_some_and(|cap| !(0..=MAX_AMOUNT).contains(&cap))
        {
            return Err(ConfigurationError);
        }
        self.budgets = Some(policy);
        Ok(self)
    }
    /// Metadata served at /.well-known/aauth-access.json. No unsupported endpoints
    /// or companion capabilities are advertised. Display members are present
    /// after [`Self::with_display`].
    pub fn metadata(&self) -> Vec<u8> {
        let mut value = json!({"issuer":self.config.issuer,"jwks_uri":format!("{}/.well-known/jwks.json",self.config.issuer),"auth_token_endpoint":format!("{}/token",self.config.issuer)});
        if self.revocation.is_some() {
            value["revocation_endpoint"] = json!(format!("{}/revoke", self.config.issuer));
        }
        for (member, display) in self.display.members() {
            value[member] = json!(display);
        }
        value.to_string().into_bytes()
    }
    /// Public JWKS for the current signing key. Hosts collocating roles must serve
    /// one merged key set; publication/rotation overlap remains host-managed.
    pub fn jwks(&self) -> Vec<u8> {
        let mut key = serde_json::to_value(self.config.signing_key.public_jwk())
            .expect("public JWK serializes");
        key["kid"] = json!(self.config.kid);
        json!({"keys":[key]}).to_string().into_bytes()
    }
    /// Process bounded buffered bytes; signature/context checks precede policy.
    /// `clock` returns Unix seconds, not milliseconds. The host must also bound
    /// collection before allocation and provide HTTPS/egress/timeout policy.
    pub fn handle(&self, request: &Request<Vec<u8>>) -> Response<Vec<u8>> {
        self.handle_inner(request).unwrap_or_else(Failure::response)
    }
    fn resolver(&self) -> Resolver<'_, K> {
        Resolver {
            config: &self.config,
            host: &self.keys,
        }
    }
    fn handle_inner(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Failure> {
        let now = (self.clock)();
        if canonical_authority(request.uri()).ok().as_deref() != Some(&self.authority) {
            return Err(Failure::proof(ProofError::TargetMismatch, request, now));
        }
        if request.uri().path().starts_with("/token/pending/") && self.deferred.is_some() {
            return self.pending(request, now).map_err(Failure::while_pending);
        }
        if let Some(response) = self.route_revocation(request, now)? {
            return Ok(response);
        }
        match (request.method().as_str(), request.uri().path()) {
            ("GET", "/.well-known/aauth-access.json") => {
                return Ok(bytes_response(self.metadata()));
            }
            ("GET", "/.well-known/jwks.json") => return Ok(bytes_response(self.jwks())),
            ("POST", "/token") => {}
            _ => return Err(Failure::status(StatusCode::NOT_FOUND, "not_found")),
        }
        let id = self.verify_ps(request, now, true)?;
        let body =
            strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))?;
        let (context, presented) = self.authorize_body(&body, &id, now)?;
        if self.deferred.is_some() {
            self.begin_deferred(context, presented, body, now)
        } else {
            self.issue(context, presented)
        }
    }
    fn verify_ps(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        body_required: bool,
    ) -> Result<String, Failure> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"])
            .map_err(|e| Failure::proof(e, request, now))?;
        let base = std::str::from_utf8(proof.signature_base())
            .map_err(|_| Failure::parameter("invalid_request"))?;
        if body_required
            && ["content-type", "content-digest"].iter().any(|name| {
                !base
                    .lines()
                    .any(|line| line.starts_with(&format!("\"{name}\":")))
            })
        {
            return Err(Failure::proof(ProofError::InvalidInput, request, now));
        }
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return Err(Failure::proof(ProofError::UnsupportedScheme, request, now));
        };
        validate_server_identifier(id)
            .map_err(|_| Failure::proof(ProofError::InvalidKey, request, now))?;
        if dwk != "aauth-person.json" {
            return Err(Failure::proof(ProofError::InvalidKey, request, now));
        }
        let ps_key = self.keys.key(id, dwk, kid).map_err(Failure::credential)?;
        proof
            .verify(&ps_key)
            .map_err(|e| Failure::proof(e, request, now))?;
        if body_required
            && request
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.split(';').next())
                .map(str::trim)
                .is_none_or(|h| !h.eq_ignore_ascii_case("application/json"))
        {
            return Err(Failure::parameter("invalid_request"));
        }
        Ok(id.clone())
    }
    fn authorize_body(
        &self,
        body: &Value,
        id: &str,
        now: i64,
    ) -> Result<(AuthorizationRequest, Presented), Failure> {
        let object = body
            .as_object()
            .ok_or_else(|| Failure::parameter("invalid_request"))?;
        if object.keys().any(|k| {
            let known = [
                "agent_token",
                "subagent_token",
                "resource_token",
                "presented_token",
                "upstream_token",
            ]
            .contains(&k.as_str());
            let budget = self.budgets.is_some() && k == "budget";
            !known && !budget
        }) {
            return Err(Failure::parameter("invalid_request"));
        }
        // An intermediary's own `ps`, if any, names its Person Server, not the
        // person's; a chained request is tied to the signing PS by the upstream
        // token instead.
        let chained = object.contains_key("upstream_token");
        if chained && object.contains_key("subagent_token") {
            return Err(Failure::parameter("invalid_request"));
        }
        let agent = AgentToken::parse(required(body, "agent_token")?)
            .and_then(|t| t.verify(&self.resolver(), now))
            .map_err(|e| Failure::token(e, "agent", now))?;
        check_iat(agent.claims().iat, now)?;
        if (!chained && agent.claims().ps.as_deref() != Some(id))
            || agent.claims().parent_agent.is_some()
        {
            return Err(Failure::parameter("invalid_agent_token"));
        }
        let upstream = if chained {
            Some(self.verify_upstream(required(body, "upstream_token")?, &agent, id, now)?)
        } else {
            None
        };
        let subagent = body
            .get("subagent_token")
            .map(|value| {
                let compact = value
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| Failure::parameter("invalid_subagent_token"))?;
                let child = verify_subagent(compact, &agent, &self.resolver(), now)
                    .map_err(|e| Failure::token(e, "subagent", now))?;
                check_iat(child.claims().iat, now)?;
                if child.claims().ps.as_deref().is_some_and(|ps| ps != id) {
                    return Err(Failure::parameter("invalid_subagent_token"));
                }
                Ok(child)
            })
            .transpose()?;
        let holder = subagent.as_ref().unwrap_or(&agent);
        let resource_compact = required(body, "resource_token")?;
        self.refuse_revoked_parameter(resource_compact, now, "resource")?;
        let resource = ResourceToken::parse(resource_compact)
            .and_then(|t| t.verify(&self.resolver(), now))
            .map_err(|e| Failure::token(e, "resource", now))?;
        let r = resource.claims();
        check_iat(r.iat, now)?;
        if r.aud != self.config.issuer
            || r.ps != id
            || r.exp - r.iat > self.config.max_resource_lifetime
            || r.agent_jkt
                != holder
                    .claims()
                    .cnf
                    .jwk
                    .thumbprint()
                    .map_err(|_| Failure::internal())?
            || r.mission_s256.is_some()
            || extra_blocks(&r.extra, self.budgets.is_some(), self.budgets.is_some())
        {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        let resource_budget = self.resource_budget(&r.extra, &r.presented_jti)?;
        let parameter = self.budget_parameter(object.get("budget"), resource_budget.as_ref())?;
        let presented_compact = required(body, "presented_token")?;
        self.refuse_revoked_parameter(presented_compact, now, "presented")?;
        let presented = presented(
            presented_compact,
            &self.resolver(),
            now,
            self.budgets.is_some(),
        )?;
        presented.matches(r)?;
        let requested_scopes = scopes(r.scope.as_deref().unwrap_or(""))
            .ok_or_else(|| Failure::parameter("invalid_resource_token"))?;
        let context = AuthorizationRequest {
            person_server: id.to_owned(),
            agent: agent.clone(),
            subagent,
            resource: resource.clone(),
            scopes: requested_scopes,
            budget: parameter,
            upstream,
        };
        Ok((context, presented))
    }
    /// Upstream Token Verification at an AS: steps 1 to 3.
    fn verify_upstream(
        &self,
        compact: &str,
        agent: &VerifiedAgentToken,
        person_server: &str,
        now: i64,
    ) -> Result<UpstreamToken, Failure> {
        self.refuse_revoked_parameter(compact, now, "upstream")?;
        let upstream = (|| -> Result<UpstreamToken, TokenError> {
            let jws = Jws::parse(compact)?;
            match jws.header().get("typ").and_then(Value::as_str) {
                Some("aa-person+jwt") => Ok(UpstreamToken::Person(
                    PersonToken::parse(compact)?.verify(&self.resolver(), now)?,
                )),
                Some("aa-auth+jwt") => Ok(UpstreamToken::Auth(
                    AuthToken::parse(compact)?.verify(&self.resolver(), now)?,
                )),
                _ => Err(TokenError::UnexpectedTokenType),
            }
        })()
        .map_err(|e| Failure::token(e, "upstream", now))?;
        check_iat(upstream.issued_at(), now)?;
        if upstream.person_server() != person_server || upstream.audience() != agent.claims().iss {
            return Err(Failure::parameter("invalid_upstream_token"));
        }
        Ok(upstream)
    }
    fn resource_budget(
        &self,
        extra: &std::collections::BTreeMap<String, Value>,
        presented_jti: &str,
    ) -> Result<Option<Budget>, Failure> {
        if self.budgets.is_none() {
            return Ok(None);
        }
        let claims = parse_resource_claims(extra, presented_jti)
            .map_err(|_| Failure::parameter("invalid_budget"))?;
        if let Some(budget) = &claims.budget {
            check_declared(budget, &self.budgets.as_ref().expect("budgets").units)
                .map_err(|_| Failure::parameter("invalid_budget"))?;
        }
        Ok(claims.budget)
    }
    fn budget_parameter(
        &self,
        value: Option<&Value>,
        offer: Option<&Budget>,
    ) -> Result<Option<Budget>, Failure> {
        let Some(policy) = &self.budgets else {
            return Ok(None);
        };
        let Some(value) = value else {
            return Ok(None);
        };
        let parameter = parse_budget(value).map_err(|_| Failure::parameter("invalid_budget"))?;
        let Some(offer) = offer else {
            return Err(Failure::parameter("invalid_budget"));
        };
        check_declared(&parameter, &policy.units)
            .map_err(|_| Failure::parameter("invalid_budget"))?;
        aauth_rust_budgets::validate_narrowing(offer, &parameter)
            .map_err(|_| Failure::parameter("invalid_budget"))?;
        Ok(Some(parameter))
    }
    fn issued_extra(
        &self,
        context: &AuthorizationRequest,
    ) -> Result<std::collections::BTreeMap<String, Value>, Failure> {
        let Some(policy) = &self.budgets else {
            return Ok(std::collections::BTreeMap::new());
        };
        let claims = context.resource.claims();
        let offer = parse_resource_claims(&claims.extra, &claims.presented_jti)
            .map_err(|_| Failure::parameter("invalid_budget"))?
            .budget;
        let issued = issue_auth_budget(offer.as_ref(), context.budget.as_ref(), policy)
            .map_err(|_| Failure::parameter("invalid_budget"))?;
        let mut extra = std::collections::BTreeMap::new();
        if let Some(budget) = issued {
            extra.insert("budget".into(), budget.to_value());
        }
        Ok(extra)
    }
    fn issue(
        &self,
        context: AuthorizationRequest,
        presented: Presented,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let holder = context.subagent.as_ref().unwrap_or(&context.agent);
        let r = context.resource.claims();
        let id = context.person_server.clone();
        let decision = (self.policy)(&context).map_err(Failure::policy)?;
        if !(1..=3600).contains(&decision.lifetime)
            || scopes(&decision.scopes.join(" ")).is_none()
            || decision.scopes.iter().any(|s| !context.scopes.contains(s))
        {
            return Err(Failure::internal());
        }
        let issued_at = (self.clock)();
        current(issued_at, &context, &presented)?;
        let mut expires_at = issued_at
            .saturating_add(decision.lifetime)
            .min(context.agent.claims().exp)
            .min(holder.claims().exp)
            .min(presented.exp);
        if let Some(upstream) = &context.upstream {
            expires_at = expires_at.min(upstream.expires_at());
        }
        if let Some(end) = self.budgets.as_ref().and_then(|policy| policy.period_end) {
            expires_at = expires_at.min(end);
        }
        let claims = AuthClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-access.json".into(),
            aud: r.iss.clone(),
            ps: id.clone(),
            sub: r.sub.clone(),
            cnf: Confirmation {
                jwk: holder.claims().cnf.jwk.clone(),
            },
            jti: (self.ids)(),
            iat: issued_at,
            exp: expires_at,
            scope: Some(decision.scopes.join(" ")),
            account: r.account.clone(),
            tenant: r.tenant.clone(),
            mission_s256: None,
            nbf: None,
            extra: self.issued_extra(&context)?,
        };
        let compact = mint_auth_token(&self.config.signing_key, &self.config.kid, &claims)
            .map_err(|_| Failure::internal())?;
        self.note_issued(revocation::IssuedAuth {
            jti: claims.jti.clone(),
            resource: claims.aud.clone(),
            exp: claims.exp,
            presented_issuer: presented.issuer.clone(),
            presented_jti: presented.jti.clone(),
        });
        let release = (self.clock)();
        current(release, &context, &presented)?;
        if release >= expires_at {
            return Err(Failure::internal());
        }
        Ok(token_response("auth_token", compact, expires_at - release))
    }
}
struct Presented {
    issuer: String,
    aud: String,
    ps: String,
    sub: String,
    jti: String,
    jkt: String,
    tenant: Option<String>,
    mission: Option<String>,
    iat: i64,
    exp: i64,
}
impl Presented {
    fn matches(&self, r: &ResourceClaims) -> Result<(), Failure> {
        if self.aud != r.iss || self.jkt != r.agent_jkt {
            return Err(Failure::parameter("invalid_presented_token"));
        }
        if self.ps != r.ps
            || self.sub != r.sub
            || self.jti != r.presented_jti
            || self.tenant != r.tenant
            || self.mission != r.mission_s256
        {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        Ok(())
    }
}
fn presented(
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
    budgets: bool,
) -> Result<Presented, Failure> {
    let result = (|| -> Result<Presented, TokenError> {
        let jws = Jws::parse(compact)?;
        match jws.header().get("typ").and_then(Value::as_str) {
            Some("aa-person+jwt") => {
                let t = PersonToken::parse(compact)?.verify(keys, now)?;
                let c = t.claims();
                if extra_blocks(&c.extra, false, false) {
                    return Err(TokenError::InvalidJwt);
                }
                Ok(Presented {
                    issuer: c.iss.clone(),
                    aud: c.aud.clone(),
                    ps: c.iss.clone(),
                    sub: c.sub.clone(),
                    jti: c.jti.clone(),
                    jkt: c.cnf.jwk.thumbprint()?,
                    tenant: c.tenant.clone(),
                    mission: c.mission_s256.clone(),
                    iat: c.iat,
                    exp: c.exp,
                })
            }
            Some("aa-auth+jwt") => {
                let t = AuthToken::parse(compact)?.verify(keys, now)?;
                let c = t.claims();
                if extra_blocks(&c.extra, budgets, false) {
                    return Err(TokenError::InvalidJwt);
                }
                if budgets && let Some(budget) = c.extra.get("budget") {
                    parse_budget(budget).map_err(|_| TokenError::InvalidJwt)?;
                }
                Ok(Presented {
                    issuer: c.iss.clone(),
                    aud: c.aud.clone(),
                    ps: c.ps.clone(),
                    sub: c.sub.clone(),
                    jti: c.jti.clone(),
                    jkt: c.cnf.jwk.thumbprint()?,
                    tenant: c.tenant.clone(),
                    mission: c.mission_s256.clone(),
                    iat: c.iat,
                    exp: c.exp,
                })
            }
            _ => Err(TokenError::UnexpectedTokenType),
        }
    })();
    let p = result.map_err(|e| Failure::token(e, "presented", now))?;
    check_iat(p.iat, now)?;
    Ok(p)
}
fn current(now: i64, context: &AuthorizationRequest, p: &Presented) -> Result<(), Failure> {
    if !(0..=(1_i64 << 33) - 1).contains(&now) {
        return Err(Failure::internal());
    }
    if context.agent.claims().exp <= now {
        return Err(Failure::parameter("expired_agent_token"));
    }
    if context
        .subagent
        .as_ref()
        .is_some_and(|child| child.claims().exp <= now)
    {
        return Err(Failure::parameter("expired_subagent_token"));
    }
    if context.resource.claims().exp <= now {
        return Err(Failure::parameter("expired_resource_token"));
    }
    if p.exp <= now {
        return Err(Failure::parameter("expired_presented_token"));
    }
    if context
        .upstream
        .as_ref()
        .is_some_and(|upstream| upstream.expires_at() <= now)
    {
        return Err(Failure::parameter("expired_upstream_token"));
    }
    Ok(())
}
fn check_iat(iat: i64, now: i64) -> Result<(), Failure> {
    if iat > now.saturating_add(60) {
        Err(Failure::clock(now))
    } else {
        Ok(())
    }
}
fn required<'a>(body: &'a Value, name: &str) -> Result<&'a str, Failure> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Failure::parameter("invalid_request"))
}
fn scopes(value: &str) -> Option<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let values: Vec<String> = value.split(' ').map(str::to_owned).collect();
    if values.iter().any(|v| {
        v.is_empty()
            || !v
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
            || !seen.insert(v)
    }) {
        None
    } else {
        Some(values)
    }
}
fn extra_blocks(
    extra: &std::collections::BTreeMap<String, Value>,
    allow_budget: bool,
    allow_consumed: bool,
) -> bool {
    extra.keys().any(|name| match name.as_str() {
        "interaction" | "r3_uri" | "r3_s256" | "r3_granted" | "r3_per_call" => true,
        "budget" => !allow_budget,
        "budget_consumed" => !allow_consumed,
        _ => false,
    })
}
