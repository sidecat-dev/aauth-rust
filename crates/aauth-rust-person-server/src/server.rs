mod continuation;
mod federation;
mod governance;
mod mission_http;
mod revocation;
pub use continuation::{AdvanceError, DeferredConfig, FederationInput};
pub use governance::{Governance, GovernanceError, InteractionDecision, OpenedInteraction};
mod lineage;
mod missions;
mod r3;
mod resource_interaction;
pub use r3::{
    BoxedR3Policy, R3AuthorizationRequest, R3Decision, R3IssuerConfig, R3Policy,
    R3ProposalDecision, R3ProposalRequest,
};
pub use resource_interaction::{
    BoxedEgress, PendingResourceInteraction, ResourceInteractionCallback,
    ResourceInteractionConfig, ResourceInteractionError,
};
mod subagents;
mod usage;
mod wire;
use wire::{Failure, bytes_response, json_response, token_response};

use crate::{
    AgentIdentity, AuthorizationRequest, Grant, Person, PersonRequest, Policy, PolicyError,
    R3IssuanceAudit, Store, StoreError, TokenKind, TokenRecord, TokenReference, TokenTie,
    UpstreamContext,
};
use aauth_rust_budgets::{
    AllocationBook, Budget, ConsentFigure, IssuerPolicy, MAX_AMOUNT, check_declared, narrow_to,
    parse_budget, parse_resource_claims, read_granted, verify_delivered,
};
use aauth_rust_core::interaction::ResourceInteraction;
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthClaims, AuthToken, Confirmation, MetadataDisplay,
    PersonClaims, PersonToken, ResourceToken, TokenError, VerifiedAgentToken,
    VerifiedResourceToken, mint_auth_token, mint_person_token, validate_server_identifier,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey, strict_json};
use aauth_rust_signature_key::{
    Error as ProofError, KeyMaterial, PreparedRequest, canonical_authority,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

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
    revocation: Option<revocation::Gate>,
    mission_http: Option<mission_http::Gate>,
    governance: Option<governance::Gate>,
    budgets: Option<BudgetState>,
    r3: Option<Box<R3IssuerConfig>>,
    r3_approvals: Mutex<Vec<r3::RecordedApproval>>,
    display: MetadataDisplay,
    resource_interaction: Option<resource_interaction::Gate>,
}
struct BudgetState {
    policy: IssuerPolicy,
    accounts: Mutex<AllocationBook>,
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
    offer: Option<Budget>,
}
struct Issuance<'a> {
    parent_agent: Option<AgentIdentity>,
    /// Generation of the principal's binding this credential is issued under.
    binding_generation: u64,
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
            revocation: None,
            mission_http: None,
            governance: None,
            budgets: None,
            r3: None,
            r3_approvals: Mutex::new(Vec::new()),
            display: MetadataDisplay::new(),
            resource_interaction: None,
        })
    }
    /// Publish `name`, `description`, `logo_uri` and the other display
    /// members in [`Self::metadata`]. The checked values replace any earlier ones.
    pub fn with_display(mut self, display: MetadataDisplay) -> Self {
        self.display = display;
        self
    }
    /// Enable AS federation for every /token request, including
    /// collocated PS=AS. No direct-issuance fallback; consent defaults denied.
    /// Host adapter owns discovery, safe HTTPS, bounds, deadlines and egress.
    pub fn with_federation(mut self, adapter: impl crate::Federation + 'static) -> Self {
        self.federation = Some(Box::new(adapter));
        self
    }
    /// Account for budgets. `policy.cap` is this server's per-token maximum and
    /// the standing sum of outstanding grants for one subject at one resource.
    /// `policy.omit_above` omits the four-party PS-to-AS parameter when the
    /// resource offer amount is above that limit. Three-party issuance still
    /// narrows that offer and counts the grant. An empty `policy.units` cache
    /// accepts the scale signed on the resource token.
    ///
    /// # Errors
    /// Returns [`ConfigurationError`] when `cap` or `omit_above` is outside the carrier.
    pub fn with_budgets(mut self, policy: IssuerPolicy) -> Result<Self, ConfigurationError> {
        if policy
            .cap
            .is_some_and(|cap| !(0..=MAX_AMOUNT).contains(&cap))
            || policy
                .omit_above
                .is_some_and(|limit| !(0..=MAX_AMOUNT).contains(&limit))
        {
            return Err(ConfigurationError);
        }
        self.budgets = Some(BudgetState {
            policy,
            accounts: Mutex::new(AllocationBook::new()),
        });
        Ok(self)
    }
    /// Sum of reported consumption, or the full amount of each allocation that
    /// has no figure yet. `None` when budgets are off.
    pub fn budget_accounted(&self) -> Option<i64> {
        self.budgets.as_ref().map(|state| {
            state
                .accounts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .accounted()
        })
    }
    /// Drop every live allocation for every subject.
    ///
    /// Tokens already issued stay valid. The next grant sees the full ceiling
    /// while those earlier grants are still live, so the standing sum starts
    /// over. This is not an HTTP route. It exists so one conformance process
    /// can reset the book between scenarios.
    #[doc(hidden)]
    pub fn clear_outstanding_budgets(&self) {
        if let Some(state) = &self.budgets {
            *state
                .accounts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = AllocationBook::new();
        }
    }
    /// Human amount and plain-text description, kept as separate strings.
    ///
    /// The description is already HTML-escaped plain text, not Markdown.
    /// Insert it as escaped text: do not render it as Markdown, and do not
    /// escape it again. The amount is a different string. `None` when budgets
    /// are off.
    pub fn budget_consent(&self, budget: &Budget, description: &str) -> Option<ConsentFigure> {
        self.budgets
            .as_ref()
            .map(|_| aauth_rust_budgets::consent_figure(budget, description))
    }
    /// Public PS metadata; only implemented Person/Auth endpoints are advertised.
    /// Display members are present after [`Self::with_display`].
    pub fn metadata(&self) -> Vec<u8> {
        let mut value = json!({"issuer":self.config.issuer,"person_token_endpoint":format!("{}/person",self.config.issuer),"auth_token_endpoint":format!("{}/token",self.config.issuer),"jwks_uri":format!("{}/.well-known/jwks.json",self.config.issuer)});
        if self.revocation.is_some() {
            value["revocation_endpoint"] = json!(format!("{}/revoke", self.config.issuer));
        }
        if self.mission_http.is_some() {
            value["mission_endpoint"] = json!(format!("{}/mission", self.config.issuer));
        }
        if self.governance.is_some() {
            value["interaction_endpoint"] = json!(format!("{}/interaction", self.config.issuer));
            value["permission_endpoint"] = json!(format!("{}/permission", self.config.issuer));
            value["audit_endpoint"] = json!(format!("{}/audit", self.config.issuer));
        }
        for (member, display) in self.display.members() {
            value[member] = json!(display);
        }
        value.to_string().into_bytes()
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
            return self.pending(request, now).map_err(Failure::while_pending);
        }
        if self.resource_interaction.is_some()
            && request.uri().path().starts_with("/token/interaction/")
        {
            return self.resource_interaction_poll(request, now);
        }
        if let Some(response) = self.route_revocation(request, now)? {
            return Ok(response);
        }
        if let Some(response) = self.route_mission(request, now)? {
            return Ok(response);
        }
        if let Some(response) = self.route_governance(request, now)? {
            return Ok(response);
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
        if upstream.is_some() && parameters.contains_key("subagent_token") {
            return Err(Failure::parameter("invalid_request"));
        }
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
        let parsed = AgentToken::parse(compact).map_err(Failure::credential)?;
        let agent_issuer = parsed.unverified_claims().iss.clone();
        let agent_jti = parsed.unverified_claims().jti.clone();
        let token = match parsed.verify(&self.resolver(), now) {
            Ok(token) => token,
            Err(TokenError::ExpiredJwt) if self.token_revoked(&agent_issuer, &agent_jti, now) => {
                return Err(Failure::revoked_jwt());
            }
            Err(error) => return Err(Failure::credential(error)),
        };
        if self.token_revoked(&agent_issuer, &agent_jti, now) {
            return Err(Failure::revoked_jwt());
        }
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
            "subagent_token",
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
            &["resource", "mission_s256"][..]
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
            if name == "platform"
                && value.as_str().is_none_or(|value| {
                    !["web", "mobile", "desktop", "workload", "self-hosted"].contains(&value)
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
        if token.ps != self.config.issuer || token.aud != agent.claims().iss {
            return Err(Failure::parameter("invalid_upstream_token"));
        }
        // The token's `iss` is this PS, or an AS this PS presented a person
        // token to for its `aud` and `sub`: only then does this PS hold its
        // record, retained on issuance or on federated delivery.
        let record = self.load_record(&token, compact, now, "upstream")?;
        // Step 4: the calling Agent is the one this record names. Its revoked
        // Agent token refuses the chain even where no cascade reached this token.
        if self.token_revoked(&record.agent.issuer, &record.agent_token_jti, now) {
            return Err(BindingContext::Upstream.revoked());
        }
        let binding = self
            .binding(&record.principal, BindingContext::Upstream)?
            .ok_or_else(|| Failure::parameter("invalid_upstream_token"))?;
        if binding.generation != record.binding_generation {
            return Err(BindingContext::Upstream.revoked());
        }
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
        let mission = if parameters.get("mission_s256").is_some() {
            if upstream.is_some() || parameters.get("subagent_token").is_some() {
                return Err(Failure::parameter("invalid_request"));
            }
            Some(self.load_mission(
                &Self::identity(&agent),
                required_string(&parameters, "mission_s256")?,
                (self.clock)(),
                binding_context,
            )?)
        } else if let Some(up) = &upstream
            && let Some(s256) = &up.token.mission
        {
            // The upstream token carries the calling Agent's mission. The
            // request is evaluated against it, and the downstream Person token
            // carries it on, so its expiry and termination reach the chain.
            Some(self.load_mission(
                &up.context.record.principal,
                s256,
                (self.clock)(),
                binding_context,
            )?)
        } else {
            None
        };
        let policy_request = PersonRequest {
            mission: mission.clone(),
            agent: agent.clone(),
            subagent: self.subagent(&agent, &parameters, (self.clock)())?,
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
        if mission.as_ref().is_some_and(|m| m.person_id != person.id)
            || binding
                .as_ref()
                .is_some_and(|binding| binding.person_id != person.id)
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
        self.subagent_current(&agent, policy_request.subagent.as_ref(), now)?;
        check_upstream_current(policy_request.upstream.as_ref(), now)?;
        self.recheck_mission(mission.as_ref(), now, binding_context)?;
        let mut expires_at = now
            .saturating_add(self.config.person_lifetime)
            .min(agent.claims().exp);
        let holder = policy_request.subagent.as_ref().unwrap_or(&agent);
        expires_at = expires_at.min(holder.claims().exp);
        if let Some(up) = &upstream {
            expires_at = expires_at.min(up.token.exp);
        }
        if let Some(exp) = mission.as_ref().and_then(|m| m.document.expires_at()) {
            expires_at = expires_at.min(exp);
        }
        let claims = PersonClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-person.json".into(),
            aud: policy_request.resource,
            sub: person.subject,
            cnf: Confirmation {
                jwk: holder.claims().cnf.jwk.clone(),
            },
            jti: (self.ids)(),
            iat: now,
            exp: expires_at,
            nbf: None,
            mission_s256: mission.as_ref().map(|m| m.document.s256().to_owned()),
            tenant: person.tenant,
            extra: Default::default(),
        };
        let compact = mint_person_token(&self.config.signing_key, &self.config.kid, &claims)
            .map_err(|_| Failure::internal())?;
        let record = self.record(
            &compact,
            holder,
            &principal,
            &person.id,
            Issuance {
                parent_agent: policy_request
                    .subagent
                    .as_ref()
                    .map(|_| Self::identity(&agent)),
                binding_generation: match (&upstream, &binding) {
                    (Some(up), _) => up.context.record.binding_generation,
                    (None, Some(binding)) => binding.generation,
                    (None, None) => 0,
                },
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
        self.commit_issuance(
            record,
            upstream.is_none(),
            mission.as_ref(),
            binding_context,
        )?;
        self.subagent_current(&agent, policy_request.subagent.as_ref(), (self.clock)())?;
        self.binding(&principal, binding_context)?
            .ok_or_else(Failure::internal)?;
        let released_at = (self.clock)();
        check_agent_current(&agent, released_at)?;
        check_subagent_current(policy_request.subagent.as_ref(), released_at)?;
        check_upstream_current(policy_request.upstream.as_ref(), released_at)?;
        self.recheck_mission(mission.as_ref(), released_at, binding_context)?;
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
        self.prepare_authorization_with(agent, parameters, verified_at, upstream, false)
    }
    /// Core verification of every exchange. `r3` admits only `r3_uri` and
    /// `r3_s256` as Resource-token companions and makes `scope` optional; the
    /// caller must then verify those claims and the referenced document.
    fn prepare_authorization_with(
        &self,
        agent: &VerifiedAgentToken,
        parameters: Value,
        verified_at: i64,
        upstream: Option<&Upstream>,
        r3: bool,
    ) -> Result<PreparedAuthorization, Failure> {
        let subagent = self.subagent(agent, &parameters, verified_at)?;
        let holder = subagent.as_ref().unwrap_or(agent);
        let resource_compact = required_string(&parameters, "resource_token")?;
        let presented_compact = required_string(&parameters, "presented_token")?;
        let parsed = ResourceToken::parse(resource_compact)
            .map_err(|error| Failure::token(error, "resource", verified_at))?;
        let resource_issuer = parsed.unverified_claims().iss.clone();
        let resource_jti = parsed.unverified_claims().jti.clone();
        let resource = match parsed.verify(&self.resolver(), verified_at) {
            Ok(token) => token,
            Err(TokenError::ExpiredJwt)
                if self.token_revoked(&resource_issuer, &resource_jti, verified_at) =>
            {
                return Err(revocation::revoked_parameter("resource"));
            }
            Err(TokenError::ExpiredJwt)
                if r3
                    && let Some(failure) = self.r3_presented_failure_on_expired_resource(
                        presented_compact,
                        &parsed,
                        verified_at,
                    ) =>
            {
                return Err(failure);
            }
            Err(error) => return Err(Failure::token(error, "resource", verified_at)),
        };
        if self.token_revoked(&resource_issuer, &resource_jti, verified_at) {
            return Err(revocation::revoked_parameter("resource"));
        }
        let r = resource.claims();
        check_parameter_iat(r.iat, verified_at)?;
        if r.ps != self.config.issuer
            || (self.federation.is_none() && r.aud != self.config.issuer)
            || r.exp - r.iat > self.config.max_resource_lifetime
            || r.agent_jkt
                != holder
                    .claims()
                    .cnf
                    .jwk
                    .thumbprint()
                    .map_err(|_| Failure::internal())?
            || (r.mission_s256.is_some() && (self.federation.is_some() || subagent.is_some()))
        {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        let (offer, scopes) = if r3 {
            let mut core = r.extra.clone();
            core.remove("r3_uri");
            core.remove("r3_s256");
            // A mission composes with direct class R3 only. Federation, chaining
            // and sub-agents were refused above; proposals are refused after fetch.
            let scopes = match r.scope.as_deref() {
                Some(scope) => parse_scopes(scope)
                    .ok_or_else(|| Failure::parameter("invalid_resource_token"))?,
                None => Vec::new(),
            };
            // A class token may carry a budget offer only when this PS meters.
            // A well-formed consumption record is not resolved. Go answers
            // `invalid_resource_token` until retained-grant resolution exists.
            // A malformed record is a budget claim error.
            let offer = if self.budgets.is_some() {
                if core.contains_key("budget_consumed") {
                    return Err(match parse_resource_claims(&core, &r.presented_jti) {
                        Ok(parsed) if parsed.consumed.is_some() => {
                            Failure::parameter("invalid_resource_token")
                        }
                        _ => Failure::parameter("invalid_budget"),
                    });
                }
                self.admit_resource_budget(&core, &r.presented_jti)?
            } else if extra_blocks(&core, false, false, false) {
                return Err(Failure::parameter("invalid_resource_token"));
            } else {
                None
            };
            (offer, scopes)
        } else {
            // The claim is read after verification, by the flow that resolves it.
            let mut core = r.extra.clone();
            if self.resource_interaction_enabled() {
                core.remove("interaction");
            }
            let offer = self.admit_resource_budget(&core, &r.presented_jti)?;
            let scopes = parse_scopes(
                r.scope
                    .as_deref()
                    .ok_or_else(|| Failure::parameter("invalid_resource_token"))?,
            )
            .ok_or_else(|| Failure::parameter("invalid_resource_token"))?;
            (offer, scopes)
        };
        let presented =
            self.verify_presented_with(presented_compact, verified_at, "presented", r3)?;
        self.match_resource(&presented, r)?;
        let retained = self.load_record(&presented, presented_compact, verified_at, "presented")?;
        if retained.agent != Self::identity(holder)
            || retained.parent_agent != subagent.as_ref().map(|_| Self::identity(agent))
            || (subagent.is_some() && retained.principal != Self::identity(agent))
        {
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
        if binding.person_id != retained.person_id
            || binding.generation != retained.binding_generation
        {
            return Err(binding_context.revoked());
        }
        if r.login_hint
            .as_deref()
            .is_some_and(|hint| parameters.get("login_hint").and_then(Value::as_str) != Some(hint))
        {
            return Err(Failure::parameter("invalid_request"));
        }
        // The mission's owner is the presented record's principal: the
        // requesting Agent, or on a chained request the calling Agent.
        let mission = if let Some(s256) = &r.mission_s256 {
            let mission =
                self.load_mission(&retained.principal, s256, verified_at, binding_context)?;
            if mission.person_id != retained.person_id {
                return Err(Failure::parameter("invalid_presented_token"));
            }
            Some(mission)
        } else {
            None
        };
        let context = AuthorizationRequest {
            mission,
            agent: agent.clone(),
            subagent,
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
            offer,
        })
    }
    fn auth(
        &self,
        agent: VerifiedAgentToken,
        parameters: Value,
        verified_at: i64,
        upstream: Option<Upstream>,
    ) -> Result<Response<Vec<u8>>, Failure> {
        // Unverified dispatch only: the R3 path verifies every claim it uses.
        if self.r3.is_some() && r3::carries_reference(&parameters) {
            return self.auth_r3(agent, parameters, verified_at, upstream);
        }
        let prepared =
            self.prepare_authorization(&agent, parameters, verified_at, upstream.as_ref())?;
        if self.federation.is_some() {
            return self.federate(&agent, &prepared);
        }
        if let Some(interaction) = ResourceInteraction::from_claims(prepared.resource.claims())
            .map_err(|_| Failure::parameter("invalid_resource_token"))?
        {
            if upstream.is_some() || prepared.context.subagent.is_some() || prepared.offer.is_some()
            {
                return Err(Failure::parameter("invalid_request"));
            }
            return self.open_resource_interaction(&agent, &prepared, interaction);
        }
        self.grant_auth(&agent, prepared)
    }
    /// Policy, issuance, commit and release of one prepared direct Auth grant.
    fn grant_auth(
        &self,
        agent: &VerifiedAgentToken,
        prepared: PreparedAuthorization,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let PreparedAuthorization {
            resource,
            presented,
            retained,
            context,
            binding_context,
            offer,
        } = prepared;
        let r = resource.claims();
        let upstream = context.upstream.as_ref();
        let grant = if upstream.is_some() {
            self.policy.authorize_upstream(&context)
        } else {
            self.policy.authorize(&context)
        }
        .map_err(Failure::policy)?;
        validate_grant(&grant, &context.scopes)?;
        let mission = context.mission.as_ref();
        let now = (self.clock)();
        self.recheck_mission(mission, now, binding_context)?;
        self.inputs_current(agent, &resource, &presented, now)?;
        self.subagent_current(agent, context.subagent.as_ref(), now)?;
        check_upstream_current(upstream, now)?;
        let mut expires_at = now
            .saturating_add(grant.lifetime)
            .min(agent.claims().exp)
            .min(presented.exp);
        let holder = context.subagent.as_ref().unwrap_or(agent);
        expires_at = expires_at.min(holder.claims().exp);
        if let Some(up) = upstream {
            expires_at = expires_at.min(up.record.expires_at);
        }
        if let Some(exp) = mission.and_then(|m| m.document.expires_at()) {
            expires_at = expires_at.min(exp);
        }
        if let Some(end) = self
            .budgets
            .as_ref()
            .and_then(|state| state.policy.period_end)
        {
            expires_at = expires_at.min(end);
        }
        let granted_budget = self.narrow_offer(offer.as_ref(), &r.sub, &r.iss, false)?;
        let mut extra = std::collections::BTreeMap::new();
        if let Some(budget) = &granted_budget {
            extra.insert("budget".into(), budget.to_value());
        }
        let claims = AuthClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-person.json".into(),
            aud: r.iss.clone(),
            ps: self.config.issuer.clone(),
            sub: r.sub.clone(),
            cnf: Confirmation {
                jwk: holder.claims().cnf.jwk.clone(),
            },
            jti: (self.ids)(),
            iat: now,
            exp: expires_at,
            scope: Some(grant.scopes.join(" ")),
            account: r.account.clone(),
            nbf: None,
            mission_s256: r.mission_s256.clone(),
            tenant: r.tenant.clone(),
            extra,
        };
        let compact = mint_auth_token(&self.config.signing_key, &self.config.kid, &claims)
            .map_err(|_| Failure::internal())?;
        let record = self.record(
            &compact,
            holder,
            &retained.principal,
            &retained.person_id,
            Issuance {
                parent_agent: context.subagent.as_ref().map(|_| Self::identity(agent)),
                binding_generation: retained.binding_generation,
                kind: TokenKind::Auth,
                jti: &claims.jti,
                resource: &claims.aud,
                subject: &claims.sub,
                tenant: claims.tenant.clone(),
                issued_at: now,
                expires_at,
                presented: Some(retained.token),
                upstream: upstream.map(|up| up.record.token.clone()),
            },
        )?;
        self.commit_issuance(record, false, mission, binding_context)?;
        self.subagent_current(agent, context.subagent.as_ref(), (self.clock)())?;
        self.binding(&retained.principal, binding_context)?
            .ok_or_else(Failure::internal)?;
        let released_at = (self.clock)();
        self.inputs_current(agent, &resource, &presented, released_at)?;
        check_subagent_current(context.subagent.as_ref(), released_at)?;
        check_upstream_current(upstream, released_at)?;
        self.recheck_mission(mission, released_at, binding_context)?;
        if expires_at <= released_at {
            return Err(Failure::internal());
        }
        // Reserve only after the token will be released. A store failure
        // withholds the token and must not occupy the cap.
        if let Some(budget) = &granted_budget
            && let Some(state) = &self.budgets
        {
            state
                .accounts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .insert_owned(
                    claims.jti.clone(),
                    budget.amount(),
                    expires_at,
                    budget_owner(&claims.sub, &claims.aud),
                );
        }
        Ok(token_response(
            "auth_token",
            compact,
            expires_at - released_at,
        ))
    }
    fn admit_resource_budget(
        &self,
        extra: &std::collections::BTreeMap<String, Value>,
        presented_jti: &str,
    ) -> Result<Option<Budget>, Failure> {
        let enabled = self.budgets.is_some();
        if extra_blocks(extra, enabled, enabled, false) {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        if !enabled {
            return Ok(None);
        }
        let claims = parse_resource_claims(extra, presented_jti)
            .map_err(|_| Failure::parameter("invalid_budget"))?;
        if let Some(budget) = &claims.budget {
            check_declared(
                budget,
                &self.budgets.as_ref().expect("budgets").policy.units,
            )
            .map_err(|_| Failure::parameter("invalid_budget"))?;
        }
        if let Some(record) = &claims.consumed {
            self.budgets
                .as_ref()
                .expect("budgets")
                .accounts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .apply_record(record)
                .map_err(|_| Failure::parameter("invalid_budget"))?;
        }
        Ok(claims.budget)
    }
    fn narrow_offer(
        &self,
        offer: Option<&Budget>,
        subject: &str,
        resource: &str,
        parameter: bool,
    ) -> Result<Option<Budget>, Failure> {
        let Some(state) = &self.budgets else {
            return Ok(None);
        };
        let Some(offer) = offer else {
            return Ok(None);
        };
        // Only the PS-to-AS parameter may be omitted. Three-party issuance
        // still narrows and counts the grant. Omitting the claim there would
        // leave this library's resource serving the token unmetered.
        if parameter
            && state
                .policy
                .omit_above
                .is_some_and(|limit| offer.amount() > limit)
        {
            return Ok(None);
        }
        let cap = match state.policy.cap {
            Some(ceiling) => {
                let room = state
                    .accounts
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .free_owned(ceiling, 0, (self.clock)(), &budget_owner(subject, resource))
                    .max(0);
                Some(room)
            }
            None => None,
        };
        narrow_to(offer, cap)
            .map(Some)
            .map_err(|_| Failure::parameter("invalid_budget"))
    }
    fn inputs_current(
        &self,
        agent: &VerifiedAgentToken,
        resource: &VerifiedResourceToken,
        presented: &Presented,
        now: i64,
    ) -> Result<(), Failure> {
        check_agent_current(agent, now)?;
        if presented.exp <= now && presented.exp <= resource.claims().exp {
            return Err(Failure::parameter("expired_presented_token"));
        }
        if resource.claims().exp <= now {
            return Err(Failure::parameter("expired_resource_token"));
        }
        if presented.exp <= now {
            return Err(Failure::parameter("expired_presented_token"));
        }
        Ok(())
    }
}
fn budget_owner(subject: &str, resource: &str) -> String {
    format!("{subject}\u{1f}{resource}")
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
// The final time fence performs no host I/O. Resolver and store callbacks must
// finish before callers sample the release clock and compute expires_in.
fn check_subagent_current(child: Option<&VerifiedAgentToken>, now: i64) -> Result<(), Failure> {
    if child.is_some_and(|child| child.claims().exp <= now) {
        return Err(Failure::parameter("expired_subagent_token"));
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
/// The retained record's `expires_at` is the upstream token's verified `exp`.
fn check_upstream_current(upstream: Option<&UpstreamContext>, now: i64) -> Result<(), Failure> {
    if upstream.is_some_and(|up| up.record.expires_at <= now) {
        return Err(Failure::parameter("expired_upstream_token"));
    }
    Ok(())
}
fn extra_blocks(
    extra: &std::collections::BTreeMap<String, Value>,
    allow_budget: bool,
    allow_consumed: bool,
    allow_r3: bool,
) -> bool {
    extra.keys().any(|name| match name.as_str() {
        "interaction" => true,
        "r3_uri" | "r3_s256" | "r3_granted" | "r3_per_call" => !allow_r3,
        "budget" => !allow_budget,
        "budget_consumed" => !allow_consumed,
        _ => false,
    })
}
fn digest(compact: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(compact.as_bytes()))
}
