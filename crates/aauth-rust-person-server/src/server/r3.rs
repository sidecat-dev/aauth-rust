//! Opt-in immediate class R3 on direct three-party issuance.
//!
//! `draft-hardt-aauth-r3`: Issuer Processing, Hash Verification, R3 Document
//! Access Restriction and Audit Log Integrity. The PS verifies the Agent's
//! proof, the presented credential's lineage and the Resource token exactly as
//! for Core, then the R3 reference, then fetches the literal `r3_uri` with its
//! own `jwks_uri` signature, checks the exact digest and account, asks host
//! policy for an explicit grant, proves that grant against the document, and
//! commits the R3 audit record and the exact issuance before release.
//! Per-call proposals, budgets, missions, sub-agents, call chaining and AS
//! federation are refused.
use super::*;
use aauth_rust_r3::{
    Document, FetchClient, FetchConfig, FetchEgress, FetchIdentity, FetchLimits, FetchTransport,
    GrantedOperations, IssuanceRecord, IssuanceStore, Reference, Registry,
    mint_direct_auth_token, validate_document_account, verify_resource_token,
};
use std::sync::Arc;

/// What host consent sees for one exact class document.
pub struct R3AuthorizationRequest<'a> {
    /// Core context verified as for any exchange. `scopes` is empty when the
    /// Resource token carried no Core scope.
    pub core: &'a AuthorizationRequest,
    /// Verified `r3_uri` and `r3_s256`.
    pub reference: &'a Reference,
    /// Document fetched from exactly `r3_uri`, matched to `r3_s256` and the
    /// Resource token's account. `display` is Resource-asserted text.
    pub document: &'a Document,
}

/// Host consent to a class grant. Nothing is granted by default.
pub struct R3Decision {
    /// Operations to place in `r3_granted`. The PS proves they are a subset
    /// of the document; a wider set is a host error and nothing is issued.
    pub granted: GrantedOperations,
    /// Core scopes to grant, a subset of the requested scopes. Empty grants none.
    pub scopes: Vec<String>,
    /// Desired positive lifetime in seconds, at most 3600, further capped by
    /// the Agent token and the presented credential.
    pub lifetime: i64,
}

/// Explicit host authorization for one class document.
pub trait R3Policy: Send + Sync {
    /// Decide what to grant from a verified exchange and its exact document.
    ///
    /// # Errors
    /// [`PolicyError::Denied`] refuses; [`PolicyError::Unavailable`] is operational.
    fn authorize_document(
        &self,
        request: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError>;
}
impl<F> R3Policy for F
where
    F: Fn(&R3AuthorizationRequest<'_>) -> Result<R3Decision, PolicyError> + Send + Sync,
{
    fn authorize_document(
        &self,
        request: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError> {
        self(request)
    }
}
/// Boxed host R3 policy.
pub type BoxedR3Policy = Box<dyn R3Policy>;

/// Host dependencies for direct class R3 issuance.
pub struct R3IssuerConfig {
    /// Vocabulary allowlist for documents and token claims.
    pub registry: Registry,
    /// Explicit egress admission for each literal `r3_uri`, before signing.
    pub egress: Box<dyn FetchEgress>,
    /// Certificate-verified, deadline-aware HTTPS transport; no redirects or retries.
    pub transport: Box<dyn FetchTransport>,
    /// Document size and total fetch time.
    pub limits: FetchLimits,
    /// Grant decision. There is no default grant.
    pub policy: BoxedR3Policy,
    /// Durable, confidential R3 audit log. Its record is committed before the
    /// issuance record, and the token is withheld unless both commit.
    pub audit: Arc<dyn IssuanceStore>,
}

/// Untrusted routing only: whether the submitted Resource token names an R3 reference.
pub(super) fn carries_reference(parameters: &Value) -> bool {
    parameters
        .get("resource_token")
        .and_then(Value::as_str)
        .and_then(|compact| ResourceToken::parse(compact).ok())
        .is_some_and(|token| {
            let extra = &token.unverified_claims().extra;
            extra.contains_key("r3_uri") || extra.contains_key("r3_s256")
        })
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Issue direct class R3 Auth tokens for Resource tokens carrying `r3_uri`.
    ///
    /// The PS signs each document fetch as itself under `aauth-person.json`.
    /// A Resource token without R3 claims keeps Core issuance unchanged.
    ///
    /// # Errors
    /// [`ConfigurationError`] for an empty registry, or when federation or
    /// budgets are already enabled: those compositions are not implemented.
    pub fn with_r3(mut self, config: R3IssuerConfig) -> Result<Self, ConfigurationError> {
        if config.registry.is_empty() || self.federation.is_some() || self.budgets.is_some() {
            return Err(ConfigurationError);
        }
        self.r3 = Some(Box::new(config));
        Ok(self)
    }

    pub(super) fn auth_r3(
        &self,
        agent: VerifiedAgentToken,
        parameters: Value,
        verified_at: i64,
        upstream: Option<Upstream>,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let r3 = self.r3.as_ref().ok_or_else(Failure::internal)?;
        if upstream.is_some() || parameters.get("subagent_token").is_some() {
            return Err(Failure::parameter("invalid_request"));
        }
        if self.budgets.is_some() {
            return Err(Failure::internal());
        }
        let resource_compact = required_string(&parameters, "resource_token")?.to_owned();
        let PreparedAuthorization {
            resource,
            presented,
            retained,
            context,
            binding_context,
            offer: _,
        } = self.prepare_authorization_with(&agent, parameters, verified_at, None, true)?;
        let verified = verify_resource_token(&resource_compact, &self.resolver(), verified_at)
            .map_err(|_| Failure::parameter("invalid_resource_token"))?;
        let r = resource.claims();
        let reference = verified.reference().clone();

        // Literal r3_uri, PS role signature, exact digest, then account parity.
        let signed_at = (self.clock)();
        let clock = move || signed_at;
        let fetch = FetchClient::new(FetchConfig {
            registry: &r3.registry,
            signing_key: &self.config.signing_key,
            identity: FetchIdentity {
                issuer: self.config.issuer.clone(),
                discovery_document: "aauth-person.json".into(),
                key_id: self.config.kid.clone(),
            },
            clock: &clock,
            admit: &*r3.egress,
            transport: &*r3.transport,
            limits: r3.limits,
        })
        .map_err(|_| Failure::internal())?;
        let (document, exact) = match fetch.fetch_document(&reference) {
            Ok(fetched) => fetched,
            Err(error) if error.is_document_error() => {
                return Err(Failure::parameter("invalid_resource_token"));
            }
            Err(_) => return Err(Failure::internal()),
        };
        validate_document_account(&document, r.account.as_deref())
            .map_err(|_| Failure::parameter("invalid_resource_token"))?;

        let decision = r3
            .policy
            .authorize_document(&R3AuthorizationRequest {
                core: &context,
                reference: &reference,
                document: &document,
            })
            .map_err(Failure::policy)?;
        if !(1..=3600).contains(&decision.lifetime)
            || (!decision.scopes.is_empty()
                && (parse_scopes(&decision.scopes.join(" ")).is_none()
                    || decision
                        .scopes
                        .iter()
                        .any(|scope| !context.scopes.contains(scope))))
        {
            return Err(Failure::internal());
        }
        // A grant wider than the exact document is a host error: nothing is issued.
        let grant = aauth_rust_r3::Grant::new(&decision.granted, &document)
            .map_err(|_| Failure::internal())?;

        let now = (self.clock)();
        self.inputs_current(&agent, &resource, &presented, now)?;
        let binding = self
            .binding(&retained.principal, binding_context)?
            .ok_or_else(|| Failure::parameter("invalid_presented_token"))?;
        if binding.person_id != retained.person_id {
            return Err(binding_context.revoked());
        }
        let expires_at = now
            .saturating_add(decision.lifetime)
            .min(agent.claims().exp)
            .min(presented.exp);
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
            scope: (!decision.scopes.is_empty()).then(|| decision.scopes.join(" ")),
            account: r.account.clone(),
            nbf: None,
            mission_s256: None,
            tenant: r.tenant.clone(),
            extra: std::collections::BTreeMap::new(),
        };
        let compact = mint_direct_auth_token(
            &r3.registry,
            &self.config.signing_key,
            &self.config.kid,
            &claims,
            &reference,
            &exact,
            &grant,
        )
        .map_err(|_| Failure::internal())?;
        let record = self.record(
            &compact,
            &agent,
            &retained.principal,
            &retained.person_id,
            Issuance {
                parent_agent: None,
                kind: TokenKind::Auth,
                jti: &claims.jti,
                resource: &claims.aud,
                subject: &claims.sub,
                tenant: claims.tenant.clone(),
                issued_at: now,
                expires_at,
                presented: Some(retained.token.clone()),
                upstream: None,
            },
        )?;
        let audit = IssuanceRecord {
            auth_token_issuer: claims.iss.clone(),
            auth_token_jti: claims.jti.clone(),
            resource: claims.aud.clone(),
            r3_reference: reference.clone(),
            vocabulary: document.operation_set().vocabulary().clone(),
            issued_at: now,
            person_server: r.ps.clone(),
            subject: r.sub.clone(),
            account: claims.account.clone(),
            presented_jti: r.presented_jti.clone(),
            agent_jkt: r.agent_jkt.clone(),
            agent: agent.claims().sub.clone(),
            parent_agent: None,
        };
        // Audit first: an audit row may outlive an unreleased token, but no
        // token is released without one. Any failure withholds the token.
        r3.audit.commit(&audit).map_err(|_| Failure::internal())?;
        self.commit_issuance(record, false, None, binding_context)?;
        self.binding(&retained.principal, binding_context)?
            .ok_or_else(Failure::internal)?;
        let released_at = (self.clock)();
        self.inputs_current(&agent, &resource, &presented, released_at)?;
        if expires_at <= released_at {
            return Err(Failure::internal());
        }
        Ok(token_response(
            "auth_token",
            compact,
            expires_at - released_at,
        ))
    }
}
