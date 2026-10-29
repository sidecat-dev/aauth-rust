//! Opt-in immediate R3 on direct three-party issuance.
//!
//! `draft-hardt-aauth-r3`: Issuer Processing, Hash Verification, R3 Document
//! Access Restriction, Audit Log Integrity and Per-Call Proposals. The PS
//! verifies the Agent's proof, the presented credential's lineage and the
//! Resource token exactly as for Core, then the R3 reference, then fetches the
//! literal `r3_uri` with its own `jwks_uri` signature and classifies the exact
//! bytes. A class document is granted through [`R3Policy::authorize_document`],
//! optionally with `r3_per_call` operations. A per-call proposal is approved
//! only through [`R3Policy::authorize_proposal`], against the presented class
//! Auth token, and yields one single-operation Auth token. A proposal carrying
//! `result` (release gating) is release consent and goes only through
//! [`R3Policy::authorize_release`]; the token shape is the same. Either way the
//! R3 audit record and the exact issuance commit before release.
//! A class document may carry a budget offer when budgets are enabled. The
//! class-R3 budget profile does not permit `r3_per_call` or `budget_consumed`.
//! Missions, sub-agents, call chaining and AS federation are refused.
use super::*;
use aauth_rust_r3::{
    Authorization, Document, FetchClient, FetchConfig, FetchEgress, FetchIdentity, FetchLimits,
    FetchTransport, GrantedOperations, IssuanceRecord, IssuanceStore, OperationAccess, Proposal,
    Reference, Registry, VerifiedR3AuthToken, VocabularyUri, mint_auth_token as mint_r3_auth_token,
    mint_budget_auth_token, mint_direct_auth_token, mint_per_call_auth_token,
    validate_document_account, verify_budget_resource_token,
    validate_proposal_account, verify_auth_token_claims, verify_resource_token,
};
use std::sync::Arc;

type TokenMint<'a> = Box<dyn Fn(&AuthClaims) -> Result<String, Failure> + 'a>;
type PreparedR3Grant<'a> = (Vec<String>, i64, Option<i64>, VocabularyUri, TokenMint<'a>);

/// Per-call approval recorded when the presented class Auth token expired
/// while host consent ran (`draft-hardt-aauth-r3`, Per-Call Flow). Consumed at
/// most once by a replacement proposal for the exact same person, principal,
/// holder, Resource, subject, tenant, account, requested Core scopes, consent
/// kind and proposal bytes, before `expires_at`.
pub(super) struct RecordedApproval {
    person_id: String,
    principal: AgentIdentity,
    agent: AgentIdentity,
    agent_jti: String,
    agent_jkt: String,
    resource: String,
    subject: String,
    tenant: Option<String>,
    account: Option<String>,
    requested_scopes: Vec<String>,
    proposal_s256: String,
    exact_proposal: Vec<u8>,
    release: bool,
    expired_presented_issuer: String,
    expired_presented_jti: String,
    expired_resource_jti: String,
    scopes: Vec<String>,
    lifetime: i64,
    expires_at: i64,
}

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
    /// Operations authorized in principle but approved per call, placed in
    /// `r3_per_call`. They must be disjoint from `granted` and inside the
    /// document. `None` issues a direct-only token.
    pub per_call: Option<GrantedOperations>,
    /// Core scopes to grant, a subset of the requested scopes. Empty grants none.
    pub scopes: Vec<String>,
    /// Desired positive lifetime in seconds, at most 3600, further capped by
    /// the Agent token and the presented credential.
    pub lifetime: i64,
}

/// What host consent sees for one exact per-call proposal.
pub struct R3ProposalRequest<'a> {
    /// Core context verified as for any exchange; `presented` is the class
    /// Auth token's retained issuance.
    pub core: &'a AuthorizationRequest,
    /// Verified proposal `r3_uri` and `r3_s256`.
    pub reference: &'a Reference,
    /// Proposal fetched from exactly `r3_uri`, matched to `r3_s256` and the
    /// account. Its `parameters` are the concrete call; `display` is
    /// Resource-asserted text. It carries `result` exactly when this request
    /// reached [`R3Policy::authorize_release`].
    pub proposal: &'a Proposal,
    /// The presented class Auth token, verified; the proposal operation is in
    /// its `r3_per_call`.
    pub class: &'a VerifiedR3AuthToken,
}

/// Host approval of one concrete call. Nothing is approved by default.
pub struct R3ProposalDecision {
    /// Core scopes to grant, a subset of the proposal Resource token's scopes.
    pub scopes: Vec<String>,
    /// Desired positive lifetime in seconds, at most 3600, further capped by
    /// the Agent token and the presented class Auth token.
    pub lifetime: i64,
}

/// Explicit host authorization for R3 documents and per-call proposals.
pub trait R3Policy: Send + Sync {
    /// Decide what to grant from a verified exchange and its exact document.
    ///
    /// # Errors
    /// [`PolicyError::Denied`] refuses; [`PolicyError::Unavailable`] is operational.
    fn authorize_document(
        &self,
        request: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError>;
    /// Approve one concrete call after evaluating its `parameters`.
    ///
    /// The default refuses, so a policy that only grants documents never
    /// approves a call it did not inspect.
    ///
    /// # Errors
    /// [`PolicyError::Denied`] refuses; [`PolicyError::Unavailable`] is operational.
    fn authorize_proposal(
        &self,
        _request: &R3ProposalRequest<'_>,
    ) -> Result<R3ProposalDecision, PolicyError> {
        Err(PolicyError::Denied)
    }
    /// Approve release of a result the Resource already computed: the
    /// proposal carries `result`, and its `display` should say the operation
    /// has run (`draft-hardt-aauth-r3`, Approving Release Rather Than
    /// Execution). This is disclosure consent, not execution consent, and
    /// `result` is what later requests from the same Agent may be judged
    /// against. Declining releases nothing.
    ///
    /// The default refuses, so a policy that approves execution never
    /// approves a release it did not inspect.
    ///
    /// # Errors
    /// [`PolicyError::Denied`] refuses; [`PolicyError::Unavailable`] is operational.
    fn authorize_release(
        &self,
        _request: &R3ProposalRequest<'_>,
    ) -> Result<R3ProposalDecision, PolicyError> {
        Err(PolicyError::Denied)
    }
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

/// Host dependencies for direct R3 issuance.
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

fn valid_grant_shape(scopes: &[String], lifetime: i64, requested: &[String]) -> bool {
    (1..=3600).contains(&lifetime)
        && (scopes.is_empty()
            || (parse_scopes(&scopes.join(" ")).is_some()
                && scopes.iter().all(|scope| requested.contains(scope))))
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Issue direct R3 Auth tokens for Resource tokens carrying `r3_uri`.
    ///
    /// The PS signs each document fetch as itself under `aauth-person.json`.
    /// A Resource token without R3 claims keeps Core issuance unchanged.
    /// Budgets may already be enabled. A class token then carries a budget
    /// offer through the same verifier as `with_budgets` after R3.
    ///
    /// # Errors
    /// [`ConfigurationError`] for an empty registry. Federation may already be
    /// enabled. A class document is fetched and consented here, then the exact
    /// tokens are relayed to the access server. A proposal is not relayed yet.
    pub fn with_r3(mut self, config: R3IssuerConfig) -> Result<Self, ConfigurationError> {
        if config.registry.is_empty() {
            return Err(ConfigurationError);
        }
        self.r3 = Some(Box::new(config));
        Ok(self)
    }

    /// Refuse when the Agent, presented or Resource token is now revoked,
    /// with the same typed errors the request-time checks use.
    fn inputs_unrevoked(
        &self,
        agent: &VerifiedAgentToken,
        resource: &VerifiedResourceToken,
        presented: &Presented,
        now: i64,
    ) -> Result<(), Failure> {
        let a = agent.claims();
        if self.token_revoked(&a.iss, &a.jti, now) {
            return Err(Failure::revoked_jwt());
        }
        if self.token_revoked(&presented.issuer, &presented.jti, now) {
            return Err(revocation::revoked_parameter("presented"));
        }
        let r = resource.claims();
        if self.token_revoked(&r.iss, &r.jti, now) {
            return Err(revocation::revoked_parameter("resource"));
        }
        Ok(())
    }

    /// When a proposal Resource token capped its `exp` to the presented class
    /// Auth token's `exp`, report the presented token's revocation or expiry
    /// rather than `expired_resource_token`.
    pub(super) fn r3_presented_failure_on_expired_resource(
        &self,
        presented_compact: &str,
        resource: &ResourceToken,
        verified_at: i64,
    ) -> Option<Failure> {
        let r = resource.unverified_claims();
        resource.verify(&self.resolver(), r.iat).ok()?;
        let parsed = AuthToken::parse(presented_compact).ok()?;
        let c = parsed.unverified_claims();
        if self.token_revoked(&c.iss, &c.jti, verified_at) {
            return Some(revocation::revoked_parameter("presented"));
        }
        parsed.verify(&self.resolver(), c.iat).ok()?;
        let jkt = c.cnf.jwk.thumbprint().ok()?;
        (c.exp <= verified_at
            && c.exp <= r.exp
            && c.jti == r.presented_jti
            && c.aud == r.iss
            && c.ps == r.ps
            && c.sub == r.sub
            && c.tenant == r.tenant
            && jkt == r.agent_jkt)
            .then(|| Failure::parameter("expired_presented_token"))
    }

    fn approval_usable(&self, entry: &RecordedApproval, now: i64) -> bool {
        entry.expires_at > now
            && !self.token_revoked(&entry.agent.issuer, &entry.agent_jti, now)
            && !self.token_revoked(
                &entry.expired_presented_issuer,
                &entry.expired_presented_jti,
                now,
            )
            && !self.token_revoked(&entry.resource, &entry.expired_resource_jti, now)
    }

    fn record_approval(&self, approval: RecordedApproval, now: i64) {
        if !self.approval_usable(&approval, now) {
            return;
        }
        let mut approvals = self
            .r3_approvals
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        approvals.retain(|entry| {
            self.approval_usable(entry, now)
                && !(entry.person_id == approval.person_id
                    && entry.principal == approval.principal
                    && entry.agent == approval.agent
                    && entry.agent_jkt == approval.agent_jkt
                    && entry.resource == approval.resource
                    && entry.subject == approval.subject
                    && entry.tenant == approval.tenant
                    && entry.account == approval.account
                    && entry.requested_scopes == approval.requested_scopes
                    && entry.proposal_s256 == approval.proposal_s256
                    && entry.release == approval.release)
        });
        approvals.push(approval);
    }

    #[allow(clippy::too_many_arguments)]
    fn take_recorded_approval(
        &self,
        retained: &TokenRecord,
        r: &aauth_rust_core::ResourceClaims,
        requested_scopes: &[String],
        proposal_s256: &str,
        exact_proposal: &[u8],
        release: bool,
        presented_jti: &str,
        now: i64,
    ) -> Option<RecordedApproval> {
        let mut approvals = self
            .r3_approvals
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        approvals.retain(|entry| self.approval_usable(entry, now));
        let position = approvals.iter().position(|entry| {
            entry.person_id == retained.person_id
                && entry.principal == retained.principal
                && entry.agent == retained.agent
                && entry.agent_jkt == r.agent_jkt
                && entry.resource == r.iss
                && entry.subject == r.sub
                && entry.tenant == r.tenant
                && entry.account == r.account
                && entry.requested_scopes == requested_scopes
                && entry.proposal_s256 == proposal_s256
                && entry.exact_proposal == exact_proposal
                && entry.release == release
                && entry.expired_presented_jti != presented_jti
                && entry.expired_resource_jti != r.jti
        })?;
        Some(approvals.remove(position))
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
        let resource_compact = required_string(&parameters, "resource_token")?.to_owned();
        let presented_compact = required_string(&parameters, "presented_token")?.to_owned();
        let PreparedAuthorization {
            resource,
            presented,
            retained,
            context,
            binding_context,
            offer,
        } = self.prepare_authorization_with(&agent, parameters, verified_at, None, true)?;
        let reference = if offer.is_some() {
            let (verified, _offer, consumed) = verify_budget_resource_token(
                &resource_compact,
                &self.resolver(),
                verified_at,
            )
            .map_err(|_| Failure::parameter("invalid_resource_token"))?;
            // Go refuses a consumption record here. The HTTP code is
            // `invalid_resource_token`: this is not a claim-parse error.
            if consumed.is_some() {
                return Err(Failure::parameter("invalid_resource_token"));
            }
            verified.reference().clone()
        } else {
            verify_resource_token(&resource_compact, &self.resolver(), verified_at)
                .map_err(|_| Failure::parameter("invalid_resource_token"))?
                .reference()
                .clone()
        };
        let r = resource.claims();
        let granted_budget = self.narrow_offer(offer.as_ref(), &r.sub, &r.iss, false)?;

        // Literal r3_uri, PS role signature, exact digest, then classification.
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
        let artifact = match fetch.fetch_artifact(&reference) {
            Ok(fetched) => fetched,
            Err(error) if error.is_document_error() => {
                return Err(Failure::parameter("invalid_resource_token"));
            }
            Err(_) => return Err(Failure::internal()),
        };
        let exact = artifact.exact_bytes().to_vec();

        // Each branch ends with the scopes, lifetime, recorded-approval cap, signer and vocabulary to issue.
        let (scopes, lifetime, approval_expires_at, vocabulary, mint): PreparedR3Grant<'_> =
            if let Some(document) = artifact.document() {
                validate_document_account(document, r.account.as_deref())
                    .map_err(|_| Failure::parameter("invalid_resource_token"))?;
                let decision = r3
                    .policy
                    .authorize_document(&R3AuthorizationRequest {
                        core: &context,
                        reference: &reference,
                        document,
                    })
                    .map_err(Failure::policy)?;
                if !valid_grant_shape(&decision.scopes, decision.lifetime, &context.scopes) {
                    return Err(Failure::internal());
                }
                // The class-R3 budget profile has no `r3_per_call` claim.
                // Leaving an operation per call while an offer is present
                // cannot be signed, so nothing is issued.
                if decision.per_call.is_some() && granted_budget.is_some() {
                    return Err(Failure::parameter("invalid_resource_token"));
                }
                // Go consents on the fetched class document, then relays the
                // exact tokens. The access server signs the Auth token.
                if self.federation.is_some() {
                    return self.federate_r3(
                        &agent,
                        &PreparedAuthorization {
                            resource,
                            presented,
                            retained,
                            context,
                            binding_context,
                            offer,
                        },
                        &reference,
                        document,
                    );
                }
                let mint: TokenMint<'_> = match &decision.per_call {
                    None => {
                        let grant = aauth_rust_r3::Grant::new(&decision.granted, document)
                            .map_err(|_| Failure::internal())?;
                        let (reference, exact) = (reference.clone(), exact.clone());
                        let budget_grant = granted_budget.clone();
                        Box::new(move |claims: &AuthClaims| {
                            if let Some(budget_grant) = &budget_grant {
                                return mint_budget_auth_token(
                                    &r3.registry,
                                    &self.config.signing_key,
                                    &self.config.kid,
                                    claims,
                                    &reference,
                                    &exact,
                                    &grant,
                                    budget_grant,
                                )
                                .map_err(|_| Failure::internal());
                            }
                            mint_direct_auth_token(
                                &r3.registry,
                                &self.config.signing_key,
                                &self.config.kid,
                                claims,
                                &reference,
                                &exact,
                                &grant,
                            )
                            .map_err(|_| Failure::internal())
                        })
                    }
                    Some(per_call) => {
                        let authorization =
                            Authorization::new(&decision.granted, per_call, document)
                                .map_err(|_| Failure::internal())?;
                        let (reference, exact) = (reference.clone(), exact.clone());
                        Box::new(move |claims: &AuthClaims| {
                            mint_r3_auth_token(
                                &r3.registry,
                                &self.config.signing_key,
                                &self.config.kid,
                                claims,
                                &reference,
                                &exact,
                                &authorization,
                            )
                            .map_err(|_| Failure::internal())
                        })
                    }
                };
                (
                    decision.scopes,
                    decision.lifetime,
                    None,
                    document.operation_set().vocabulary().clone(),
                    mint,
                )
            } else if let Some(proposal) = artifact.proposal() {
                // A federated proposal must be relayed after its own consent.
                // Do not sign it on this Person Server.
                if self.federation.is_some() {
                    return Err(Failure::internal());
                }
                // A proposal plus a budget offer is the same unsigned composition.
                // Do not record approval or mint a per-call token that drops the offer.
                if granted_budget.is_some() {
                    return Err(Failure::parameter("invalid_resource_token"));
                }
                // Release gating executed before approval: release consent, never
                // execution consent. A person cannot be told it already ran
                // without a display.
                let release = proposal.result().is_some();
                if release && proposal.display().is_none() {
                    return Err(Failure::parameter("invalid_resource_token"));
                }
                validate_proposal_account(proposal, r.account.as_deref())
                    .map_err(|_| Failure::parameter("invalid_resource_token"))?;
                // The presented token is the class Auth token this PS issued; its
                // retained lineage was verified above. Its R3 claims come from its
                // signed payload, and the operation must be one it left per call.
                if presented.kind != TokenKind::Auth {
                    return Err(Failure::parameter("invalid_resource_token"));
                }
                let class = verify_auth_token_claims(
                    &r3.registry,
                    &presented_compact,
                    &self.resolver(),
                    verified_at,
                )
                .map_err(|_| Failure::parameter("invalid_presented_token"))?;
                let c = class.claims();
                if c.iss != self.config.issuer || c.dwk != "aauth-person.json" || c.ps != r.ps {
                    return Err(Failure::parameter("invalid_presented_token"));
                }
                if !matches!(
                    class.operations().access_for(&proposal.operation()),
                    Ok(OperationAccess::PerCall)
                ) {
                    return Err(Failure::parameter("invalid_resource_token"));
                }
                let check_now = (self.clock)();
                let (decision, approval_expires_at) = if let Some(recorded) = self
                    .take_recorded_approval(
                        &retained,
                        r,
                        &context.scopes,
                        reference.digest(),
                        &exact,
                        release,
                        &presented.jti,
                        check_now,
                    ) {
                    if !valid_grant_shape(&recorded.scopes, recorded.lifetime, &context.scopes) {
                        return Err(Failure::internal());
                    }
                    (
                        R3ProposalDecision {
                            scopes: recorded.scopes,
                            lifetime: recorded.lifetime,
                        },
                        Some(recorded.expires_at),
                    )
                } else {
                    let request = R3ProposalRequest {
                        core: &context,
                        reference: &reference,
                        proposal,
                        class: &class,
                    };
                    let decision = if release {
                        r3.policy.authorize_release(&request)
                    } else {
                        r3.policy.authorize_proposal(&request)
                    }
                    .map_err(Failure::policy)?;
                    if !valid_grant_shape(&decision.scopes, decision.lifetime, &context.scopes) {
                        return Err(Failure::internal());
                    }
                    let approved_at = (self.clock)();
                    self.inputs_unrevoked(&agent, &resource, &presented, approved_at)?;
                    check_agent_current(&agent, approved_at)?;
                    let binding = self
                        .binding(&retained.principal, binding_context)?
                        .ok_or_else(|| Failure::parameter("invalid_presented_token"))?;
                    if binding.person_id != retained.person_id {
                        return Err(binding_context.revoked());
                    }
                    if presented.exp <= approved_at && presented.exp <= r.exp {
                        self.record_approval(
                            RecordedApproval {
                                person_id: retained.person_id.clone(),
                                principal: retained.principal.clone(),
                                agent: retained.agent.clone(),
                                agent_jti: agent.claims().jti.clone(),
                                agent_jkt: r.agent_jkt.clone(),
                                resource: r.iss.clone(),
                                subject: r.sub.clone(),
                                tenant: r.tenant.clone(),
                                account: r.account.clone(),
                                requested_scopes: context.scopes.clone(),
                                proposal_s256: reference.digest().to_owned(),
                                exact_proposal: exact.clone(),
                                release,
                                expired_presented_issuer: presented.issuer.clone(),
                                expired_presented_jti: presented.jti.clone(),
                                expired_resource_jti: r.jti.clone(),
                                scopes: decision.scopes,
                                lifetime: decision.lifetime,
                                expires_at: approved_at
                                    .saturating_add(decision.lifetime)
                                    .min(agent.claims().exp),
                            },
                            approved_at,
                        );
                        return Err(Failure::parameter("expired_presented_token"));
                    }
                    (decision, None)
                };
                let (reference, exact) = (reference.clone(), exact.clone());
                let mint: TokenMint<'_> = Box::new(move |claims: &AuthClaims| {
                    mint_per_call_auth_token(
                        &r3.registry,
                        &self.config.signing_key,
                        &self.config.kid,
                        claims,
                        &reference,
                        &exact,
                    )
                    .map_err(|_| Failure::internal())
                });
                (
                    decision.scopes,
                    decision.lifetime,
                    approval_expires_at,
                    proposal.operation().vocabulary().clone(),
                    mint,
                )
            } else {
                return Err(Failure::parameter("invalid_resource_token"));
            };

        let now = (self.clock)();
        // Fetch and policy may block; a revocation recorded meanwhile refuses
        // here. Known revocation precedes expiry, as at request verification.
        self.inputs_unrevoked(&agent, &resource, &presented, now)?;
        self.inputs_current(&agent, &resource, &presented, now)?;
        let binding = self
            .binding(&retained.principal, binding_context)?
            .ok_or_else(|| Failure::parameter("invalid_presented_token"))?;
        if binding.person_id != retained.person_id {
            return Err(binding_context.revoked());
        }
        // A per-call token never outlives the class Auth token it was presented with
        // or the recorded approval window it consumed.
        let mut expires_at = now
            .saturating_add(lifetime)
            .min(agent.claims().exp)
            .min(presented.exp);
        if let Some(cap) = approval_expires_at {
            expires_at = expires_at.min(cap);
        }
        if let Some(end) = self
            .budgets
            .as_ref()
            .and_then(|state| state.policy.period_end)
        {
            expires_at = expires_at.min(end);
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
            scope: (!scopes.is_empty()).then(|| scopes.join(" ")),
            account: r.account.clone(),
            nbf: None,
            mission_s256: None,
            tenant: r.tenant.clone(),
            extra: std::collections::BTreeMap::new(),
        };
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
        let compact = mint(&claims)?;
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
            vocabulary,
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
        // Checked only after the issuance is registered in the store. A
        // revocation records its token in the ledger before it reads the store
        // for its cascade: one that began before this check sees it here and
        // the token is withheld; one that begins after reads this issuance.
        // Known revocation precedes expiry.
        self.inputs_unrevoked(&agent, &resource, &presented, released_at)?;
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
