//! Opt-in R3 issuance in four-party access.
//!
//! `draft-hardt-aauth-r3`: Issuer Processing, Hash Verification, R3 Document
//! Access Restriction and Audit Log Integrity. The AS verifies the PS proof and
//! the Agent, Resource and presented tokens exactly as for Core, then the R3
//! reference. It fetches the literal `r3_uri` with its own `jwks_uri`
//! signature under `aauth-access.json` and refuses bytes that do not hash to
//! `r3_s256` with `invalid_resource_token`. The exact class document goes to
//! [`R3Policy::authorize_document`], which decides both the operations and
//! the Core scopes. The Auth token carries `r3_uri`, `r3_s256` and
//! `r3_granted`. Its audit entry is committed before the token is released.
//!
//! This AS grants operations directly. It signs no `r3_per_call`, and it
//! refuses a per-call proposal and an R3 Resource token that carries a budget
//! offer with `invalid_resource_token`. Deferred continuations hold Core grants
//! only: an R3 request is decided at once, and an R3 Resource token presented
//! while a request waits is refused.
use super::*;
use aauth_rust_r3::{
    Document, FetchClient, FetchConfig, FetchEgress, FetchIdentity, FetchLimits, FetchTransport,
    Grant, GrantedOperations, IssuanceRecord, IssuanceStore, Reference, Registry,
    mint_direct_auth_token, validate_document_account, verify_resource_token,
};
use std::sync::Arc;

/// What host policy sees for one exact class document.
pub struct R3AuthorizationRequest<'a> {
    /// Core context verified as for any request. `scopes` is empty when the
    /// Resource token carried no Core scope.
    pub core: &'a AuthorizationRequest,
    /// Verified `r3_uri` and `r3_s256`.
    pub reference: &'a Reference,
    /// Document this AS fetched from exactly `r3_uri`, matched to `r3_s256`
    /// and the Resource token's account.
    pub document: &'a Document,
}

/// Host grant for one class document. Nothing is granted by default.
pub struct R3Decision {
    /// Operations to place in `r3_granted`. The AS proves they are a subset
    /// of the document; a wider set is a host error and nothing is issued.
    pub granted: GrantedOperations,
    /// Core scopes to grant, a subset of the requested scopes. Empty grants none.
    pub scopes: Vec<String>,
    /// Desired positive lifetime in seconds, at most 3600, further capped as
    /// for a Core grant.
    pub lifetime: i64,
}

/// Explicit host authorization for R3 class documents.
pub trait R3Policy: Send + Sync {
    /// Decide what to grant from a verified request and its exact document.
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

/// Host dependencies for R3 issuance.
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
    /// Durable, confidential R3 audit log. The entry is committed after the
    /// token is signed and before it is released; a failed commit withholds it.
    pub audit: Arc<dyn IssuanceStore>,
}

/// Untrusted routing only: whether the submitted Resource token names an R3 reference.
fn carries_reference(compact: &str) -> bool {
    ResourceToken::parse(compact).is_ok_and(|token| {
        let extra = &token.unverified_claims().extra;
        extra.contains_key("r3_uri") || extra.contains_key("r3_s256")
    })
}

impl<
    K: AgentKeyResolver,
    P: Fn(&AuthorizationRequest) -> Result<Decision, PolicyError>,
    C: Fn() -> i64,
    I: Fn() -> String,
> AccessServer<K, P, C, I>
{
    /// Issue R3 Auth tokens for Resource tokens carrying `r3_uri`.
    ///
    /// This AS signs each document fetch as itself under `aauth-access.json`.
    /// A Resource token without R3 claims keeps Core issuance unchanged.
    ///
    /// # Errors
    /// [`ConfigurationError`] for an empty registry.
    pub fn with_r3(mut self, config: R3IssuerConfig) -> Result<Self, ConfigurationError> {
        if config.registry.is_empty() {
            return Err(ConfigurationError);
        }
        self.r3 = Some(Box::new(config));
        Ok(self)
    }
    /// The verified reference of an R3 Resource token, when R3 is enabled.
    /// Without R3 the token's claims are refused by the Core checks.
    pub(super) fn r3_reference(
        &self,
        compact: &str,
        now: i64,
    ) -> Result<Option<Reference>, Failure> {
        if self.r3.is_none() || !carries_reference(compact) {
            return Ok(None);
        }
        let verified = verify_resource_token(compact, &self.resolver(), now)
            .map_err(|_| Failure::parameter("invalid_resource_token"))?;
        Ok(Some(verified.reference().clone()))
    }
    /// Issuer Processing steps 2 to 6 for a verified request.
    pub(super) fn issue_r3(
        &self,
        context: AuthorizationRequest,
        presented: Presented,
        reference: &Reference,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let r3 = self.r3.as_ref().ok_or_else(Failure::internal)?;
        let signed_at = (self.clock)();
        let clock = move || signed_at;
        let fetch = FetchClient::new(FetchConfig {
            registry: &r3.registry,
            signing_key: &self.config.signing_key,
            identity: FetchIdentity {
                issuer: self.config.issuer.clone(),
                discovery_document: "aauth-access.json".into(),
                key_id: self.config.kid.clone(),
            },
            clock: &clock,
            admit: &*r3.egress,
            transport: &*r3.transport,
            limits: r3.limits,
        })
        .map_err(|_| Failure::internal())?;
        // A proposal is not a class document, so it is refused here too.
        let (document, exact) = match fetch.fetch_document(reference) {
            Ok(fetched) => fetched,
            Err(error) if error.is_document_error() => {
                return Err(Failure::parameter("invalid_resource_token"));
            }
            Err(_) => return Err(Failure::internal()),
        };
        let r = context.resource.claims();
        validate_document_account(&document, r.account.as_deref())
            .map_err(|_| Failure::parameter("invalid_resource_token"))?;
        let decision = r3
            .policy
            .authorize_document(&R3AuthorizationRequest {
                core: &context,
                reference,
                document: &document,
            })
            .map_err(Failure::policy)?;
        let grant = Grant::new(&decision.granted, &document).map_err(|_| Failure::internal())?;
        if !(1..=3600).contains(&decision.lifetime)
            || (!decision.scopes.is_empty()
                && (scopes(&decision.scopes.join(" ")).is_none()
                    || decision.scopes.iter().any(|s| !context.scopes.contains(s))))
        {
            return Err(Failure::internal());
        }
        let holder = context.subagent.as_ref().unwrap_or(&context.agent);
        let parent_agent = context
            .subagent
            .as_ref()
            .map(|_| context.agent.claims().sub.clone());
        let vocabulary = document.operation_set().vocabulary().clone();
        let granted = Decision {
            scopes: decision.scopes,
            lifetime: decision.lifetime,
        };
        self.release(
            &context,
            &presented,
            &granted,
            std::collections::BTreeMap::new(),
            |claims| {
                let compact = mint_direct_auth_token(
                    &r3.registry,
                    &self.config.signing_key,
                    &self.config.kid,
                    claims,
                    reference,
                    &exact,
                    &grant,
                )
                .map_err(|_| Failure::internal())?;
                // Issuer Processing step 4, before the token is observable.
                r3.audit
                    .commit(&IssuanceRecord {
                        auth_token_issuer: claims.iss.clone(),
                        auth_token_jti: claims.jti.clone(),
                        resource: claims.aud.clone(),
                        r3_reference: reference.clone(),
                        vocabulary,
                        issued_at: claims.iat,
                        person_server: r.ps.clone(),
                        subject: r.sub.clone(),
                        account: claims.account.clone(),
                        presented_jti: r.presented_jti.clone(),
                        agent_jkt: r.agent_jkt.clone(),
                        agent: holder.claims().sub.clone(),
                        parent_agent,
                    })
                    .map_err(|_| Failure::internal())?;
                Ok(compact)
            },
        )
    }
}
