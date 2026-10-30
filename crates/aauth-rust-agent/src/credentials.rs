//! Pure credential-context checks; no network, retries or admission policy.
use crate::Agent;
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthToken, PersonToken, ResourceClaims, ResourceToken,
    TokenError, VerifiedAuthToken, VerifiedResourceToken, validate_server_identifier,
};
use aauth_rust_jose::{Jwk, Jws};

pub(crate) fn credential_key(compact: &str) -> Result<Jwk, TokenError> {
    let parsed = Jws::parse(compact)?;
    match parsed.header().get("typ").and_then(|value| value.as_str()) {
        Some("aa-agent+jwt") => Ok(AgentToken::parse(compact)?
            .unverified_claims()
            .cnf
            .jwk
            .clone()),
        Some("aa-person+jwt") => Ok(PersonToken::parse(compact)?
            .unverified_claims()
            .cnf
            .jwk
            .clone()),
        Some("aa-auth+jwt") => Ok(AuthToken::parse(compact)?
            .unverified_claims()
            .cnf
            .jwk
            .clone()),
        _ => Err(TokenError::UnexpectedTokenType),
    }
}
// Credential-context verification needs only a public holder key, including
// when a parent host checks a child's returned credentials.
pub(crate) struct CredentialVerifier<'a> {
    key: &'a Jwk,
}
impl<'a> CredentialVerifier<'a> {
    pub(crate) fn new(key: &'a Jwk) -> Self {
        Self { key }
    }
    fn public_jwk(&self) -> Jwk {
        self.key.clone()
    }
}

pub(crate) struct ParentContext {
    pub(crate) ps: String,
    aud: String,
    pub(crate) sub: String,
    jti: String,
    pub(crate) iat: i64,
    pub(crate) exp: i64,
    cnf: Jwk,
    mission: Option<String>,
    tenant: Option<String>,
    /// Issuer of the presented credential itself. A Person token's issuer is
    /// `ps`. An Auth token's issuer is its own `iss`, which may be an Access
    /// Server rather than `ps`.
    pub(crate) issuer: String,
    /// `dwk` of an Auth parent. A Person token leaves this empty.
    pub(crate) auth_dwk: Option<String>,
}

/// Auth role accepted for a presented parent credential.
pub(crate) enum PresentedAuthRole<'a> {
    /// Person Server grant: `aauth-person.json`.
    PersonServer,
    /// Access Server grant: `aauth-access.json` from this issuer.
    AccessServer(&'a str),
    /// R3 class grant. The signed `dwk` is `aauth-person.json` or
    /// `aauth-access.json`. Core still requires `iss == ps` for the former.
    R3Class,
}

pub(crate) fn verify_parent(
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
    role: PresentedAuthRole<'_>,
) -> Result<ParentContext, TokenError> {
    let parsed = Jws::parse(compact)?;
    match parsed.header().get("typ").and_then(|value| value.as_str()) {
        Some("aa-person+jwt") => {
            let token = PersonToken::parse(compact)?.verify(keys, now)?;
            let claims = token.claims();
            Ok(ParentContext {
                ps: claims.iss.clone(),
                aud: claims.aud.clone(),
                sub: claims.sub.clone(),
                jti: claims.jti.clone(),
                iat: claims.iat,
                exp: claims.exp,
                cnf: claims.cnf.jwk.clone(),
                mission: claims.mission_s256.clone(),
                tenant: claims.tenant.clone(),
                issuer: claims.iss.clone(),
                auth_dwk: None,
            })
        }
        Some("aa-auth+jwt") => {
            let token = AuthToken::parse(compact)?.verify(keys, now)?;
            let claims = token.claims();
            let valid = match role {
                PresentedAuthRole::PersonServer => claims.dwk == "aauth-person.json",
                PresentedAuthRole::AccessServer(issuer) => {
                    claims.dwk == "aauth-access.json" && claims.iss == issuer
                }
                PresentedAuthRole::R3Class => {
                    matches!(
                        claims.dwk.as_str(),
                        "aauth-person.json" | "aauth-access.json"
                    )
                }
            };
            if !valid {
                return Err(TokenError::InvalidJwt);
            }
            Ok(ParentContext {
                ps: claims.ps.clone(),
                aud: claims.aud.clone(),
                sub: claims.sub.clone(),
                jti: claims.jti.clone(),
                iat: claims.iat,
                exp: claims.exp,
                cnf: claims.cnf.jwk.clone(),
                mission: claims.mission_s256.clone(),
                tenant: claims.tenant.clone(),
                issuer: claims.iss.clone(),
                auth_dwk: Some(claims.dwk.clone()),
            })
        }
        _ => Err(TokenError::UnexpectedTokenType),
    }
}
pub(crate) fn challenge_context(
    claims: &ResourceClaims,
    intended_resource: &str,
    parent: &ParentContext,
    own_key: &Jwk,
    recipient: &str,
) -> Result<(), TokenError> {
    validate_server_identifier(intended_resource)?;
    let own_jkt = own_key.thumbprint()?;
    if claims.iss != intended_resource
        || parent.aud != intended_resource
        || claims.aud != recipient
        || claims.ps != parent.ps
        || claims.sub != parent.sub
        || claims.presented_jti != parent.jti
        || claims.tenant != parent.tenant
        || claims.mission_s256 != parent.mission
        || claims.agent_jkt != own_jkt
        || parent.cnf.thumbprint()? != own_jkt
    {
        return Err(TokenError::InvalidJwt);
    }
    Ok(())
}
impl CredentialVerifier<'_> {
    /// Authenticate a Resource challenge against the actual target, PS, presented
    /// Person/Auth credential and this retained proof key. The host extracts the
    /// compact resource-token parameter with Requirement::from_headers before calling.
    /// This implements immediate PS authorization, without AS federation or
    /// companion authorization. It performs no discovery fetch or HTTP request.
    ///
    /// # Errors
    /// Rejects signature/time/trust failures or any target, key or parent-lineage mismatch.
    pub(crate) fn verify_resource_challenge(
        &self,
        compact: &str,
        intended_resource: &str,
        person_server: &str,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedResourceToken, TokenError> {
        validate_server_identifier(person_server)?;
        let parent = verify_parent(
            presented_compact,
            keys,
            now,
            PresentedAuthRole::PersonServer,
        )?;
        let token = ResourceToken::parse(compact)?.verify(keys, now)?;
        challenge_context(
            token.claims(),
            intended_resource,
            &parent,
            &self.public_jwk(),
            &parent.ps,
        )?;
        if parent.ps != person_server {
            return Err(TokenError::InvalidJwt);
        }
        Ok(token)
    }

    /// Authenticate delivered PS authorization against the actual intended
    /// Resource, Resource challenge, presented credential and retained proof key.
    /// Checks account/tenant/mission continuity, scope narrowing and parent expiry.
    /// A Resource challenge's expiry does not cap the Auth token's expiry.
    /// Companion claims retain no authorization through this Core-only helper.
    ///
    /// # Errors
    /// Rejects signature/time/trust failures, foreign targets, widened grants,
    /// changed lineage or an Auth token outliving its actual presented credential.
    pub(crate) fn verify_auth_delivery(
        &self,
        compact: &str,
        intended_resource: &str,
        resource: &VerifiedResourceToken,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAuthToken, TokenError> {
        let parent = verify_parent(
            presented_compact,
            keys,
            now,
            PresentedAuthRole::PersonServer,
        )?;
        let requested = resource.claims();
        challenge_context(
            requested,
            intended_resource,
            &parent,
            &self.public_jwk(),
            &parent.ps,
        )?;
        let token = AuthToken::parse(compact)?.verify(keys, now)?;
        let claims = token.claims();
        if claims.dwk != "aauth-person.json"
            || claims.iss != requested.aud
            || claims.aud != intended_resource
            || claims.ps != requested.ps
            || claims.sub != parent.sub
            || claims.tenant != requested.tenant
            || claims.mission_s256 != requested.mission_s256
            || claims.account != requested.account
            || claims.cnf.jwk.thumbprint()? != self.public_jwk().thumbprint()?
            || claims.exp > parent.exp
            || !narrowed_scope(claims.scope.as_deref(), requested.scope.as_deref())
        {
            return Err(TokenError::InvalidJwt);
        }
        Ok(token)
    }
}
pub(crate) fn narrowed_scope(granted: Option<&str>, requested: Option<&str>) -> bool {
    match (granted, requested) {
        (Some(granted), Some(requested)) => granted
            .split(' ')
            .all(|scope| requested.split(' ').any(|wanted| scope == wanted)),
        (None, None) => true,
        _ => false,
    }
}

/// Expected identities and actual presented bytes for immediate AS federation.
/// Values come from the host's intended Resource/PS/AS, not unverified JWT fields.
pub struct FederatedContext<'a> {
    /// Published intended Resource identifier.
    pub resource: &'a str,
    /// Person Server representing this person.
    pub person_server: &'a str,
    /// Access Server chosen for this Resource.
    pub access_server: &'a str,
    /// Exact Person/Auth token presented to obtain the challenge.
    pub presented_token: &'a str,
}
impl CredentialVerifier<'_> {
    /// Verify a federated challenge against explicit intended identities and the
    /// actual presented credential. Supports AS Auth step-up as well as Person.
    /// No HTTP request, discovery fetch or retry is performed.
    ///
    /// # Errors
    /// Rejects JWT trust/time or any issuer, audience, key or lineage mismatch.
    pub(crate) fn verify_federated_resource_challenge(
        &self,
        compact: &str,
        context: &FederatedContext<'_>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedResourceToken, TokenError> {
        validate_server_identifier(context.person_server)?;
        validate_server_identifier(context.access_server)?;
        let parent = verify_parent(
            context.presented_token,
            keys,
            now,
            PresentedAuthRole::AccessServer(context.access_server),
        )?;
        let token = ResourceToken::parse(compact)?.verify(keys, now)?;
        challenge_context(
            token.claims(),
            context.resource,
            &parent,
            &self.public_jwk(),
            context.access_server,
        )?;
        if parent.ps != context.person_server {
            return Err(TokenError::InvalidJwt);
        }
        Ok(token)
    }
    /// Verify an AS grant before use, pinning issuer and aauth-access.json even
    /// when PS=AS, plus scope/account/tenant/key/context and actual parent expiry.
    /// A current missionless challenge does not cap the delivered Auth expiry.
    ///
    /// # Errors
    /// Rejects trust/time failures, changed identities, widened grants or expiry.
    pub(crate) fn verify_federated_auth_delivery(
        &self,
        compact: &str,
        resource: &VerifiedResourceToken,
        context: &FederatedContext<'_>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAuthToken, TokenError> {
        validate_server_identifier(context.person_server)?;
        validate_server_identifier(context.access_server)?;
        let parent = verify_parent(
            context.presented_token,
            keys,
            now,
            PresentedAuthRole::AccessServer(context.access_server),
        )?;
        let requested = resource.claims();
        challenge_context(
            requested,
            context.resource,
            &parent,
            &self.public_jwk(),
            context.access_server,
        )?;
        let token = AuthToken::parse(compact)?.verify(keys, now)?;
        let c = token.claims();
        if parent.ps != context.person_server
            || c.dwk != "aauth-access.json"
            || c.iss != context.access_server
            || c.aud != context.resource
            || c.ps != context.person_server
            || c.sub != parent.sub
            || c.tenant != requested.tenant
            || c.mission_s256 != requested.mission_s256
            || c.account != requested.account
            || c.cnf.jwk.thumbprint()? != self.public_jwk().thumbprint()?
            || c.exp > parent.exp
            || !narrowed_scope(c.scope.as_deref(), requested.scope.as_deref())
        {
            return Err(TokenError::InvalidJwt);
        }
        Ok(token)
    }
}

impl Agent {
    /// Authenticate a direct PS Resource challenge against the intended Resource,
    /// PS, exact presented Person/Auth credential and this Agent's proof key.
    /// Performs no transport, discovery fetch or companion authorization.
    ///
    /// # Errors
    /// Rejects trust/time failures or target, key and credential-lineage mismatch.
    pub fn verify_resource_challenge(
        &self,
        compact: &str,
        intended_resource: &str,
        person_server: &str,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedResourceToken, TokenError> {
        CredentialVerifier::new(&self.public_jwk()).verify_resource_challenge(
            compact,
            intended_resource,
            person_server,
            presented_compact,
            keys,
            now,
        )
    }
    /// Authenticate a direct PS grant against the intended Resource, challenge,
    /// presented credential and this Agent's proof key. Checks scope narrowing,
    /// account/tenant/mission continuity and presented credential expiry.
    /// Challenge expiry does not cap the delivered grant's expiry.
    ///
    /// # Errors
    /// Rejects trust/time failures, changed context, widened scope or expiry.
    pub fn verify_auth_delivery(
        &self,
        compact: &str,
        intended_resource: &str,
        resource: &VerifiedResourceToken,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAuthToken, TokenError> {
        CredentialVerifier::new(&self.public_jwk()).verify_auth_delivery(
            compact,
            intended_resource,
            resource,
            presented_compact,
            keys,
            now,
        )
    }
    /// Authenticate a federated challenge against explicit intended identities,
    /// actual presented Person/AS Auth credential and this Agent's proof key.
    /// Performs no transport, discovery fetch or retry.
    ///
    /// # Errors
    /// Rejects trust/time failures or issuer, audience, key and lineage mismatch.
    pub fn verify_federated_resource_challenge(
        &self,
        compact: &str,
        context: &FederatedContext<'_>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedResourceToken, TokenError> {
        CredentialVerifier::new(&self.public_jwk())
            .verify_federated_resource_challenge(compact, context, keys, now)
    }
    /// Authenticate an AS grant against explicit intended identities, challenge,
    /// actual presented credential and this Agent's proof key, including AS=PS.
    /// Checks scope/account/tenant/mission continuity and presented expiry;
    /// challenge expiry does not cap the delivered grant's expiry.
    ///
    /// # Errors
    /// Rejects trust/time failures, changed context, widened scope or expiry.
    pub fn verify_federated_auth_delivery(
        &self,
        compact: &str,
        resource: &VerifiedResourceToken,
        context: &FederatedContext<'_>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAuthToken, TokenError> {
        CredentialVerifier::new(&self.public_jwk())
            .verify_federated_auth_delivery(compact, resource, context, keys, now)
    }
}
