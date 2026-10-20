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
struct ParentContext {
    ps: String,
    aud: String,
    sub: String,
    jti: String,
    exp: i64,
    cnf: Jwk,
    mission: Option<String>,
    tenant: Option<String>,
}
fn verify_parent(
    compact: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
    access_server: Option<&str>,
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
                exp: claims.exp,
                cnf: claims.cnf.jwk.clone(),
                mission: claims.mission_s256.clone(),
                tenant: claims.tenant.clone(),
            })
        }
        Some("aa-auth+jwt") => {
            let token = AuthToken::parse(compact)?.verify(keys, now)?;
            let claims = token.claims();
            let valid = match access_server {
                Some(issuer) => claims.dwk == "aauth-access.json" && claims.iss == issuer,
                None => claims.dwk == "aauth-person.json",
            };
            if !valid {
                return Err(TokenError::InvalidJwt);
            }
            Ok(ParentContext {
                ps: claims.ps.clone(),
                aud: claims.aud.clone(),
                sub: claims.sub.clone(),
                jti: claims.jti.clone(),
                exp: claims.exp,
                cnf: claims.cnf.jwk.clone(),
                mission: claims.mission_s256.clone(),
                tenant: claims.tenant.clone(),
            })
        }
        _ => Err(TokenError::UnexpectedTokenType),
    }
}
fn challenge_context(
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
impl Agent {
    /// Authenticate a Resource challenge against the actual target, PS, presented
    /// Person/Auth credential and this retained proof key. The host extracts the
    /// compact resource-token parameter with Requirement::from_headers before calling.
    /// This implements immediate PS authorization, without AS federation or
    /// companion authorization. It performs no discovery fetch or HTTP request.
    ///
    /// # Errors
    /// Rejects signature/time/trust failures or any target, key or parent-lineage mismatch.
    pub fn verify_resource_challenge(
        &self,
        compact: &str,
        intended_resource: &str,
        person_server: &str,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedResourceToken, TokenError> {
        validate_server_identifier(person_server)?;
        let parent = verify_parent(presented_compact, keys, now, None)?;
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
    pub fn verify_auth_delivery(
        &self,
        compact: &str,
        intended_resource: &str,
        resource: &VerifiedResourceToken,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAuthToken, TokenError> {
        let parent = verify_parent(presented_compact, keys, now, None)?;
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
fn narrowed_scope(granted: Option<&str>, requested: Option<&str>) -> bool {
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
impl Agent {
    /// Verify a federated challenge against explicit intended identities and the
    /// actual presented credential. Supports AS Auth step-up as well as Person.
    /// No HTTP request, discovery fetch or retry is performed.
    ///
    /// # Errors
    /// Rejects JWT trust/time or any issuer, audience, key or lineage mismatch.
    pub fn verify_federated_resource_challenge(
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
            Some(context.access_server),
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
    pub fn verify_federated_auth_delivery(
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
            Some(context.access_server),
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
