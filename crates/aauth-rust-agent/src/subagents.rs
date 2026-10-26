//! Parent-mediated one-level Core requests and public-key delivery verification.
use crate::{Agent, FederatedContext, ResourceTokenAttempts, credentials::CredentialVerifier};
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthToken, PersonToken, ResourceToken, TokenError,
    VerifiedAgentToken, VerifiedAuthToken, VerifiedPersonToken, VerifiedResourceToken,
    validate_server_identifier, verify_subagent,
};
use aauth_rust_jose::Jws;
use http::Request;
use serde_json::{Value, json};

/// Verified parent/child identities for missionless, one-level Core authorization.
/// Retains exact Agent tokens and public keys, with no child signing key.
/// The parent host supplies trusted key snapshots and admitted transport endpoints;
/// this value performs no network request, retry or durable continuation recovery.
#[derive(Debug)]
pub struct Subagent {
    parent: VerifiedAgentToken,
    child: VerifiedAgentToken,
}
impl Subagent {
    /// Authenticate both exact Agent tokens and the one-level relationship.
    /// Each later verification/request rechecks both against its current keys/clock.
    ///
    /// # Errors
    /// Rejects invalid signatures, trust, time, parent, provider, naming or key reuse.
    pub fn verify(
        parent_compact: &str,
        child_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<Self, TokenError> {
        let parent = AgentToken::parse(parent_compact)?.verify(keys, now)?;
        let child = verify_subagent(child_compact, &parent, keys, now)?;
        Ok(Self { parent, child })
    }
    /// Authenticated parent identity; its exact token supplies request proof identity.
    pub fn parent(&self) -> &VerifiedAgentToken {
        &self.parent
    }
    /// Authenticated child identity and exact token for the `subagent_token` field.
    pub fn token(&self) -> &VerifiedAgentToken {
        &self.child
    }
    fn current(&self, keys: &dyn AgentKeyResolver, now: i64) -> Result<(), TokenError> {
        verify_subagent(self.child.compact(), &self.parent, keys, now)?;
        Ok(())
    }
    fn person_server(&self, expected: &str) -> Result<(), TokenError> {
        validate_server_identifier(expected)?;
        for token in [&self.parent, &self.child] {
            if token
                .claims()
                .ps
                .as_deref()
                .is_some_and(|ps| ps != expected)
            {
                return Err(TokenError::InvalidJwt);
            }
        }
        Ok(())
    }
    fn credential_lifetime(&self, exp: i64, mission: Option<&str>) -> Result<(), TokenError> {
        if exp > self.parent.claims().exp || exp > self.child.claims().exp || mission.is_some() {
            return Err(TokenError::InvalidJwt);
        }
        Ok(())
    }
    fn presented(
        &self,
        compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<(), TokenError> {
        match Jws::parse(compact)?
            .header()
            .get("typ")
            .and_then(Value::as_str)
        {
            Some("aa-person+jwt") => {
                let token = PersonToken::parse(compact)?.verify(keys, now)?;
                self.credential_lifetime(token.claims().exp, token.claims().mission_s256.as_deref())
            }
            Some("aa-auth+jwt") => {
                let token = AuthToken::parse(compact)?.verify(keys, now)?;
                self.credential_lifetime(token.claims().exp, token.claims().mission_s256.as_deref())
            }
            _ => Err(TokenError::UnexpectedTokenType),
        }
    }
    fn verifier(&self) -> CredentialVerifier<'_> {
        CredentialVerifier::new(&self.child.claims().cnf.jwk)
    }
    /// Authenticate a delivered child-bound Person token against explicit intended
    /// Resource and PS identities. Its expiry cannot exceed either Agent token.
    /// This missionless helper does not make consent or admission decisions.
    ///
    /// # Errors
    /// Rejects trust/time failures, wrong issuer/audience/key, missions or expiry.
    pub fn verify_person_delivery(
        &self,
        compact: &str,
        intended_resource: &str,
        person_server: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedPersonToken, TokenError> {
        self.current(keys, now)?;
        validate_server_identifier(intended_resource)?;
        self.person_server(person_server)?;
        let token = PersonToken::parse(compact)?.verify(keys, now)?;
        let c = token.claims();
        if c.iss != person_server
            || c.aud != intended_resource
            || c.cnf.jwk.thumbprint()? != self.child.claims().cnf.jwk.thumbprint()?
        {
            return Err(TokenError::InvalidJwt);
        }
        self.credential_lifetime(c.exp, c.mission_s256.as_deref())?;
        Ok(token)
    }
    /// Authenticate a direct PS challenge for the child's public key and actual
    /// presented credential, without retaining the child's private key.
    ///
    /// # Errors
    /// Rejects current identity, trust/time, mission, key or context mismatch.
    pub fn verify_resource_challenge(
        &self,
        compact: &str,
        intended_resource: &str,
        person_server: &str,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedResourceToken, TokenError> {
        self.current(keys, now)?;
        self.person_server(person_server)?;
        self.presented(presented_compact, keys, now)?;
        self.verifier().verify_resource_challenge(
            compact,
            intended_resource,
            person_server,
            presented_compact,
            keys,
            now,
        )
    }
    /// Authenticate a direct PS grant for the child, preserving scope narrowing,
    /// lineage, account and tenant. Expiry is capped by the presented credential
    /// and both Agent tokens; a challenge's earlier expiry does not shorten it.
    ///
    /// # Errors
    /// Rejects current identity, trust/time, mission, key, context or expiry mismatch.
    pub fn verify_auth_delivery(
        &self,
        compact: &str,
        intended_resource: &str,
        resource: &VerifiedResourceToken,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAuthToken, TokenError> {
        self.current(keys, now)?;
        self.person_server(&resource.claims().ps)?;
        self.presented(presented_compact, keys, now)?;
        let token = self.verifier().verify_auth_delivery(
            compact,
            intended_resource,
            resource,
            presented_compact,
            keys,
            now,
        )?;
        self.credential_lifetime(token.claims().exp, token.claims().mission_s256.as_deref())?;
        Ok(token)
    }
    /// Authenticate a federated challenge against explicit intended Resource,
    /// PS and AS identities and the child's presented Person/AS Auth credential.
    ///
    /// # Errors
    /// Rejects current identity, trust/time, mission, key or context mismatch.
    pub fn verify_federated_resource_challenge(
        &self,
        compact: &str,
        context: &FederatedContext<'_>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedResourceToken, TokenError> {
        self.current(keys, now)?;
        self.person_server(context.person_server)?;
        self.presented(context.presented_token, keys, now)?;
        self.verifier()
            .verify_federated_resource_challenge(compact, context, keys, now)
    }
    /// Authenticate a child-bound AS grant with scope, account, tenant and exact
    /// lineage checks. Supports AS Auth step-up. Expiry cannot exceed the actual
    /// presented credential or either Agent token. No child proof key is required.
    ///
    /// # Errors
    /// Rejects current identity, trust/time, mission, key, context or expiry mismatch.
    pub fn verify_federated_auth_delivery(
        &self,
        compact: &str,
        resource: &VerifiedResourceToken,
        context: &FederatedContext<'_>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAuthToken, TokenError> {
        self.current(keys, now)?;
        self.person_server(context.person_server)?;
        self.presented(context.presented_token, keys, now)?;
        let token = self
            .verifier()
            .verify_federated_auth_delivery(compact, resource, context, keys, now)?;
        self.credential_lifetime(token.claims().exp, token.claims().mission_s256.as_deref())?;
        Ok(token)
    }
    /// Build and parent-sign a missionless Person request containing the exact
    /// child Agent token. The host must admit `endpoint` from trusted PS metadata
    /// before calling; endpoint syntax checks do not establish endpoint authority.
    /// Send the returned bytes unchanged. No transport or retry is performed.
    ///
    /// # Errors
    /// Rejects stale identities, a different parent, invalid Resource/endpoint,
    /// oversized serialization or failed signing.
    pub fn person_request(
        &self,
        parent: &Agent,
        endpoint: &str,
        resource: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<Request<Vec<u8>>, TokenError> {
        self.current(keys, now)?;
        validate_server_identifier(resource)?;
        self.request(
            parent,
            endpoint,
            json!({"resource":resource,"subagent_token":self.child.compact()}),
            now,
        )
    }
    /// Build and parent-sign an Auth request with exact child, Resource and
    /// presented token bytes, forwarding a Resource `login_hint` unchanged.
    /// `resource` must come from challenge verification against the host's
    /// intended identities. The host must admit `endpoint` from trusted PS
    /// metadata, then send these bytes unchanged. No transport or retry occurs.
    /// `attempts` is the set of resource tokens already refused as
    /// `revoked_resource_token`. The host records that error before calling again.
    ///
    /// # Errors
    /// Rejects a remembered revoked resource token, stale identities/challenge,
    /// another parent, an invalid endpoint, mission/context/key mismatch,
    /// oversized serialization or failed signing.
    #[allow(clippy::too_many_arguments)]
    pub fn auth_request(
        &self,
        parent: &Agent,
        endpoint: &str,
        resource: &VerifiedResourceToken,
        presented_compact: &str,
        keys: &dyn AgentKeyResolver,
        now: i64,
        attempts: &ResourceTokenAttempts,
    ) -> Result<Request<Vec<u8>>, TokenError> {
        if !attempts.may_submit(resource.compact()) {
            return Err(TokenError::InvalidJwt);
        }
        self.current(keys, now)?;
        let resource = ResourceToken::parse(resource.compact())?.verify(keys, now)?;
        self.person_server(&resource.claims().ps)?;
        self.presented(presented_compact, keys, now)?;
        let c = resource.claims();
        let context = FederatedContext {
            resource: &c.iss,
            person_server: &c.ps,
            access_server: &c.aud,
            presented_token: presented_compact,
        };
        self.verifier()
            .verify_resource_challenge(
                resource.compact(),
                &c.iss,
                &c.ps,
                presented_compact,
                keys,
                now,
            )
            .or_else(|_| {
                self.verifier().verify_federated_resource_challenge(
                    resource.compact(),
                    &context,
                    keys,
                    now,
                )
            })?;
        let mut body = json!({"resource_token":resource.compact(),"presented_token":presented_compact,"subagent_token":self.child.compact()});
        if let Some(hint) = &c.login_hint {
            body["login_hint"] = json!(hint);
        }
        self.request(parent, endpoint, body, now)
    }
    fn request(
        &self,
        parent: &Agent,
        endpoint: &str,
        body: Value,
        now: i64,
    ) -> Result<Request<Vec<u8>>, TokenError> {
        if parent.token() != self.parent.compact()
            || parent.public_jwk().thumbprint()? != self.parent.claims().cnf.jwk.thumbprint()?
        {
            return Err(TokenError::InvalidJwt);
        }
        let uri: http::Uri = endpoint.parse().map_err(|_| TokenError::InvalidJwt)?;
        let authority = uri.authority().ok_or(TokenError::InvalidJwt)?;
        if uri.scheme_str() != Some("https")
            || authority.host().is_empty()
            || authority.as_str().contains('@')
            || uri.query().is_some()
            || endpoint.contains('#')
        {
            return Err(TokenError::InvalidJwt);
        }
        let mut request = Request::post(uri)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).map_err(|_| TokenError::InvalidJwt)?)
            .map_err(|_| TokenError::InvalidJwt)?;
        parent
            .sign(&mut request, now)
            .map_err(|_| TokenError::InvalidJwt)?;
        Ok(request)
    }
}
