//! Immediate class R3 with a direct Person Server.
//!
//! `draft-hardt-aauth-r3`: Authorization Endpoint Extensions, Resource Token
//! Extensions and Auth Token Extensions. This module prepares the signed
//! `r3_operations` request and verifies what comes back before use. The host
//! supplies transport, trust snapshots and the clock. Per-call proposals,
//! budgets, missions and AS federation are not handled here; a delivered token
//! carrying `r3_per_call` is refused rather than partly used.
use crate::Agent;
use crate::credentials::{challenge_context, narrowed_scope, verify_parent};
use aauth_rust_core::{AgentKeyResolver, TokenError, validate_server_identifier};
use aauth_rust_r3::{
    OperationSet, R3TokenError, Registry, VerifiedR3AuthToken, VerifiedR3ResourceToken,
    verify_direct_auth_token, verify_resource_token,
};
use http::{Request, Response};

/// Boxed host transport failure.
pub type R3TransportError = Box<dyn std::error::Error + Send + Sync>;

/// An R3 request could not be prepared, sent, or verified.
#[derive(Debug, thiserror::Error)]
pub enum R3AgentError {
    /// The endpoint, scope or operations cannot form a request.
    #[error("r3 agent: invalid request input")]
    InvalidInput,
    /// The request could not be signed with the presented credential.
    #[error("r3 agent: signing failed: {0}")]
    Signing(aauth_rust_signature_key::Error),
    /// The host transport failed; no response was received.
    #[error("r3 agent: transport failed: {0}")]
    Transport(R3TransportError),
    /// The authorization endpoint answered with a refusal.
    #[error("r3 agent: authorization endpoint refused with HTTP {status}")]
    Refused {
        /// HTTP status of the refusal.
        status: u16,
        /// `error` member of the problem body, when present.
        error: Option<String>,
    },
    /// A JWT failed Core trust, signature or time verification.
    #[error("r3 agent: token verification failed: {0}")]
    Token(TokenError),
    /// The R3 claims are missing, malformed, or outside this immediate profile.
    #[error("r3 agent: R3 claims refused: {0}")]
    R3(R3TokenError),
    /// The verified token names another Resource, PS, holder, lineage, reference or grant.
    #[error("r3 agent: returned token does not match this request")]
    Context,
}
impl From<TokenError> for R3AgentError {
    fn from(error: TokenError) -> Self {
        Self::Token(error)
    }
}

fn scope_values(scope: &str) -> bool {
    !scope.is_empty()
        && scope.split(' ').all(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
        })
}

/// Core scope on an R3 grant: absent grants none, which is never broader than
/// the request; present must be a subset of a requested scope (Core `scope` is
/// optional and no broader than requested; R3 enforces it independently).
fn r3_granted_scope(granted: Option<&str>, requested: Option<&str>) -> bool {
    granted.is_none() || narrowed_scope(granted, requested)
}

impl Agent {
    /// Prepare `POST` to the Resource's advertised `authorization_endpoint`.
    ///
    /// The body is `{"r3_operations":…}` with the exact serialized operation
    /// set, plus `scope` only when the caller asks for Core scope too. The
    /// request is signed with `person_token` as the `jwt` credential and covers
    /// `content-type` and `content-digest`. No request is sent.
    ///
    /// # Errors
    /// [`R3AgentError::InvalidInput`] for a non-HTTPS endpoint or malformed
    /// scope, [`R3AgentError::Token`] for an unusable credential, and
    /// [`R3AgentError::Signing`] when signing fails.
    pub fn r3_authorization_request(
        &self,
        authorization_endpoint: &str,
        person_token: &str,
        operations: &OperationSet,
        scope: Option<&str>,
        now: i64,
    ) -> Result<Request<Vec<u8>>, R3AgentError> {
        let uri: http::Uri = authorization_endpoint
            .parse()
            .map_err(|_| R3AgentError::InvalidInput)?;
        if uri.scheme_str() != Some("https") || uri.query().is_some() {
            return Err(R3AgentError::InvalidInput);
        }
        if scope.is_some_and(|scope| !scope_values(scope)) {
            return Err(R3AgentError::InvalidInput);
        }
        let exact = serde_json::to_vec(operations).map_err(|_| R3AgentError::InvalidInput)?;
        let mut body = b"{\"r3_operations\":".to_vec();
        body.extend_from_slice(&exact);
        if let Some(scope) = scope {
            body.extend_from_slice(b",\"scope\":");
            body.extend_from_slice(
                &serde_json::to_vec(scope).map_err(|_| R3AgentError::InvalidInput)?,
            );
        }
        body.push(b'}');
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(body)
            .map_err(|_| R3AgentError::InvalidInput)?;
        self.with_token(person_token.to_owned())?
            .sign(&mut request, now)
            .map_err(R3AgentError::Signing)?;
        Ok(request)
    }

    /// Send the prepared request once through `transport` and return the
    /// compact Resource token. Verify it with [`Self::verify_r3_resource_token`]
    /// before forwarding it to the Person Server.
    ///
    /// # Errors
    /// As for [`Self::r3_authorization_request`], plus
    /// [`R3AgentError::Transport`] and [`R3AgentError::Refused`].
    pub fn r3_authorize<E>(
        &self,
        transport: impl FnOnce(Request<Vec<u8>>) -> Result<Response<Vec<u8>>, E>,
        authorization_endpoint: &str,
        person_token: &str,
        operations: &OperationSet,
        scope: Option<&str>,
        now: i64,
    ) -> Result<String, R3AgentError>
    where
        E: Into<R3TransportError>,
    {
        let request = self.r3_authorization_request(
            authorization_endpoint,
            person_token,
            operations,
            scope,
            now,
        )?;
        let response = transport(request).map_err(|error| R3AgentError::Transport(error.into()))?;
        let body: Option<serde_json::Value> = serde_json::from_slice(response.body()).ok();
        if response.status() != 200 {
            return Err(R3AgentError::Refused {
                status: response.status().as_u16(),
                error: body
                    .as_ref()
                    .and_then(|value| value.get("error"))
                    .and_then(|value| value.as_str())
                    .map(str::to_owned),
            });
        }
        body.as_ref()
            .and_then(|value| value.get("resource_token"))
            .and_then(|value| value.as_str())
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .ok_or(R3AgentError::Refused {
                status: 200,
                error: None,
            })
    }

    /// Verify an R3 Resource token from `/authorize` before using it.
    ///
    /// Core trust and both `r3_uri` and `r3_s256` must verify. The token must
    /// be issued by `intended_resource` to `person_server`, carry the presented
    /// Person token's subject, tenant, mission and `jti`, bind this Agent's key,
    /// be issued inside that Person token's validity, carry no `interaction`
    /// or `account`, and carry `scope` only within `requested_scope`. With no
    /// requested scope, any `scope` is refused. The document is not fetched:
    /// Agents are not entitled to read it.
    ///
    /// # Errors
    /// [`R3AgentError::Token`] or [`R3AgentError::R3`] for verification
    /// failures, [`R3AgentError::Context`] for any mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_r3_resource_token(
        &self,
        compact: &str,
        intended_resource: &str,
        person_server: &str,
        presented_compact: &str,
        requested_scope: Option<&str>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedR3ResourceToken, R3AgentError> {
        validate_server_identifier(person_server)?;
        let parent = verify_parent(presented_compact, keys, now, None)?;
        let token = verify_resource_token(compact, keys, now).map_err(R3AgentError::R3)?;
        let claims = token.claims();
        challenge_context(
            claims,
            intended_resource,
            &parent,
            &self.public_jwk(),
            &parent.ps,
        )
        .map_err(|_| R3AgentError::Context)?;
        if parent.ps != person_server
            || claims.iat < parent.iat
            || claims.iat >= parent.exp
            || claims.account.is_some()
            || claims.extra.contains_key("interaction")
            || !narrowed_scope(claims.scope.as_deref(), requested_scope)
        {
            return Err(R3AgentError::Context);
        }
        Ok(token)
    }

    /// Verify a direct PS class grant against the verified R3 Resource token.
    ///
    /// Core checks match [`Self::verify_auth_delivery`]: PS role and issuer,
    /// audience, subject, tenant, mission, account, holder key, and expiry no
    /// later than the presented credential. A granted `scope` must be within the
    /// requested scope; an absent `scope` grants no Core scope and is accepted
    /// even when scope was requested. The R3
    /// reference must equal the Resource token's, and the token must be
    /// direct-only: `r3_per_call` is refused because per-call proposals are not
    /// implemented. The Agent cannot prove `r3_granted` against the document it
    /// may not read; the Person Server and Resource each do that.
    ///
    /// # Errors
    /// [`R3AgentError::R3`] for an invalid or per-call token,
    /// [`R3AgentError::Context`] for any mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_r3_auth_delivery(
        &self,
        compact: &str,
        intended_resource: &str,
        resource: &VerifiedR3ResourceToken,
        presented_compact: &str,
        registry: &Registry,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedR3AuthToken, R3AgentError> {
        let parent = verify_parent(presented_compact, keys, now, None)?;
        let requested = resource.claims();
        challenge_context(
            requested,
            intended_resource,
            &parent,
            &self.public_jwk(),
            &parent.ps,
        )
        .map_err(|_| R3AgentError::Context)?;
        let token =
            verify_direct_auth_token(registry, compact, keys, now).map_err(R3AgentError::R3)?;
        let claims = token.claims();
        let holder = claims
            .cnf
            .jwk
            .thumbprint()
            .map_err(|_| R3AgentError::Context)?;
        let own = self
            .public_jwk()
            .thumbprint()
            .map_err(|_| R3AgentError::Context)?;
        if claims.dwk != "aauth-person.json"
            || claims.iss != requested.aud
            || claims.aud != intended_resource
            || claims.ps != requested.ps
            || claims.sub != parent.sub
            || claims.tenant != requested.tenant
            || claims.mission_s256 != requested.mission_s256
            || claims.account != requested.account
            || holder != own
            || claims.exp > parent.exp
            || !r3_granted_scope(claims.scope.as_deref(), requested.scope.as_deref())
            || token.reference() != resource.reference()
        {
            return Err(R3AgentError::Context);
        }
        Ok(token)
    }
}
