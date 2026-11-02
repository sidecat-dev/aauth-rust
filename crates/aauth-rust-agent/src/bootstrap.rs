//! Bootstrap at the agent (`draft-hardt-aauth-bootstrap`): enrollment of an
//! install's durable key, refresh of its Agent token, and a parent's request
//! for a sub-agent token. Requests are built and signed here; the host sends
//! them and hands the answers back.
use crate::Agent;
use aauth_rust_core::events::generate_identifier;
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, REFRESH_MARGIN, TokenError, validate_server_identifier,
};
use aauth_rust_jose::{JWS_ALGORITHMS, Jwk, Jws, SigningKey};
use aauth_rust_signature_key::{Error, KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::Arc;

/// Seconds from a naming JWT's `iat` to its `exp`. The JWT names one
/// refresh, so it needs to outlive only that request.
pub const NAMING_JWT_LIFETIME: i64 = 120;

/// A bootstrap step failed at the agent.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// The request could not be signed.
    #[error(transparent)]
    Signing(#[from] Error),
    /// A key, identifier or token failed a profile check, or the issued token
    /// did not verify under the Agent Provider's keys.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The Agent Provider refused. `error` is its Problem Details `error`.
    #[error("the Agent Provider refused the request with status {status}")]
    Refused {
        /// HTTP status.
        status: u16,
        /// The `error` member of the answer, when it had one.
        error: Option<String>,
    },
    /// A `200` answer that is not a JSON object with a string `agent_token`.
    #[error("the Agent Provider's answer has no agent_token")]
    InvalidResponse,
    /// The issued token names another provider or agent identifier, names a
    /// parent, or binds a key other than the one this refresh named.
    #[error(
        "the issued Agent token does not match the refresh: check its iss, sub, parent_agent and cnf.jwk"
    )]
    UnexpectedToken,
}

/// The `agent_token` of an Agent Provider's `200` answer, as a refresh or a
/// sub-agent request receives it. The token is not verified here: a refresh
/// is completed with [`BootstrapClient::complete_refresh`], and a sub-agent
/// token is checked with [`crate::Subagent::verify`].
///
/// # Errors
/// [`BootstrapError::Refused`] for any other status, and
/// [`BootstrapError::InvalidResponse`] for a body without `agent_token`.
pub fn issued_agent_token(response: &Response<Vec<u8>>) -> Result<String, BootstrapError> {
    let body: Option<Value> = serde_json::from_slice(response.body()).ok();
    if response.status() != 200 {
        return Err(BootstrapError::Refused {
            status: response.status().as_u16(),
            error: body
                .as_ref()
                .and_then(|body| body.get("error"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    body.as_ref()
        .and_then(|body| body.get("agent_token"))
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or(BootstrapError::InvalidResponse)
}

/// One install's enrollment and refresh client (Bootstrap, Per-Platform Key
/// Handling and Refresh Patterns).
///
/// It holds the install's durable key, which signs only enrollment and the
/// naming JWT of each refresh, and is never used for requests to Person
/// Servers, Access Servers or Resources. Each two-key refresh binds a fresh
/// ephemeral key, which the returned [`Agent`] signs with until the next
/// refresh. Hold a hardware-backed durable key with
/// [`SigningKey::external`].
pub struct BootstrapClient {
    durable: Arc<SigningKey>,
    provider: String,
    agent: Option<String>,
    expires_at: Option<i64>,
}

/// A signed refresh request and the key its token will bind. Send
/// [`Self::request`] and pass the answer to
/// [`BootstrapClient::complete_refresh`].
pub struct PendingRefresh {
    request: Request<Vec<u8>>,
    key: Arc<SigningKey>,
}

impl PendingRefresh {
    /// The signed request, to send unchanged.
    pub fn request(&self) -> &Request<Vec<u8>> {
        &self.request
    }
}

impl BootstrapClient {
    /// A client for the Agent Provider `agent_provider`, holding `durable`.
    ///
    /// # Errors
    /// `InvalidServerIdentifier` for a provider that is not a lowercase HTTPS
    /// origin, and `UnsupportedAlgorithm` for a durable key that is not
    /// Ed25519 or ES256: it signs naming JWTs, which are compact JWS.
    pub fn new(durable: SigningKey, agent_provider: &str) -> Result<Self, TokenError> {
        validate_server_identifier(agent_provider)?;
        if !JWS_ALGORITHMS.contains(&durable.algorithm()) {
            return Err(TokenError::UnsupportedAlgorithm);
        }
        Ok(Self {
            durable: Arc::new(durable),
            provider: agent_provider.to_owned(),
            agent: None,
            expires_at: None,
        })
    }

    /// The durable key's public JWK, the install's enrollment anchor.
    pub fn durable_jwk(&self) -> Jwk {
        self.durable.public_jwk()
    }

    /// The agent identifier of the last completed refresh. Every later
    /// refresh must keep it.
    pub fn agent(&self) -> Option<&str> {
        self.agent.as_deref()
    }

    /// Whether to refresh at `now`: no token yet, or fewer than
    /// [`REFRESH_MARGIN`] seconds before its `exp` (Protocol, Expiry and the
    /// Refresh Margin). Person and Auth tokens obtained with the old token
    /// are replaced after a refresh too.
    pub fn needs_refresh(&self, now: i64) -> bool {
        self.expires_at
            .is_none_or(|exp| exp.saturating_sub(now) < REFRESH_MARGIN)
    }

    /// A POST of `{"evidence"}` to `endpoint`, signed under `hwk` by the
    /// durable key and covering the body (Bootstrap, Web App Enrollment step
    /// 3). `evidence` is what the provider requires, such as an attestation;
    /// pass `{}` when it requires nothing.
    ///
    /// # Errors
    /// Signing errors: a non-HTTPS endpoint, an invalid clock, or a failing
    /// external signer.
    pub fn enrollment_request(
        &self,
        endpoint: &str,
        evidence: &Value,
        now: i64,
    ) -> Result<Request<Vec<u8>>, BootstrapError> {
        let mut request = json_post(endpoint, &json!({ "evidence": evidence }))?;
        sign_request(
            &mut request,
            &self.durable,
            KeyMaterial::Hwk(self.durable.public_jwk()),
            now,
        )?;
        Ok(request)
    }

    /// A two-key refresh with a freshly generated Ed25519 ephemeral key
    /// (Bootstrap, Two-Key Refresh steps 1 to 3). See
    /// [`Self::refresh_request_with`].
    ///
    /// # Errors
    /// As for [`Self::refresh_request_with`].
    pub fn refresh_request(
        &self,
        endpoint: &str,
        ps: Option<&str>,
        evidence: &Value,
        now: i64,
    ) -> Result<PendingRefresh, BootstrapError> {
        self.refresh_request_with(SigningKey::generate(), endpoint, ps, evidence, now)
    }

    /// A two-key refresh binding `ephemeral`, which must be new for this
    /// refresh. The durable key signs a `jkt-s256+jwt` naming JWT whose `iss`
    /// is its JWK Thumbprint URI, with `cnf.jwk` the ephemeral key and a
    /// fresh `jti`, valid for [`NAMING_JWT_LIFETIME`] seconds. The ephemeral
    /// key signs the POST of `{"ps"?, "evidence"}` under `jkt-jwt`, covering
    /// the body. `ps` names the agent's Person Server.
    ///
    /// # Errors
    /// `Token(InvalidKey)` when `ephemeral` is the durable key or not
    /// Ed25519 or ES256, `Token(InvalidServerIdentifier)` for an invalid `ps`,
    /// and signing errors.
    pub fn refresh_request_with(
        &self,
        ephemeral: SigningKey,
        endpoint: &str,
        ps: Option<&str>,
        evidence: &Value,
        now: i64,
    ) -> Result<PendingRefresh, BootstrapError> {
        let durable = self.durable.public_jwk();
        let delegated = ephemeral.public_jwk();
        if !JWS_ALGORITHMS.contains(&ephemeral.algorithm())
            || delegated.thumbprint().map_err(TokenError::from)?
                == durable.thumbprint().map_err(TokenError::from)?
        {
            return Err(TokenError::InvalidKey.into());
        }
        let naming = self.naming_jwt(&durable, &delegated, now)?;
        let mut request = json_post(endpoint, &refresh_body(ps, evidence)?)?;
        sign_request(
            &mut request,
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: naming,
                cache: false,
            },
            now,
        )?;
        Ok(PendingRefresh {
            request,
            key: Arc::new(ephemeral),
        })
    }

    /// A single-key refresh: the same body signed under `hwk` by the durable
    /// key, whose token binds the durable key itself (Bootstrap, Single-Key
    /// Refresh). Use it only with a provider that chose that pattern.
    ///
    /// # Errors
    /// `Token(InvalidServerIdentifier)` for an invalid `ps`, and signing
    /// errors.
    pub fn single_key_refresh_request(
        &self,
        endpoint: &str,
        ps: Option<&str>,
        evidence: &Value,
        now: i64,
    ) -> Result<PendingRefresh, BootstrapError> {
        let mut request = json_post(endpoint, &refresh_body(ps, evidence)?)?;
        sign_request(
            &mut request,
            &self.durable,
            KeyMaterial::Hwk(self.durable.public_jwk()),
            now,
        )?;
        Ok(PendingRefresh {
            request,
            key: self.durable.clone(),
        })
    }

    /// Check the provider's answer to `pending` and return the [`Agent`]
    /// that signs with the new token and key (Bootstrap, Two-Key Refresh
    /// step 5). The token must verify under `keys`, the Agent Provider's
    /// published keys, at `now`; name this provider; be top-level; bind the
    /// key the refresh named; and keep the agent identifier of any earlier
    /// refresh (Bootstrap, Per-Install Identity).
    ///
    /// # Errors
    /// [`BootstrapError::Refused`], [`BootstrapError::InvalidResponse`], the
    /// token's verification errors, or [`BootstrapError::UnexpectedToken`].
    pub fn complete_refresh(
        &mut self,
        pending: PendingRefresh,
        response: &Response<Vec<u8>>,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<Agent, BootstrapError> {
        let compact = issued_agent_token(response)?;
        let verified = AgentToken::parse(&compact)?.verify(keys, now)?;
        let claims = verified.claims();
        if claims.iss != self.provider
            || claims.parent_agent.is_some()
            || claims.cnf.jwk.thumbprint().map_err(TokenError::from)?
                != pending
                    .key
                    .public_jwk()
                    .thumbprint()
                    .map_err(TokenError::from)?
            || self
                .agent
                .as_deref()
                .is_some_and(|agent| agent != claims.sub)
        {
            return Err(BootstrapError::UnexpectedToken);
        }
        self.agent = Some(claims.sub.clone());
        self.expires_at = Some(claims.exp);
        Ok(Agent::from_shared_key(pending.key, compact)?)
    }

    fn naming_jwt(&self, durable: &Jwk, delegated: &Jwk, now: i64) -> Result<String, TokenError> {
        let header = json!({
            "typ": "jkt-s256+jwt",
            "alg": self.durable.algorithm(),
            "jwk": durable,
        });
        let claims = json!({
            "iss": format!("urn:jkt:sha-256:{}", durable.thumbprint()?),
            "iat": now,
            "exp": now.saturating_add(NAMING_JWT_LIFETIME),
            "jti": generate_identifier(),
            "cnf": { "jwk": delegated },
        });
        let payload = serde_json::to_vec(&claims).map_err(|_| TokenError::InvalidJwt)?;
        Ok(Jws::sign(&header, &payload, &self.durable)?)
    }
}

impl Agent {
    /// A parent's request for a sub-agent token at its Agent Provider
    /// (Bootstrap, Sub-Agents Under a Hosted AP step 2): a POST of
    /// `{"jwk", "discriminator"?}` signed with this Agent's token and key,
    /// covering the body. `key` is the sub-agent's public key; its private
    /// key stays with the sub-agent. The durable key is not involved. Check
    /// the answer with [`issued_agent_token`] and [`crate::Subagent::verify`].
    ///
    /// # Errors
    /// Signing errors, and `InvalidKey` for a `key` that does not serialize.
    pub fn subagent_request(
        &self,
        endpoint: &str,
        key: &Jwk,
        discriminator: Option<&str>,
        now: i64,
    ) -> Result<Request<Vec<u8>>, Error> {
        let mut body = json!({ "jwk": key });
        if let Some(discriminator) = discriminator {
            body["discriminator"] = json!(discriminator);
        }
        let mut request = json_post(endpoint, &body)?;
        self.sign(&mut request, now)?;
        Ok(request)
    }
}

fn refresh_body(ps: Option<&str>, evidence: &Value) -> Result<Value, TokenError> {
    let mut body = json!({ "evidence": evidence });
    if let Some(ps) = ps {
        validate_server_identifier(ps)?;
        body["ps"] = json!(ps);
    }
    Ok(body)
}

fn json_post(endpoint: &str, body: &Value) -> Result<Request<Vec<u8>>, Error> {
    let bytes = serde_json::to_vec(body).map_err(|_| Error::InvalidKey)?;
    Request::builder()
        .method("POST")
        .uri(endpoint)
        .header("content-type", "application/json")
        .body(bytes)
        .map_err(|_| Error::InvalidUri)
}
