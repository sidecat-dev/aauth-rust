//! Immediate Core-scope Access Server with host-supplied issuer trust and policy.
//!
//! This buffered role verifies a PS service proof plus Agent, Resource and actual
//! presented credentials before policy. It performs no discovery fetch or HTTP
//! transport. Hosts admit issuers before key resolution and bound request collection.
//! Full R3, missions, subagents, call chaining and deferred federation are outside
//! this profile and are refused rather than interpreted as scope authorization.
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
mod wire;
use aauth_rust_core::{
    AgentKeyResolver, AgentToken, AuthClaims, AuthToken, Confirmation, PersonToken, ResourceClaims,
    ResourceToken, TokenError, VerifiedAgentToken, VerifiedResourceToken, mint_auth_token,
    validate_server_identifier,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey, strict_json};
use aauth_rust_signature_key::{
    Error as ProofError, KeyMaterial, PreparedRequest, canonical_authority,
};
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
    /// Agent identity and posture authenticated by its admitted provider.
    pub agent: VerifiedAgentToken,
    /// Verified Resource challenge, matched to the actual presented credential.
    pub resource: VerifiedResourceToken,
    /// Nonempty distinct requested Core scope values.
    pub scopes: Vec<String>,
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
        })
    }
    /// Metadata served at /.well-known/aauth-access.json. No unsupported endpoints
    /// or companion capabilities are advertised.
    pub fn metadata(&self) -> Vec<u8> {
        json!({"issuer":self.config.issuer,"jwks_uri":format!("{}/.well-known/jwks.json",self.config.issuer),"auth_token_endpoint":format!("{}/token",self.config.issuer)}).to_string().into_bytes()
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
        match (request.method().as_str(), request.uri().path()) {
            ("GET", "/.well-known/aauth-access.json") => {
                return Ok(bytes_response(self.metadata()));
            }
            ("GET", "/.well-known/jwks.json") => return Ok(bytes_response(self.jwks())),
            ("POST", "/token") => {}
            _ => return Err(Failure::status(StatusCode::NOT_FOUND, "not_found")),
        }
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"])
            .map_err(|e| Failure::proof(e, request, now))?;
        let base = std::str::from_utf8(proof.signature_base())
            .map_err(|_| Failure::parameter("invalid_request"))?;
        if ["content-type", "content-digest"].iter().any(|name| {
            !base
                .lines()
                .any(|line| line.starts_with(&format!("\"{name}\":")))
        }) {
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
        if request
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split(';').next())
            .map(str::trim)
            .is_none_or(|h| !h.eq_ignore_ascii_case("application/json"))
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let body =
            strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))?;
        let object = body
            .as_object()
            .ok_or_else(|| Failure::parameter("invalid_request"))?;
        if object
            .keys()
            .any(|k| !["agent_token", "resource_token", "presented_token"].contains(&k.as_str()))
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let agent = AgentToken::parse(required(&body, "agent_token")?)
            .and_then(|t| t.verify(&self.resolver(), now))
            .map_err(|e| Failure::token(e, "agent", now))?;
        check_iat(agent.claims().iat, now)?;
        if agent.claims().ps.as_deref() != Some(id) || agent.claims().parent_agent.is_some() {
            return Err(Failure::parameter("invalid_agent_token"));
        }
        let resource = ResourceToken::parse(required(&body, "resource_token")?)
            .and_then(|t| t.verify(&self.resolver(), now))
            .map_err(|e| Failure::token(e, "resource", now))?;
        let r = resource.claims();
        check_iat(r.iat, now)?;
        if r.aud != self.config.issuer
            || r.ps != *id
            || r.exp - r.iat > self.config.max_resource_lifetime
            || r.agent_jkt
                != agent
                    .claims()
                    .cnf
                    .jwk
                    .thumbprint()
                    .map_err(|_| Failure::internal())?
            || r.mission_s256.is_some()
            || unsupported(&r.extra)
        {
            return Err(Failure::parameter("invalid_resource_token"));
        }
        let presented = presented(required(&body, "presented_token")?, &self.resolver(), now)?;
        presented.matches(r)?;
        let requested_scopes = scopes(r.scope.as_deref().unwrap_or(""))
            .ok_or_else(|| Failure::parameter("invalid_resource_token"))?;
        let context = AuthorizationRequest {
            person_server: id.clone(),
            agent: agent.clone(),
            resource: resource.clone(),
            scopes: requested_scopes,
        };
        let decision = (self.policy)(&context).map_err(Failure::policy)?;
        if !(1..=3600).contains(&decision.lifetime)
            || scopes(&decision.scopes.join(" ")).is_none()
            || decision.scopes.iter().any(|s| !context.scopes.contains(s))
        {
            return Err(Failure::internal());
        }
        let issued_at = (self.clock)();
        current(issued_at, &agent, r, &presented)?;
        let expires_at = issued_at
            .saturating_add(decision.lifetime)
            .min(agent.claims().exp)
            .min(presented.exp);
        let claims = AuthClaims {
            iss: self.config.issuer.clone(),
            dwk: "aauth-access.json".into(),
            aud: r.iss.clone(),
            ps: id.clone(),
            sub: r.sub.clone(),
            cnf: Confirmation {
                jwk: agent.claims().cnf.jwk.clone(),
            },
            jti: (self.ids)(),
            iat: issued_at,
            exp: expires_at,
            scope: Some(decision.scopes.join(" ")),
            account: r.account.clone(),
            tenant: r.tenant.clone(),
            mission_s256: None,
            nbf: None,
            extra: Default::default(),
        };
        let compact = mint_auth_token(&self.config.signing_key, &self.config.kid, &claims)
            .map_err(|_| Failure::internal())?;
        let release = (self.clock)();
        current(release, &agent, r, &presented)?;
        if release >= expires_at {
            return Err(Failure::internal());
        }
        Ok(token_response("auth_token", compact, expires_at - release))
    }
}
struct Presented {
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
fn presented(compact: &str, keys: &dyn AgentKeyResolver, now: i64) -> Result<Presented, Failure> {
    let result = (|| -> Result<Presented, TokenError> {
        let jws = Jws::parse(compact)?;
        match jws.header().get("typ").and_then(Value::as_str) {
            Some("aa-person+jwt") => {
                let t = PersonToken::parse(compact)?.verify(keys, now)?;
                let c = t.claims();
                if unsupported(&c.extra) {
                    return Err(TokenError::InvalidJwt);
                }
                Ok(Presented {
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
                if unsupported(&c.extra) {
                    return Err(TokenError::InvalidJwt);
                }
                Ok(Presented {
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
fn current(
    now: i64,
    a: &VerifiedAgentToken,
    r: &ResourceClaims,
    p: &Presented,
) -> Result<(), Failure> {
    if !(0..=(1_i64 << 33) - 1).contains(&now) {
        return Err(Failure::internal());
    }
    if a.claims().exp <= now {
        return Err(Failure::parameter("expired_agent_token"));
    }
    if r.exp <= now {
        return Err(Failure::parameter("expired_resource_token"));
    }
    if p.exp <= now {
        return Err(Failure::parameter("expired_presented_token"));
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
fn unsupported(extra: &std::collections::BTreeMap<String, Value>) -> bool {
    [
        "interaction",
        "r3_uri",
        "r3_s256",
        "r3_granted",
        "r3_per_call",
        "budget",
        "budget_consumed",
    ]
    .iter()
    .any(|k| extra.contains_key(*k))
}
