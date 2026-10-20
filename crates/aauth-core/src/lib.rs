//! AAuth Agent-token wire semantics. No enrollment, HTTP or admission policy.
mod discovery;
mod identifiers;
pub use discovery::{AgentKeyResolver, AgentProviderKeys, metadata_jwks_uri};
pub use identifiers::{validate_agent_identifier, validate_server_identifier};

use aauth_jose::{Jwk, Jws, strict_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("invalid_jwt")]
    InvalidJwt,
    #[error("expired_jwt")]
    ExpiredJwt,
    #[error("unknown_key")]
    UnknownKey,
    #[error("issuer_missing")]
    IssuerMissing,
    #[error("issuer_mismatch")]
    IssuerMismatch,
    #[error("unsupported_algorithm")]
    UnsupportedAlgorithm,
}
impl From<aauth_jose::Error> for TokenError {
    fn from(e: aauth_jose::Error) -> Self {
        match e {
            aauth_jose::Error::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            _ => Self::InvalidJwt,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Confirmation {
    pub jwk: Jwk,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentClaims {
    pub iss: String,
    pub dwk: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub cnf: Confirmation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl AgentClaims {
    pub fn validate(&self) -> Result<(), TokenError> {
        validate_server_identifier(&self.iss)?;
        validate_agent_identifier(&self.sub)?;
        if self.dwk != "aauth-agent.json" || self.jti.is_empty() || self.iat < 0 || self.exp < 0 {
            return Err(TokenError::InvalidJwt);
        }
        if self.sub.rsplit_once('@').map(|(_, d)| d) != self.iss.strip_prefix("https://") {
            return Err(TokenError::InvalidJwt);
        }
        if let Some(ps) = &self.ps {
            validate_server_identifier(ps)?
        }
        if let Some(parent) = &self.parent_agent {
            validate_agent_identifier(parent)?
        }
        for name in [
            "iss",
            "dwk",
            "sub",
            "jti",
            "iat",
            "exp",
            "cnf",
            "ps",
            "parent_agent",
            "nbf",
        ] {
            if self.extra.contains_key(name) {
                return Err(TokenError::InvalidJwt);
            }
        }
        self.cnf.jwk.validate()?;
        Ok(())
    }
}

/// Unverified token. Parsing never confers authority.
pub struct AgentToken {
    jws: Jws,
    claims: AgentClaims,
    kid: String,
}
impl AgentToken {
    pub fn parse(compact: &str) -> Result<Self, TokenError> {
        let jws = Jws::parse(compact)?;
        if jws.header().get("typ").and_then(Value::as_str) != Some("aa-agent+jwt") {
            return Err(TokenError::InvalidJwt);
        }
        let kid = jws
            .header()
            .get("kid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(TokenError::UnknownKey)?
            .to_owned();
        let claims: AgentClaims =
            serde_json::from_value(strict_json(jws.payload()).map_err(|_| TokenError::InvalidJwt)?)
                .map_err(|_| TokenError::InvalidJwt)?;
        claims.validate()?;
        Ok(Self { jws, claims, kid })
    }
    /// Inspect an unverified claim only for discovery/routing, never permission.
    pub fn unverified_claims(&self) -> &AgentClaims {
        &self.claims
    }
    pub fn verify(
        &self,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAgentToken, TokenError> {
        if now < 0 {
            return Err(TokenError::InvalidJwt);
        }
        if self.claims.exp <= now {
            return Err(TokenError::ExpiredJwt);
        }
        if self.claims.nbf.is_some_and(|nbf| nbf > now) {
            return Err(TokenError::InvalidJwt);
        }
        let key = keys.key(&self.claims.iss, &self.claims.dwk, &self.kid)?;
        self.jws.verify(&key)?;
        Ok(VerifiedAgentToken {
            claims: self.claims.clone(),
            compact: self.jws.compact().into(),
        })
    }
}

/// Only Core's verified-token path constructs this value.
pub struct VerifiedAgentToken {
    claims: AgentClaims,
    compact: String,
}
impl VerifiedAgentToken {
    pub fn claims(&self) -> &AgentClaims {
        &self.claims
    }
    pub fn compact(&self) -> &str {
        &self.compact
    }
}
