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
    #[error("invalid Agent JWT: check compact encoding, required claim types and issuer signature")]
    InvalidJwt,
    #[error(
        "Agent token expired: obtain a fresh token; exp and the verifier clock use Unix seconds with no expiry leeway"
    )]
    ExpiredJwt,
    #[error(
        "no trusted issuer key matches kid: check the AP JWKS and refresh the host's retained key snapshot"
    )]
    UnknownKey,
    #[error(
        "AP metadata is missing its issuer string: publish the exact HTTPS Agent Provider identifier"
    )]
    IssuerMissing,
    #[error(
        "AP metadata issuer differs from the configured issuer: use exact string equality, including case and trailing slash"
    )]
    IssuerMismatch,
    #[error(
        "unsupported or missing JWK/JWS alg: this implementation requires the fully specified Ed25519 algorithm"
    )]
    UnsupportedAlgorithm,
    #[error(
        "issuer must be a lowercase https:// DNS name with no port, path, trailing slash, query, fragment, userinfo or IP literal"
    )]
    InvalidServerIdentifier,
    #[error(
        "sub or parent_agent must be an aauth:local@domain identifier; local uses ASCII letters, digits, -_+. and domain is lowercase DNS"
    )]
    InvalidAgentIdentifier,
    #[error(
        "Agent token dwk must be exactly aauth-agent.json, the Agent Provider's well-known metadata document name"
    )]
    InvalidDiscoveryDocument,
    #[error("sub domain must match the Agent Provider issuer host")]
    AgentIssuerMismatch,
    #[error(
        "Agent signing key does not match cnf.jwk: put key.public_jwk() in the token, then move that same key into Agent::new"
    )]
    ConfirmationKeyMismatch,
    #[error("kid must be a non-empty string naming the issuer's signing key in its JWKS")]
    InvalidKeyId,
    #[error(
        "invalid public key or JWKS: check JSON, a unique selected kid, OKP/Ed25519 shape, public-only key members and canonical key bytes"
    )]
    InvalidKey,
    #[error(
        "invalid issuance fields: jti must be non-empty and exp must be later than iat; all timestamps use non-negative Unix seconds"
    )]
    InvalidTokenLifetime,
    #[error(
        "this Agent Provider issues top-level agents only: sub must not contain + and parent_agent must be absent"
    )]
    UnsupportedAgentProfile,
    #[error("expected typ aa-agent+jwt: present an Agent token rather than another JWT type")]
    UnexpectedTokenType,
}
impl TokenError {
    /// Stable protocol code. Display is intended for local developer diagnostics.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidJwt
            | Self::InvalidServerIdentifier
            | Self::InvalidAgentIdentifier
            | Self::InvalidDiscoveryDocument
            | Self::AgentIssuerMismatch
            | Self::ConfirmationKeyMismatch
            | Self::InvalidKeyId
            | Self::InvalidTokenLifetime
            | Self::UnsupportedAgentProfile
            | Self::UnexpectedTokenType => "invalid_jwt",
            Self::ExpiredJwt => "expired_jwt",
            Self::UnknownKey => "unknown_key",
            Self::IssuerMissing => "issuer_missing",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::InvalidKey => "invalid_key",
        }
    }
}
impl From<aauth_jose::Error> for TokenError {
    fn from(e: aauth_jose::Error) -> Self {
        match e {
            aauth_jose::Error::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            aauth_jose::Error::InvalidKey => Self::InvalidKey,
            _ => Self::InvalidJwt,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Confirmation {
    /// Public confirmation key: every request proof must verify with this key.
    pub jwk: Jwk,
}

/// Claims of an Agent token (`typ: aa-agent+jwt`). Times are Unix seconds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentClaims {
    /// Agent Provider identifier, e.g. `https://ap.example` (scheme and DNS host only).
    pub iss: String,
    /// Discovery well-known document name; exactly `aauth-agent.json` for Agents.
    pub dwk: String,
    /// Stable Agent identifier, e.g. `aauth:Agent@ap.example`; domain matches `iss`.
    pub sub: String,
    /// Token identifier assigned uniquely by the issuer for each issuance.
    pub jti: String,
    /// Issued-at time. Core does not treat a future `iat` as invalidity.
    pub iat: i64,
    /// Expiry time. Verification requires `exp > now`, without clock leeway.
    pub exp: i64,
    /// Confirmation key bound to the Agent's HTTP request signatures.
    pub cnf: Confirmation,
    /// Optional Person Server identifier; a lowercase HTTPS DNS origin.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub ps: Option<String>,
    /// Explicit sub-agent marker. Issuing/delegating sub-agents is not implemented.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_agent: Option<String>,
    /// Optional not-before time; if present it must be at most `now`.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub nbf: Option<i64>,
    /// Retained additive claims; their interpretation belongs to host policy.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
fn present_claim<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}
impl AgentClaims {
    pub fn validate(&self) -> Result<(), TokenError> {
        validate_server_identifier(&self.iss)?;
        validate_agent_identifier(&self.sub)?;
        if self.dwk != "aauth-agent.json" {
            return Err(TokenError::InvalidDiscoveryDocument);
        }
        if self.jti.is_empty() || self.iat < 0 || self.exp < 0 {
            return Err(TokenError::InvalidTokenLifetime);
        }
        if self.sub.rsplit_once('@').map(|(_, d)| d) != self.iss.strip_prefix("https://") {
            return Err(TokenError::AgentIssuerMismatch);
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
            return Err(TokenError::UnexpectedTokenType);
        }
        let kid = jws
            .header()
            .get("kid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(TokenError::InvalidKeyId)?
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
