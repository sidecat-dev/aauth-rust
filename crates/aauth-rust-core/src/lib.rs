//! AAuth Agent, Person, Resource and Auth JWT trust verification, plus the
//! Events subscribe and event tokens in [`events`] and the Supervision wire
//! values in [`supervision`].
//! No enrollment, HTTP proof verification or application admission policy.
#![deny(missing_docs)]
pub mod capabilities;
pub mod continuation;
mod discovery;
pub mod events;
mod identifiers;
pub mod interaction;
mod metadata;
mod mission;
pub mod resource_link;
pub mod revocation;
pub mod session;
pub mod supervision;
pub use mission::{ApprovedMission, MissionError};
mod tokens;
pub use discovery::{
    AgentKeyResolver, AgentProviderKeys, TrustedIssuerKeys, metadata_jwks_uri, verify_with_refresh,
};
pub use identifiers::{validate_agent_identifier, validate_server_identifier};
pub use metadata::{DISPLAY_URI_MEMBERS, DisplayError, MetadataDisplay};
pub use revocation::{
    CallOutcome, DownstreamReport, RevocationBody, RevocationDirectory, RevocationLedger,
    RevocationLimits, RevocationSender, RevocationTarget,
};
pub use session::{
    SessionTokenError, format_aauth_access, format_session_authorization, parse_aauth_access,
    parse_session_authorization,
};
pub use tokens::{
    AuthClaims, AuthToken, PersonClaims, PersonToken, ResourceClaims, ResourceToken,
    VerifiedAuthToken, VerifiedPersonToken, VerifiedResourceToken, mint_auth_token,
    mint_person_token, mint_resource_token,
};

use aauth_rust_jose::{Jwk, Jws, strict_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
/// Token, identifier or trusted discovery failure with a stable wire code.
pub enum TokenError {
    /// invalid JWT: check compact encoding, required claim types and issuer signature.
    #[error("invalid JWT: check compact encoding, required claim types and issuer signature")]
    InvalidJwt,
    /// A verified token targets another recipient; maps to the draft's invalid_jwt.
    #[error(
        "token audience differs from the intended recipient: obtain a token for this Resource or Person Server"
    )]
    AudienceMismatch,
    #[error(
        "issuer is not trusted by this key snapshot: do not refresh or fetch keys from this issuer"
    )]
    /// Issuer is outside the configured trust snapshot; do not fetch or refresh it.
    /// Maps to `invalid_key` because the key does not meet server trust requirements.
    UntrustedIssuer,
    #[error(
        "token expired: obtain a fresh token; exp and the verifier clock use Unix seconds with no expiry leeway"
    )]
    /// Token exp is not in the future.
    ExpiredJwt,
    #[error(
        "no trusted issuer key matches kid: check the issuer's JWKS and refresh the host's retained key snapshot"
    )]
    /// No matching kid on a trusted issuer; configured refresh may help.
    UnknownKey,
    #[error("metadata is missing its issuer string: publish the exact HTTPS server identifier")]
    /// Metadata lacks a string issuer member.
    IssuerMissing,
    #[error(
        "metadata issuer differs from the expected issuer: use exact string equality, including case and trailing slash"
    )]
    /// Metadata or issuance issuer does not equal the expected identifier.
    IssuerMismatch,
    #[error(
        "unsupported or missing JWK/JWS alg: AAuth tokens and their keys use the fully specified Ed25519 or ES256 algorithm"
    )]
    /// The algorithm is absent or outside the token profile: Ed25519 or ES256.
    UnsupportedAlgorithm,
    #[error(
        "issuer must be a lowercase https:// DNS name with no port, path, trailing slash, query, fragment, userinfo or IP literal"
    )]
    /// Server identifier is not a canonical lowercase HTTPS DNS origin.
    InvalidServerIdentifier,
    #[error(
        "sub or parent_agent must be an aauth:local@domain identifier; local uses ASCII letters, digits, -_+. and domain is lowercase DNS"
    )]
    /// Agent subject or parent identifier has invalid syntax.
    InvalidAgentIdentifier,
    #[error(
        "dwk must be exactly the issuer role's well-known metadata document name, such as aauth-agent.json in an Agent token"
    )]
    /// A token's dwk does not name its issuer role's metadata document.
    InvalidDiscoveryDocument,
    /// Discovery metadata has no usable HTTPS JWKS URL, or a display URL such
    /// as `logo_uri` is not `https`; a key refresh cannot fix it.
    #[error(
        "invalid metadata jwks_uri or display URL: provide HTTPS URLs with a host and valid port, without userinfo; jwks_uri also without fragment"
    )]
    InvalidDiscoveryMetadata,
    /// sub domain must match the Agent Provider issuer host.
    #[error("sub domain must match the Agent Provider issuer host")]
    AgentIssuerMismatch,
    #[error(
        "Agent signing key does not match cnf.jwk: put key.public_jwk() in the token, then move that same key into Agent::new"
    )]
    /// Caller signing key differs from the token confirmation key.
    ConfirmationKeyMismatch,
    /// kid must be a non-empty string naming the issuer's signing key in its JWKS.
    #[error("kid must be a non-empty string naming the issuer's signing key in its JWKS")]
    InvalidKeyId,
    #[error(
        "invalid public key or JWKS: check JSON, a unique selected kid, an OKP Ed25519 or EC P-256 shape matching alg, public-only key members and canonical key bytes"
    )]
    /// Selected public key or JWKS is malformed or ambiguous.
    InvalidKey,
    #[error(
        "invalid issuance fields: jti must be non-empty and exp must be later than iat and within the AP 24-hour issuance limit; iat/exp use Unix seconds in 0..=8589934591 for local issuance"
    )]
    /// Issuance fields or required timestamps are outside the supported profile.
    InvalidTokenLifetime,
    #[error(
        "top-level issuance requires sub without + and no parent_agent; use authenticated sub-agent issuance for a child"
    )]
    /// Top-level issuance was requested with a sub-agent profile.
    UnsupportedAgentProfile,
    /// The JWT `typ` is not the token type this verifier expects.
    #[error(
        "unexpected JWT typ: present the token type this verifier expects, such as aa-agent+jwt for an Agent token"
    )]
    UnexpectedTokenType,
    /// The issuer's signing key could not sign: an external signer failed or
    /// returned a signature its public key does not verify. Nothing was minted.
    #[error(
        "token signing failed: the issuer key's external signer failed or returned a signature its public key does not verify"
    )]
    SigningFailed,
}
impl TokenError {
    /// Stable protocol code. Display is intended for local developer diagnostics.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidJwt
            | Self::AudienceMismatch
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
            Self::InvalidKey | Self::UntrustedIssuer | Self::InvalidDiscoveryMetadata => {
                "invalid_key"
            }
            Self::SigningFailed => "server_error",
        }
    }
}
/// Seconds before an Agent, Person or Auth token's `exp` at which an agent
/// refreshes it, and inside which it does not present it (Protocol, Expiry
/// and the Refresh Margin). An Agent token's lifetime must exceed it.
pub const REFRESH_MARGIN: i64 = 300;

/// Token issuer keys and `cnf.jwk` confirmation keys use the compact JWS
/// profile: Ed25519 or ES256.
pub(crate) fn require_token_key(jwk: &Jwk) -> Result<(), TokenError> {
    jwk.validate()?;
    if aauth_rust_jose::JWS_ALGORITHMS.contains(&jwk.alg.as_str()) {
        Ok(())
    } else {
        Err(TokenError::UnsupportedAlgorithm)
    }
}

impl From<aauth_rust_jose::Error> for TokenError {
    fn from(e: aauth_rust_jose::Error) -> Self {
        match e {
            aauth_rust_jose::Error::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            aauth_rust_jose::Error::InvalidKey => Self::InvalidKey,
            aauth_rust_jose::Error::Signer(_) => Self::SigningFailed,
            _ => Self::InvalidJwt,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Public confirmation key binding a token to its request-signing holder.
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
    /// Authoritative sub-agent marker naming the top-level parent Agent.
    /// Use `verify_subagent` to authenticate the relationship to that parent.
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
    /// Validate required Agent-profile syntax without authenticating an issuer.
    ///
    /// # Errors
    /// Rejects invalid issuer/subject/PS identifiers, wrong dwk, missing jti,
    /// negative required times, reserved extra members or an invalid public key.
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
        crate::require_token_key(&self.cnf.jwk)?;
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
    /// Parse an unverified Agent token, preserving its exact compact bytes.
    ///
    /// # Errors
    /// Rejects malformed JWS/JSON, wrong typ, missing kid, incorrectly typed
    /// claims (including explicit null optionals), invalid identifiers or keys.
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
    /// Verify the issuer signature, then exp/nbf, at `now` in Unix seconds.
    /// This does not verify a holder request or make an application policy decision.
    /// An invalid signature stays an invalid signature when `exp` has also passed.
    ///
    /// # Errors
    /// Returns resolver trust/key errors, invalid issuer signatures, then
    /// expiry/not-before failures. A future iat is not itself a Core validity failure.
    pub fn verify(
        &self,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedAgentToken, TokenError> {
        if now < 0 {
            return Err(TokenError::InvalidJwt);
        }
        discovery::verify_jws(
            &self.jws,
            keys,
            (&self.claims.iss, &self.claims.dwk, &self.kid),
        )?;
        if self.claims.exp <= now {
            return Err(TokenError::ExpiredJwt);
        }
        if self.claims.nbf.is_some_and(|nbf| nbf > now) {
            return Err(TokenError::InvalidJwt);
        }
        Ok(VerifiedAgentToken {
            claims: self.claims.clone(),
            compact: self.jws.compact().into(),
        })
    }
}

/// Only Core's verified-token path constructs this value.
#[derive(Clone)]
pub struct VerifiedAgentToken {
    claims: AgentClaims,
    compact: String,
}
impl VerifiedAgentToken {
    /// Authenticated issuer claims; application admission policy remains separate.
    pub fn claims(&self) -> &AgentClaims {
        &self.claims
    }
    /// Exact authenticated token bytes for forwarding without reserialization.
    pub fn compact(&self) -> &str {
        &self.compact
    }
}

impl std::fmt::Debug for VerifiedAgentToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedAgentToken")
            .field("issuer", &self.claims.iss)
            .field("subject", &self.claims.sub)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AgentToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentToken")
            .field("unverified_issuer", &self.claims.iss)
            .field("unverified_subject", &self.claims.sub)
            .finish_non_exhaustive()
    }
}

/// Authenticate a child Agent token and its one-level relationship to a verified
/// top-level parent. The `parent_agent` claim supplies authority; subject naming
/// is checked only as profile validation. Optional PS binding is a role duty.
///
/// # Errors
/// Rejects signature, trust, time, provider, parent, naming, depth or key-profile
/// mismatches. Expired inputs preserve `ExpiredJwt` for role-specific mapping.
pub fn verify_subagent(
    compact: &str,
    parent: &VerifiedAgentToken,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<VerifiedAgentToken, TokenError> {
    // A retained verified parent can be stale; authenticate its exact bytes
    // against the current key snapshot and clock before admitting a child.
    let parent = AgentToken::parse(parent.compact())?.verify(keys, now)?;
    let child = AgentToken::parse(compact)?.verify(keys, now)?;
    let p = parent.claims();
    let c = child.claims();
    if p.parent_agent.is_some()
        || c.parent_agent.as_deref() != Some(p.sub.as_str())
        || c.iss != p.iss
        || c.cnf.jwk.thumbprint()? == p.cnf.jwk.thumbprint()?
    {
        return Err(TokenError::InvalidJwt);
    }
    // Authority was established from authenticated parent_agent above. Naming
    // is a separate profile check, never a source of delegation authority.
    let parent_local = p.sub.rsplit_once('@').ok_or(TokenError::InvalidJwt)?.0;
    let child_local = c.sub.rsplit_once('@').ok_or(TokenError::InvalidJwt)?.0;
    let discriminator = child_local
        .strip_prefix(parent_local)
        .and_then(|suffix| suffix.strip_prefix('+'))
        .ok_or(TokenError::InvalidJwt)?;
    if parent_local.contains('+') || discriminator.is_empty() || discriminator.contains('+') {
        return Err(TokenError::InvalidJwt);
    }
    Ok(child)
}
