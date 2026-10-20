//! Host-controlled Agent-token issuance and public discovery documents.
//! Enrollment and issuance policy are supplied by the application.
#![deny(missing_docs)]
use aauth_rust_core::{AgentClaims, TokenError, validate_server_identifier};
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::json;

/// One host-configured issuer signing key and top-level Agent issuance profile.
pub struct AgentProvider {
    issuer: String,
    kid: String,
    key: SigningKey,
}
impl AgentProvider {
    /// Configure the issuer identity, public JWKS kid and caller-owned signing key.
    ///
    /// # Errors
    /// Rejects a noncanonical server identifier or empty kid.
    pub fn new(issuer: &str, kid: &str, key: SigningKey) -> Result<Self, TokenError> {
        validate_server_identifier(issuer)?;
        if kid.is_empty() {
            return Err(TokenError::InvalidKeyId);
        }
        Ok(Self {
            issuer: issuer.into(),
            kid: kid.into(),
            key,
        })
    }
    /// Issue a top-level Agent token after the host approves enrollment and
    /// assigns a unique `jti`. `iat`/`exp` use Unix seconds, with `exp > iat` and a lifetime of at most 24 hours.
    ///
    /// `iat` and `exp` must be in 0..=8589934591 Unix seconds (through 2242);
    /// contemporary millisecond values are refused before token serialization.
    ///
    /// # Errors
    /// Rejects malformed claims, a different issuer, nonpositive or over-24-hour
    /// lifetime, sub-agent issuance, or token serialization/signing errors.
    pub fn issue(&self, claims: &AgentClaims) -> Result<String, TokenError> {
        claims.validate()?;
        if claims.iss != self.issuer {
            return Err(TokenError::IssuerMismatch);
        }
        if !(0..=(1_i64 << 33) - 1).contains(&claims.iat)
            || !(0..=(1_i64 << 33) - 1).contains(&claims.exp)
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > 86400
        {
            return Err(TokenError::InvalidTokenLifetime);
        }
        // Sub-agent issuance requires checking the parent's actual token/state.
        // That role capability has not been implemented in this first cycle.
        if claims.parent_agent.is_some()
            || claims
                .sub
                .split('@')
                .next()
                .is_some_and(|s| s.contains('+'))
        {
            return Err(TokenError::UnsupportedAgentProfile);
        }
        Jws::sign(
            &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":self.kid}),
            &serde_json::to_vec(claims).map_err(|_| TokenError::InvalidJwt)?,
            &self.key,
        )
        .map_err(Into::into)
    }
    /// Public AP metadata bytes with the configured issuer and default JWKS URL.
    /// Serve at `/.well-known/aauth-agent.json` over verified HTTPS.
    ///
    /// # Errors
    /// Returns `InvalidJwt` if discovery serialization fails.
    pub fn metadata(&self) -> Result<Vec<u8>, TokenError> {
        serde_json::to_vec(&json!({"issuer":self.issuer,"jwks_uri":format!("{}/.well-known/jwks.json",self.issuer)})).map_err(|_|TokenError::InvalidJwt)
    }
    /// Public JWKS bytes for the configured signing key and kid; no secret bytes.
    ///
    /// # Errors
    /// Returns `InvalidJwt` if public-key or discovery serialization fails.
    pub fn jwks(&self) -> Result<Vec<u8>, TokenError> {
        let mut jwk =
            serde_json::to_value(self.key.public_jwk()).map_err(|_| TokenError::InvalidJwt)?;
        jwk["kid"] = json!(self.kid);
        serde_json::to_vec(&json!({"keys":[jwk]})).map_err(|_| TokenError::InvalidJwt)
    }
}
