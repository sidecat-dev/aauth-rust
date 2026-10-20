//! Host-controlled Agent-token issuance and public discovery documents.
//! Enrollment and issuance policy are supplied by the application.
use aauth_core::{AgentClaims, TokenError, validate_server_identifier};
use aauth_jose::{Jws, SigningKey};
use serde_json::json;

pub struct AgentProvider {
    issuer: String,
    kid: String,
    key: SigningKey,
}
impl AgentProvider {
    pub fn new(issuer: &str, kid: &str, key: SigningKey) -> Result<Self, TokenError> {
        validate_server_identifier(issuer)?;
        if kid.is_empty() {
            return Err(TokenError::UnknownKey);
        }
        Ok(Self {
            issuer: issuer.into(),
            kid: kid.into(),
            key,
        })
    }
    /// The host has already approved issuance and assigned a unique jti.
    pub fn issue(&self, claims: &AgentClaims) -> Result<String, TokenError> {
        claims.validate()?;
        if claims.iss != self.issuer || claims.exp <= claims.iat {
            return Err(TokenError::InvalidJwt);
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
            return Err(TokenError::InvalidJwt);
        }
        Jws::sign(
            &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":self.kid}),
            &serde_json::to_vec(claims).map_err(|_| TokenError::InvalidJwt)?,
            &self.key,
        )
        .map_err(Into::into)
    }
    pub fn metadata(&self) -> Result<Vec<u8>, TokenError> {
        serde_json::to_vec(&json!({"issuer":self.issuer,"jwks_uri":format!("{}/.well-known/jwks.json",self.issuer)})).map_err(|_|TokenError::InvalidJwt)
    }
    pub fn jwks(&self) -> Result<Vec<u8>, TokenError> {
        let mut jwk =
            serde_json::to_value(self.key.public_jwk()).map_err(|_| TokenError::InvalidJwt)?;
        jwk["kid"] = json!(self.kid);
        serde_json::to_vec(&json!({"keys":[jwk]})).map_err(|_| TokenError::InvalidJwt)
    }
}
