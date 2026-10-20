use crate::TokenError;
use aauth_jose::{Jwk, strict_json};
use serde_json::Value;

/// Host-supplied resolution. Implementations own egress admission and caching.
pub trait AgentKeyResolver: Send + Sync {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError>;
}

pub fn metadata_jwks_uri(expected_issuer: &str, bytes: &[u8]) -> Result<String, TokenError> {
    crate::validate_server_identifier(expected_issuer)?;
    if bytes.len() > 65536 {
        return Err(TokenError::InvalidJwt);
    }
    let metadata = strict_json(bytes).map_err(|_| TokenError::InvalidJwt)?;
    let issuer = metadata
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(TokenError::IssuerMissing)?;
    if issuer != expected_issuer {
        return Err(TokenError::IssuerMismatch);
    }
    let uri = metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or(TokenError::UnknownKey)?;
    let parsed = url::Url::parse(uri).map_err(|_| TokenError::UnknownKey)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(TokenError::UnknownKey);
    }
    Ok(uri.into())
}

/// Immutable host-retained discovery snapshot for one explicitly trusted AP.
/// Never performs a fetch; constructing it is not a trust decision for the host.
pub struct AgentProviderKeys {
    issuer: String,
    jwks_uri: String,
    keys: Vec<Value>,
}
impl AgentProviderKeys {
    pub fn from_documents(issuer: &str, metadata: &[u8], jwks: &[u8]) -> Result<Self, TokenError> {
        let jwks_uri = metadata_jwks_uri(issuer, metadata)?;
        if jwks.len() > 65536 {
            return Err(TokenError::UnknownKey);
        }
        let document = strict_json(jwks).map_err(|_| TokenError::UnknownKey)?;
        let keys = document
            .get("keys")
            .and_then(Value::as_array)
            .filter(|a| a.len() <= 128)
            .ok_or(TokenError::UnknownKey)?
            .clone();
        Ok(Self {
            issuer: issuer.into(),
            jwks_uri,
            keys,
        })
    }
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }
    pub fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        <Self as AgentKeyResolver>::key(self, issuer, dwk, kid)
    }
}
impl AgentKeyResolver for AgentProviderKeys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if issuer != self.issuer || dwk != "aauth-agent.json" || kid.is_empty() {
            return Err(TokenError::UnknownKey);
        }
        let mut matches = self
            .keys
            .iter()
            .filter(|v| v.get("kid").and_then(Value::as_str) == Some(kid));
        let value = matches.next().ok_or(TokenError::UnknownKey)?;
        if matches.next().is_some() {
            return Err(TokenError::UnknownKey);
        }
        let key: Jwk = serde_json::from_value(value.clone()).map_err(|_| TokenError::InvalidJwt)?;
        key.validate()?;
        Ok(key)
    }
}
