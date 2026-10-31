use crate::TokenError;
use aauth_rust_jose::{Jwk, strict_json};
use serde_json::Value;

/// Host-supplied resolution. Implementations own egress admission and caching.
pub trait AgentKeyResolver: Send + Sync {
    /// Resolve `kid` for a trusted issuer and discovery well-known document
    /// name (`dwk`). An implementation must apply host trust before fetching.
    ///
    /// # Errors
    /// Implementations must reject untrusted issuers before network access.
    /// Reserve `UnknownKey` for missing kid on a trusted issuer, so a host may
    /// refresh only its configured source after checking the issuer allowlist.
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError>;
}

/// Validate issuer binding and return the HTTPS JWKS location from metadata.
/// URLs may contain queries or use a different host; network admission is a host duty.
///
/// # Errors
/// Rejects oversized/malformed metadata, missing/mismatched issuer, or a missing
/// or invalid HTTPS location (userinfo and fragments are forbidden). A present
/// `logo_uri`, `logo_dark_uri`, `documentation_uri`, `tos_uri` or `policy_uri`
/// that is not an `https` URL is also `InvalidDiscoveryMetadata`.
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
    crate::metadata::check_display_uris(&metadata)
        .map_err(|_| TokenError::InvalidDiscoveryMetadata)?;
    let uri = metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or(TokenError::InvalidDiscoveryMetadata)?;
    let parsed: http::Uri = uri
        .parse()
        .map_err(|_| TokenError::InvalidDiscoveryMetadata)?;
    let authority = parsed
        .authority()
        .ok_or(TokenError::InvalidDiscoveryMetadata)?;
    if parsed.scheme_str() != Some("https")
        || authority.host().is_empty()
        || authority.as_str().contains('@')
        || uri.contains('#')
    {
        return Err(TokenError::InvalidDiscoveryMetadata);
    }
    let suffix = &authority.as_str()[authority.host().len()..];
    if !suffix.is_empty()
        && suffix
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .is_none()
    {
        return Err(TokenError::InvalidDiscoveryMetadata);
    }
    Ok(uri.into())
}

/// Immutable host-retained discovery snapshot for one explicitly trusted AP.
/// Never performs a fetch; constructing it is not a trust decision for the host.
#[derive(Clone)]
pub struct AgentProviderKeys {
    issuer: String,
    jwks_uri: String,
    keys: Vec<Value>,
}
impl AgentProviderKeys {
    /// Retain metadata/JWKS bytes for an issuer the host already trusts.
    /// Checks exact metadata issuer equality and bounds document sizes. Fetching,
    /// destination admission, cache lifetime and refresh belong to the host.
    ///
    /// # Errors
    /// Returns metadata validation errors or `InvalidKey` for malformed/oversized
    /// JWKS. Unselected key algorithms are checked only if selected later.
    pub fn from_documents(issuer: &str, metadata: &[u8], jwks: &[u8]) -> Result<Self, TokenError> {
        let jwks_uri = metadata_jwks_uri(issuer, metadata)?;
        if jwks.len() > 65536 {
            return Err(TokenError::InvalidKey);
        }
        let document = strict_json(jwks).map_err(|_| TokenError::InvalidKey)?;
        let keys = document
            .get("keys")
            .and_then(Value::as_array)
            .filter(|a| a.len() <= 128)
            .ok_or(TokenError::InvalidKey)?
            .clone();
        Ok(Self {
            issuer: issuer.into(),
            jwks_uri,
            keys,
        })
    }
    /// Original validated JWKS URL; this snapshot never fetches it.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }
    /// Resolve one issuer-named key from this already trusted snapshot.
    ///
    /// # Errors
    /// `UntrustedIssuer` is terminal: never fetch a token-named foreign issuer.
    /// `UnknownKey` means a missing kid on this trusted issuer; host-controlled
    /// refresh may help. Malformed/ambiguous selected keys return `InvalidKey`.
    pub fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        <Self as AgentKeyResolver>::key(self, issuer, dwk, kid)
    }
}
impl AgentProviderKeys {
    fn selected_key(&self, kid: &str) -> Result<Jwk, TokenError> {
        if kid.is_empty() {
            return Err(TokenError::InvalidKeyId);
        }
        let mut matches = self
            .keys
            .iter()
            .filter(|v| v.get("kid").and_then(Value::as_str) == Some(kid));
        let value = matches.next().ok_or(TokenError::UnknownKey)?;
        if matches.next().is_some() {
            return Err(TokenError::InvalidKey);
        }
        let key: Jwk = serde_json::from_value(value.clone()).map_err(|_| TokenError::InvalidKey)?;
        crate::require_ed25519(&key)?;
        Ok(key)
    }
}

impl AgentKeyResolver for AgentProviderKeys {
    ///
    /// # Errors
    /// Implementations must reject untrusted issuers before network access.
    /// Reserve `UnknownKey` for missing kid on a trusted issuer, so a host may
    /// refresh only its configured source after checking the issuer allowlist.
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if issuer != self.issuer {
            return Err(TokenError::UntrustedIssuer);
        }
        if dwk != "aauth-agent.json" {
            return Err(TokenError::InvalidDiscoveryDocument);
        }
        self.selected_key(kid)
    }
}

impl<T: AgentKeyResolver + ?Sized> AgentKeyResolver for &T {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        (**self).key(issuer, dwk, kid)
    }
}
impl<T: AgentKeyResolver + ?Sized> AgentKeyResolver for std::sync::Arc<T> {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        (**self).key(issuer, dwk, kid)
    }
}
impl<T: AgentKeyResolver + ?Sized> AgentKeyResolver for Box<T> {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        (**self).key(issuer, dwk, kid)
    }
}

/// Immutable metadata/JWKS snapshot for one explicitly trusted issuer and role.
/// It never fetches token-named endpoints or makes a host trust decision.
#[derive(Clone)]
pub struct TrustedIssuerKeys {
    snapshot: AgentProviderKeys,
    dwk: String,
}
impl TrustedIssuerKeys {
    /// Retain discovery documents for the exact issuer and metadata role the host trusts.
    /// Supports Agent, Person, Resource, Access and Supervisor well-known document names.
    ///
    /// # Errors
    /// Rejects an unknown role, invalid metadata/issuer or malformed/oversized JWKS.
    pub fn from_documents(
        issuer: &str,
        dwk: &str,
        metadata: &[u8],
        jwks: &[u8],
    ) -> Result<Self, TokenError> {
        if ![
            "aauth-agent.json",
            "aauth-person.json",
            "aauth-resource.json",
            "aauth-access.json",
            crate::supervision::SUPERVISOR_DOCUMENT,
        ]
        .contains(&dwk)
        {
            return Err(TokenError::InvalidDiscoveryDocument);
        }
        Ok(Self {
            snapshot: AgentProviderKeys::from_documents(issuer, metadata, jwks)?,
            dwk: dwk.into(),
        })
    }
    /// Original validated JWKS location; this snapshot never contacts it.
    pub fn jwks_uri(&self) -> &str {
        self.snapshot.jwks_uri()
    }
    /// Resolve a key only inside this exact issuer/role trust boundary.
    ///
    /// # Errors
    /// Rejects a foreign issuer or role, empty/missing kid, or malformed selected key.
    pub fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        <Self as AgentKeyResolver>::key(self, issuer, dwk, kid)
    }
}
impl AgentKeyResolver for TrustedIssuerKeys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if issuer != self.snapshot.issuer {
            return Err(TokenError::UntrustedIssuer);
        }
        if dwk != self.dwk {
            return Err(TokenError::InvalidDiscoveryDocument);
        }
        self.snapshot.selected_key(kid)
    }
}
