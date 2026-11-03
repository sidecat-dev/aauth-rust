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

    /// Resolve `kid` again from a fresh fetch, because a signature failed
    /// under the key [`Self::key`] answered (protocol line 2286;
    /// Signature-Key line 1218): the issuer may have replaced the key and
    /// kept its `kid`. [`verify_with_refresh`] calls this at most once per
    /// verification.
    ///
    /// `Ok(None)` means no fresher key is available, and the failure
    /// stands: the resolver does not fetch, or already fetched this issuer
    /// within the last minute. The default answers `Ok(None)`, as a fixed
    /// snapshot does.
    ///
    /// # Errors
    /// As for [`Self::key`]; `UnknownKey` when the fresh key set no longer
    /// has `kid`.
    fn refreshed_key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Option<Jwk>, TokenError> {
        let _ = (issuer, dwk, kid);
        Ok(None)
    }
}

/// Verify with the key `keys` resolves for (`issuer`, `dwk`, `kid`), and once
/// more with [`AgentKeyResolver::refreshed_key`] when `verify` fails with an
/// error `signature_failed` accepts (protocol line 2286; Signature-Key line
/// 1218). Use it for a token signature and for a `jwks_uri` request
/// signature alike.
///
/// The outer `Err` is the key lookup's: the first one, or the refresh's,
/// such as `UnknownKey` when the refreshed set no longer has `kid`. The inner
/// result is `verify`'s, from the refreshed key when there was one.
///
/// # Errors
/// As described: resolver errors outside, `verify` errors inside.
pub fn verify_with_refresh<T, E>(
    keys: &dyn AgentKeyResolver,
    (issuer, dwk, kid): (&str, &str, &str),
    verify: impl Fn(&Jwk) -> Result<T, E>,
    signature_failed: impl Fn(&E) -> bool,
) -> Result<Result<T, E>, TokenError> {
    let key = keys.key(issuer, dwk, kid)?;
    match verify(&key) {
        Err(error) if signature_failed(&error) => match keys.refreshed_key(issuer, dwk, kid)? {
            Some(fresh) => Ok(verify(&fresh)),
            None => Ok(Err(error)),
        },
        result => Ok(result),
    }
}

/// Verify a compact JWS with the key `keys` resolves, refreshing it once
/// when the signature does not verify ([`verify_with_refresh`]). Returns the
/// key that verified it.
pub(crate) fn verify_jws(
    jws: &aauth_rust_jose::Jws,
    keys: &dyn AgentKeyResolver,
    names: (&str, &str, &str),
) -> Result<Jwk, TokenError> {
    verify_with_refresh(
        keys,
        names,
        |key| jws.verify(key).map(|()| key.clone()),
        |error| matches!(error, aauth_rust_jose::Error::InvalidJws),
    )?
    .map_err(Into::into)
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
        crate::require_token_key(&key)?;
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
    fn refreshed_key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Option<Jwk>, TokenError> {
        (**self).refreshed_key(issuer, dwk, kid)
    }
}
impl<T: AgentKeyResolver + ?Sized> AgentKeyResolver for std::sync::Arc<T> {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        (**self).key(issuer, dwk, kid)
    }
    fn refreshed_key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Option<Jwk>, TokenError> {
        (**self).refreshed_key(issuer, dwk, kid)
    }
}
impl<T: AgentKeyResolver + ?Sized> AgentKeyResolver for Box<T> {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        (**self).key(issuer, dwk, kid)
    }
    fn refreshed_key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Option<Jwk>, TokenError> {
        (**self).refreshed_key(issuer, dwk, kid)
    }
}

/// Immutable metadata/JWKS snapshot for one explicitly trusted issuer and
/// metadata document.
/// It never fetches token-named endpoints or makes a host trust decision.
#[derive(Clone)]
pub struct TrustedIssuerKeys {
    snapshot: AgentProviderKeys,
    dwk: String,
}
impl TrustedIssuerKeys {
    /// Retain discovery documents for the exact issuer and metadata document
    /// the host trusts. `dwk` is any well-known document name
    /// ([`crate::validate_document_name`]): an AAuth role document such as
    /// `aauth-person.json`, or another one a `jwks_uri` signer names, such as
    /// `example-configuration` (Signature-Key, JWKS URI Discovery). The
    /// snapshot answers only for that name, and each token still requires
    /// its own role's document in its `dwk` claim.
    ///
    /// # Errors
    /// Rejects a malformed document name, invalid metadata/issuer or
    /// malformed/oversized JWKS.
    pub fn from_documents(
        issuer: &str,
        dwk: &str,
        metadata: &[u8],
        jwks: &[u8],
    ) -> Result<Self, TokenError> {
        crate::validate_document_name(dwk)?;
        Ok(Self {
            snapshot: AgentProviderKeys::from_documents(issuer, metadata, jwks)?,
            dwk: dwk.into(),
        })
    }
    /// Original validated JWKS location; this snapshot never contacts it.
    pub fn jwks_uri(&self) -> &str {
        self.snapshot.jwks_uri()
    }
    /// Resolve a key only inside this exact issuer/document trust boundary.
    ///
    /// # Errors
    /// Rejects a foreign issuer or document name, empty/missing kid, or malformed selected key.
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
