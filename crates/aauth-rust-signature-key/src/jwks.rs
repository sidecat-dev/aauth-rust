//! Direct `jwks`. The JWKS URL is the signer identity.
//! This crate does not fetch it. The host resolves the exact `url` and `kid`.
use super::{Error, KeyMaterial, PreparedRequest};
use aauth_rust_jose::Jwk;

/// Host lookup of one key in the JWKS named by `url`.
///
/// `url` is the parameter as presented. Do not canonicalize it before matching.
/// The host fetches over HTTPS only after egress admission, and does not
/// refetch a document that is still fresh (never sooner than 60 seconds).
/// This crate does not fetch. Return [`Error::UnknownKey`] when `kid` is absent.
pub trait JwksResolver {
    /// Resolve `kid` at this exact JWKS URL.
    ///
    /// # Errors
    /// [`Error::UnknownKey`] when the kid is absent. Other [`Error`] values
    /// propagate unchanged.
    fn key(&self, url: &str, kid: &str) -> Result<Jwk, Error>;
}

impl<F> JwksResolver for F
where
    F: Fn(&str, &str) -> Result<Jwk, Error>,
{
    fn key(&self, url: &str, kid: &str) -> Result<Jwk, Error> {
        self(url, kid)
    }
}

/// Verified direct-JWKS signer. `url` is the identity, byte for byte.
#[derive(Clone, Debug)]
pub struct JwksIdentity {
    /// Exact `url` parameter.
    pub url: String,
    /// Exact `kid` parameter.
    pub key_id: String,
    /// Public key the host returned for that pair. It verified the HTTP signature.
    pub key: Jwk,
}

pub(crate) fn validate(url: &str, kid: &str) -> Result<(), Error> {
    https_url(url)?;
    super::quoted(kid)?;
    super::quoted(url)?;
    Ok(())
}

/// Accept an HTTPS URL without rewriting it. The caller keeps `value`.
fn https_url(value: &str) -> Result<(), Error> {
    if value.contains('#') || value.contains('@') || value.contains(' ') {
        return Err(Error::InvalidKey);
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(Error::InvalidKey);
    };
    if rest.is_empty() {
        return Err(Error::InvalidKey);
    }
    let uri: http::Uri = value.parse().map_err(|_| Error::InvalidKey)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidKey)?;
    let authority = uri.authority().ok_or(Error::InvalidKey)?.as_str();
    if !rest.starts_with(authority) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

impl PreparedRequest {
    /// Resolve the selected `jwks` member and verify the HTTP signature.
    ///
    /// The resolver receives the `url` and `kid` strings unchanged. Two URLs
    /// that differ by any byte are different identities.
    ///
    /// # Errors
    /// `invalid_key` when this request is not `jwks`. `unknown_key` when the
    /// resolver reports that kid. `unsupported_algorithm` when the resolved
    /// key names an algorithm this profile does not implement.
    /// `invalid_signature` when the HTTP signature does not match that key.
    pub fn verify_jwks(&self, resolver: &impl JwksResolver) -> Result<JwksIdentity, Error> {
        let KeyMaterial::Jwks { url, kid } = &self.key else {
            return Err(Error::InvalidKey);
        };
        let key = resolver.key(url, kid)?;
        key.validate().map_err(|err| match err {
            aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
            aauth_rust_jose::Error::InvalidKey => Error::InvalidKey,
            _ => Error::InvalidKey,
        })?;
        if key.alg != "Ed25519" {
            return Err(Error::UnsupportedAlgorithm);
        }
        self.verify(&key)?;
        Ok(JwksIdentity {
            url: url.clone(),
            key_id: kid.clone(),
            key,
        })
    }
}
