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

    /// Resolve `kid` again from a fresh fetch of `url`, because the HTTP
    /// signature failed under the key [`Self::key`] answered (Signature-Key
    /// line 1218 and unknown_key, line 1054): the signer may have replaced
    /// the key and kept its `kid`. Called at most once per verification.
    ///
    /// `Ok(None)` means no fresher key is available and the failure stands:
    /// the resolver does not fetch, or fetched `url` within the last minute.
    /// The default answers `Ok(None)`.
    ///
    /// # Errors
    /// As for [`Self::key`].
    fn refreshed_key(&self, url: &str, kid: &str) -> Result<Option<Jwk>, Error> {
        let _ = (url, kid);
        Ok(None)
    }
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
    /// key is not Ed25519 or ES256.
    /// `invalid_signature` when the HTTP signature does not match that key,
    /// nor the key [`JwksResolver::refreshed_key`] then answers.
    pub fn verify_jwks(&self, resolver: &impl JwksResolver) -> Result<JwksIdentity, Error> {
        let KeyMaterial::Jwks { url, kid } = &self.key else {
            return Err(Error::InvalidKey);
        };
        let check = |key: &Jwk| {
            key.validate().map_err(|err| match err {
                aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
                _ => Error::InvalidKey,
            })?;
            self.verify(key)
        };
        let mut key = resolver.key(url, kid)?;
        match check(&key) {
            Err(Error::InvalidSignature) => match resolver.refreshed_key(url, kid)? {
                Some(fresh) => {
                    check(&fresh)?;
                    key = fresh;
                }
                None => return Err(Error::InvalidSignature),
            },
            other => other?,
        }
        Ok(JwksIdentity {
            url: url.clone(),
            key_id: kid.clone(),
            key,
        })
    }
}
