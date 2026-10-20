//! Buffered request signing and immediate PS credential-context verification.
//! Transport, response-header extraction and retries belong to hosts.
#![deny(missing_docs)]
mod credentials;
use aauth_rust_core::{AgentToken, TokenError};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{Error, KeyMaterial, sign_request};
use http::Request;
use std::sync::Arc;

/// Caller-owned proof key and exact issuer token; no transport or refresh loop.
pub struct Agent {
    key: Arc<SigningKey>,
    token: String,
}
impl Agent {
    /// Retain exact issuer-provided bytes and ensure the local proof key matches.
    /// This is not issuer authentication; the Resource verifies issuer authority.
    ///
    /// # Errors
    /// Returns token-profile errors or `ConfirmationKeyMismatch` if the local
    /// signing key differs from cnf.jwk. This does not verify the issuer signature.
    pub fn new(key: SigningKey, token: String) -> Result<Self, TokenError> {
        Self::from_shared_key(Arc::new(key), token)
    }
    /// Retain an Agent, Person or Auth token with the existing proof key. Earlier
    /// values remain usable for in-flight requests; secret bytes are never exported.
    /// Parsing and matching cnf are not issuer authentication. Use the credential
    /// verification helpers or let the accepting role authenticate the issuer.
    ///
    /// # Errors
    /// Rejects malformed tokens or a new cnf.jwk that differs from this Agent key.
    /// Issuer authentication still belongs to the caller or receiving Resource.
    pub fn with_token(&self, token: String) -> Result<Self, TokenError> {
        let confirmation = credentials::credential_key(&token)?;
        if confirmation.thumbprint()? != self.key.public_jwk().thumbprint()? {
            return Err(TokenError::ConfirmationKeyMismatch);
        }
        Ok(Self {
            key: self.key.clone(),
            token,
        })
    }
    fn from_shared_key(key: Arc<SigningKey>, token: String) -> Result<Self, TokenError> {
        let parsed = AgentToken::parse(&token)?;
        if parsed.unverified_claims().cnf.jwk.thumbprint()? != key.public_jwk().thumbprint()? {
            return Err(TokenError::ConfirmationKeyMismatch);
        }
        Ok(Self { key, token })
    }
    /// Return an owned copy of the retained proof key's public JWK.
    /// Use it for enrollment or renewed token claims without parsing an old token.
    /// Mutating the returned public value never changes this Agent's signing key.
    pub fn public_jwk(&self) -> Jwk {
        self.key.public_jwk()
    }
    /// Retained compact token; treat it as a credential when logging.
    pub fn token(&self) -> &str {
        &self.token
    }
    /// Sign once, last, after URI and headers are final. `now` is Unix seconds.
    /// This replaces any signature headers; it never sends or retries a request.
    ///
    /// # Errors
    /// Nonempty content is digest-covered (up to 1 MiB), including Content-Type
    /// when present. Hosts must pass actual bytes and bound body collection.
    /// Rejects oversized/non-HTTPS requests, invalid clocks and malformed
    /// signing material. See the Signature-Key error explanation for a remedy.
    pub fn sign(&self, request: &mut Request<Vec<u8>>, now: i64) -> Result<(), Error> {
        sign_request(
            request,
            &self.key,
            KeyMaterial::Jwt(self.token.clone()),
            now,
        )
    }
}
