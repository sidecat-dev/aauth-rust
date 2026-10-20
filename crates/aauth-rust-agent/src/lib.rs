//! One signed request at a time. Transport and challenge handling belong to hosts.
#![deny(missing_docs)]
use aauth_rust_core::{AgentToken, TokenError};
use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::{Error, KeyMaterial, sign_request};
use http::Request;

/// Caller-owned proof key and exact issuer token; no transport or refresh loop.
pub struct Agent {
    key: SigningKey,
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
        let parsed = AgentToken::parse(&token)?;
        if parsed.unverified_claims().cnf.jwk.thumbprint()? != key.public_jwk().thumbprint()? {
            return Err(TokenError::ConfirmationKeyMismatch);
        }
        Ok(Self { key, token })
    }
    /// Retained compact token; treat it as a credential when logging.
    pub fn token(&self) -> &str {
        &self.token
    }
    /// Sign once, last, after URI and headers are final. `now` is Unix seconds.
    /// This replaces any signature headers; it never sends or retries a request.
    ///
    /// # Errors
    /// Rejects body-bearing/non-HTTPS requests, invalid clocks and malformed
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
