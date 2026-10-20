//! One signed request at a time. Transport and challenge handling belong to hosts.
use aauth_core::{AgentToken, TokenError};
use aauth_jose::SigningKey;
use aauth_signature_key::{Error, KeyMaterial, sign_request};
use http::Request;

pub struct Agent {
    key: SigningKey,
    token: String,
}
impl Agent {
    /// Retain exact issuer-provided bytes and ensure the local proof key matches.
    /// This is not issuer authentication; the Resource verifies issuer authority.
    pub fn new(key: SigningKey, token: String) -> Result<Self, TokenError> {
        let parsed = AgentToken::parse(&token)?;
        if parsed.unverified_claims().cnf.jwk.thumbprint()? != key.public_jwk().thumbprint()? {
            return Err(TokenError::ConfirmationKeyMismatch);
        }
        Ok(Self { key, token })
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn sign(&self, request: &mut Request<Vec<u8>>, now: i64) -> Result<(), Error> {
        sign_request(
            request,
            &self.key,
            KeyMaterial::Jwt(self.token.clone()),
            now,
        )
    }
}
