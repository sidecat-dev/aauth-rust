//! Latest opaque resource session token for one resource.
//! The token is applied as `Authorization: AAuth` before the caller signs.
//! Signing covers `authorization` when that header is present.

use aauth_rust_core::{SessionTokenError, format_session_authorization, parse_aauth_access};
use http::{HeaderValue, Request};

/// The newest `AAuth-Access` value retained for one resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessSession {
    token: String,
}

impl AccessSession {
    /// Retain the single credential from an `AAuth-Access` response.
    ///
    /// # Errors
    /// Returns [`SessionTokenError`] when the response carries no credential,
    /// more than one credential, or a value that is not `token68`.
    pub fn receive<I, S>(values: I) -> Result<Self, SessionTokenError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self {
            token: parse_aauth_access(values)?,
        })
    }

    /// Replace the retained token when the resource sends a new `AAuth-Access`.
    /// No header leaves the retained token unchanged. A rejected header also
    /// leaves it unchanged.
    ///
    /// # Errors
    /// Returns [`SessionTokenError`] when a presented value is empty, contains
    /// whitespace or a control character, or more than one credential is present.
    pub fn note<I, S>(&mut self, values: I) -> Result<(), SessionTokenError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let values: Vec<String> = values
            .into_iter()
            .map(|value| value.as_ref().to_owned())
            .collect();
        if values.is_empty() {
            return Ok(());
        }
        self.token = parse_aauth_access(values)?;
        Ok(())
    }

    /// Opaque token currently retained for subsequent requests.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Set `Authorization: AAuth` to the retained token.
    /// Call this before [`crate::Agent::sign`] so the signature covers it.
    ///
    /// # Errors
    /// Returns [`SessionTokenError`] when the retained token is no longer
    /// `token68`. A header the HTTP parser rejects is the same error.
    pub fn apply(&self, request: &mut Request<Vec<u8>>) -> Result<(), SessionTokenError> {
        let value = format_session_authorization(&self.token)?;
        let header = HeaderValue::from_str(&value).map_err(|_| SessionTokenError)?;
        request.headers_mut().insert("authorization", header);
        Ok(())
    }
}
