//! Process-memory session tokens a Resource issues for its own consumption.
//! The opaque value is bound to one verified agent subject. Presenting it
//! without that agent's signature does not reveal or accept the binding.

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use aauth_rust_core::{SessionTokenError, format_aauth_access, parse_session_authorization};
use http::{HeaderValue, Request, Response};

/// Outcome of presenting one opaque session token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionAdmit {
    /// The verified agent subject matches the subject wrapped by this token.
    Granted {
        /// Agent subject stored with the token.
        holder: String,
    },
    /// `Authorization` was present and the agent signature was not verified.
    Standalone,
    /// The header was missing, empty, or not one `AAuth` `token68` credential.
    Invalid,
    /// The token is unknown or bound to a different agent subject.
    Unbound,
}

/// Opaque session tokens keyed to the agent subject that may present them.
#[derive(Debug, Default)]
pub struct SessionLedger {
    records: Mutex<BTreeMap<String, String>>,
}

impl SessionLedger {
    /// Empty process-memory ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `token` to `holder`, replacing any earlier token for that subject.
    ///
    /// # Errors
    /// Returns [`SessionTokenError`] when `holder` is empty or `token` is not
    /// `token68`.
    pub fn issue(&self, holder: &str, token: &str) -> Result<(), SessionTokenError> {
        if holder.is_empty() {
            return Err(SessionTokenError);
        }
        format_aauth_access(token)?;
        let mut records = self.records();
        records.retain(|_, existing| existing != holder);
        records.insert(token.to_owned(), holder.to_owned());
        Ok(())
    }

    /// Set one `AAuth-Access` response header to `token`.
    ///
    /// # Errors
    /// Returns [`SessionTokenError`] when `token` is not `token68`.
    pub fn set_access_header(
        response: &mut Response<Vec<u8>>,
        token: &str,
    ) -> Result<(), SessionTokenError> {
        let value = format_aauth_access(token)?;
        let header = HeaderValue::from_str(&value).map_err(|_| SessionTokenError)?;
        response.headers_mut().insert("aauth-access", header);
        Ok(())
    }

    /// Match `token` to `holder` after the caller verified this same request.
    pub(crate) fn grant(&self, token: &str, holder: &str) -> SessionAdmit {
        match self.records().get(token) {
            Some(bound) if bound == holder => SessionAdmit::Granted {
                holder: holder.to_owned(),
            },
            _ => SessionAdmit::Unbound,
        }
    }

    fn records(&self) -> MutexGuard<'_, BTreeMap<String, String>> {
        self.records
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

/// Read one `AAuth` credential, or the reason it cannot be admitted.
pub(crate) fn presented_token(request: &Request<Vec<u8>>) -> Result<String, SessionAdmit> {
    let mut values = Vec::new();
    for value in request.headers().get_all("authorization") {
        let Ok(text) = value.to_str() else {
            return Err(SessionAdmit::Invalid);
        };
        values.push(text.to_owned());
    }
    if values.is_empty() {
        return Err(SessionAdmit::Invalid);
    }
    parse_session_authorization(&values).map_err(|_| SessionAdmit::Invalid)
}
