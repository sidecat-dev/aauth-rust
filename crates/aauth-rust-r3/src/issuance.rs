//! Mandatory audit facts for one R3 Auth-token issuance.
//!
//! Ported from Go `r3/issuance.go`. The issuer commits one record before the
//! token becomes observable (draft, Issuer Processing step 4 and Audit Log
//! Integrity). This module defines the record and the store contract only.

use std::fmt;

use crate::reference::Reference;
use crate::uri::VocabularyUri;

/// What the issuer records for one R3 Auth token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceRecord {
    /// `iss` of the issued Auth token.
    pub auth_token_issuer: String,
    /// `jti` of the issued Auth token. With the issuer, this keys the record.
    pub auth_token_jti: String,
    /// The Resource the token is for (its `aud`).
    pub resource: String,
    /// `r3_uri` and `r3_s256` of the document or proposal.
    pub r3_reference: Reference,
    /// Vocabulary URI selected while parsing that artifact.
    pub vocabulary: VocabularyUri,
    /// Issuance time in Unix seconds.
    pub issued_at: i64,
    /// `ps` from the resource token.
    pub person_server: String,
    /// `sub` from the resource token.
    pub subject: String,
    /// `account` from the resource token. `Some("")` is present and empty.
    pub account: Option<String>,
    /// `presented_jti` from the resource token.
    pub presented_jti: String,
    /// `agent_jkt` from the resource token.
    pub agent_jkt: String,
    /// `sub` of the agent token the Auth token is bound to.
    pub agent: String,
    /// `sub` of the parent agent token when a sub-agent token was presented.
    pub parent_agent: Option<String>,
}

/// Durable, confidential issuance audit storage.
///
/// Commits for one Auth-token issuer and `jti` must be linearizable. `commit`
/// copies the record. Concurrent exact repeats succeed;
/// a different record for the same key returns [`IssuanceError::Conflict`].
/// Any other error may have committed: withhold the token and do not retry,
/// because R3 defines no request replay key.
pub trait IssuanceStore: Send + Sync {
    /// Commit `record` before the token is released.
    ///
    /// # Errors
    /// Returns [`IssuanceError`] as described on the trait.
    fn commit(&self, record: &IssuanceRecord) -> Result<(), IssuanceError>;
}

/// An issuance record could not be committed.
#[derive(Debug)]
pub enum IssuanceError {
    /// A different record is already retained for the same Auth token.
    Conflict,
    /// Storage failed. The record may or may not have been committed.
    Store(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for IssuanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("r3: issuance conflicts with retained state"),
            Self::Store(err) => write!(formatter, "r3: issuance store: {err}"),
        }
    }
}

impl std::error::Error for IssuanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Conflict => None,
            Self::Store(err) => Some(err.as_ref()),
        }
    }
}
