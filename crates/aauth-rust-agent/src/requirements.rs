//! Immediate requirement extraction, before credential verification or transport.
use http::{HeaderMap, HeaderValue};
use sfv::{BareItem, Dictionary, ListEntry, Parser};

/// An immediate requirement the current Agent helpers can satisfy.
/// Parsing never verifies a challenge or authorizes a retry.
#[derive(Clone, PartialEq, Eq)]
pub enum Requirement {
    /// Present the Agent token with its holder proof.
    AgentToken,
    /// Obtain Resource-directed Person identity from the configured PS.
    PersonToken,
    /// Verify this Resource challenge, then exchange it with the presented token.
    AuthToken {
        /// Exact decoded parameter bytes, still an unverified credential.
        resource_token: String,
    },
}
impl std::fmt::Debug for Requirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentToken => f.write_str("AgentToken"),
            Self::PersonToken => f.write_str("PersonToken"),
            Self::AuthToken { .. } => f.debug_struct("AuthToken").finish_non_exhaustive(),
        }
    }
}

/// A malformed or unsupported requirement; never an instruction to retry.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequirementError {
    /// Field syntax/type is invalid, or the local 64 KiB field bound is exceeded.
    #[error(
        "invalid AAuth-Requirement: use an RFC 9651 dictionary with a requirement token, bounded to 65536 bytes"
    )]
    Malformed,
    /// Auth-token requires a nonempty SF String parameter on requirement.
    #[error(
        "auth-token requires a nonempty resource-token string parameter on the requirement member; verify the extracted JWT before exchange"
    )]
    InvalidResourceToken,
    /// The requirement needs behavior outside this immediate Agent subset.
    #[error(
        "unsupported AAuth requirement {0}: surface this to the caller; do not treat it as satisfiable"
    )]
    Unsupported(String),
}
impl Requirement {
    /// Parse an RFC 9651 dictionary, ignoring unknown members and parameters.
    /// Repeated members/parameters follow RFC 9651 last-wins parsing. Auth-token
    /// extraction does not validate the JWT: call Agent::verify_resource_challenge.
    /// Interaction, approval, clarification, claims and extension values return
    /// Unsupported. Parsing does not inspect status or implement deferred delivery.
    ///
    /// # Errors
    /// Returns malformed/type/size failures, missing challenge or unsupported value.
    pub fn parse(value: &HeaderValue) -> Result<Self, RequirementError> {
        Self::parse_field(value.to_str().map_err(|_| RequirementError::Malformed)?)
    }

    /// Combine all AAuth-Requirement field lines as one dictionary. Absence is
    /// Ok(None), distinct from a present malformed field. HTTP status handling,
    /// discovery admission, verification, polling and retries belong to the host.
    ///
    /// # Errors
    /// Returns the same validation errors as parse, including the combined size bound.
    pub fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, RequirementError> {
        let mut field = String::new();
        let mut present = false;
        for value in headers.get_all("aauth-requirement") {
            let value = value.to_str().map_err(|_| RequirementError::Malformed)?;
            if field.len() + value.len() + usize::from(present) * 2 > 65536 {
                return Err(RequirementError::Malformed);
            }
            if present {
                field.push_str(", ");
            }
            field.push_str(value);
            present = true;
        }
        if present {
            Self::parse_field(&field).map(Some)
        } else {
            Ok(None)
        }
    }
    fn parse_field(field: &str) -> Result<Self, RequirementError> {
        if field.len() > 65536 {
            return Err(RequirementError::Malformed);
        }
        let dictionary: Dictionary = Parser::new(field)
            .parse()
            .map_err(|_| RequirementError::Malformed)?;
        let Some(ListEntry::Item(item)) = dictionary.get("requirement") else {
            return Err(RequirementError::Malformed);
        };
        let BareItem::Token(value) = &item.bare_item else {
            return Err(RequirementError::Malformed);
        };
        match value.as_str() {
            "agent-token" => Ok(Self::AgentToken),
            "person-token" => Ok(Self::PersonToken),
            "auth-token" => {
                let Some(BareItem::String(compact)) = item.params.get("resource-token") else {
                    return Err(RequirementError::InvalidResourceToken);
                };
                if compact.as_str().is_empty() {
                    return Err(RequirementError::InvalidResourceToken);
                }
                Ok(Self::AuthToken {
                    resource_token: compact.as_str().to_owned(),
                })
            }
            other => Err(RequirementError::Unsupported(other.to_owned())),
        }
    }
}
