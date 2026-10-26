//! Operation access annotations and agent-side access planning.
//!
//! Ported from Go `r3/hints.go`. A hint is sparse and advisory. It is never
//! evidence of a grant, and the runtime `AAuth-Requirement` stays
//! authoritative. Reading a hint out of a vocabulary definition is the
//! definition adapter's job, not this module's.

use std::fmt;

use crate::error::Error;

/// A credential-flow value: the four Core `access_mode` values plus R3 `per-call`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessMode {
    /// `agent-token`: the agent token alone.
    AgentToken,
    /// `person-token`: a person token from the agent's Person Server.
    PersonToken,
    /// `session-token`: a Resource-managed session. Never an operation annotation.
    SessionToken,
    /// `auth-token`: an auth token obtained with a resource token.
    AuthToken,
    /// `per-call`: an auth token obtained for one call from a per-call proposal.
    PerCall,
}

impl AccessMode {
    /// Parse the exact wire spelling.
    ///
    /// # Errors
    /// Returns [`Error`] for any other text, including a case variant.
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "agent-token" => Ok(Self::AgentToken),
            "person-token" => Ok(Self::PersonToken),
            "session-token" => Ok(Self::SessionToken),
            "auth-token" => Ok(Self::AuthToken),
            "per-call" => Ok(Self::PerCall),
            other => Err(Error::new(format!("r3: invalid access mode \"{other}\""))),
        }
    }

    /// Wire spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AgentToken => "agent-token",
            Self::PersonToken => "person-token",
            Self::SessionToken => "session-token",
            Self::AuthToken => "auth-token",
            Self::PerCall => "per-call",
        }
    }

    fn below_auth_token(self) -> bool {
        matches!(
            self,
            Self::AgentToken | Self::PersonToken | Self::SessionToken
        )
    }
}

impl fmt::Display for AccessMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The sparse annotations published beside one operation.
///
/// `None` means the publisher omitted the annotation. A present `budget:false`
/// is kept distinct from an absent budget annotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationHints {
    access_mode: Option<AccessMode>,
    budget: Option<bool>,
}

impl OperationHints {
    /// Hold the published annotations.
    ///
    /// # Errors
    /// Returns [`Error`] for a `session-token` access-mode annotation, which the
    /// draft forbids because a session belongs to the whole Resource.
    pub fn new(access_mode: Option<AccessMode>, budget: Option<bool>) -> Result<Self, Error> {
        if access_mode == Some(AccessMode::SessionToken) {
            return Err(Error::new(
                "r3: invalid operation access-mode annotation \"session-token\"",
            ));
        }
        Ok(Self {
            access_mode,
            budget,
        })
    }

    /// The published replacement for the Resource-wide `access_mode`, when present.
    pub fn access_mode(&self) -> Option<AccessMode> {
        self.access_mode
    }

    /// The published budget annotation, when present.
    pub fn budget(&self) -> Option<bool> {
        self.budget
    }

    /// Publisher rule: `budget:true` must not be published with `agent-token`
    /// or `person-token`.
    ///
    /// An agent reading a remote publication uses [`Self::plan`] instead, which
    /// applies the receiver fallback rather than refusing.
    ///
    /// # Errors
    /// Returns [`Error`] for that combination.
    pub fn validate_for_publication(&self) -> Result<(), Error> {
        if let (Some(mode @ (AccessMode::AgentToken | AccessMode::PersonToken)), Some(true)) =
            (self.access_mode, self.budget)
        {
            return Err(Error::new(format!(
                "r3: budget:true must not be published with access mode \"{mode}\""
            )));
        }
        Ok(())
    }

    /// The credential an agent should expect to need. It grants nothing.
    ///
    /// An absent access-mode annotation takes `resource_default`. With
    /// `budget:true`, a mode below `auth-token` (including a `session-token`
    /// default) becomes `auth-token`; `per-call` stays `per-call`.
    pub fn plan(&self, resource_default: AccessMode) -> ExpectedAccess {
        let budget_required = self.budget == Some(true);
        let publisher_conflict = budget_required
            && matches!(
                self.access_mode,
                Some(AccessMode::AgentToken | AccessMode::PersonToken)
            );
        let mut access_mode = self.access_mode.unwrap_or(resource_default);
        if budget_required && access_mode.below_auth_token() {
            access_mode = AccessMode::AuthToken;
        }
        ExpectedAccess {
            access_mode,
            budget_required,
            publisher_conflict,
        }
    }
}

/// An agent's planning interpretation of published hints. It carries no credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedAccess {
    access_mode: AccessMode,
    budget_required: bool,
    publisher_conflict: bool,
}

impl ExpectedAccess {
    /// Credential mode the agent should expect to need.
    pub fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    /// Whether the operation is published as drawing a budget.
    pub fn budget_required(&self) -> bool {
        self.budget_required
    }

    /// Whether the publication combined `budget:true` with an explicit
    /// `agent-token` or `person-token` annotation, which the draft forbids.
    pub fn publisher_conflict(&self) -> bool {
        self.publisher_conflict
    }
}
