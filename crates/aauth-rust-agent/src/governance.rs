//! Signed posts to a Person Server interaction, permission, or audit endpoint.
//! No transport. [`PermissionDecision`] and [`InteractionCompletion`] are helpers
//! for the host. No library poller calls them. A denied permission does not
//! proceed. A Person Server relay resolving does not complete a resource-hosted
//! interaction.
use crate::Agent;
use aauth_rust_signature_key::Error as SignError;
use http::Request;
use serde_json::{Value, json};

/// The agent could not build a governance request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// A required field was missing or not one of the accepted tokens.
    #[error("governance request is missing a required field")]
    Incomplete,
    /// The Signature-Key proof could not be attached.
    #[error("could not sign governance request")]
    Signing,
    /// The Person Server reported this mission terminated. The agent stops
    /// acting on it; propose a new mission instead.
    #[error("mission is terminated; stop acting on it")]
    MissionTerminated,
}

/// Whether the person allowed an action that no resource governs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionDecision {
    /// The agent may perform the action.
    Granted,
    /// The agent must not perform the action.
    Denied,
}

impl PermissionDecision {
    /// Read the permission field. Any other body is incomplete.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Incomplete`] when `permission` is missing or neither
    /// `granted` nor `denied`.
    pub fn parse(bytes: &[u8]) -> Result<Self, ChannelError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| ChannelError::Incomplete)?;
        match value.get("permission").and_then(Value::as_str) {
            Some("granted") => Ok(Self::Granted),
            Some("denied") => Ok(Self::Denied),
            _ => Err(ChannelError::Incomplete),
        }
    }

    /// `true` only for an explicit grant.
    pub fn may_proceed(&self) -> bool {
        matches!(self, Self::Granted)
    }
}

/// Which pending URL says a resource-hosted interaction is finished.
/// The resource's pending URL stays authoritative after the Person Server relay resolves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InteractionCompletion {
    resource_pending: String,
    resource_done: bool,
    person_server_done: bool,
}

impl InteractionCompletion {
    /// Track the resource pending URL from the original `202`.
    pub fn new(resource_pending: impl Into<String>) -> Self {
        Self {
            resource_pending: resource_pending.into(),
            resource_done: false,
            person_server_done: false,
        }
    }

    /// The URL the agent keeps polling for completion.
    pub fn poll_target(&self) -> &str {
        &self.resource_pending
    }

    /// The Person Server relay reached a terminal response. This does not complete
    /// the interaction.
    pub fn note_person_server_resolved(&mut self) {
        self.person_server_done = true;
    }

    /// The resource's own pending URL returned a terminal response.
    pub fn note_resource_resolved(&mut self) {
        self.resource_done = true;
    }

    /// Complete only when the resource pending URL has resolved.
    pub fn is_complete(&self) -> bool {
        self.resource_done
    }

    /// Whether the Person Server relay has already resolved.
    pub fn person_server_resolved(&self) -> bool {
        self.person_server_done
    }
}

impl Agent {
    /// Signed `jwt` POST asking the Person Server to relay an `interaction`
    /// or `payment` to the person: the `url` and `code` a resource gave.
    ///
    /// # Errors
    ///
    /// `kind` must be `interaction` or `payment`, and `url` and `code` must
    /// not be empty. Signing failures become [`ChannelError::Signing`].
    pub fn post_interaction(
        &self,
        endpoint: &str,
        kind: &str,
        url: &str,
        code: &str,
        now: i64,
    ) -> Result<Request<Vec<u8>>, ChannelError> {
        if (kind != "interaction" && kind != "payment") || url.is_empty() || code.is_empty() {
            return Err(ChannelError::Incomplete);
        }
        self.post_json(
            endpoint,
            json!({ "type": kind, "url": url, "code": code }),
            now,
        )
    }

    /// Signed `jwt` POST of a question for the person.
    ///
    /// # Errors
    ///
    /// An empty question is [`ChannelError::Incomplete`].
    pub fn post_question(
        &self,
        endpoint: &str,
        question: &str,
        now: i64,
    ) -> Result<Request<Vec<u8>>, ChannelError> {
        if question.is_empty() {
            return Err(ChannelError::Incomplete);
        }
        self.post_json(
            endpoint,
            json!({ "type": "question", "question": question }),
            now,
        )
    }

    /// Signed `jwt` POST asking permission for one action.
    ///
    /// # Errors
    ///
    /// An empty action is [`ChannelError::Incomplete`].
    pub fn post_permission(
        &self,
        endpoint: &str,
        action: &str,
        now: i64,
    ) -> Result<Request<Vec<u8>>, ChannelError> {
        if action.is_empty() {
            return Err(ChannelError::Incomplete);
        }
        self.post_json(endpoint, json!({ "action": action }), now)
    }

    /// Signed `jwt` POST recording an action against a mission.
    ///
    /// Pass the Person Server's answer to [`crate::Missions::observe`] on
    /// [`Agent::missions`]. Once it reports the mission terminated, no further
    /// audit is built for it.
    ///
    /// # Errors
    ///
    /// An empty mission digest or action is [`ChannelError::Incomplete`]. A
    /// mission recorded as terminated is [`ChannelError::MissionTerminated`].
    pub fn post_audit(
        &self,
        endpoint: &str,
        mission_s256: &str,
        action: &str,
        now: i64,
    ) -> Result<Request<Vec<u8>>, ChannelError> {
        if mission_s256.is_empty() || action.is_empty() {
            return Err(ChannelError::Incomplete);
        }
        if !self.missions().is_active(mission_s256) {
            return Err(ChannelError::MissionTerminated);
        }
        self.post_json(
            endpoint,
            json!({ "mission_s256": mission_s256, "action": action }),
            now,
        )
    }

    fn post_json(
        &self,
        endpoint: &str,
        body: Value,
        now: i64,
    ) -> Result<Request<Vec<u8>>, ChannelError> {
        let mut request = Request::builder()
            .method("POST")
            .uri(endpoint)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).map_err(|_| ChannelError::Incomplete)?)
            .map_err(|_| ChannelError::Incomplete)?;
        self.sign(&mut request, now).map_err(|error: SignError| {
            let _ = error;
            ChannelError::Signing
        })?;
        Ok(request)
    }
}
