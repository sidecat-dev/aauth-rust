//! Agent Provider bootstrap state: enrollments, used naming-JWT identifiers
//! and the sub-agent tokens each parent requested.
use aauth_rust_jose::Jwk;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Whether an enrollment may still be refreshed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentState {
    /// Refreshes are decided by host policy.
    Active,
    /// Refreshes are refused until the host makes the enrollment active again.
    Disabled,
    /// Refreshes are refused for good (Bootstrap, Durable Key Compromise). A
    /// revoked durable key cannot enroll again; a new install brings a new one.
    Revoked,
}

/// One enrolled install: its durable key and the agent identifier the Agent
/// Provider assigned to it (Bootstrap, Per-Install Identity).
#[derive(Clone, Debug)]
pub struct Enrollment {
    /// RFC 7638 thumbprint of `durable_key`, the record's key.
    pub durable_thumbprint: String,
    /// The durable public key, as the enrollment request carried it.
    pub durable_key: Jwk,
    /// The agent identifier, `aauth:local@domain`, of every token refreshed
    /// under this enrollment.
    pub agent: String,
    /// The host's account that enrolled the install, when policy named one.
    pub account: Option<String>,
    /// Current state.
    pub state: EnrollmentState,
    /// Enrollment time, Unix seconds.
    pub enrolled_at: i64,
}

/// One sub-agent token as the Agent Provider recorded it before release
/// (Bootstrap, Sub-Agents Under a Hosted AP: record which parent requested
/// each sub-agent token, and how many are live per parent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubagentRecord {
    /// The sub-agent's identifier: the token's `sub`.
    pub agent: String,
    /// The requesting parent: the token's `parent_agent`.
    pub parent: String,
    /// The token's `jti`.
    pub jti: String,
    /// RFC 7638 thumbprint of the token's `cnf.jwk`.
    pub key_thumbprint: String,
    /// The token's `iat`, Unix seconds.
    pub issued_at: i64,
    /// The token's `exp`, Unix seconds. The record is live until then.
    pub expires_at: i64,
}

/// Bootstrap store failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapStoreError {
    /// No enrollment has this durable key thumbprint.
    NotFound,
    /// The durable key or the agent identifier is already enrolled, a live
    /// sub-agent already has this identifier, or a revoked enrollment was
    /// asked to change state.
    Conflict,
    /// The backend failed. Nothing may be assumed written.
    Unavailable,
}

impl std::fmt::Display for BootstrapStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no enrollment has this durable key",
            Self::Conflict => {
                "the durable key, agent identifier or sub-agent identifier is already taken, or the enrollment is revoked"
            }
            Self::Unavailable => "the bootstrap store failed; nothing was written",
        })
    }
}
impl std::error::Error for BootstrapStoreError {}

/// Agent Provider bootstrap state.
///
/// Each successful write must be durable before it returns: an enrollment
/// is answered, a refresh is issued and a sub-agent token is released only
/// after the write it depends on succeeds. [`MemoryBootstrapStore`] is a
/// volatile reference for tests.
pub trait BootstrapStore: Send + Sync {
    /// Record a new enrollment.
    ///
    /// # Errors
    /// [`BootstrapStoreError::Conflict`] when the durable key thumbprint or
    /// the agent identifier is already enrolled.
    /// [`BootstrapStoreError::Unavailable`] when the write did not complete.
    fn enroll(&self, enrollment: &Enrollment) -> Result<(), BootstrapStoreError>;

    /// The enrollment of the durable key with this thumbprint.
    ///
    /// # Errors
    /// [`BootstrapStoreError::Unavailable`] when the read failed.
    fn enrollment(
        &self,
        durable_thumbprint: &str,
    ) -> Result<Option<Enrollment>, BootstrapStoreError>;

    /// Change an enrollment's state, for example to let a person revoke a
    /// durable enrollment (Bootstrap, Durable Key Compromise).
    ///
    /// # Errors
    /// `NotFound` for an unknown thumbprint, `Conflict` for a revoked
    /// enrollment, `Unavailable` when the write did not complete.
    fn set_state(
        &self,
        durable_thumbprint: &str,
        state: EnrollmentState,
    ) -> Result<(), BootstrapStoreError>;

    /// In one atomic step: when the naming JWT `jti` is already recorded for
    /// this durable key, return `false`. Otherwise record it until
    /// `expires_at`, the naming JWT's `exp`, and return `true`. Entries whose
    /// `expires_at` is not after `now` may be dropped, since an expired naming
    /// JWT is refused before this call.
    ///
    /// # Errors
    /// [`BootstrapStoreError::Unavailable`] when the write did not complete.
    fn use_naming_jti(
        &self,
        durable_thumbprint: &str,
        jti: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, BootstrapStoreError>;

    /// Record a sub-agent token before it is released.
    ///
    /// # Errors
    /// [`BootstrapStoreError::Conflict`] when a record for the same sub-agent
    /// identifier is still live at `record.issued_at`, so the identifier
    /// stays unique among the parent's sub-agents while any token naming it
    /// is valid (Bootstrap, Self-Hosted Sub-Agents).
    /// [`BootstrapStoreError::Unavailable`] when the write did not complete.
    fn record_subagent(&self, record: &SubagentRecord) -> Result<(), BootstrapStoreError>;

    /// The parent's sub-agent records whose `expires_at` is after `now`.
    ///
    /// # Errors
    /// [`BootstrapStoreError::Unavailable`] when the read failed.
    fn live_subagents(
        &self,
        parent: &str,
        now: i64,
    ) -> Result<Vec<SubagentRecord>, BootstrapStoreError>;
}

impl<T: BootstrapStore + ?Sized> BootstrapStore for std::sync::Arc<T> {
    fn enroll(&self, enrollment: &Enrollment) -> Result<(), BootstrapStoreError> {
        (**self).enroll(enrollment)
    }
    fn enrollment(
        &self,
        durable_thumbprint: &str,
    ) -> Result<Option<Enrollment>, BootstrapStoreError> {
        (**self).enrollment(durable_thumbprint)
    }
    fn set_state(
        &self,
        durable_thumbprint: &str,
        state: EnrollmentState,
    ) -> Result<(), BootstrapStoreError> {
        (**self).set_state(durable_thumbprint, state)
    }
    fn use_naming_jti(
        &self,
        durable_thumbprint: &str,
        jti: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, BootstrapStoreError> {
        (**self).use_naming_jti(durable_thumbprint, jti, expires_at, now)
    }
    fn record_subagent(&self, record: &SubagentRecord) -> Result<(), BootstrapStoreError> {
        (**self).record_subagent(record)
    }
    fn live_subagents(
        &self,
        parent: &str,
        now: i64,
    ) -> Result<Vec<SubagentRecord>, BootstrapStoreError> {
        (**self).live_subagents(parent, now)
    }
}

#[derive(Default)]
struct MemoryInner {
    enrollments: BTreeMap<String, Enrollment>,
    // (durable thumbprint, jti) -> naming JWT exp.
    naming: BTreeMap<(String, String), i64>,
    // sub-agent identifier -> its latest record.
    subagents: BTreeMap<String, SubagentRecord>,
}

/// Volatile in-memory [`BootstrapStore`]. Its records do not survive the
/// process, so it does not meet the durability an Agent Provider needs in
/// production. Expired naming-JWT identifiers and sub-agent records are
/// dropped as later writes find them.
#[derive(Default)]
pub struct MemoryBootstrapStore {
    inner: Mutex<MemoryInner>,
}

impl MemoryBootstrapStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryInner>, BootstrapStoreError> {
        self.inner
            .lock()
            .map_err(|_| BootstrapStoreError::Unavailable)
    }
}

impl BootstrapStore for MemoryBootstrapStore {
    fn enroll(&self, enrollment: &Enrollment) -> Result<(), BootstrapStoreError> {
        let mut inner = self.lock()?;
        if inner
            .enrollments
            .contains_key(&enrollment.durable_thumbprint)
            || inner
                .enrollments
                .values()
                .any(|known| known.agent == enrollment.agent)
        {
            return Err(BootstrapStoreError::Conflict);
        }
        inner
            .enrollments
            .insert(enrollment.durable_thumbprint.clone(), enrollment.clone());
        Ok(())
    }
    fn enrollment(
        &self,
        durable_thumbprint: &str,
    ) -> Result<Option<Enrollment>, BootstrapStoreError> {
        Ok(self.lock()?.enrollments.get(durable_thumbprint).cloned())
    }
    fn set_state(
        &self,
        durable_thumbprint: &str,
        state: EnrollmentState,
    ) -> Result<(), BootstrapStoreError> {
        let mut inner = self.lock()?;
        let enrollment = inner
            .enrollments
            .get_mut(durable_thumbprint)
            .ok_or(BootstrapStoreError::NotFound)?;
        if enrollment.state == EnrollmentState::Revoked && state != EnrollmentState::Revoked {
            return Err(BootstrapStoreError::Conflict);
        }
        enrollment.state = state;
        Ok(())
    }
    fn use_naming_jti(
        &self,
        durable_thumbprint: &str,
        jti: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, BootstrapStoreError> {
        let mut inner = self.lock()?;
        inner.naming.retain(|_, until| *until > now);
        let key = (durable_thumbprint.to_owned(), jti.to_owned());
        if inner.naming.contains_key(&key) {
            return Ok(false);
        }
        inner.naming.insert(key, expires_at);
        Ok(true)
    }
    fn record_subagent(&self, record: &SubagentRecord) -> Result<(), BootstrapStoreError> {
        let mut inner = self.lock()?;
        let now = record.issued_at;
        inner.subagents.retain(|_, known| known.expires_at > now);
        if inner.subagents.contains_key(&record.agent) {
            return Err(BootstrapStoreError::Conflict);
        }
        inner.subagents.insert(record.agent.clone(), record.clone());
        Ok(())
    }
    fn live_subagents(
        &self,
        parent: &str,
        now: i64,
    ) -> Result<Vec<SubagentRecord>, BootstrapStoreError> {
        Ok(self
            .lock()?
            .subagents
            .values()
            .filter(|record| record.parent == parent && record.expires_at > now)
            .cloned()
            .collect())
    }
}
