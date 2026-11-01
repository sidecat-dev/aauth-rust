use super::*;
use crate::{MissionRecord, MissionState, MissionStoreError};

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Load `owner`'s active mission. The owner is the requesting Agent, or on
    /// a chained request the calling Agent the upstream token was issued to.
    pub(super) fn load_mission(
        &self,
        owner: &AgentIdentity,
        s256: &str,
        at: i64,
        context: BindingContext,
    ) -> Result<MissionRecord, Failure> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s256)
            .map_err(|_| Failure::parameter("invalid_request"))?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != s256 {
            return Err(Failure::parameter("invalid_request"));
        }
        let record = self
            .store
            .missions()
            .ok_or_else(|| Failure::parameter("invalid_request"))?
            .load_mission(&self.config.issuer, owner, s256, at)
            .map_err(|e| {
                if let MissionStoreError::Terminated(reason) = &e {
                    self.report_mission_end(owner, s256, reason, None);
                }
                mission_failure(e, context)
            })?;
        record.validate().map_err(|_| Failure::internal())?;
        if record.person_server != self.config.issuer
            || &record.owner != owner
            || record.document.s256() != s256
        {
            return Err(Failure::internal());
        }
        if let MissionState::Terminated(reason) = &record.state {
            return Err(self.mission_ended(owner, s256, reason));
        }
        if record.document.expires_at().is_some_and(|exp| at >= exp) {
            return Err(self.mission_ended(owner, s256, "expired"));
        }
        Ok(record)
    }
    /// A mission found ended: its supervision server is told once, and the
    /// request is refused with `mission_terminated`.
    pub(super) fn mission_ended(&self, owner: &AgentIdentity, s256: &str, reason: &str) -> Failure {
        self.report_mission_end(owner, s256, reason, None);
        Failure::mission_terminated(reason)
    }
    pub(super) fn recheck_mission(
        &self,
        expected: Option<&MissionRecord>,
        at: i64,
        context: BindingContext,
    ) -> Result<(), Failure> {
        if let Some(expected) = expected {
            let current =
                self.load_mission(&expected.owner, expected.document.s256(), at, context)?;
            if &current != expected {
                return Err(Failure::internal());
            }
        }
        Ok(())
    }
    pub(super) fn commit_issuance(
        &self,
        record: TokenRecord,
        establish: bool,
        mission: Option<&MissionRecord>,
        context: BindingContext,
    ) -> Result<(), Failure> {
        self.retain(record, establish, mission)
            .map_err(|e| mission_failure(e, context))
    }
    /// Retain `record`, through the mission boundary when a mission bounds it,
    /// so the store checks the unchanged active mission atomically with the
    /// write. A federated receipt goes the same way.
    pub(super) fn retain(
        &self,
        record: TokenRecord,
        establish: bool,
        mission: Option<&MissionRecord>,
    ) -> Result<(), MissionStoreError> {
        match mission {
            Some(mission) => self
                .store
                .missions()
                .ok_or(StoreError::Unavailable)?
                .commit_mission_token(mission, (self.clock)(), record, establish)
                .inspect_err(|e| {
                    if let MissionStoreError::Terminated(reason) = e {
                        self.report_mission_end(
                            &mission.owner,
                            mission.document.s256(),
                            reason,
                            None,
                        );
                    }
                }),
            None => Ok(self.store.commit(record, establish)?),
        }
    }
}
pub(super) fn mission_failure(error: MissionStoreError, context: BindingContext) -> Failure {
    match error {
        // On a chained request the mission comes from the upstream token,
        // not from a parameter the intermediary sent.
        MissionStoreError::NotFound => match context {
            BindingContext::Upstream => Failure::parameter("invalid_upstream_token"),
            _ => Failure::parameter("invalid_request"),
        },
        MissionStoreError::Terminated(reason) => Failure::mission_terminated(&reason),
        MissionStoreError::Storage(error) => store_issuance_failure(error, context),
        MissionStoreError::Conflict => Failure::internal(),
    }
}
