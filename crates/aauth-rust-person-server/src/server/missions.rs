use super::*;
use crate::{MissionRecord, MissionState, MissionStoreError};

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    pub(super) fn load_mission(
        &self,
        agent: &VerifiedAgentToken,
        s256: &str,
        at: i64,
        context: BindingContext,
    ) -> Result<MissionRecord, Failure> {
        if self.federation.is_some() || agent.claims().parent_agent.is_some() {
            return Err(Failure::parameter("invalid_request"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(s256)
            .map_err(|_| Failure::parameter("invalid_request"))?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != s256 {
            return Err(Failure::parameter("invalid_request"));
        }
        let owner = Self::identity(agent);
        let record = self
            .store
            .missions()
            .ok_or_else(|| Failure::parameter("invalid_request"))?
            .load_mission(&self.config.issuer, &owner, s256, at)
            .map_err(|e| mission_failure(e, context))?;
        record.validate().map_err(|_| Failure::internal())?;
        if record.person_server != self.config.issuer
            || record.owner != owner
            || record.document.s256() != s256
        {
            return Err(Failure::internal());
        }
        if let MissionState::Terminated(reason) = &record.state {
            return Err(Failure::mission_terminated(reason));
        }
        if record.document.expires_at().is_some_and(|exp| at >= exp) {
            return Err(Failure::mission_terminated("expired"));
        }
        Ok(record)
    }
    pub(super) fn recheck_mission(
        &self,
        agent: &VerifiedAgentToken,
        expected: Option<&MissionRecord>,
        at: i64,
        context: BindingContext,
    ) -> Result<(), Failure> {
        if let Some(expected) = expected {
            let current = self.load_mission(agent, expected.document.s256(), at, context)?;
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
        if let Some(mission) = mission {
            self.store
                .missions()
                .ok_or_else(Failure::internal)?
                .commit_mission_token(mission, (self.clock)(), record, establish)
                .map_err(|e| mission_failure(e, context))
        } else {
            self.store
                .commit(record, establish)
                .map_err(|e| store_issuance_failure(e, context))
        }
    }
}
fn mission_failure(error: MissionStoreError, context: BindingContext) -> Failure {
    match error {
        MissionStoreError::NotFound => Failure::parameter("invalid_request"),
        MissionStoreError::Terminated(reason) => Failure::mission_terminated(&reason),
        MissionStoreError::Storage(error) => store_issuance_failure(error, context),
        MissionStoreError::Conflict => Failure::internal(),
    }
}
