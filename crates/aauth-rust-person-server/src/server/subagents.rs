use super::*;

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    pub(super) fn subagent(
        &self,
        parent: &VerifiedAgentToken,
        parameters: &Value,
        now: i64,
    ) -> Result<Option<VerifiedAgentToken>, Failure> {
        let Some(compact) = parameters.get("subagent_token") else {
            return Ok(None);
        };
        let compact = compact
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Failure::parameter("invalid_subagent_token"))?;
        let child = aauth_rust_core::verify_subagent(compact, parent, &self.resolver(), now)
            .map_err(|error| Failure::token(error, "subagent", now))?;
        if child
            .claims()
            .ps
            .as_deref()
            .is_some_and(|ps| ps != self.config.issuer)
        {
            return Err(Failure::parameter("invalid_subagent_token"));
        }
        check_parameter_iat(child.claims().iat, now)?;
        Ok(Some(child))
    }

    pub(super) fn subagent_current(
        &self,
        parent: &VerifiedAgentToken,
        child: Option<&VerifiedAgentToken>,
        now: i64,
    ) -> Result<(), Failure> {
        if let Some(child) = child {
            // A host boundary may change keys or time after the original check.
            let parent = AgentToken::parse(parent.compact())
                .and_then(|t| t.verify(&self.resolver(), now))
                .map_err(Failure::credential)?;
            aauth_rust_core::verify_subagent(child.compact(), &parent, &self.resolver(), now)
                .map_err(|error| Failure::token(error, "subagent", now))?;
            let current = (self.clock)();
            check_agent_current(&parent, current)?;
            check_subagent_current(Some(child), current)?;
        }
        Ok(())
    }
}
