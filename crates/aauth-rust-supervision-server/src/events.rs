//! What happened: events, and the mission endpoint's approval and
//! termination reports. Each is recorded once per `(iss, id)` and answered
//! `201` with no body; nothing here is decided.
use crate::records::{self, DECISION, MISSION, SEEN};
use crate::{Answer, Observation, Policy, Refusal, SupervisionServer, refuse, server_error};
use aauth_rust_core::continuation::ContinuationStore;
use aauth_rust_core::supervision::{
    Answer as Reach, Envelope, EventKind, Resolution, Resolved, SupervisionError,
};
use aauth_rust_core::{AgentKeyResolver, ApprovedMission};
use http::{Request, Response, StatusCode};
use serde_json::{Map, Value, json};

fn invalid() -> Refusal {
    refuse(SupervisionError::InvalidRequest)
}

fn created() -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = StatusCode::CREATED;
    response
}

impl<K: AgentKeyResolver, P: Policy, S: ContinuationStore, C: Fn() -> i64>
    SupervisionServer<K, P, S, C>
{
    pub(crate) fn event(&self, request: &Request<Vec<u8>>, now: i64) -> Answer {
        let ps = self.authenticate(request, now)?;
        let body = Self::object(request)?;
        let envelope = Envelope::parse(&body).map_err(|_| invalid())?;
        let id = envelope.id.clone().ok_or_else(invalid)?;
        let kind = body
            .get("event")
            .and_then(Value::as_str)
            .and_then(EventKind::parse)
            .ok_or_else(invalid)?;
        if kind
            .required_members()
            .iter()
            .any(|member| !body.contains_key(*member))
        {
            return Err(invalid());
        }
        let resolution = match kind {
            EventKind::DecisionResolved => Some(Resolution::parse(&body).map_err(|_| invalid())?),
            _ => None,
        };
        self.require_connection(&ps, &envelope.sub)?;
        if let Some(s256) = &envelope.mission_s256 {
            let (_, owner) = self
                .mission_view(&ps, &envelope.sub, s256)
                .map_err(|_| server_error())?
                .ok_or_else(|| refuse(SupervisionError::UnknownMission))?;
            if owner != envelope.agent {
                return Err(invalid());
            }
        }
        if !self.first_delivery(&ps, &id)? {
            return Ok(created());
        }
        if let (Some(resolution), Some(sdi)) = (&resolution, &envelope.sdi) {
            self.resolve(&ps, sdi, resolution)
                .map_err(|_| server_error())?;
        }
        self.policy.observe(&Observation {
            ps,
            sub: envelope.sub,
            name: kind.name().to_owned(),
            body,
        });
        Ok(created())
    }

    /// Record the mission bytes the agent received, after checking them.
    pub(crate) fn approved(&self, ps: &str, body: Map<String, Value>, s256: &str) -> Answer {
        let envelope = Envelope::parse(&body).map_err(|_| invalid())?;
        let id = envelope.id.clone().ok_or_else(invalid)?;
        if body.get("s256").and_then(Value::as_str) != Some(s256) {
            return Err(invalid());
        }
        let encoded = body
            .get("mission")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        // The SHOULD of Approved: s256 is the digest of the mission bytes.
        let mission = ApprovedMission::decode(s256, encoded).map_err(|_| invalid())?;
        if mission.agent() != envelope.agent {
            return Err(invalid());
        }
        self.require_connection(ps, &envelope.sub)?;
        if !self.first_delivery(ps, &id)? {
            return Ok(created());
        }
        let record = json!({
            "agent": envelope.agent, "mission": encoded, "description": mission.description(),
            "sdi": envelope.sdi,
        });
        records::update(
            &self.store,
            &records::key(MISSION, &[ps, &envelope.sub, s256]),
            |current| match current {
                Some(existing) => Some(existing.clone()),
                None => Some(record.clone()),
            },
        )
        .map_err(|_| server_error())?;
        self.policy.observe(&Observation {
            ps: ps.to_owned(),
            sub: envelope.sub,
            name: "approved".into(),
            body,
        });
        Ok(created())
    }

    /// Mark a mission ended and drop answers limited to it.
    pub(crate) fn terminated(&self, ps: &str, body: Map<String, Value>, s256: &str) -> Answer {
        let envelope = Envelope::parse(&body).map_err(|_| invalid())?;
        let id = envelope.id.clone().ok_or_else(invalid)?;
        let reason = body
            .get("reason")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty() && r.len() <= 256)
            .ok_or_else(invalid)?
            .to_owned();
        if envelope.mission_s256.as_deref().is_some_and(|m| m != s256) {
            return Err(invalid());
        }
        self.require_connection(ps, &envelope.sub)?;
        if !self.first_delivery(ps, &id)? {
            return Ok(created());
        }
        records::update(
            &self.store,
            &records::key(MISSION, &[ps, &envelope.sub, s256]),
            |current| {
                let mut record = current?.clone();
                record["terminated"] = json!(reason);
                Some(record)
            },
        )
        .map_err(|_| server_error())?;
        self.forget_mission(ps, &envelope.sub, &envelope.agent, s256)
            .map_err(|_| server_error())?;
        self.policy.observe(&Observation {
            ps: ps.to_owned(),
            sub: envelope.sub,
            name: "terminated".into(),
            body,
        });
        Ok(created())
    }

    /// `true` the first time `(iss, id)` arrives.
    fn first_delivery(&self, ps: &str, id: &str) -> Result<bool, Refusal> {
        records::insert_new(&self.store, &records::key(SEEN, &[ps, id]), json!({}))
            .map_err(|_| server_error())
    }

    /// Note what the person decided against the decision it follows, and
    /// remember an answer whose reach goes beyond this act.
    fn resolve(&self, ps: &str, sdi: &str, resolution: &Resolution) -> Result<(), records::Fault> {
        records::update(
            &self.store,
            &records::key(DECISION, &[ps, sdi]),
            |current| {
                let mut record = current?.clone();
                record["resolved"] = json!(resolution.answer.as_str());
                Some(record)
            },
        )?;
        let answer = match resolution.answer {
            Resolved::Allow => Reach::Allow,
            Resolved::Deny => Reach::Deny,
            Resolved::Abandoned => return Ok(()),
        };
        match &resolution.apply {
            Some(apply) => self.remember(ps, sdi, apply, answer),
            None => Ok(()),
        }
    }
}
