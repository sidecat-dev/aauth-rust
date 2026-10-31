//! The mission and decision endpoints: supervision requests, their pending
//! URLs, clarification, idempotence and the person's standing answers.
use crate::records::{self, DECISION, MISSION, PENDING, STANDING};
use crate::{
    Answer, Case, HostError, MissionView, Policy, Refusal, Round, SupervisionServer, Verdict,
    deferred, json_response, refuse, server_error,
};
use aauth_rust_core::continuation::ContinuationStore;
use aauth_rust_core::supervision::{
    Act, Allowance, Answer as Reach, Decision, Envelope, REACH_ALWAYS, REACH_MISSION,
    SupervisionError, Tool, is_digest, server_list, valid_scope,
};
use aauth_rust_core::{AgentKeyResolver, AgentToken, validate_server_identifier};
use http::{Request, Response, StatusCode};
use serde_json::{Map, Value, json};

const MAX_ROUNDS: usize = 16;
const MAX_STANDING: usize = 256;

/// An answer the person gave with the `mission` or `always` reach, which
/// this server applies to later acts of the same kind before its policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingAnswer {
    /// The kind of act, as [`Policy::kind`] names it.
    pub kind: String,
    /// The mission it is limited to; `None` for `always`.
    pub mission_s256: Option<String>,
    /// The person's answer.
    pub answer: Reach,
}

fn invalid() -> Refusal {
    refuse(SupervisionError::InvalidRequest)
}

impl<K: AgentKeyResolver, P: Policy, S: ContinuationStore, C: Fn() -> i64>
    SupervisionServer<K, P, S, C>
{
    pub(crate) fn decision(&self, request: &Request<Vec<u8>>, now: i64) -> Answer {
        let ps = self.authenticate(request, now)?;
        let body = Self::object(request)?;
        let act = body
            .get("act")
            .and_then(Value::as_str)
            .and_then(Act::from_decision_act)
            .ok_or_else(invalid)?;
        self.supervise(request, now, &ps, act, body, None)
    }

    pub(crate) fn mission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        s256: Option<&str>,
    ) -> Answer {
        let ps = self.authenticate(request, now)?;
        let body = Self::object(request)?;
        let Some(s256) = s256 else {
            return self.supervise(request, now, &ps, Act::MissionProposal, body, None);
        };
        if !is_digest(s256) {
            return Err(invalid());
        }
        match body.get("action").and_then(Value::as_str) {
            Some("update") => {
                self.supervise(request, now, &ps, Act::MissionUpdate, body, Some(s256))
            }
            Some("completion") => {
                self.supervise(request, now, &ps, Act::MissionCompletion, body, Some(s256))
            }
            Some("approved") => self.approved(&ps, body, s256),
            Some("terminated") => self.terminated(&ps, body, s256),
            _ => Err(invalid()),
        }
    }

    fn supervise(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        ps: &str,
        act: Act,
        body: Map<String, Value>,
        path_mission: Option<&str>,
    ) -> Answer {
        let envelope = Envelope::parse(&body).map_err(|_| invalid())?;
        let sdi = envelope.sdi.clone().ok_or_else(invalid)?;
        self.require_connection(ps, &envelope.sub)?;
        check_members(act, &body, &envelope).map_err(|_| invalid())?;
        let mission_s256 = match (path_mission, envelope.mission_s256.as_deref()) {
            (Some(path), Some(named)) if path != named => return Err(invalid()),
            (Some(path), _) => Some(path.to_owned()),
            (None, named) => named.map(str::to_owned),
        };
        let mission = match &mission_s256 {
            Some(s256) => Some(self.known_mission(ps, &envelope.sub, &envelope.agent, s256)?),
            None => None,
        };
        let key = records::key(DECISION, &[ps, &sdi]);
        if let Some(existing) = records::load(&self.store, &key).map_err(|_| server_error())? {
            return self.repeat(request, &existing, act, &envelope.agent);
        }
        let case = Case {
            ps: ps.to_owned(),
            sub: envelope.sub.clone(),
            agent: envelope.agent.clone(),
            act,
            sdi: sdi.clone(),
            mission,
            request: body.clone(),
            rounds: Vec::new(),
        };
        let verdict = match self.standing_verdict(&case).map_err(|_| server_error())? {
            Some(verdict) => verdict,
            None => self.policy.decide(&case),
        };
        let mut record = json!({
            "ps": ps, "sub": envelope.sub, "agent": envelope.agent, "act": act.name(),
            "sdi": sdi, "mission_s256": mission_s256, "request": Value::Object(body),
            "rounds": [], "created": now, "state": "new",
        });
        let settled = self
            .settle(&mut record, verdict)
            .map_err(|_| server_error())?;
        let response = self.render(request, &record, settled)?;
        if record["state"] == "decided" {
            record["response"] = records::encode_response(&response);
        }
        if !records::insert_new(&self.store, &key, record).map_err(|_| server_error())? {
            // A concurrent copy of this request won; answer as it was answered.
            let existing = records::load(&self.store, &key)
                .map_err(|_| server_error())?
                .ok_or_else(server_error)?;
            return self.repeat(request, &existing, act, &envelope.agent);
        }
        Ok(response)
    }

    /// Answer a repeated supervision request under a known `sdi`: the same
    /// signed response for a synchronous decision, the decision signed for
    /// this request when it was reached later, or `202` with the same `Location`.
    fn repeat(
        &self,
        request: &Request<Vec<u8>>,
        existing: &Value,
        act: Act,
        agent: &str,
    ) -> Answer {
        if existing["act"].as_str() != Some(act.name()) || existing["agent"].as_str() != Some(agent)
        {
            return Err(invalid());
        }
        if existing["state"] == "decided" {
            if let Some(stored) = existing.get("response") {
                return records::decode_response(stored).map_err(|_| server_error());
            }
            return self.sign(
                json_response(StatusCode::OK, existing["decision"].clone()),
                request,
            );
        }
        Ok(self.pending_wire(existing))
    }

    /// Apply a verdict to a decision record. A pending URL is assigned the
    /// first time the record leaves the synchronous path.
    fn settle(&self, record: &mut Value, verdict: Verdict) -> Result<bool, records::Fault> {
        let act = record["act"]
            .as_str()
            .and_then(Act::from_name)
            .ok_or(records::Fault)?;
        let sdi = record["sdi"].as_str().ok_or(records::Fault)?.to_owned();
        let decision = match verdict {
            Verdict::Allow(allowance) => Some(Decision::Allow(fit(act, allowance)?)),
            Verdict::Deny(reason) => Some(Decision::Deny { reason }),
            Verdict::Ask(mut ask) => {
                if act != Act::MissionProposal {
                    ask.proposed = None;
                }
                Some(Decision::Ask(ask))
            }
            Verdict::Clarify {
                question,
                timeout,
                options,
            } => {
                if question.is_empty() {
                    return Err(records::Fault);
                }
                record["state"] = json!("clarifying");
                record["question"] = json!({
                    "clarification": question, "timeout": timeout, "options": options,
                });
                None
            }
            Verdict::Defer => {
                record["state"] = json!("deciding");
                None
            }
        };
        if let Some(decision) = decision {
            record["state"] = json!("decided");
            record["decision"] = decision.to_value(&sdi);
            return Ok(true);
        }
        if record.get("pending").is_none_or(Value::is_null) {
            let id = aauth_rust_core::continuation::generate_pending_id();
            let ps = record["ps"].as_str().ok_or(records::Fault)?;
            records::insert_new(
                &self.store,
                &records::key(PENDING, &[&id]),
                json!({ "ps": ps, "sdi": sdi }),
            )?;
            record["pending"] = json!(id);
        }
        Ok(false)
    }

    /// The answer a settled record gives to `request`.
    fn render(&self, request: &Request<Vec<u8>>, record: &Value, decided: bool) -> Answer {
        if decided {
            return self.sign(
                json_response(StatusCode::OK, record["decision"].clone()),
                request,
            );
        }
        Ok(self.pending_wire(record))
    }

    fn pending_wire(&self, record: &Value) -> Response<Vec<u8>> {
        let location = self.pending_url("/pending/", record["pending"].as_str().unwrap_or(""));
        let sdi = record["sdi"].clone();
        if record["state"] == "clarifying" {
            let question = &record["question"];
            let mut body = json!({
                "sdi": sdi, "status": "pending", "decision": "clarify",
                "clarification": question["clarification"],
            });
            if let Some(timeout) = question["timeout"].as_u64() {
                body["timeout"] = json!(timeout);
            }
            if question["options"]
                .as_array()
                .is_some_and(|o| !o.is_empty())
            {
                body["options"] = question["options"].clone();
            }
            return deferred(&location, 0, Some("requirement=clarification".into()), body);
        }
        deferred(
            &location,
            self.config.retry_after,
            None,
            json!({ "sdi": sdi, "status": "pending" }),
        )
    }

    /// A poll, clarification reply or cancellation at a pending URL.
    pub(crate) fn pending(&self, request: &Request<Vec<u8>>, now: i64, id: &str) -> Answer {
        let ps = self.authenticate(request, now)?;
        let unknown = || refuse(SupervisionError::UnknownPending);
        let index_key = records::key(PENDING, &[id]);
        let index = records::load(&self.store, &index_key)
            .map_err(|_| server_error())?
            .ok_or_else(unknown)?;
        if index["ps"].as_str() != Some(ps.as_str()) {
            return Err(unknown());
        }
        let sdi = index["sdi"].as_str().ok_or_else(server_error)?.to_owned();
        let key = records::key(DECISION, &[&ps, &sdi]);
        let mut record = records::load(&self.store, &key)
            .map_err(|_| server_error())?
            .ok_or_else(unknown)?;
        let decided = record["state"] == "decided";
        let expired = record["created"]
            .as_i64()
            .is_none_or(|at| now >= at.saturating_add(self.config.pending_lifetime));
        if !decided && expired {
            records::remove(&self.store, &index_key).map_err(|_| server_error())?;
            return Err(unknown());
        }
        match request.method().as_str() {
            "GET" => {
                if !request.body().is_empty() {
                    return Err(invalid());
                }
                self.render(request, &record, decided)
            }
            "DELETE" => {
                records::remove(&self.store, &index_key).map_err(|_| server_error())?;
                if !decided {
                    records::remove(&self.store, &key).map_err(|_| server_error())?;
                }
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "status": "cancelled" }),
                ))
            }
            _ => {
                let body = Self::object(request)?;
                if record["state"] != "clarifying" {
                    return Err(invalid());
                }
                let question = record["question"]["clarification"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned();
                let answer = match body.get("action").and_then(Value::as_str) {
                    Some("clarification_response") => body
                        .get("clarification_response")
                        .and_then(Value::as_str)
                        .filter(|a| !a.is_empty() && a.len() <= 65_536)
                        .ok_or_else(invalid)?
                        .to_owned(),
                    Some("updated_request") => {
                        if record["act"] != Act::AuthToken.name() {
                            return Err(invalid());
                        }
                        for member in ["resource_token", "presented_token"] {
                            let token = body
                                .get(member)
                                .and_then(Value::as_str)
                                .filter(|t| !t.is_empty())
                                .ok_or_else(invalid)?;
                            record["request"][member] = json!(token);
                        }
                        match body.get("justification") {
                            None => "The agent updated its request.".to_owned(),
                            Some(Value::String(text)) if !text.is_empty() => {
                                record["request"]["justification"] = json!(text);
                                text.clone()
                            }
                            Some(_) => return Err(invalid()),
                        }
                    }
                    _ => return Err(invalid()),
                };
                let rounds = record["rounds"].as_array_mut().ok_or_else(server_error)?;
                if rounds.len() >= MAX_ROUNDS {
                    return Err(invalid());
                }
                rounds.push(json!({ "question": question, "answer": answer }));
                let case = self.case(&record).map_err(|_| server_error())?;
                let verdict = self.policy.decide(&case);
                let decided = self
                    .settle(&mut record, verdict)
                    .map_err(|_| server_error())?;
                records::update(&self.store, &key, |_| Some(record.clone()))
                    .map_err(|_| server_error())?;
                self.render(request, &record, decided)
            }
        }
    }

    /// Decide an act the policy deferred, or ask the agent about it. The
    /// Person Server's next poll receives the answer, signed for that poll.
    ///
    /// # Errors
    /// [`HostError::NotFound`] when `(ps, sdi)` is unknown or already
    /// decided, and [`HostError::InvalidVerdict`] for a proposal allowed
    /// without mission terms or an empty question.
    pub fn decide_pending(&self, ps: &str, sdi: &str, verdict: Verdict) -> Result<(), HostError> {
        let key = records::key(DECISION, &[ps, sdi]);
        let mut record = records::load(&self.store, &key)?.ok_or(HostError::NotFound)?;
        if record["state"] == "decided" {
            return Err(HostError::NotFound);
        }
        self.settle(&mut record, verdict)
            .map_err(|_| HostError::InvalidVerdict)?;
        records::update(&self.store, &key, |_| Some(record.clone()))?;
        Ok(())
    }

    /// The act behind a pending decision, as the policy saw it.
    ///
    /// # Errors
    /// [`HostError::NotFound`] when `(ps, sdi)` is unknown.
    pub fn pending_case(&self, ps: &str, sdi: &str) -> Result<Case, HostError> {
        let record = records::load(&self.store, &records::key(DECISION, &[ps, sdi]))?
            .ok_or(HostError::NotFound)?;
        self.case(&record).map_err(|_| HostError::Unavailable)
    }

    /// The person's standing answers for one agent, oldest first.
    ///
    /// # Errors
    /// [`HostError::Unavailable`] when the store fails.
    pub fn standing(
        &self,
        ps: &str,
        sub: &str,
        agent: &str,
    ) -> Result<Vec<StandingAnswer>, HostError> {
        let record = records::load(&self.store, &records::key(STANDING, &[ps, sub, agent]))?;
        Ok(record
            .as_ref()
            .and_then(|r| r["entries"].as_array())
            .map(|entries| entries.iter().filter_map(standing_entry).collect())
            .unwrap_or_default())
    }

    pub(crate) fn case(&self, record: &Value) -> Result<Case, records::Fault> {
        let text = |name: &str| {
            record[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(records::Fault)
        };
        let ps = text("ps")?;
        let sub = text("sub")?;
        let mission = match record["mission_s256"].as_str() {
            Some(s256) => self.mission_view(&ps, &sub, s256)?.map(|(view, _)| view),
            None => None,
        };
        Ok(Case {
            act: record["act"]
                .as_str()
                .and_then(Act::from_name)
                .ok_or(records::Fault)?,
            agent: text("agent")?,
            sdi: text("sdi")?,
            mission,
            request: record["request"]
                .as_object()
                .cloned()
                .ok_or(records::Fault)?,
            rounds: record["rounds"]
                .as_array()
                .map(|rounds| {
                    rounds
                        .iter()
                        .map(|r| Round {
                            question: r["question"].as_str().unwrap_or("").into(),
                            answer: r["answer"].as_str().unwrap_or("").into(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            ps,
            sub,
        })
    }

    /// The mission this server holds for `(ps, sub, s256)` and its agent.
    pub(crate) fn mission_view(
        &self,
        ps: &str,
        sub: &str,
        s256: &str,
    ) -> Result<Option<(MissionView, String)>, records::Fault> {
        let Some(record) = records::load(&self.store, &records::key(MISSION, &[ps, sub, s256]))?
        else {
            return Ok(None);
        };
        Ok(Some((
            MissionView {
                s256: s256.into(),
                mission: record["mission"].as_str().unwrap_or("").into(),
                description: record["description"].as_str().unwrap_or("").into(),
                terminated: record["terminated"].as_str().map(str::to_owned),
            },
            record["agent"].as_str().unwrap_or("").into(),
        )))
    }

    /// The mission an act names, or `unknown_mission`. Another agent's
    /// mission is `invalid_request`.
    fn known_mission(
        &self,
        ps: &str,
        sub: &str,
        agent: &str,
        s256: &str,
    ) -> Result<MissionView, Refusal> {
        let (view, owner) = self
            .mission_view(ps, sub, s256)
            .map_err(|_| server_error())?
            .ok_or_else(|| refuse(SupervisionError::UnknownMission))?;
        if owner != agent {
            return Err(invalid());
        }
        Ok(view)
    }

    /// The person's latest standing answer for an act of this kind.
    fn standing_verdict(&self, case: &Case) -> Result<Option<Verdict>, records::Fault> {
        if !matches!(
            case.act,
            Act::PersonToken | Act::AuthToken | Act::Permission | Act::MissionUpdate
        ) {
            return Ok(None);
        }
        let kind = self.policy.kind(case);
        let mission = case
            .mission
            .as_ref()
            .filter(|m| m.terminated.is_none())
            .map(|m| m.s256.as_str());
        let answers = self
            .standing(&case.ps, &case.sub, &case.agent)
            .map_err(|_| records::Fault)?;
        let found = answers.iter().rev().find(|entry| {
            entry.kind == kind
                && entry
                    .mission_s256
                    .as_deref()
                    .is_none_or(|limited| Some(limited) == mission)
        });
        Ok(found.map(|entry| match entry.answer {
            Reach::Allow => Verdict::Allow(Allowance::default()),
            Reach::Deny => Verdict::Deny(None),
        }))
    }

    /// Remember an answer given with the `mission` or `always` reach.
    pub(crate) fn remember(
        &self,
        ps: &str,
        sdi: &str,
        apply: &str,
        answer: Reach,
    ) -> Result<(), records::Fault> {
        if apply != REACH_MISSION && apply != REACH_ALWAYS {
            return Ok(());
        }
        let Some(record) = records::load(&self.store, &records::key(DECISION, &[ps, sdi]))? else {
            return Ok(());
        };
        let case = self.case(&record)?;
        if !matches!(
            case.act,
            Act::PersonToken | Act::AuthToken | Act::Permission | Act::MissionUpdate
        ) {
            return Ok(());
        }
        let mission = if apply == REACH_MISSION {
            match &case.mission {
                Some(mission) => Some(mission.s256.clone()),
                None => return Ok(()),
            }
        } else {
            None
        };
        let entry = json!({
            "kind": self.policy.kind(&case),
            "mission_s256": mission,
            "answer": answer.as_str(),
        });
        records::update(
            &self.store,
            &records::key(STANDING, &[ps, &case.sub, &case.agent]),
            |current| {
                let mut entries = current
                    .and_then(|v| v["entries"].as_array().cloned())
                    .unwrap_or_default();
                entries.push(entry.clone());
                if entries.len() > MAX_STANDING {
                    entries.remove(0);
                }
                Some(json!({ "entries": entries }))
            },
        )
    }

    /// Drop standing answers limited to a mission that ended.
    pub(crate) fn forget_mission(
        &self,
        ps: &str,
        sub: &str,
        agent: &str,
        s256: &str,
    ) -> Result<(), records::Fault> {
        records::update(
            &self.store,
            &records::key(STANDING, &[ps, sub, agent]),
            |current| {
                let entries = current?
                    .get("entries")?
                    .as_array()?
                    .iter()
                    .filter(|e| e["mission_s256"].as_str() != Some(s256))
                    .cloned()
                    .collect::<Vec<_>>();
                Some(json!({ "entries": entries }))
            },
        )
    }
}

fn standing_entry(value: &Value) -> Option<StandingAnswer> {
    Some(StandingAnswer {
        kind: value["kind"].as_str()?.into(),
        mission_s256: value["mission_s256"].as_str().map(str::to_owned),
        answer: match value["answer"].as_str()? {
            "allow" => Reach::Allow,
            "deny" => Reach::Deny,
            _ => return None,
        },
    })
}

/// Keep only what an allowance may say for `act`. A proposal must carry terms.
fn fit(act: Act, mut allowance: Allowance) -> Result<Allowance, records::Fault> {
    if act == Act::MissionProposal {
        let terms = allowance.mission.take().ok_or(records::Fault)?;
        if terms.description.is_empty() {
            return Err(records::Fault);
        }
        return Ok(Allowance {
            scope: None,
            exp: None,
            mission: Some(terms),
        });
    }
    allowance.mission = None;
    if act != Act::AuthToken {
        allowance.scope = None;
    }
    if !matches!(act, Act::AuthToken | Act::PersonToken) {
        allowance.exp = None;
    }
    if allowance.scope.as_deref().is_some_and(|s| !valid_scope(s)) {
        return Err(records::Fault);
    }
    Ok(allowance)
}

/// The members each act requires, beyond the envelope.
fn check_members(act: Act, body: &Map<String, Value>, envelope: &Envelope) -> Result<(), ()> {
    let text = |name: &str| match body.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.as_str()),
        _ => Err(()),
    };
    let optional = |name: &str| match body.get(name) {
        None | Some(Value::String(_)) => Ok(()),
        Some(_) => Err(()),
    };
    match act {
        Act::PersonToken => {
            validate_server_identifier(text("resource")?).map_err(|_| ())?;
            text("agent_token")?;
        }
        Act::AuthToken => {
            text("resource_token")?;
            text("presented_token")?;
            optional("justification")?;
        }
        Act::Permission => {
            text("action")?;
            optional("description")?;
            if body.get("parameters").is_some_and(|p| !p.is_object()) {
                return Err(());
            }
        }
        Act::MissionProposal => {
            text("agent_token")?;
            text("description")?;
            if let Some(tools) = body.get("tools") {
                Tool::parse_list(tools).map_err(|_| ())?;
            }
            if let Some(resources) = body.get("resources") {
                server_list(resources).map_err(|_| ())?;
            }
        }
        Act::MissionUpdate => {
            text("description")?;
        }
        Act::MissionCompletion => {
            text("summary")?;
        }
    }
    for name in ["upstream_token", "subagent_token"] {
        optional(name)?;
    }
    if body.contains_key("agent_token") {
        let token = AgentToken::parse(text("agent_token")?).map_err(|_| ())?;
        if token.unverified_claims().sub != envelope.agent {
            return Err(());
        }
    }
    Ok(())
}
