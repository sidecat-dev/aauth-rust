//! Acts held for the supervision server or the person.
//!
//! The agent polls `{signed_origin}/pending/{id}` as for any deferred
//! response. A question from the server reaches it as a clarification, and
//! its answer is relayed back. The host answers for the person with
//! [`PersonServer::resolve_supervision`] and polls a deciding server with
//! [`PersonServer::advance_supervision`]. Once allowed, the agent's next
//! poll carries out the act through the same checks as the original request.
use super::*;
use aauth_rust_core::supervision::{EventKind, Resolution, Resolved};
use journal::Report;

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Hold an act the SS did not allow or deny, and answer the agent `202`.
    pub(super) fn hold(
        &self,
        held: HeldAct<'_>,
        answered: Answered,
    ) -> Result<Supervised, Failure> {
        let config = self.gate().ok_or_else(Failure::internal)?;
        let now = (self.clock)();
        let identity = Self::identity(held.agent);
        let mut record = json!({
            "act": held.act.name(), "sdi": held.sdi, "supervisor": held.supervisor,
            "sub": held.sub, "person_id": held.person_id,
            "agent": { "issuer": identity.issuer, "subject": identity.subject },
            "agent_token": held.agent.compact(), "path": held.path,
            "parameters": held.parameters, "mission_s256": held.mission_s256,
            "target": held.target, "body": held.body, "deadline": held.deadline,
            "rounds": 0, "resolved": false, "requested_scopes": held.requested_scopes,
        });
        self.apply_answered(&mut record, answered, now);
        let id = generate_pending_id();
        config
            .store
            .insert(&held_key(&id), record.clone())
            .map_err(|_| Failure::internal())?;
        let mut response = self.agent_wire(&id, &record)?;
        response
            .extensions_mut()
            .insert(self.hold_of(&id, &record, now));
        Ok(Supervised::Held(response))
    }

    /// Move a held act to what the SS just said.
    pub(super) fn apply_answered(&self, record: &mut Value, answered: Answered, now: i64) {
        let act = act_of(record);
        let sdi = record["sdi"].as_str().unwrap_or("").to_owned();
        let deadline = record["deadline"].as_i64().unwrap_or(0);
        let unavailable = |record: &mut Value, reason: Unconsulted| {
            record["state"] = json!("unavailable");
            record["unconsulted"] = unconsulted_value(&reason);
            record["question"] = Value::Null;
        };
        match answered {
            Answered::Decision(Decision::Allow(allowance)) => {
                let requested: Option<Vec<String>> =
                    record["requested_scopes"].as_array().map(|s| {
                        s.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    });
                if check_allowance(act, &allowance, requested.as_deref(), now).is_ok() {
                    record["state"] = json!("allowed");
                    record["allowance"] = Decision::Allow(allowance).to_value(&sdi);
                    self.log_outcome(&sdi, "allow");
                } else {
                    unavailable(record, Unconsulted::Unreachable);
                    self.log_outcome(&sdi, "unavailable");
                }
            }
            Answered::Decision(Decision::Deny { reason }) => {
                record["state"] = json!("denied");
                record["reason"] = json!(reason);
                self.log_outcome(&sdi, "deny");
            }
            Answered::Decision(Decision::Ask(ask)) => {
                record["state"] = json!("asking");
                record["ask"] = Decision::Ask(ask).to_value(&sdi);
                record["question"] = Value::Null;
                self.log_outcome(&sdi, "ask");
            }
            Answered::Pending {
                location,
                retry_after,
                question,
            } => {
                record["state"] = json!("deciding");
                record["location"] = json!(location);
                record["next"] = json!(now.saturating_add(retry_after as i64));
                record["question"] = match question {
                    Some(Requirement::Clarification {
                        question,
                        timeout,
                        options,
                    }) => {
                        json!({ "clarification": question, "timeout": timeout, "options": options })
                    }
                    _ => Value::Null,
                };
                self.log_outcome(&sdi, "held");
            }
            Answered::Failed(SupervisionError::RateLimited, Some(wait))
                if now.saturating_add(wait as i64) < deadline =>
            {
                record["state"] = json!("resend");
                record["next"] = json!(now.saturating_add(wait as i64));
                self.log_outcome(&sdi, "held");
            }
            Answered::Failed(error, _) => {
                let reason = match error {
                    SupervisionError::RateLimited => Unconsulted::RateLimited,
                    SupervisionError::UnsupportedIss => Unconsulted::PairingDropped,
                    other => Unconsulted::Failed(other),
                };
                unavailable(record, reason);
                self.log_outcome(&sdi, "unavailable");
            }
            Answered::Unreachable(reason) => {
                unavailable(record, reason);
                self.log_outcome(&sdi, "unavailable");
            }
        }
    }

    /// The agent's `202`: a relayed clarification, or approval pending.
    fn agent_wire(&self, id: &str, record: &Value) -> Result<Response<Vec<u8>>, Failure> {
        let config = self.gate().ok_or_else(Failure::internal)?;
        let location = format!("{}/pending/{id}", self.config.signed_origin);
        let question = record["question"]
            .as_object()
            .filter(|_| record["state"] == "deciding");
        let (retry_after, requirement) = match question {
            Some(question) => (
                0,
                Requirement::Clarification {
                    question: question["clarification"].as_str().unwrap_or("").into(),
                    timeout: question.get("timeout").and_then(Value::as_u64),
                    options: question
                        .get("options")
                        .and_then(Value::as_array)
                        .map(|o| {
                            o.iter()
                                .filter_map(|v| v.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                },
            ),
            None => (config.retry_after, Requirement::Approval),
        };
        PendingResponse::new(
            &self.config.signed_origin,
            &location,
            retry_after,
            requirement,
        )
        .and_then(|pending| pending.response())
        .map_err(|_| Failure::internal())
    }

    fn hold_of(&self, id: &str, record: &Value, now: i64) -> SupervisionHold {
        let act = act_of(record);
        let sdi = record["sdi"].as_str().unwrap_or("").to_owned();
        let waiting = match record["state"].as_str() {
            Some("asking") => match Decision::parse(&record["ask"], &sdi, act) {
                Ok(Decision::Ask(ask)) => Waiting::Person(ask),
                _ => Waiting::Person(Ask::default()),
            },
            Some("unavailable") => Waiting::Unavailable(unconsulted_from(&record["unconsulted"])),
            Some("deciding") if record["question"].is_object() => Waiting::Agent {
                question: record["question"]["clarification"]
                    .as_str()
                    .unwrap_or("")
                    .into(),
            },
            Some("federating") => Waiting::AccessServer {
                reference: record["federation"].as_str().unwrap_or("").into(),
            },
            Some("deciding" | "resend") => Waiting::Supervisor {
                retry_after: record["next"]
                    .as_i64()
                    .map_or(0, |next| next.saturating_sub(now).max(0) as u64),
            },
            _ => Waiting::Decided,
        };
        SupervisionHold {
            reference: id.to_owned(),
            sdi,
            act,
            supervisor: record["supervisor"].as_str().unwrap_or("").into(),
            agent: agent_of(record),
            waiting,
            parameters: record["parameters"].clone(),
        }
    }

    /// The agent's pending URL for a held act.
    pub(in crate::server) fn route_supervision(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Option<Response<Vec<u8>>>, Failure> {
        if self.supervision.is_none() {
            return Ok(None);
        }
        let Some(id) = request.uri().path().strip_prefix("/pending/") else {
            return Ok(None);
        };
        self.supervised_pending(request, now, id).map(Some)
    }

    fn supervised_pending(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        id: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let config = self.gate().ok_or_else(Failure::internal)?;
        let method = request.method().as_str();
        if request.uri().query().is_some()
            || !["GET", "POST", "DELETE"].contains(&method)
            || (method != "POST" && !request.body().is_empty())
        {
            return Err(Failure::parameter("invalid_request"));
        }
        let caller = self.verify_agent(request, now, method == "POST")?;
        if !safe_reference(id) {
            return Err(gone());
        }
        let key = held_key(id);
        let snapshot = config
            .store
            .load(&key)
            .map_err(|_| Failure::internal())?
            .ok_or_else(gone)?;
        let mut record = snapshot.value;
        let original = AgentToken::parse(record["agent_token"].as_str().unwrap_or(""))
            .map_err(Failure::credential)?;
        let original = original.unverified_claims();
        if caller.claims().iss != original.iss
            || caller.claims().sub != original.sub
            || caller.claims().cnf.jwk.thumbprint().ok() != original.cnf.jwk.thumbprint().ok()
            || caller.claims().parent_agent.is_some()
        {
            return Err(Failure::status(StatusCode::FORBIDDEN, "wrong_poller"));
        }
        if record["state"] == "federating" {
            return self.federation_relay(request, now, id, &record);
        }
        if record["deadline"].as_i64().is_none_or(|at| now >= at) {
            self.expire(&key, snapshot.revision, &record);
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let replace = |record: Option<Value>| {
            config
                .store
                .replace(&key, snapshot.revision, record)
                .map_err(|_| Failure::internal())
        };
        match method {
            "DELETE" => {
                if record["state"] == "deciding"
                    && let Some(location) = record["location"].as_str()
                    && let Ok(cancel) =
                        self.ss_request("DELETE", location, None, Outbound::Report, now)
                {
                    let response = config.host.send(&cancel).ok();
                    let _ = self.log_exchange(
                        record["sdi"].as_str().unwrap_or(""),
                        &cancel,
                        response.as_ref(),
                    );
                }
                if !replace(None)? {
                    return self.agent_wire(id, &record);
                }
                self.abandon_if_asked(&record);
                Ok(json_response(
                    StatusCode::OK,
                    json!({ "status": "cancelled" }),
                ))
            }
            "POST" => {
                self.relay_clarification(request, now, &mut record)?;
                if !replace(Some(record.clone()))? {
                    return Err(Failure::parameter("invalid_request"));
                }
                self.agent_wire(id, &record)
            }
            _ => match record["state"].as_str() {
                Some("allowed") => {
                    record["state"] = json!("delivering");
                    if !replace(Some(record.clone()))? {
                        return self.agent_wire(id, &record);
                    }
                    let result = self.resume(&record, now);
                    let finish = |config: &SupervisionConfig| {
                        let _ = update(config.store.as_ref(), &key, |_| None);
                    };
                    match result {
                        Ok(response) => {
                            if let Some(federation) =
                                federation_reference(&self.config.signed_origin, &response)
                            {
                                record["state"] = json!("federating");
                                record["federation"] = json!(federation);
                                update(config.store.as_ref(), &key, |_| Some(record.clone()))
                                    .map_err(|_| Failure::internal())?;
                                return Ok(relocated(response, &self.config.signed_origin, id));
                            }
                            finish(config);
                            Ok(response)
                        }
                        Err(failure) => {
                            finish(config);
                            Err(failure.while_pending())
                        }
                    }
                }
                Some("denied") => {
                    if !replace(None)? {
                        return self.agent_wire(id, &record);
                    }
                    Ok(self.denial(act_of(&record), record["reason"].as_str(), true))
                }
                _ => self.agent_wire(id, &record),
            },
        }
    }

    /// Relay the agent's answer to the SS's question, or its updated request.
    fn relay_clarification(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        record: &mut Value,
    ) -> Result<(), Failure> {
        let config = self.gate().ok_or_else(Failure::internal)?;
        let invalid = || Failure::parameter("invalid_request");
        if record["state"] != "deciding" || !record["question"].is_object() {
            return Err(invalid());
        }
        let body = strict_json(request.body()).map_err(|_| invalid())?;
        let object = body.as_object().ok_or_else(invalid)?;
        let relay = match object.get("action").and_then(Value::as_str) {
            Some("clarification_response") => {
                if object
                    .keys()
                    .any(|k| !["action", "clarification_response"].contains(&k.as_str()))
                {
                    return Err(invalid());
                }
                let answer = object
                    .get("clarification_response")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty() && s.len() <= 65_536)
                    .ok_or_else(invalid)?;
                json!({ "action": "clarification_response", "clarification_response": answer })
            }
            Some("updated_request") => {
                if act_of(record) != Act::AuthToken
                    || object.keys().any(|k| {
                        ![
                            "action",
                            "resource_token",
                            "presented_token",
                            "justification",
                        ]
                        .contains(&k.as_str())
                    })
                {
                    return Err(invalid());
                }
                let agent = AgentToken::parse(record["agent_token"].as_str().unwrap_or(""))
                    .and_then(|t| t.verify(&self.resolver(), now))
                    .map_err(Failure::credential)?;
                let original = self.prepare_stored(&agent, record["parameters"].clone(), now)?;
                let mut parameters = record["parameters"].clone();
                for member in ["resource_token", "presented_token"] {
                    parameters[member] = json!(
                        object
                            .get(member)
                            .and_then(Value::as_str)
                            .filter(|t| !t.is_empty())
                            .ok_or_else(invalid)?
                    );
                }
                if let Some(justification) = object.get("justification") {
                    let text = justification
                        .as_str()
                        .filter(|t| !t.is_empty() && t.len() <= 65_536)
                        .ok_or_else(invalid)?;
                    parameters["justification"] = json!(text);
                }
                let updated = self.prepare_stored(&agent, parameters.clone(), now)?;
                if !continuation::same_updated_resource(&original.resource, &updated.resource) {
                    return Err(Failure::parameter("invalid_resource_token"));
                }
                record["requested_scopes"] = json!(updated.context.scopes);
                for member in ["resource_token", "presented_token", "justification"] {
                    if let Some(value) = parameters.get(member) {
                        record["body"][member] = value.clone();
                    }
                }
                record["parameters"] = parameters;
                Value::Object(object.clone())
            }
            _ => return Err(invalid()),
        };
        let rounds = record["rounds"].as_u64().unwrap_or(0) + 1;
        record["rounds"] = json!(rounds);
        if rounds as usize > config.max_rounds {
            self.apply_answered(
                record,
                Answered::Unreachable(Unconsulted::TooManyRounds),
                now,
            );
            return Ok(());
        }
        let location = record["location"].as_str().unwrap_or("").to_owned();
        let answered = match self.supervisor_metadata(record["supervisor"].as_str().unwrap_or("")) {
            None => Answered::Unreachable(Unconsulted::Unreachable),
            Some(metadata) => {
                match self.ss_request("POST", &location, Some(&relay), Outbound::Supervision, now) {
                    Ok(relayed) => self.exchange(
                        &metadata,
                        act_of(record),
                        record["sdi"].as_str().unwrap_or(""),
                        &location,
                        relayed,
                    ),
                    Err(()) => Answered::Unreachable(Unconsulted::Unreachable),
                }
            }
        };
        self.apply_answered(record, answered, now);
        Ok(())
    }

    /// Carry out an allowed act, with the allowance already obtained.
    fn resume(&self, record: &Value, now: i64) -> Result<Response<Vec<u8>>, Failure> {
        let act = act_of(record);
        let sdi = record["sdi"].as_str().unwrap_or("").to_owned();
        let Ok(Decision::Allow(allowance)) = Decision::parse(&record["allowance"], &sdi, act)
        else {
            return Err(Failure::internal());
        };
        let resumed = Resumed { sdi, allowance };
        let agent = AgentToken::parse(record["agent_token"].as_str().unwrap_or(""))
            .and_then(|t| t.verify(&self.resolver(), now))
            .map_err(Failure::credential)?;
        let parameters = record["parameters"].clone();
        let upstream = match parameters.get("upstream_token") {
            Some(_) => Some(self.verify_upstream(
                required_string(&parameters, "upstream_token")?,
                &agent,
                now,
            )?),
            None => None,
        };
        match act {
            Act::PersonToken => self.person(agent, parameters, upstream, Some(&resumed)),
            Act::AuthToken => self.auth(agent, parameters, now, upstream, Some(&resumed)),
            Act::Permission => Ok(json_response(
                StatusCode::OK,
                json!({ "permission": "granted" }),
            )),
            Act::MissionProposal => self.record_supervised_mission(
                &agent,
                record["person_id"].as_str().unwrap_or(""),
                &resumed,
            ),
            Act::MissionUpdate | Act::MissionCompletion => {
                let s256 = record["mission_s256"].as_str().unwrap_or("").to_owned();
                self.apply_mission_edit(&agent, &s256, &parameters, now, Some(&resumed))
            }
        }
    }

    /// Answer the agent for an act the SS or the person refused. A
    /// permission is answered `denied` with the reason, a mission request
    /// `403` with it, and a token request `403` without it.
    pub(in crate::server) fn denial(
        &self,
        act: Act,
        reason: Option<&str>,
        pending: bool,
    ) -> Response<Vec<u8>> {
        if act == Act::Permission {
            let mut body = json!({ "permission": "denied" });
            if let Some(reason) = reason {
                body["reason"] = json!(reason);
            }
            return json_response(StatusCode::OK, body);
        }
        let code = if pending { "denied" } else { "access_denied" };
        let mut body = json!({
            "type": "about:blank", "title": "Forbidden", "status": 403, "error": code,
        });
        if act.is_mission()
            && let Some(reason) = reason
        {
            body["reason"] = json!(reason);
        }
        let mut response = json_response(StatusCode::FORBIDDEN, body);
        response.headers_mut().insert(
            "content-type",
            http::HeaderValue::from_static("application/problem+json"),
        );
        response
    }

    /// The current state of a held act.
    ///
    /// # Errors
    /// [`SupervisionHostError::Gone`] for an unknown or finished reference.
    pub fn supervision_hold(
        &self,
        reference: &str,
    ) -> Result<SupervisionHold, SupervisionHostError> {
        let config = self.gate().ok_or(SupervisionHostError::Disabled)?;
        if !safe_reference(reference) {
            return Err(SupervisionHostError::Gone);
        }
        let record =
            load(config.store.as_ref(), &held_key(reference)).ok_or(SupervisionHostError::Gone)?;
        Ok(self.hold_of(reference, &record, (self.clock)()))
    }

    /// Record the person's answer to an act the SS put to them, or that went
    /// to them because the SS could not be consulted. The agent's next poll
    /// receives the outcome, and `decision.resolved` is queued for the SS
    /// with the reach the person chose. This server applies no reach itself.
    ///
    /// # Errors
    /// [`SupervisionHostError::NotReady`] when the act is not waiting for the
    /// person, [`SupervisionHostError::Gone`] when it finished or expired,
    /// and [`SupervisionHostError::InvalidAnswer`] for an allowed proposal
    /// with no description to approve.
    pub fn resolve_supervision(
        &self,
        reference: &str,
        answer: PersonAnswer,
    ) -> Result<(), SupervisionHostError> {
        let config = self.gate().ok_or(SupervisionHostError::Disabled)?;
        if !safe_reference(reference) {
            return Err(SupervisionHostError::Gone);
        }
        let key = held_key(reference);
        let snapshot = config
            .store
            .load(&key)
            .map_err(|_| SupervisionHostError::Unavailable)?
            .ok_or(SupervisionHostError::Gone)?;
        let mut record = snapshot.value;
        let now = (self.clock)();
        if record["deadline"].as_i64().is_none_or(|at| now >= at) {
            self.expire(&key, snapshot.revision, &record);
            return Err(SupervisionHostError::Gone);
        }
        let unavailable = record["state"] == "unavailable";
        if !unavailable && record["state"] != "asking" {
            return Err(SupervisionHostError::NotReady);
        }
        let act = act_of(&record);
        let sdi = record["sdi"].as_str().unwrap_or("").to_owned();
        let ask = match Decision::parse(&record["ask"], &sdi, act) {
            Ok(Decision::Ask(ask)) => ask,
            _ => Ask::default(),
        };
        let mut approved_terms = None;
        match answer.answer {
            aauth_rust_core::supervision::Answer::Allow => {
                let mut allowance = Allowance::default();
                if act == Act::MissionProposal {
                    let terms = answer
                        .proposed
                        .clone()
                        .or_else(|| ask.proposed.clone())
                        .or_else(|| {
                            record["parameters"]["description"]
                                .as_str()
                                .map(MissionTerms::described)
                        })
                        .ok_or(SupervisionHostError::InvalidAnswer)?;
                    if terms.description.is_empty() {
                        return Err(SupervisionHostError::InvalidAnswer);
                    }
                    approved_terms = Some(terms.clone());
                    allowance.mission = Some(terms);
                }
                record["state"] = json!("allowed");
                record["allowance"] = Decision::Allow(allowance).to_value(&sdi);
            }
            aauth_rust_core::supervision::Answer::Deny => {
                record["state"] = json!("denied");
                record["reason"] = json!(answer.reason);
            }
        }
        record["resolved"] = json!(true);
        if !config
            .store
            .replace(&key, snapshot.revision, Some(record.clone()))
            .map_err(|_| SupervisionHostError::Unavailable)?
        {
            return Err(SupervisionHostError::NotReady);
        }
        let resolved = match answer.answer {
            aauth_rust_core::supervision::Answer::Allow => Resolved::Allow,
            aauth_rust_core::supervision::Answer::Deny => Resolved::Deny,
        };
        let resolution = Resolution {
            answer: resolved,
            apply: answer.apply,
            recommendation: if unavailable {
                None
            } else {
                ask.recommendation
            },
            proposed: approved_terms,
            transcript: answer.transcript,
            supervisor_unavailable: unavailable,
            reason: answer.reason,
        };
        self.report_resolution(&record, resolution);
        self.log_outcome(
            &sdi,
            if resolved == Resolved::Allow {
                "person allow"
            } else {
                "person deny"
            },
        );
        Ok(())
    }

    /// Poll the SS for an act it is still deciding, or send again an act it
    /// answered `rate_limited`. One request at most. The returned hold says
    /// what the act waits for now.
    ///
    /// # Errors
    /// [`SupervisionHostError::NotReady`] before the server's `Retry-After`
    /// has passed or when the act does not wait for the server, and
    /// [`SupervisionHostError::Gone`] when it finished or expired.
    pub fn advance_supervision(
        &self,
        reference: &str,
    ) -> Result<SupervisionHold, SupervisionHostError> {
        let config = self.gate().ok_or(SupervisionHostError::Disabled)?;
        if !safe_reference(reference) {
            return Err(SupervisionHostError::Gone);
        }
        let key = held_key(reference);
        let snapshot = config
            .store
            .load(&key)
            .map_err(|_| SupervisionHostError::Unavailable)?
            .ok_or(SupervisionHostError::Gone)?;
        let mut record = snapshot.value;
        let now = (self.clock)();
        if record["deadline"].as_i64().is_none_or(|at| now >= at) {
            self.expire(&key, snapshot.revision, &record);
            return Err(SupervisionHostError::Gone);
        }
        let waiting_on_server = (record["state"] == "deciding" && record["question"].is_null())
            || record["state"] == "resend";
        if !waiting_on_server || record["next"].as_i64().is_some_and(|next| now < next) {
            return Err(SupervisionHostError::NotReady);
        }
        let act = act_of(&record);
        let sdi = record["sdi"].as_str().unwrap_or("").to_owned();
        let answered = match self.supervisor_metadata(record["supervisor"].as_str().unwrap_or("")) {
            None => Answered::Unreachable(Unconsulted::Unreachable),
            Some(metadata) if record["state"] == "resend" => {
                let target = record["target"].as_str().unwrap_or("decision").to_owned();
                let body = record["body"].clone();
                self.put(&metadata, act, &sdi, &target, &body, now)
            }
            Some(metadata) => {
                let location = record["location"].as_str().unwrap_or("").to_owned();
                match self.ss_request("GET", &location, None, Outbound::Supervision, now) {
                    Ok(poll) => self.exchange(&metadata, act, &sdi, &location, poll),
                    Err(()) => Answered::Unreachable(Unconsulted::Unreachable),
                }
            }
        };
        self.apply_answered(&mut record, answered, now);
        if !config
            .store
            .replace(&key, snapshot.revision, Some(record.clone()))
            .map_err(|_| SupervisionHostError::Unavailable)?
        {
            return Err(SupervisionHostError::NotReady);
        }
        Ok(self.hold_of(reference, &record, now))
    }

    /// Drop an expired act. One the person was asked about and did not
    /// answer is reported `abandoned`.
    fn expire(&self, key: &str, revision: u64, record: &Value) {
        let Some(config) = self.gate() else {
            return;
        };
        if config.store.replace(key, revision, None).unwrap_or(false) {
            self.abandon_if_asked(record);
        }
    }

    fn abandon_if_asked(&self, record: &Value) {
        let unavailable = record["state"] == "unavailable";
        if record["resolved"] == true || (!unavailable && record["state"] != "asking") {
            return;
        }
        let act = act_of(record);
        let sdi = record["sdi"].as_str().unwrap_or("");
        let recommendation = match Decision::parse(&record["ask"], sdi, act) {
            Ok(Decision::Ask(ask)) if !unavailable => ask.recommendation,
            _ => None,
        };
        let mut resolution = Resolution::answered(Resolved::Abandoned);
        resolution.recommendation = recommendation;
        resolution.supervisor_unavailable = unavailable;
        self.report_resolution(record, resolution);
        self.log_outcome(sdi, "abandoned");
    }

    fn report_resolution(&self, record: &Value, resolution: Resolution) {
        let mut members = Map::new();
        resolution.write(&mut members);
        self.report(
            record["person_id"].as_str().unwrap_or(""),
            &agent_of(record),
            Report::Event(EventKind::DecisionResolved, members),
            record["sdi"].as_str(),
            record["mission_s256"].as_str(),
            None,
        );
    }

    /// Answer a poll of an act whose auth token the Access Server is still
    /// deciding, from that exchange's custody, at this act's own URL.
    fn federation_relay(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        id: &str,
        record: &Value,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let federation = record["federation"]
            .as_str()
            .ok_or_else(Failure::internal)?;
        // An updated request would be consented by host policy there; this
        // act's decision was the supervision server's, so it is refused.
        if request.method() == "POST"
            && strict_json(request.body())
                .ok()
                .is_some_and(|body| body["action"] == "updated_request")
        {
            return Err(Failure::policy(PolicyError::Denied));
        }
        let result = self.pending_at(request, now, Some(federation));
        let pending = matches!(&result, Ok(response) if response.status() == StatusCode::ACCEPTED);
        if !pending && let Some(config) = self.gate() {
            let _ = update(config.store.as_ref(), &held_key(id), |_| None);
        }
        result.map(|response| relocated(response, &self.config.signed_origin, id))
    }
}

fn held_key(id: &str) -> String {
    format!("sv.h.{id}")
}

fn gone() -> Failure {
    Failure::status(StatusCode::GONE, "gone")
}

fn safe_reference(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn act_of(record: &Value) -> Act {
    record["act"]
        .as_str()
        .and_then(Act::from_name)
        .unwrap_or(Act::PersonToken)
}

fn agent_of(record: &Value) -> AgentIdentity {
    AgentIdentity {
        issuer: record["agent"]["issuer"].as_str().unwrap_or("").into(),
        subject: record["agent"]["subject"].as_str().unwrap_or("").into(),
    }
}

/// The federation custody id of a `202` the Access Server answered with.
fn federation_reference(origin: &str, response: &Response<Vec<u8>>) -> Option<String> {
    if response.status() != StatusCode::ACCEPTED {
        return None;
    }
    let location = response.headers().get("location")?.to_str().ok()?;
    location
        .strip_prefix(&format!("{origin}/token/pending/"))
        .map(str::to_owned)
}

/// The same `202`, at this act's pending URL.
fn relocated(mut response: Response<Vec<u8>>, origin: &str, id: &str) -> Response<Vec<u8>> {
    if response.status() == StatusCode::ACCEPTED
        && let Ok(location) = format!("{origin}/pending/{id}").parse()
    {
        response.headers_mut().insert("location", location);
    }
    response
}

fn unconsulted_value(reason: &Unconsulted) -> Value {
    match reason {
        Unconsulted::Unreachable => json!({ "kind": "unreachable" }),
        Unconsulted::Failed(error) => json!({ "kind": "failed", "error": error.code() }),
        Unconsulted::BadSignature => json!({ "kind": "bad_signature" }),
        Unconsulted::Unsigned => json!({ "kind": "unsigned" }),
        Unconsulted::PairingDropped => json!({ "kind": "pairing_dropped" }),
        Unconsulted::ConnectPending { url, code } => {
            json!({ "kind": "connect_pending", "url": url, "code": code })
        }
        Unconsulted::RateLimited => json!({ "kind": "rate_limited" }),
        Unconsulted::TooManyRounds => json!({ "kind": "too_many_rounds" }),
    }
}

fn unconsulted_from(value: &Value) -> Unconsulted {
    match value["kind"].as_str() {
        Some("failed") => Unconsulted::Failed(match value["error"].as_str() {
            Some("invalid_request") => SupervisionError::InvalidRequest,
            Some("unknown_sub") => SupervisionError::UnknownSub,
            Some("unknown_mission") => SupervisionError::UnknownMission,
            Some("unknown_pending") => SupervisionError::UnknownPending,
            _ => SupervisionError::ServerError,
        }),
        Some("bad_signature") => Unconsulted::BadSignature,
        Some("unsigned") => Unconsulted::Unsigned,
        Some("pairing_dropped") => Unconsulted::PairingDropped,
        Some("connect_pending") => Unconsulted::ConnectPending {
            url: value["url"].as_str().unwrap_or("").into(),
            code: value["code"].as_str().unwrap_or("").into(),
        },
        Some("rate_limited") => Unconsulted::RateLimited,
        Some("too_many_rounds") => Unconsulted::TooManyRounds,
        _ => Unconsulted::Unreachable,
    }
}
