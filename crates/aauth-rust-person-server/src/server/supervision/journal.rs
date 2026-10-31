//! What this server tells supervision servers, and in what order.
//!
//! Every report is kept in the agent's journal, its copy of the agent's
//! active state: the binding, each active mission with what happened under
//! it, and each outstanding token. A report goes to the agent's deciding
//! server through the outbox of that `(server, sub)` pair, which delivers in
//! order and retries under the same `id`. A server that becomes an agent's
//! deciding server, or answers `unknown_mission`, is sent the journal first
//! (Replay and Recovery). This server's own records stay authoritative.
use super::*;
use aauth_rust_core::supervision::EventKind;

const MAX_JOURNAL: usize = 512;
const OUTBOX_INDEX: &str = "sv.oi";

/// Something to report to the agent's supervision server.
pub(in crate::server) enum Report<'a> {
    /// An event, with its members.
    Event(EventKind, Map<String, Value>),
    /// A mission this server built and recorded.
    Approved {
        /// Mission identifier.
        s256: &'a str,
        /// The blob, base64url, as returned to the agent.
        mission: &'a str,
    },
    /// A mission that ended, for a termination reason.
    Terminated {
        /// Mission identifier.
        s256: &'a str,
        /// Termination reason.
        reason: &'a str,
    },
}

/// One outbox delivery attempt.
enum Delivery {
    Done,
    Dropped,
    Stop,
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Record a report for an agent and queue it for its deciding server.
    ///
    /// A report that cannot be recorded is dropped: the act it reports has
    /// already happened, and refusing the agent now would undo nothing.
    pub(in crate::server) fn report(
        &self,
        person_id: &str,
        agent: &AgentIdentity,
        report: Report<'_>,
        sdi: Option<&str>,
        mission_s256: Option<&str>,
        expires: Option<i64>,
    ) {
        let Some(config) = self.gate() else {
            return;
        };
        let now = (self.clock)();
        let id = format!("e-{}", generate_pending_id());
        let mut approved = None;
        let (target, kind, mut body, ended) = match report {
            Report::Event(event, mut members) => {
                members.insert("event".into(), json!(event.name()));
                ("event".to_owned(), event.name(), members, None)
            }
            Report::Approved { s256, mission } => {
                let mut members = Map::new();
                members.insert("action".into(), json!("approved"));
                members.insert("s256".into(), json!(s256));
                members.insert("mission".into(), json!(mission));
                approved = Some(s256);
                (format!("mission/{s256}"), "approved", members, None)
            }
            Report::Terminated { s256, reason } => {
                let mut members = Map::new();
                members.insert("action".into(), json!("terminated"));
                members.insert("reason".into(), json!(reason));
                (format!("mission/{s256}"), "terminated", members, Some(s256))
            }
        };
        Envelope {
            sdi: sdi.map(str::to_owned),
            id: Some(id.clone()),
            iat: now,
            sub: String::new(),
            agent: agent.subject.clone(),
            mission_s256: mission_s256.map(str::to_owned),
        }
        .write(&mut body);
        body.remove("sub");
        let entry = json!({
            "id": id, "target": target, "kind": kind, "body": body,
            "mission_s256": mission_s256.or(ended).or(approved), "expires": expires,
            "person_id": person_id,
            "agent": { "issuer": agent.issuer, "subject": agent.subject },
        });
        // A report for a server not yet brought current is kept until it is.
        let route = config.host.route(person_id, agent);
        let key = journal_key(person_id, agent);
        let current = load(config.store.as_ref(), &key)
            .and_then(|journal| journal["supervisor"].as_str().map(str::to_owned));
        let deliver = route.is_some() && route == current;
        let keep = ended.is_none()
            && (matches!(
                kind,
                "agent.bound" | "approved" | "person_token.issued" | "auth_token.issued"
            ) || mission_s256.is_some()
                || (route.is_some() && !deliver));
        let _ = update(config.store.as_ref(), &key, |value| {
            let supervisor = value
                .and_then(|v| v["supervisor"].as_str())
                .map(str::to_owned);
            let mut entries: Vec<Value> = value
                .and_then(|v| v["entries"].as_array().cloned())
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e["expires"].as_i64().is_none_or(|at| at > now))
                .filter(|e| ended.is_none_or(|s256| e["mission_s256"].as_str() != Some(s256)))
                .collect();
            if keep {
                entries.push(entry.clone());
                if entries.len() > MAX_JOURNAL
                    && let Some(index) = entries.iter().position(|e| {
                        !matches!(e["kind"].as_str(), Some("agent.bound" | "approved"))
                    })
                {
                    entries.remove(index);
                }
            }
            Some(json!({ "supervisor": supervisor, "entries": entries }))
        });
        if deliver && let Some(supervisor) = route {
            let sub = config.host.subject(person_id, &supervisor);
            let _ = self.enqueue(&supervisor, &sub, entry);
        }
    }

    /// Tell each agent's server that its agent token was revoked
    /// (`revocation.received`). The server has no part in the cascade.
    pub(in crate::server) fn report_agent_revocation(&self, issuer: &str, jti: &str, exp: i64) {
        if self.supervision.is_none() {
            return;
        }
        let Ok(records) = self.store.retained() else {
            return;
        };
        let mut reported = std::collections::BTreeSet::new();
        for record in records
            .iter()
            .filter(|r| r.agent.issuer == issuer && r.agent_token_jti == jti)
        {
            if !reported.insert((record.person_id.clone(), record.agent.clone())) {
                continue;
            }
            let mut members = Map::new();
            members.insert("token_type".into(), json!("agent_token"));
            members.insert("iss".into(), json!(issuer));
            members.insert("jti".into(), json!(jti));
            members.insert("exp".into(), json!(exp));
            self.report(
                &record.person_id,
                &record.agent,
                Report::Event(EventKind::RevocationReceived, members),
                None,
                None,
                None,
            );
        }
    }

    /// Queue one journal entry for `(supervisor, sub)`.
    fn enqueue(&self, supervisor: &str, sub: &str, mut entry: Value) -> Result<(), ()> {
        let config = self.gate().ok_or(())?;
        entry["body"]["sub"] = json!(sub);
        update(
            config.store.as_ref(),
            &outbox_key(supervisor, sub),
            |current| {
                let mut entries = current
                    .and_then(|v| v["entries"].as_array().cloned())
                    .unwrap_or_default();
                entries.push(entry.clone());
                Some(json!({ "entries": entries }))
            },
        )?;
        update(config.store.as_ref(), OUTBOX_INDEX, |current| {
            let mut pairs = current
                .and_then(|v| v["pairs"].as_array().cloned())
                .unwrap_or_default();
            let pair = json!([supervisor, sub]);
            if !pairs.contains(&pair) {
                pairs.push(pair);
            }
            Some(json!({ "pairs": pairs }))
        })
    }

    /// When `metadata`'s server is not yet the one the agent's journal was
    /// given to, queue the whole journal for it (Routing change).
    pub(super) fn bring_current(
        &self,
        metadata: &SupervisorMetadata,
        sub: &str,
        person_id: &str,
        agent: &AgentIdentity,
    ) -> Result<(), ()> {
        let config = self.gate().ok_or(())?;
        let key = journal_key(person_id, agent);
        let journal = load(config.store.as_ref(), &key);
        if journal.as_ref().and_then(|j| j["supervisor"].as_str()) == Some(metadata.issuer.as_str())
        {
            return Ok(());
        }
        let now = (self.clock)();
        let entries = journal
            .as_ref()
            .and_then(|j| j["entries"].as_array().cloned())
            .unwrap_or_default();
        for entry in entries {
            if entry["expires"].as_i64().is_none_or(|at| at > now) {
                self.enqueue(&metadata.issuer, sub, entry)?;
            }
        }
        update(config.store.as_ref(), &key, |current| {
            let mut journal = current.cloned().unwrap_or_else(|| json!({ "entries": [] }));
            journal["supervisor"] = json!(metadata.issuer);
            Some(journal)
        })
    }

    /// Deliver the pair's outbox in order. `true` when it is empty.
    pub(super) fn flush(&self, metadata: &SupervisorMetadata, sub: &str, now: i64) -> bool {
        let Some(config) = self.gate() else {
            return false;
        };
        let key = outbox_key(&metadata.issuer, sub);
        loop {
            let first = load(config.store.as_ref(), &key)
                .and_then(|outbox| outbox["entries"].as_array()?.first().cloned());
            let Some(first) = first else {
                let _ = update(config.store.as_ref(), &key, |_| None);
                let _ = update(config.store.as_ref(), OUTBOX_INDEX, |current| {
                    let pairs: Vec<Value> = current?
                        .get("pairs")?
                        .as_array()?
                        .iter()
                        .filter(|p| **p != json!([metadata.issuer, sub]))
                        .cloned()
                        .collect();
                    Some(json!({ "pairs": pairs }))
                });
                return true;
            };
            match self.deliver_entry(metadata, sub, &first, now, true) {
                Delivery::Done | Delivery::Dropped => {
                    let delivered = first["id"].clone();
                    if update(config.store.as_ref(), &key, |current| {
                        let entries: Vec<Value> = current?
                            .get("entries")?
                            .as_array()?
                            .iter()
                            .filter(|e| e["id"] != delivered)
                            .cloned()
                            .collect();
                        Some(json!({ "entries": entries }))
                    })
                    .is_err()
                    {
                        return false;
                    }
                }
                Delivery::Stop => return false,
            }
        }
    }

    /// Send one report. `unknown_sub` connects and `unknown_mission` replays
    /// the mission, once, then the report is sent again under the same `id`.
    /// `invalid_request` drops it: retrying will not help.
    fn deliver_entry(
        &self,
        metadata: &SupervisorMetadata,
        sub: &str,
        entry: &Value,
        now: i64,
        recover: bool,
    ) -> Delivery {
        let Some(config) = self.gate() else {
            return Delivery::Stop;
        };
        let target = entry["target"].as_str().unwrap_or("event");
        let mut body = entry["body"].clone();
        body["sub"] = json!(sub);
        let Ok(request) = self.ss_request(
            "POST",
            &endpoint_for(metadata, target),
            Some(&body),
            Outbound::Report,
            now,
        ) else {
            return Delivery::Stop;
        };
        let Ok(response) = config.host.send(&request) else {
            return Delivery::Stop;
        };
        if response.status().is_success() {
            return Delivery::Done;
        }
        let person_id = entry["person_id"].as_str().unwrap_or("");
        let agent = AgentIdentity {
            issuer: entry["agent"]["issuer"].as_str().unwrap_or("").into(),
            subject: entry["agent"]["subject"].as_str().unwrap_or("").into(),
        };
        match SupervisionError::from_response(&response) {
            SupervisionError::InvalidRequest => Delivery::Dropped,
            SupervisionError::UnknownSub if recover => {
                self.forget_connection(&metadata.issuer, sub);
                if self.ensure_connected(metadata, sub, person_id, now) == ConnectOutcome::Connected
                {
                    self.deliver_entry(metadata, sub, entry, now, false)
                } else {
                    Delivery::Stop
                }
            }
            SupervisionError::UnknownMission if recover => {
                let Some(s256) = entry["mission_s256"]
                    .as_str()
                    .or_else(|| target.strip_prefix("mission/"))
                else {
                    return Delivery::Stop;
                };
                if self.replay_mission(metadata, sub, person_id, &agent, s256, now) {
                    self.deliver_entry(metadata, sub, entry, now, false)
                } else {
                    Delivery::Stop
                }
            }
            _ => Delivery::Stop,
        }
    }

    /// Give the server the mission: its approval, then what happened under
    /// it, in order (Unknown mission). A mission this server holds but never
    /// reported is approved under an `id` minted now.
    pub(super) fn replay_mission(
        &self,
        metadata: &SupervisorMetadata,
        sub: &str,
        person_id: &str,
        agent: &AgentIdentity,
        s256: &str,
        now: i64,
    ) -> bool {
        let Some(config) = self.gate() else {
            return false;
        };
        let mut entries: Vec<Value> = load(config.store.as_ref(), &journal_key(person_id, agent))
            .and_then(|j| j["entries"].as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e["mission_s256"].as_str() == Some(s256))
            .collect();
        if !entries.iter().any(|e| e["kind"] == "approved") {
            let Some(encoded) = self.recorded_mission(agent, s256, now) else {
                return false;
            };
            let mut body = Map::new();
            body.insert("action".into(), json!("approved"));
            body.insert("s256".into(), json!(s256));
            body.insert("mission".into(), json!(encoded));
            Envelope {
                sdi: None,
                id: Some(format!("e-{}", generate_pending_id())),
                iat: now,
                sub: String::new(),
                agent: agent.subject.clone(),
                mission_s256: None,
            }
            .write(&mut body);
            entries.insert(
                0,
                json!({ "target": format!("mission/{s256}"), "kind": "approved", "body": body }),
            );
        }
        entries.into_iter().all(|entry| {
            !matches!(
                self.deliver_entry(metadata, sub, &entry, now, false),
                Delivery::Stop
            )
        })
    }

    /// The mission blob this server holds for `agent`, from the mission
    /// audit or the issuance record.
    fn recorded_mission(&self, agent: &AgentIdentity, s256: &str, now: i64) -> Option<String> {
        if let Ok(Some(audit)) =
            self.store
                .read_mission_audit(&self.config.issuer, &agent.issuer, &agent.subject, s256)
        {
            return Some(audit.encoded);
        }
        let record = self
            .store
            .missions()?
            .load_mission(&self.config.issuer, agent, s256, now)
            .ok()?;
        Some(record.document.encoded().to_owned())
    }

    /// Connect the person at the server, or poll a connect that waits for
    /// them to confirm.
    pub(super) fn ensure_connected(
        &self,
        metadata: &SupervisorMetadata,
        sub: &str,
        person_id: &str,
        now: i64,
    ) -> ConnectOutcome {
        let Some(config) = self.gate() else {
            return ConnectOutcome::Unreachable;
        };
        let key = connection_key(&metadata.issuer, sub);
        let stored = load(config.store.as_ref(), &key);
        if let Some(stored) = &stored {
            if stored["state"] == "connected" {
                return ConnectOutcome::Connected;
            }
            let (Some(location), Some(url), Some(code)) = (
                stored["location"].as_str(),
                stored["url"].as_str(),
                stored["code"].as_str(),
            ) else {
                return ConnectOutcome::Unreachable;
            };
            let Ok(request) = self.ss_request("GET", location, None, Outbound::Connect, now) else {
                return ConnectOutcome::Unreachable;
            };
            let Ok(response) = config.host.send(&request) else {
                return ConnectOutcome::Unreachable;
            };
            return match response.status() {
                StatusCode::OK => self.connected(&key),
                StatusCode::ACCEPTED => ConnectOutcome::Confirm {
                    url: url.into(),
                    code: code.into(),
                },
                StatusCode::REQUEST_TIMEOUT | StatusCode::GONE => {
                    let _ = update(config.store.as_ref(), &key, |_| None);
                    ConnectOutcome::Unreachable
                }
                StatusCode::FORBIDDEN => {
                    let _ = update(config.store.as_ref(), &key, |_| None);
                    ConnectOutcome::Refused
                }
                _ => ConnectOutcome::Unreachable,
            };
        }
        let mut body = json!({
            "action": "connect",
            "id": format!("c-{}", generate_pending_id()),
            "iat": now,
            "sub": sub,
        });
        if let Some(tenant) = config.host.tenant(person_id) {
            body["tenant"] = json!(tenant);
        }
        let Ok(request) = self.ss_request(
            "POST",
            &metadata.connect_endpoint,
            Some(&body),
            Outbound::Connect,
            now,
        ) else {
            return ConnectOutcome::Unreachable;
        };
        let Ok(response) = config.host.send(&request) else {
            return ConnectOutcome::Unreachable;
        };
        match response.status() {
            StatusCode::OK => self.connected(&key),
            StatusCode::ACCEPTED => {
                let Ok(pending) = PendingResponse::parse(&metadata.connect_endpoint, &response)
                else {
                    return ConnectOutcome::Unreachable;
                };
                let Requirement::Interaction { url, code } = pending.requirement else {
                    return ConnectOutcome::Unreachable;
                };
                let _ = update(config.store.as_ref(), &key, |_| {
                    Some(json!({
                        "state": "connecting", "location": pending.location,
                        "url": url, "code": code,
                    }))
                });
                ConnectOutcome::Confirm { url, code }
            }
            _ if SupervisionError::from_response(&response) == SupervisionError::UnsupportedIss => {
                ConnectOutcome::Refused
            }
            _ => ConnectOutcome::Unreachable,
        }
    }

    fn connected(&self, key: &str) -> ConnectOutcome {
        let Some(config) = self.gate() else {
            return ConnectOutcome::Unreachable;
        };
        match update(config.store.as_ref(), key, |_| {
            Some(json!({ "state": "connected" }))
        }) {
            Ok(()) => ConnectOutcome::Connected,
            Err(()) => ConnectOutcome::Unreachable,
        }
    }

    pub(super) fn forget_connection(&self, supervisor: &str, sub: &str) {
        if let Some(config) = self.gate() {
            let _ = update(
                config.store.as_ref(),
                &connection_key(supervisor, sub),
                |_| None,
            );
        }
    }

    /// Connect a person at a supervision server they registered, before any
    /// act is put to it (Connect). Call it when the person registers the
    /// server, and again to finish a connect the person must confirm there.
    ///
    /// # Errors
    /// [`SupervisionHostError::Disabled`] without supervision.
    pub fn connect_supervisor(
        &self,
        person_id: &str,
        supervisor: &str,
    ) -> Result<ConnectOutcome, SupervisionHostError> {
        let config = self.gate().ok_or(SupervisionHostError::Disabled)?;
        let Some(metadata) = self.supervisor_metadata(supervisor) else {
            return Ok(ConnectOutcome::Unreachable);
        };
        let sub = config.host.subject(person_id, supervisor);
        Ok(self.ensure_connected(&metadata, &sub, person_id, (self.clock)()))
    }

    /// Tell a server the person removed it (Connect, `disconnect`). The
    /// pairing is forgotten here even when the server cannot be reached.
    ///
    /// # Errors
    /// [`SupervisionHostError::Disabled`] without supervision.
    pub fn disconnect_supervisor(
        &self,
        person_id: &str,
        supervisor: &str,
    ) -> Result<bool, SupervisionHostError> {
        let config = self.gate().ok_or(SupervisionHostError::Disabled)?;
        let sub = config.host.subject(person_id, supervisor);
        self.forget_connection(supervisor, &sub);
        let Some(metadata) = self.supervisor_metadata(supervisor) else {
            return Ok(false);
        };
        let now = (self.clock)();
        let body = json!({
            "action": "disconnect",
            "id": format!("c-{}", generate_pending_id()),
            "iat": now,
            "sub": sub,
        });
        let Ok(request) = self.ss_request(
            "POST",
            &metadata.connect_endpoint,
            Some(&body),
            Outbound::Report,
            now,
        ) else {
            return Ok(false);
        };
        Ok(config
            .host
            .send(&request)
            .is_ok_and(|response| response.status() == StatusCode::OK))
    }

    /// Deliver every queued report, pair by pair and in order within each.
    /// Returns how many `(server, sub)` pairs still hold undelivered
    /// reports. Call it when a server may be reachable again; every
    /// supervision request also delivers its pair's queue first.
    ///
    /// # Errors
    /// [`SupervisionHostError::Disabled`] without supervision.
    pub fn deliver_supervision(&self) -> Result<usize, SupervisionHostError> {
        let config = self.gate().ok_or(SupervisionHostError::Disabled)?;
        let pairs = load(config.store.as_ref(), OUTBOX_INDEX)
            .and_then(|index| index["pairs"].as_array().cloned())
            .unwrap_or_default();
        let now = (self.clock)();
        let mut waiting = 0;
        for pair in pairs {
            let (Some(supervisor), Some(sub)) = (pair[0].as_str(), pair[1].as_str()) else {
                continue;
            };
            let delivered = self
                .supervisor_metadata(supervisor)
                .is_some_and(|metadata| self.flush(&metadata, sub, now));
            if !delivered {
                waiting += 1;
            }
        }
        Ok(waiting)
    }
}

fn journal_key(person_id: &str, agent: &AgentIdentity) -> String {
    key("j", &[person_id, &agent.issuer, &agent.subject])
}

fn outbox_key(supervisor: &str, sub: &str) -> String {
    key("o", &[supervisor, sub])
}

fn connection_key(supervisor: &str, sub: &str) -> String {
    key("c", &[supervisor, sub])
}
