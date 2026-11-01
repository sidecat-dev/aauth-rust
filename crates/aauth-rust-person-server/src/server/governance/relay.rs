//! Relaying an agent's `interaction` or `payment` to the person
//! (`draft-hardt-oauth-aauth-protocol`: Interaction Endpoint, Interaction
//! Response, Relaying Through the Person Server).
//!
//! The host's [`RelayChannel`] takes the relay to the person. The agent polls
//! `{signed_origin}/interaction/relay/{id}`: `202` while the relay waits, then
//! once `200` with `status` `interacting` when the person engaged, or
//! `pending` when this server can do no more or the wait ended. The
//! resource's own pending URL stays authoritative for the interaction itself.
use super::*;
use aauth_rust_core::continuation::{ContinuationStore, PendingResponse, Requirement};
use std::sync::Arc;

/// The host has no channel to the person for a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("no channel to the person for this relay")]
pub struct RelayUnavailable;

/// The host's channel to the person for relays.
pub trait RelayChannel: Send + Sync {
    /// Take `relay` to the person, through an open session, a registered app
    /// or a notification: send them to `{url}?code={code}`. Its
    /// `description` is untrusted Markdown. Then call
    /// [`PersonServer::relay_engaged`] once they engage, or
    /// [`PersonServer::relay_finished`] when you can do no more.
    ///
    /// # Errors
    /// [`RelayUnavailable`] when there is no channel for it now: the agent is
    /// answered `424 interaction_unavailable` and directs the person itself.
    fn relay(&self, relay: &InteractionRelay) -> Result<(), RelayUnavailable>;
}

impl<T: RelayChannel + ?Sized> RelayChannel for Box<T> {
    fn relay(&self, relay: &InteractionRelay) -> Result<(), RelayUnavailable> {
        (**self).relay(relay)
    }
}

/// Relay settings and custody.
pub struct InteractionRelayConfig {
    /// The person channel.
    pub channel: Box<dyn RelayChannel>,
    /// Custody for relays waiting for the person. Use a store of its own;
    /// restart durability needs a host adapter.
    pub store: Arc<dyn ContinuationStore>,
    /// Seconds a relay waits, 1..=3600, shortened by the agent's `max_wait`
    /// and capped by its agent token. Default 600.
    pub lifetime: i64,
    /// Agent poll interval in seconds, 0..=3600. Default 5.
    pub retry_after: u64,
}

impl InteractionRelayConfig {
    /// Defaults with this channel and custody.
    pub fn new(
        channel: impl RelayChannel + 'static,
        store: impl ContinuationStore + 'static,
    ) -> Self {
        Self {
            channel: Box::new(channel),
            store: Arc::new(store),
            lifetime: 600,
            retry_after: 5,
        }
    }
}

/// A relay waiting for the person, for the host. It is attached to the
/// agent's `202` in `http::Response::extensions` and never serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InteractionRelay {
    /// Reference for [`PersonServer::relay_engaged`] and the other host calls.
    pub reference: String,
    /// The agent that asked.
    pub agent: AgentIdentity,
    /// `interaction` or `payment`.
    pub kind: String,
    /// The interaction URL: HTTPS, without query or fragment. Never fetched.
    pub url: String,
    /// The interaction code, as the agent sent it.
    pub code: String,
    /// Context for the person, untrusted Markdown.
    pub description: Option<String>,
    /// The mission the relay belongs to.
    pub mission_s256: Option<String>,
    /// When the relay stops waiting, Unix seconds.
    pub expires_at: i64,
}

/// A host relay call that could not be carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// `with_interaction_relay` was not called.
    #[error("interaction relays are not enabled")]
    Disabled,
    /// No relay waits under that reference: it is unknown, resolved with
    /// another answer, delivered or past its wait.
    #[error("no relay waits under that reference")]
    Gone,
    /// The store failed.
    #[error("relay custody is unavailable")]
    Unavailable,
}

pub(in crate::server) struct Gate {
    config: InteractionRelayConfig,
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Relay agents' `interaction` and `payment` requests to the person
    /// through `config.channel`, at the interaction endpoint
    /// [`Self::with_governance`] publishes. Without it, both are answered
    /// `424 interaction_unavailable`.
    ///
    /// A relay needs `url` and `code`, and may carry `description`,
    /// `max_wait` and `mission_s256`; a mission must be active. It is kept
    /// before the agent's `202`, and the agent's poll answers from it once
    /// (see [`Self::relay_engaged`]). With [`Self::with_supervision`], the
    /// agent's supervision server is told (`interaction.requested`), without
    /// the code.
    ///
    /// # Errors
    /// [`ConfigurationError`] for a lifetime or interval outside its range.
    pub fn with_interaction_relay(
        mut self,
        config: InteractionRelayConfig,
    ) -> Result<Self, ConfigurationError> {
        if !(1..=3600).contains(&config.lifetime) || config.retry_after > 3600 {
            return Err(ConfigurationError);
        }
        self.relay = Some(Gate { config });
        Ok(self)
    }

    /// Keep an agent's relay, hand it to the host's channel and answer `202`.
    pub(super) fn relay_request(
        &self,
        agent: &VerifiedAgentToken,
        body: &serde_json::Map<String, Value>,
        kind: &str,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let Some(gate) = &self.relay else {
            return Err(unavailable());
        };
        let config = &gate.config;
        let invalid = || Failure::parameter("invalid_request");
        if body.contains_key("question") {
            return Err(invalid());
        }
        let url = body
            .get("url")
            .and_then(Value::as_str)
            .filter(|url| relay_url(url))
            .ok_or_else(invalid)?;
        let code = body
            .get("code")
            .and_then(Value::as_str)
            .filter(|code| canonical_interaction_code(code).is_some())
            .ok_or_else(invalid)?;
        let description = match body.get("description") {
            None => None,
            Some(Value::String(text)) if text.len() <= MAX_TEXT => Some(text.clone()),
            Some(_) => return Err(invalid()),
        };
        let max_wait = match body.get("max_wait") {
            None => None,
            Some(value) => Some(value.as_u64().ok_or_else(invalid)?),
        };
        let mut expires_at = now.saturating_add(config.lifetime).min(agent.claims().exp);
        if let Some(wait) = max_wait.filter(|wait| *wait > 0) {
            expires_at =
                expires_at.min(now.saturating_add(i64::try_from(wait).unwrap_or(i64::MAX)));
        }
        if expires_at <= now {
            return Err(Failure::status(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        let identity = Self::identity(agent);
        let relay = InteractionRelay {
            reference: generate_pending_id(),
            agent: identity.clone(),
            kind: kind.into(),
            url: url.into(),
            code: code.into(),
            description,
            mission_s256: body
                .get("mission_s256")
                .and_then(Value::as_str)
                .map(str::to_owned),
            expires_at,
        };
        let key = relay_key(&relay.reference);
        config
            .store
            .insert(
                &key,
                json!({
                    "state": "pending",
                    "agent": {
                        "issuer": identity.issuer, "subject": identity.subject,
                        "jkt": agent.claims().cnf.jwk.thumbprint().map_err(|_| Failure::internal())?,
                    },
                    "type": relay.kind, "url": relay.url, "code": relay.code,
                    "description": relay.description, "mission_s256": relay.mission_s256,
                    "expires_at": relay.expires_at,
                }),
            )
            .map_err(|_| Failure::internal())?;
        if config.channel.relay(&relay).is_err() {
            if let Ok(Some(snapshot)) = config.store.load(&key) {
                let _ = config.store.replace(&key, snapshot.revision, None);
            }
            return Err(unavailable());
        }
        self.report_interaction(
            agent,
            &relay.kind,
            Some(&relay.url),
            relay.mission_s256.as_deref(),
        );
        let mut response = self.relay_pending(&relay.reference)?;
        response.extensions_mut().insert(relay);
        Ok(response)
    }

    /// The agent's poll of its relay. A terminal answer is given once.
    pub(super) fn poll_relay(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        id: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let gate = self.relay.as_ref().ok_or_else(Failure::internal)?;
        if request.uri().query().is_some() || !request.body().is_empty() {
            return Err(Failure::parameter("invalid_request"));
        }
        let agent = self.verify_agent(request, now, false)?;
        direct_agent(&agent)?;
        let key = relay_key(id);
        let snapshot = gate
            .config
            .store
            .load(&key)
            .map_err(|_| Failure::internal())?
            .ok_or_else(invalid_code)?;
        let record = snapshot.value;
        let claims = agent.claims();
        // Another agent's poll is answered as for an unknown relay.
        if record["agent"]["issuer"].as_str() != Some(&claims.iss)
            || record["agent"]["subject"].as_str() != Some(&claims.sub)
            || record["agent"]["jkt"].as_str() != claims.cnf.jwk.thumbprint().ok().as_deref()
        {
            return Err(invalid_code());
        }
        if let Some(s256) = record["mission_s256"].as_str() {
            self.active_mission(&agent, s256, now)?;
        }
        let status = match record["state"].as_str() {
            Some("pending") if record["expires_at"].as_i64().is_some_and(|at| now < at) => {
                return self.relay_pending(id);
            }
            Some("interacting") => "interacting",
            _ => "pending",
        };
        if !gate
            .config
            .store
            .replace(&key, snapshot.revision, None)
            .map_err(|_| Failure::internal())?
        {
            return Err(invalid_code());
        }
        let mut response = json_response(StatusCode::OK, json!({ "status": status }));
        response
            .headers_mut()
            .insert("cache-control", http::HeaderValue::from_static("no-store"));
        Ok(response)
    }

    /// The relay waiting under `reference`.
    ///
    /// # Errors
    /// [`RelayError::Gone`] when no relay waits under it.
    pub fn interaction_relay(&self, reference: &str) -> Result<InteractionRelay, RelayError> {
        let gate = self.relay.as_ref().ok_or(RelayError::Disabled)?;
        if !path_token(reference) {
            return Err(RelayError::Gone);
        }
        let record = gate
            .config
            .store
            .load(&relay_key(reference))
            .map_err(|_| RelayError::Unavailable)?
            .ok_or(RelayError::Gone)?
            .value;
        if !waiting(&record, (self.clock)()) {
            return Err(RelayError::Gone);
        }
        Ok(InteractionRelay {
            reference: reference.into(),
            agent: AgentIdentity {
                issuer: record["agent"]["issuer"].as_str().unwrap_or("").into(),
                subject: record["agent"]["subject"].as_str().unwrap_or("").into(),
            },
            kind: record["type"].as_str().unwrap_or("").into(),
            url: record["url"].as_str().unwrap_or("").into(),
            code: record["code"].as_str().unwrap_or("").into(),
            description: record["description"].as_str().map(str::to_owned),
            mission_s256: record["mission_s256"].as_str().map(str::to_owned),
            expires_at: record["expires_at"].as_i64().unwrap_or(0),
        })
    }

    /// The person engaged with the relayed interaction. The agent's next poll
    /// gets `200 {"status":"interacting"}`; it keeps polling the resource.
    ///
    /// # Errors
    /// [`RelayError::Gone`] when no relay waits under `reference`.
    pub fn relay_engaged(&self, reference: &str) -> Result<(), RelayError> {
        self.resolve_relay(reference, "interacting")
    }

    /// This server can do no more for the relay. The agent's next poll gets
    /// `200 {"status":"pending"}`; it keeps polling the resource.
    ///
    /// # Errors
    /// [`RelayError::Gone`] when no relay waits under `reference`.
    pub fn relay_finished(&self, reference: &str) -> Result<(), RelayError> {
        self.resolve_relay(reference, "finished")
    }

    fn resolve_relay(&self, reference: &str, state: &str) -> Result<(), RelayError> {
        let gate = self.relay.as_ref().ok_or(RelayError::Disabled)?;
        if !path_token(reference) {
            return Err(RelayError::Gone);
        }
        let key = relay_key(reference);
        for _ in 0..8 {
            let snapshot = gate
                .config
                .store
                .load(&key)
                .map_err(|_| RelayError::Unavailable)?
                .ok_or(RelayError::Gone)?;
            // The same answer again converges; another one is refused.
            if snapshot.value["state"] == state {
                return Ok(());
            }
            if !waiting(&snapshot.value, (self.clock)()) {
                return Err(RelayError::Gone);
            }
            let mut record = snapshot.value;
            record["state"] = json!(state);
            if gate
                .config
                .store
                .replace(&key, snapshot.revision, Some(record))
                .map_err(|_| RelayError::Unavailable)?
            {
                return Ok(());
            }
        }
        Err(RelayError::Unavailable)
    }

    fn relay_pending(&self, id: &str) -> Result<Response<Vec<u8>>, Failure> {
        let gate = self.relay.as_ref().ok_or_else(Failure::internal)?;
        let origin = &self.config.signed_origin;
        PendingResponse::new(
            origin,
            &format!("{origin}/interaction/relay/{id}"),
            gate.config.retry_after,
            Requirement::Waiting,
        )
        .and_then(|pending| pending.response())
        .map_err(|_| Failure::internal())
    }

    /// `interaction.requested`: the agent asked this server to take an
    /// interaction to the person, and it did. Not a decision, and the code
    /// is not forwarded.
    pub(super) fn report_interaction(
        &self,
        agent: &VerifiedAgentToken,
        kind: &str,
        url: Option<&str>,
        mission_s256: Option<&str>,
    ) {
        let identity = Self::identity(agent);
        let Some(person_id) = self.bound_person(&identity) else {
            return;
        };
        let mut members = serde_json::Map::new();
        members.insert("type".into(), json!(kind));
        if let Some(url) = url {
            members.insert("url".into(), json!(url));
        }
        self.report(
            &person_id,
            &identity,
            Report::Event(EventKind::InteractionRequested, members),
            None,
            mission_s256,
            None,
        );
    }
}

fn relay_key(id: &str) -> String {
    format!("ir.{id}")
}

fn waiting(record: &Value, now: i64) -> bool {
    record["state"] == "pending" && record["expires_at"].as_i64().is_some_and(|at| now < at)
}

fn unavailable() -> Failure {
    Failure::status(StatusCode::FAILED_DEPENDENCY, "interaction_unavailable")
}

/// An interaction URL: HTTPS with a host, no user information, query or
/// fragment (Interaction Required).
fn relay_url(value: &str) -> bool {
    let Ok(uri) = value.parse::<http::Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && uri.host().is_some_and(|host| !host.is_empty())
        && uri
            .authority()
            .is_some_and(|authority| !authority.as_str().contains('@'))
        && uri.query().is_none()
        && !value.contains('#')
}
