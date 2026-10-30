//! Missions a Person Server reported terminated
//! (`draft-hardt-oauth-aauth-protocol`, Mission Status Errors).
//!
//! A `403` answer with `error` `mission_terminated` ends the mission for good:
//! the agent must stop acting on it. [`Missions`] records that answer, and the
//! signed requests this crate builds for a mission refuse a terminated one.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aauth_rust_core::{AuthToken, PersonToken, ResourceToken};
use aauth_rust_jose::Jws;
use http::{Response, StatusCode};
use serde_json::Value;

/// One mission the Person Server ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionTerminated {
    /// The mission digest the request named.
    pub mission_s256: String,
    /// `termination_reason`, when the answer carried one. `expired` invites a
    /// new mission proposal; `revoked` does not.
    pub reason: Option<String>,
}

/// Termination state shared by every copy of one agent.
///
/// Clones share the same state, and [`crate::Agent::with_token`] keeps it, so
/// an answer observed through one handle stops every helper that uses
/// another. Nothing here contacts the Person Server: the host reads each
/// response to a request that named a mission with [`Self::observe`].
#[derive(Clone, Debug, Default)]
pub struct Missions {
    terminated: Arc<Mutex<BTreeMap<String, Option<String>>>>,
}

impl Missions {
    /// No mission has been reported terminated.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the Person Server's answer to a request that named `mission_s256`.
    ///
    /// A `403` whose JSON body has `error` `mission_terminated` ends that
    /// mission here and returns it. Any other answer changes nothing. An ended
    /// mission stays ended, and its first reason is kept.
    pub fn observe(
        &self,
        mission_s256: &str,
        response: &Response<Vec<u8>>,
    ) -> Option<MissionTerminated> {
        if mission_s256.is_empty() || response.status() != StatusCode::FORBIDDEN {
            return None;
        }
        let body: Value = serde_json::from_slice(response.body()).ok()?;
        if body.get("error").and_then(Value::as_str) != Some("mission_terminated") {
            return None;
        }
        let reason = body
            .get("termination_reason")
            .and_then(Value::as_str)
            .filter(|reason| !reason.is_empty());
        self.terminate(mission_s256, reason);
        self.termination(mission_s256)
    }

    /// End a mission the host learned was terminated some other way.
    pub fn terminate(&self, mission_s256: &str, reason: Option<&str>) {
        if mission_s256.is_empty() {
            return;
        }
        self.state()
            .entry(mission_s256.to_owned())
            .or_insert_with(|| reason.map(str::to_owned));
    }

    /// The recorded termination of `mission_s256`, if any.
    pub fn termination(&self, mission_s256: &str) -> Option<MissionTerminated> {
        self.state()
            .get(mission_s256)
            .map(|reason| MissionTerminated {
                mission_s256: mission_s256.to_owned(),
                reason: reason.clone(),
            })
    }

    /// `false` once `mission_s256` was reported terminated.
    pub fn is_active(&self, mission_s256: &str) -> bool {
        !self.state().contains_key(mission_s256)
    }

    /// `false` when `credential` is a Person, Auth or Resource token whose
    /// `mission_s256` names a terminated mission. A missionless token, or a
    /// value that is not one of those tokens, is `true`. The claim is read
    /// without verification; this only stops the agent's own use.
    pub fn may_present(&self, credential: &str) -> bool {
        credential_mission(credential).is_none_or(|mission| self.is_active(&mission))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Option<String>>> {
        self.terminated
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

fn credential_mission(compact: &str) -> Option<String> {
    let parsed = Jws::parse(compact).ok()?;
    match parsed.header().get("typ").and_then(Value::as_str)? {
        "aa-person+jwt" => PersonToken::parse(compact)
            .ok()?
            .unverified_claims()
            .mission_s256
            .clone(),
        "aa-auth+jwt" => AuthToken::parse(compact)
            .ok()?
            .unverified_claims()
            .mission_s256
            .clone(),
        "aa-resource+jwt" => ResourceToken::parse(compact)
            .ok()?
            .unverified_claims()
            .mission_s256
            .clone(),
        _ => None,
    }
}
