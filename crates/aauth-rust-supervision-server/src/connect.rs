//! Connect: a Person Server establishes that it speaks for a person here.
use crate::records::{self, CONNECT_CODE, CONNECTING, CONNECTION};
use crate::{
    Answer, ConnectAnswer, ConnectRequest, HostError, Policy, SupervisionServer, deferred,
    json_response, polling_error, refuse, server_error, sf_string,
};
use aauth_rust_core::AgentKeyResolver;
use aauth_rust_core::continuation::{
    ContinuationStore, canonical_interaction_code, generate_interaction_code, generate_pending_id,
};
use aauth_rust_core::supervision::SupervisionError;
use http::{Request, StatusCode};
use serde_json::{Value, json};

/// A connect waiting for the person, for the host's confirmation page.
///
/// The page must show the connecting Person Server's `issuer` and its
/// metadata `name`, and should show the `code`, so the person can recognize
/// a connect they did not start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingConnection {
    /// The connecting Person Server.
    pub ps: String,
    /// The person, as that Person Server directs them here.
    pub sub: String,
    /// The tenant the Person Server asserted, if any.
    pub tenant: Option<String>,
    /// The code the person arrived with, as this server issued it.
    pub code: String,
}

impl<K: AgentKeyResolver, P: Policy, S: ContinuationStore, C: Fn() -> i64>
    SupervisionServer<K, P, S, C>
{
    pub(crate) fn connect(&self, request: &Request<Vec<u8>>, now: i64) -> Answer {
        let ps = self.authenticate(request, now)?;
        let body = Self::object(request)?;
        let invalid = || refuse(SupervisionError::InvalidRequest);
        let action = body
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let sub = body
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(invalid)?
            .to_owned();
        if body
            .get("iat")
            .and_then(Value::as_i64)
            .is_none_or(|iat| iat < 0)
            || body
                .get("id")
                .and_then(Value::as_str)
                .is_none_or(|id| id.is_empty() || id.len() > 256)
        {
            return Err(invalid());
        }
        let tenant = match body.get("tenant") {
            None => None,
            Some(Value::String(t)) if !t.is_empty() && t.len() <= 256 => Some(t.clone()),
            Some(_) => return Err(invalid()),
        };
        let key = records::key(CONNECTION, &[&ps, &sub]);
        match action {
            "disconnect" => {
                records::remove(&self.store, &key).map_err(|_| server_error())?;
                return Ok(json_response(
                    StatusCode::OK,
                    json!({ "status": "disconnected" }),
                ));
            }
            "connect" => {}
            _ => return Err(invalid()),
        }
        if records::load(&self.store, &key)
            .map_err(|_| server_error())?
            .is_some()
        {
            return Ok(connected());
        }
        let asked = ConnectRequest {
            ps: ps.clone(),
            sub: sub.clone(),
            tenant: tenant.clone(),
        };
        match self.policy.connect(&asked) {
            ConnectAnswer::Connected => {
                self.record_connection(&ps, &sub, tenant.as_deref())
                    .map_err(|_| server_error())?;
                Ok(connected())
            }
            ConnectAnswer::Refused => Err(refuse(SupervisionError::UnsupportedIss)),
            ConnectAnswer::Confirm => {
                let Some(url) = &self.config.interaction_url else {
                    return Err(server_error());
                };
                let id = generate_pending_id();
                let code = generate_interaction_code();
                let canonical = canonical_interaction_code(&code).ok_or_else(server_error)?;
                let record = json!({
                    "ps": ps, "sub": sub, "tenant": tenant, "code": code,
                    "state": "waiting",
                    "expires": now.saturating_add(self.config.pending_lifetime),
                });
                records::insert_new(&self.store, &records::key(CONNECTING, &[&id]), record)
                    .map_err(|_| server_error())?;
                records::insert_new(
                    &self.store,
                    &records::key(CONNECT_CODE, &[&canonical]),
                    json!({ "id": id }),
                )
                .map_err(|_| server_error())?;
                Ok(self.connect_pending(&id, url, &code))
            }
        }
    }

    fn connect_pending(&self, id: &str, url: &str, code: &str) -> http::Response<Vec<u8>> {
        deferred(
            &self.pending_url("/connect/pending/", id),
            self.config.retry_after,
            Some(format!(
                "requirement=interaction; url={}; code={}",
                sf_string(url),
                sf_string(code)
            )),
            json!({ "status": "pending" }),
        )
    }

    pub(crate) fn poll_connect(&self, request: &Request<Vec<u8>>, now: i64, id: &str) -> Answer {
        let ps = self.authenticate(request, now)?;
        let key = records::key(CONNECTING, &[id]);
        let Some(record) = records::load(&self.store, &key).map_err(|_| server_error())? else {
            return Err(polling_error(StatusCode::GONE, "invalid_code"));
        };
        if record["ps"].as_str() != Some(ps.as_str()) {
            return Err(refuse(SupervisionError::UnknownPending));
        }
        if record["expires"].as_i64().is_none_or(|at| now >= at) {
            records::remove(&self.store, &key).map_err(|_| server_error())?;
            return Err(polling_error(StatusCode::REQUEST_TIMEOUT, "expired"));
        }
        match record["state"].as_str() {
            Some("confirmed") => {
                records::remove(&self.store, &key).map_err(|_| server_error())?;
                Ok(connected())
            }
            Some("refused") => {
                records::remove(&self.store, &key).map_err(|_| server_error())?;
                Err(polling_error(StatusCode::FORBIDDEN, "denied"))
            }
            _ => {
                let url = self
                    .config
                    .interaction_url
                    .as_deref()
                    .ok_or_else(server_error)?;
                let code = record["code"].as_str().ok_or_else(server_error)?;
                Ok(self.connect_pending(id, url, code))
            }
        }
    }

    /// The connect a person arrived at the confirmation page with. Codes
    /// compare without case or hyphens.
    ///
    /// # Errors
    /// [`HostError::NotFound`] for an unknown, consumed or expired code.
    pub fn pending_connection(&self, code: &str) -> Result<PendingConnection, HostError> {
        let (_, record) = self.connecting(code)?;
        Ok(PendingConnection {
            ps: record["ps"].as_str().ok_or(HostError::Unavailable)?.into(),
            sub: record["sub"].as_str().ok_or(HostError::Unavailable)?.into(),
            tenant: record["tenant"].as_str().map(str::to_owned),
            code: record["code"]
                .as_str()
                .ok_or(HostError::Unavailable)?
                .into(),
        })
    }

    /// Record the person's answer at the confirmation page. The code is
    /// consumed; an accepted connect is recorded for `(ps, sub)` at once, and
    /// the Person Server's next poll returns `200`.
    ///
    /// # Errors
    /// [`HostError::NotFound`] for an unknown, consumed or expired code.
    pub fn confirm_connection(&self, code: &str, accept: bool) -> Result<(), HostError> {
        let (id, record) = self.connecting(code)?;
        let canonical = canonical_interaction_code(code).ok_or(HostError::NotFound)?;
        records::remove(&self.store, &records::key(CONNECT_CODE, &[&canonical]))?;
        if accept {
            self.record_connection(
                record["ps"].as_str().ok_or(HostError::Unavailable)?,
                record["sub"].as_str().ok_or(HostError::Unavailable)?,
                record["tenant"].as_str(),
            )?;
        }
        let state = if accept { "confirmed" } else { "refused" };
        records::update(&self.store, &records::key(CONNECTING, &[&id]), |current| {
            current.map(|value| {
                let mut value = value.clone();
                value["state"] = json!(state);
                value
            })
        })?;
        Ok(())
    }

    /// Whether `(ps, sub)` is connected.
    ///
    /// # Errors
    /// [`HostError::Unavailable`] when the store fails.
    pub fn connected(&self, ps: &str, sub: &str) -> Result<bool, HostError> {
        Ok(records::load(&self.store, &records::key(CONNECTION, &[ps, sub]))?.is_some())
    }

    fn connecting(&self, code: &str) -> Result<(String, Value), HostError> {
        let canonical = canonical_interaction_code(code).ok_or(HostError::NotFound)?;
        let index = records::load(&self.store, &records::key(CONNECT_CODE, &[&canonical]))?
            .ok_or(HostError::NotFound)?;
        let id = index["id"]
            .as_str()
            .ok_or(HostError::Unavailable)?
            .to_owned();
        let record = records::load(&self.store, &records::key(CONNECTING, &[&id]))?
            .ok_or(HostError::NotFound)?;
        if record["state"] != "waiting"
            || record["expires"]
                .as_i64()
                .is_none_or(|at| (self.clock)() >= at)
        {
            return Err(HostError::NotFound);
        }
        Ok((id, record))
    }

    fn record_connection(
        &self,
        ps: &str,
        sub: &str,
        tenant: Option<&str>,
    ) -> Result<(), records::Fault> {
        records::update(&self.store, &records::key(CONNECTION, &[ps, sub]), |_| {
            Some(json!({ "ps": ps, "sub": sub, "tenant": tenant }))
        })
    }
}

fn connected() -> http::Response<Vec<u8>> {
    json_response(StatusCode::OK, json!({ "status": "connected" }))
}
