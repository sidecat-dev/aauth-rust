//! The decision log: every exchange about one `sdi`, the request as this
//! server signed it and the response as it arrived (Signed Decisions).
use super::*;

const MAX_EXCHANGES: usize = 32;

/// One request this server sent about a decision, and what came back.
#[derive(Debug)]
pub struct SupervisionExchange {
    /// The request as signed.
    pub request: Request<Vec<u8>>,
    /// The response as received; `None` when the server could not be reached.
    pub response: Option<Response<Vec<u8>>>,
}

/// The log entry for one supervision decision.
#[derive(Debug)]
pub struct SupervisionRecord {
    /// The supervision decision identifier.
    pub sdi: String,
    /// The supervision server the act was put to.
    pub supervisor: String,
    /// The act.
    pub act: Act,
    /// The agent.
    pub agent: AgentIdentity,
    /// Every exchange, oldest first. Empty when no request could be built.
    pub exchanges: Vec<SupervisionExchange>,
    /// How the act ended: `allow`, `deny` or `ask` from the server; `held`
    /// while it waits; `unavailable` when the server was not consulted; and
    /// `person allow` or `person deny` once the person answered.
    pub outcome: Option<String>,
}

/// A signed decision, verified from a record alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDecision {
    /// The signer, read from the response's own `Signature-Key`.
    pub supervisor: String,
    /// The decision it signed.
    pub decision: Decision,
    /// When it was signed, Unix seconds.
    pub signed_at: i64,
}

/// A record whose decision cannot be verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The record holds no terminal `200` decision.
    #[error("the record holds no decision")]
    NoDecision,
    /// The decision is not signed.
    #[error("the decision is unsigned")]
    Unsigned,
    /// The signature, its coverage or its signer's key did not verify.
    #[error("the decision signature does not verify")]
    BadSignature,
    /// The signed body is not a decision for this `sdi` and act.
    #[error("the signed body is not this decision")]
    Malformed,
}

impl SupervisionRecord {
    /// Verify the last decision in this record with the keys `keys` resolves
    /// for the signer the response names, `(id, "aauth-supervisor.json",
    /// kid)`. Anyone holding the record can do this later, without knowing
    /// which server was configured at the time.
    ///
    /// # Errors
    /// See [`RecordError`].
    pub fn verify(&self, keys: &dyn AgentKeyResolver) -> Result<VerifiedDecision, RecordError> {
        let (request, response) = self
            .exchanges
            .iter()
            .rev()
            .find_map(|exchange| {
                exchange
                    .response
                    .as_ref()
                    .filter(|response| response.status() == StatusCode::OK)
                    .map(|response| (&exchange.request, response))
            })
            .ok_or(RecordError::NoDecision)?;
        if !response.headers().contains_key("signature") {
            return Err(RecordError::Unsigned);
        }
        let prepared = PreparedResponse::prepare(response, request, "sig", &["jwks_uri"])
            .map_err(|_| RecordError::BadSignature)?;
        if REQUIRED_DECISION_COMPONENTS
            .iter()
            .any(|component| !prepared.covers(component))
        {
            return Err(RecordError::BadSignature);
        }
        let KeyMaterial::JwksUri { id, dwk, kid } = prepared.key() else {
            return Err(RecordError::BadSignature);
        };
        if dwk != SUPERVISOR_DOCUMENT {
            return Err(RecordError::BadSignature);
        }
        aauth_rust_core::verify_with_refresh(
            keys,
            (id, dwk, kid),
            |key| prepared.verify(key),
            |error| *error == aauth_rust_signature_key::Error::InvalidSignature,
        )
        .map_err(|_| RecordError::BadSignature)?
        .map_err(|_| RecordError::BadSignature)?;
        let body = strict_json(response.body()).map_err(|_| RecordError::Malformed)?;
        let decision =
            Decision::parse(&body, &self.sdi, self.act).map_err(|_| RecordError::Malformed)?;
        Ok(VerifiedDecision {
            supervisor: id.clone(),
            decision,
            signed_at: prepared.created(),
        })
    }
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// The log entry for `sdi`, when this server put or held that decision.
    ///
    /// # Errors
    /// [`SupervisionHostError::Disabled`] without supervision, and
    /// [`SupervisionHostError::Unavailable`] for a store failure or a record
    /// that does not decode.
    pub fn supervision_record(
        &self,
        sdi: &str,
    ) -> Result<Option<SupervisionRecord>, SupervisionHostError> {
        let config = self.gate().ok_or(SupervisionHostError::Disabled)?;
        let Some(value) = config
            .store
            .load(&log_key(sdi))
            .map_err(|_| SupervisionHostError::Unavailable)?
            .map(|snapshot| snapshot.value)
        else {
            return Ok(None);
        };
        let broken = || SupervisionHostError::Unavailable;
        let exchanges = value["exchanges"]
            .as_array()
            .ok_or_else(broken)?
            .iter()
            .map(|exchange| {
                Ok(SupervisionExchange {
                    request: decode_request(&exchange["request"]).ok_or_else(broken)?,
                    response: match &exchange["response"] {
                        Value::Null => None,
                        stored => Some(decode_response(stored).ok_or_else(broken)?),
                    },
                })
            })
            .collect::<Result<Vec<_>, SupervisionHostError>>()?;
        Ok(Some(SupervisionRecord {
            sdi: sdi.to_owned(),
            supervisor: value["supervisor"].as_str().ok_or_else(broken)?.into(),
            act: value["act"]
                .as_str()
                .and_then(Act::from_name)
                .ok_or_else(broken)?,
            agent: AgentIdentity {
                issuer: value["agent"]["issuer"].as_str().ok_or_else(broken)?.into(),
                subject: value["agent"]["subject"]
                    .as_str()
                    .ok_or_else(broken)?
                    .into(),
            },
            exchanges,
            outcome: value["outcome"].as_str().map(str::to_owned),
        }))
    }

    /// Begin the log entry for a decision before anything is sent, so a
    /// decision the server never answers still has a complete entry.
    pub(super) fn log_open(
        &self,
        sdi: &str,
        supervisor: &str,
        act: Act,
        agent: &AgentIdentity,
    ) -> Result<(), ()> {
        let config = self.gate().ok_or(())?;
        config
            .store
            .insert(
                &log_key(sdi),
                json!({
                    "supervisor": supervisor, "act": act.name(),
                    "agent": { "issuer": agent.issuer, "subject": agent.subject },
                    "exchanges": [], "outcome": null,
                }),
            )
            .map_err(|_| ())
    }

    pub(super) fn log_exchange(
        &self,
        sdi: &str,
        request: &Request<Vec<u8>>,
        response: Option<&Response<Vec<u8>>>,
    ) -> Result<(), ()> {
        let config = self.gate().ok_or(())?;
        let exchange = json!({
            "request": encode_request(request),
            "response": response.map(encode_response),
        });
        update(config.store.as_ref(), &log_key(sdi), |current| {
            let mut entry = current?.clone();
            let exchanges = entry["exchanges"].as_array_mut()?;
            if exchanges.len() >= MAX_EXCHANGES {
                exchanges.remove(0);
            }
            exchanges.push(exchange.clone());
            Some(entry)
        })
    }

    pub(super) fn log_outcome(&self, sdi: &str, outcome: &str) {
        let Some(config) = self.gate() else {
            return;
        };
        let _ = update(config.store.as_ref(), &log_key(sdi), |current| {
            let mut entry = current?.clone();
            entry["outcome"] = json!(outcome);
            Some(entry)
        });
    }
}

fn log_key(sdi: &str) -> String {
    key("l", &[sdi])
}

fn headers_value(headers: &http::HeaderMap) -> Value {
    Value::Array(
        headers
            .iter()
            .filter_map(|(name, value)| Some(json!([name.as_str(), value.to_str().ok()?])))
            .collect(),
    )
}

fn encode_request(request: &Request<Vec<u8>>) -> Value {
    json!({
        "method": request.method().as_str(),
        "uri": request.uri().to_string(),
        "headers": headers_value(request.headers()),
        "body": URL_SAFE_NO_PAD.encode(request.body()),
    })
}

pub(super) fn encode_response(response: &Response<Vec<u8>>) -> Value {
    json!({
        "status": response.status().as_u16(),
        "headers": headers_value(response.headers()),
        "body": URL_SAFE_NO_PAD.encode(response.body()),
    })
}

fn decode_request(value: &Value) -> Option<Request<Vec<u8>>> {
    let mut builder = Request::builder()
        .method(value["method"].as_str()?)
        .uri(value["uri"].as_str()?);
    for header in value["headers"].as_array()? {
        builder = builder.header(header[0].as_str()?, header[1].as_str()?);
    }
    builder
        .body(URL_SAFE_NO_PAD.decode(value["body"].as_str()?).ok()?)
        .ok()
}

fn decode_response(value: &Value) -> Option<Response<Vec<u8>>> {
    let mut builder = Response::builder().status(u16::try_from(value["status"].as_u64()?).ok()?);
    for header in value["headers"].as_array()? {
        builder = builder.header(header[0].as_str()?, header[1].as_str()?);
    }
    builder
        .body(URL_SAFE_NO_PAD.decode(value["body"].as_str()?).ok()?)
        .ok()
}
