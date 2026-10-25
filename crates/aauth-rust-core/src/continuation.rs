//! Bounded deferred wire messages and atomic, role-local continuation storage.
//! These values do not authenticate a peer or authorize network access. Hosts
//! admit endpoints, authenticate each poll and supply unpredictable unique IDs.
mod payment;
pub use payment::{PaymentChallenge, PaymentChallengeError};

use http::{Response, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sfv::{BareItem, Dictionary, ListEntry, Parser};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// Requirement raised by an authenticated deferred endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Requirement {
    /// Processing continues without an additional requirement.
    Waiting,
    /// Obtain these additional identity claims from the host's trusted source.
    Claims(Vec<String>),
    /// Untrusted Markdown question; sanitize before displaying to a person.
    Clarification {
        /// Question supplied by the remote policy.
        question: String,
        /// Optional response deadline in seconds.
        timeout: Option<u64>,
        /// Optional discrete answer strings.
        options: Vec<String>,
    },
    /// Host directs the person to this HTTPS URL; the code is not a credential.
    Interaction {
        /// HTTPS interaction target without a query or fragment; never fetched.
        url: String,
        /// At least eight case-insensitive Crockford Base32 symbols, optionally
        /// hyphenated. The host manages unpredictability and single use.
        code: String,
    },
    /// Host is obtaining approval without directing the person at the Agent.
    Approval,
    /// Resource held the invocation and requires an auth token before it runs.
    /// The resource token is the challenge; the later poll presents the auth token.
    AuthToken {
        /// Compact resource token from the `resource-token` parameter.
        resource_token: String,
    },
    /// Payment details are opaque and settlement belongs to the host.
    Payment {
        /// Exact bounded WWW-Authenticate value supplied by the AS.
        authenticate: String,
    },
}
/// Unusable deferred framing, body, requirement or pending target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid deferred response: require bounded 202/402 framing and a safe same-origin HTTPS Location"
)]
pub struct PendingError;

/// Parsed bounded response. It remains untrusted until authenticated transport
/// and role policy have admitted its origin. Construction also validates inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingResponse {
    /// Absolute same-origin HTTPS pending URL; no query, fragment or encoded path.
    pub location: String,
    /// Poll interval in seconds, bounded to one hour by this local profile.
    pub retry_after: u64,
    /// Additional input or host action required before completion.
    pub requirement: Requirement,
    /// Exact parsed JSON payload, including opaque payment details.
    pub body: Value,
}
impl PendingResponse {
    /// Validate and parse actual buffered response bytes, bounded to 1 MiB.
    /// Missing required framing and unsupported requirements fail closed.
    pub fn parse(endpoint: &str, response: &Response<Vec<u8>>) -> Result<Self, PendingError> {
        if ![StatusCode::ACCEPTED, StatusCode::PAYMENT_REQUIRED].contains(&response.status())
            || response.body().len() > 1_048_576
        {
            return Err(PendingError);
        }
        let header = |name: &str| -> Result<&str, PendingError> {
            if response.headers().get_all(name).iter().count() != 1 {
                return Err(PendingError);
            }
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .ok_or(PendingError)
        };
        let location = same_origin_location(endpoint, header("location")?)?;
        let retry_after = if response.headers().contains_key("retry-after") {
            header("retry-after")?
                .parse::<u64>()
                .map_err(|_| PendingError)?
        } else {
            5
        };
        let payment = response.status() == StatusCode::PAYMENT_REQUIRED;
        if retry_after > 3600 {
            return Err(PendingError);
        }
        if !payment
            && !header("cache-control")?
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("no-store"))
        {
            return Err(PendingError);
        }
        if (!payment || !response.body().is_empty())
            && !header("content-type")?
                .split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(PendingError);
        }
        let body = if payment && response.body().is_empty() {
            json!({})
        } else {
            aauth_rust_jose::strict_json(response.body()).map_err(|_| PendingError)?
        };
        let object = body.as_object().ok_or(PendingError)?;
        if object.contains_key("auth_token") {
            return Err(PendingError);
        }
        let requirement = if response.status() == StatusCode::PAYMENT_REQUIRED {
            if response.headers().contains_key("aauth-requirement") {
                return Err(PendingError);
            }
            let authenticate = header("www-authenticate")?;
            if authenticate.is_empty() || authenticate.len() > 65536 {
                return Err(PendingError);
            }
            Requirement::Payment {
                authenticate: authenticate.into(),
            }
        } else {
            if !object.get("status").is_some_and(Value::is_string) {
                return Err(PendingError);
            }
            match response.headers().get("aauth-requirement") {
                None => Requirement::Waiting,
                Some(_) => {
                    let field = header("aauth-requirement")?;
                    if field.len() > 65536 {
                        return Err(PendingError);
                    }
                    let dictionary: Dictionary =
                        Parser::new(field).parse().map_err(|_| PendingError)?;
                    let Some(ListEntry::Item(item)) = dictionary.get("requirement") else {
                        return Err(PendingError);
                    };
                    let BareItem::Token(token) = &item.bare_item else {
                        return Err(PendingError);
                    };
                    match token.as_str() {
                        "claims" => Requirement::Claims(strings(
                            object.get("required_claims").ok_or(PendingError)?,
                            true,
                        )?),
                        "clarification" => Requirement::Clarification {
                            question: object
                                .get("clarification")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .ok_or(PendingError)?
                                .into(),
                            timeout: object
                                .get("timeout")
                                .map(|v| v.as_u64().filter(|v| *v > 0).ok_or(PendingError))
                                .transpose()?,
                            options: object
                                .get("options")
                                .map(|v| strings(v, false))
                                .transpose()?
                                .unwrap_or_default(),
                        },
                        "interaction" => {
                            let param = |name: &str| match item.params.get(name) {
                                Some(BareItem::String(v)) if !v.as_str().is_empty() => {
                                    Ok(v.as_str().to_owned())
                                }
                                _ => Err(PendingError),
                            };
                            let url = param("url")?;
                            if https_uri(&url)?.query().is_some() {
                                return Err(PendingError);
                            }
                            let code = param("code")?;
                            if !valid_interaction_code(&code) {
                                return Err(PendingError);
                            }
                            Requirement::Interaction { url, code }
                        }
                        "approval" => Requirement::Approval,
                        "auth-token" => {
                            let resource_token = match item.params.get("resource-token") {
                                Some(BareItem::String(value)) if !value.as_str().is_empty() => {
                                    value.as_str().to_owned()
                                }
                                _ => return Err(PendingError),
                            };
                            Requirement::AuthToken { resource_token }
                        }
                        _ => return Err(PendingError),
                    }
                }
            }
        };
        if matches!(&requirement, Requirement::Claims(names) if names.iter().any(|name| name == "sub"))
        {
            return Err(PendingError);
        }
        Ok(Self {
            location,
            retry_after,
            requirement,
            body,
        })
    }
    /// Build validated deferred framing. Bodies are bounded and cannot contain
    /// a grant. `response` returns an error if a caller mutates these public fields
    /// into an invalid combination.
    pub fn new(
        endpoint: &str,
        location: &str,
        retry_after: u64,
        requirement: Requirement,
    ) -> Result<Self, PendingError> {
        let mut body = json!({"status":"pending"});
        match &requirement {
            Requirement::Claims(names) => body["required_claims"] = json!(names),
            Requirement::Clarification {
                question,
                timeout,
                options,
            } => {
                body["clarification"] = json!(question);
                if let Some(timeout) = timeout {
                    body["timeout"] = json!(timeout);
                }
                if !options.is_empty() {
                    body["options"] = json!(options);
                }
            }
            _ => {}
        }
        let value = Self {
            location: same_origin_location(endpoint, location)?,
            retry_after,
            requirement,
            body,
        };
        let wire = value.wire()?;
        Self::parse(endpoint, &wire)
    }
    /// Render a validated response with `no-store`, Location and Retry-After.
    pub fn response(&self) -> Result<Response<Vec<u8>>, PendingError> {
        let wire = self.wire()?;
        Self::parse(&self.location, &wire)?;
        Ok(wire)
    }
    /// Parse one unambiguous Payment HTTP authentication challenge, leaving the
    /// original header untouched. Nonpayment requirements return `None`.
    /// Details remain untrusted; the host owns payment method admission and
    /// settlement. This accessor performs no network access or other I/O.
    pub fn payment_challenge(&self) -> Result<Option<PaymentChallenge>, PaymentChallengeError> {
        match &self.requirement {
            Requirement::Payment { authenticate } => payment::parse(authenticate).map(Some),
            _ => Ok(None),
        }
    }
    fn wire(&self) -> Result<Response<Vec<u8>>, PendingError> {
        let mut response = Response::builder()
            .status(if matches!(self.requirement, Requirement::Payment { .. }) {
                402
            } else {
                202
            })
            .header("location", &self.location)
            .header("retry-after", self.retry_after.to_string())
            .header("cache-control", "no-store")
            .header("content-type", "application/json");
        let field = match &self.requirement {
            Requirement::Waiting => None,
            Requirement::Approval => Some("requirement=approval".into()),
            Requirement::AuthToken { resource_token } => Some(format!(
                "requirement=auth-token; resource-token={}",
                sf_string(resource_token)?
            )),
            Requirement::Claims(_) => Some("requirement=claims".into()),
            Requirement::Clarification { .. } => Some("requirement=clarification".into()),
            Requirement::Interaction { url, code } => Some(format!(
                "requirement=interaction; url={}; code={}",
                sf_string(url)?,
                sf_string(code)?
            )),
            Requirement::Payment { authenticate } => {
                response = response.header("www-authenticate", authenticate);
                None
            }
        };
        if let Some(field) = field {
            response = response.header("aauth-requirement", field);
        }
        response
            .body(self.body.to_string().into_bytes())
            .map_err(|_| PendingError)
    }
}
fn valid_interaction_code(code: &str) -> bool {
    let mut symbols = 0;
    for byte in code.bytes() {
        match byte.to_ascii_uppercase() {
            b'-' => {}
            b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z' => {
                symbols += 1
            }
            _ => return false,
        }
    }
    (8..=128).contains(&symbols)
}

/// Comparison value of an interaction code.
/// Hyphens are removed. Case is folded. Crockford aliases `I` and `L` become `1`,
/// and `O` becomes `0`. The result is `None` unless eight to 128 symbols remain
/// from the Crockford alphabet after that folding.
pub fn canonical_interaction_code(code: &str) -> Option<String> {
    let mut out = String::new();
    for byte in code.bytes() {
        let upper = byte.to_ascii_uppercase();
        let symbol = match upper {
            b'-' => continue,
            b'I' | b'L' => b'1',
            b'O' => b'0',
            b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z' => {
                upper
            }
            _ => return None,
        };
        out.push(char::from(symbol));
    }
    (8..=128).contains(&out.len()).then_some(out)
}

/// True when a server may emit this code. Aliases `I`, `L`, and `O` are rejected.
/// Hyphens are allowed and do not count as symbols.
pub fn is_emitted_interaction_code(code: &str) -> bool {
    valid_interaction_code(code)
}
fn sf_string(value: &str) -> Result<String, PendingError> {
    if !value.bytes().all(|v| (0x20..=0x7e).contains(&v)) {
        return Err(PendingError);
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
fn strings(value: &Value, nonempty: bool) -> Result<Vec<String>, PendingError> {
    let values = value.as_array().ok_or(PendingError)?;
    if (nonempty && values.is_empty()) || values.len() > 128 {
        return Err(PendingError);
    }
    let mut out = Vec::new();
    for value in values {
        let s = value
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .ok_or(PendingError)?;
        if out.iter().any(|v| v == s) {
            return Err(PendingError);
        }
        out.push(s.into());
    }
    Ok(out)
}
fn https_uri(value: &str) -> Result<Uri, PendingError> {
    let uri: Uri = value.parse().map_err(|_| PendingError)?;
    if uri.scheme_str() != Some("https")
        || uri.host().is_none()
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
        || value.contains('#')
    {
        return Err(PendingError);
    }
    Ok(uri)
}
/// Resolve an absolute or root-relative pending URL against the admitted HTTPS
/// endpoint. This local profile rejects queries, encoded paths and dot segments.
/// It does not perform discovery, DNS resolution or any network access.
pub fn same_origin_location(endpoint: &str, location: &str) -> Result<String, PendingError> {
    let base = https_uri(endpoint)?;
    let absolute = if location.starts_with('/') && !location.starts_with("//") {
        format!(
            "https://{}{}",
            base.authority().ok_or(PendingError)?,
            location
        )
    } else {
        location.into()
    };
    let uri = https_uri(&absolute)?;
    if base.authority() != uri.authority()
        || uri.query().is_some()
        || uri.path().contains('%')
        || uri.path().contains('\\')
        || uri.path().split('/').any(|v| v == "." || v == "..")
    {
        return Err(PendingError);
    }
    Ok(absolute)
}

/// Store failure is distinct from an optimistic revision conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// ID already exists; the caller must not overwrite another request.
    #[error("continuation ID already exists")]
    Conflict,
    /// Host count or per-record byte budget is exhausted.
    #[error("continuation store capacity exhausted")]
    Capacity,
    /// Persistence or synchronization failed; never release terminal output.
    #[error("continuation store unavailable")]
    Unavailable,
}
/// Snapshot used for conditional transition or one-shot removal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Opaque monotonically changing revision, including across delete/reinsert.
    pub revision: u64,
    /// Role-local state containing exact compact credentials and verified context.
    pub value: Value,
}
/// Atomic continuation custody. Each role uses its own namespace/store instance.
/// Durable implementations must commit before returning, prevent stale-revision
/// updates and preserve records across host recomposition. Returning an error
/// never authorizes delivery. IDs are host-owned, unique and unpredictable.
pub trait ContinuationStore: Send + Sync {
    /// Insert a new unique bounded record; never replace an existing ID.
    fn insert(&self, id: &str, value: Value) -> Result<(), StoreError>;
    /// Read a consistent snapshot; missing and consumed IDs return None.
    fn load(&self, id: &str) -> Result<Option<Snapshot>, StoreError>;
    /// Replace or remove only the specified revision, atomically. A false result
    /// means a concurrent transition won; it is not a persistence error.
    fn replace(&self, id: &str, revision: u64, value: Option<Value>) -> Result<bool, StoreError>;
}
impl<T: ContinuationStore + ?Sized> ContinuationStore for Arc<T> {
    fn insert(&self, id: &str, value: Value) -> Result<(), StoreError> {
        (**self).insert(id, value)
    }
    fn load(&self, id: &str) -> Result<Option<Snapshot>, StoreError> {
        (**self).load(id)
    }
    fn replace(&self, id: &str, revision: u64, value: Option<Value>) -> Result<bool, StoreError> {
        (**self).replace(id, revision, value)
    }
}
/// Bounded process-memory fixture. Share via Arc to recompose a role without
/// losing state; process restart durability requires a host store implementation.
/// Each serialized record is bounded to 1 MiB. Explicit terminal removal frees
/// capacity; hosts own expiry collection of records no caller returns to poll.
pub struct MemoryContinuations {
    capacity: usize,
    state: Mutex<(u64, BTreeMap<String, Snapshot>)>,
}
impl MemoryContinuations {
    /// Set an explicit maximum number of retained pending records.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new((0, BTreeMap::new())),
        }
    }
}
impl ContinuationStore for MemoryContinuations {
    fn insert(&self, id: &str, value: Value) -> Result<(), StoreError> {
        if id.is_empty() || id.len() > 256 || value.to_string().len() > 1_048_576 {
            return Err(StoreError::Capacity);
        }
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        if state.1.contains_key(id) {
            return Err(StoreError::Conflict);
        }
        if state.1.len() >= self.capacity {
            return Err(StoreError::Capacity);
        }
        state.0 = state.0.checked_add(1).ok_or(StoreError::Unavailable)?;
        let revision = state.0;
        state.1.insert(id.into(), Snapshot { revision, value });
        Ok(())
    }
    fn load(&self, id: &str) -> Result<Option<Snapshot>, StoreError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .1
            .get(id)
            .cloned())
    }
    fn replace(&self, id: &str, revision: u64, value: Option<Value>) -> Result<bool, StoreError> {
        if value
            .as_ref()
            .is_some_and(|v| v.to_string().len() > 1_048_576)
        {
            return Err(StoreError::Capacity);
        }
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        if state.1.get(id).is_none_or(|s| s.revision != revision) {
            return Ok(false);
        }
        state.0 = state.0.checked_add(1).ok_or(StoreError::Unavailable)?;
        let revision = state.0;
        if let Some(value) = value {
            state.1.insert(id.into(), Snapshot { revision, value });
        } else {
            state.1.remove(id);
        }
        Ok(true)
    }
}
