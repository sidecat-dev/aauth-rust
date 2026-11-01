//! Revocation request, ledger and response shapes shared by PS, AS and Resource.
//!
//! Transport stays with the host. A [`RevocationDirectory`] delivers one
//! downstream call; this module does not open a connection. The ledger is process memory:
//! an entry is `(iss, jti) -> exp`, and `iss` is the verified caller, never a
//! request field.

use aauth_rust_jose::{SigningKey, strict_json};
use http::{Response, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// How far ahead of the verifier clock a revocation `exp` may sit, and how
/// often one caller may submit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationLimits {
    /// Maximum `exp - now`, in seconds. A larger `exp` is `invalid_request`.
    pub max_ahead: i64,
    /// Seconds after `exp` during which a presentation is still `revoked`.
    pub skew: i64,
    /// Authenticated revocation POSTs one caller may make inside `window`.
    pub rate: u32,
    /// Rate-limit window in seconds.
    pub window: i64,
    /// `Retry-After` delta-seconds on `rate_limited`.
    pub retry_after: u64,
}
impl Default for RevocationLimits {
    fn default() -> Self {
        Self {
            max_ahead: 86_400,
            skew: 60,
            rate: 60,
            window: 60,
            retry_after: 5,
        }
    }
}
impl RevocationLimits {
    fn window(&self) -> i64 {
        self.window.max(1)
    }
    fn skew(&self) -> i64 {
        self.skew.max(0)
    }
}

/// Parsed revocation body. The caller identity is not in here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationBody {
    /// Token identifier in the caller's own namespace.
    pub jti: String,
    /// The revoked token's expiration, Unix seconds.
    pub exp: i64,
}

/// The body is not a revocation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRevocationBody;

/// Read `jti` and `exp`. Unknown members are ignored, including any `iss`.
///
/// # Errors
/// Missing members, a non-object, a non-integer `exp`, a negative `exp`, or a
/// `jti` that is empty or contains whitespace or a control character.
pub fn parse_revocation_body(bytes: &[u8]) -> Result<RevocationBody, InvalidRevocationBody> {
    let value = strict_json(bytes).map_err(|_| InvalidRevocationBody)?;
    let object = value.as_object().ok_or(InvalidRevocationBody)?;
    let jti = object
        .get("jti")
        .and_then(Value::as_str)
        .ok_or(InvalidRevocationBody)?;
    if jti.is_empty()
        || jti.len() > 1024
        || jti.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(InvalidRevocationBody);
    }
    let exp = object
        .get("exp")
        .and_then(Value::as_i64)
        .filter(|exp| *exp >= 0)
        .ok_or(InvalidRevocationBody)?;
    Ok(RevocationBody {
        jti: jti.to_owned(),
        exp,
    })
}

/// `true` when the signature base covers both body components.
pub fn covers_revocation_body(signature_base: &str) -> bool {
    let covered = |name: &str| {
        signature_base
            .lines()
            .any(|line| line.starts_with(&format!("\"{name}\":")))
    };
    covered("content-digest") && covered("content-type")
}

#[derive(Default)]
struct LedgerState {
    entries: BTreeMap<(String, String), i64>,
    hits: BTreeMap<String, Vec<i64>>,
}

/// Process-local `(iss, jti)` revocation set.
#[derive(Clone)]
pub struct RevocationLedger {
    limits: RevocationLimits,
    state: Arc<Mutex<LedgerState>>,
}
impl RevocationLedger {
    /// Empty ledger with the given limits.
    pub fn new(limits: RevocationLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(LedgerState::default())),
        }
    }
    /// Limits supplied at construction.
    pub fn limits(&self) -> RevocationLimits {
        self.limits
    }
    /// `exp` is inside the lifetime this ledger will remember.
    pub fn exp_allowed(&self, exp: i64, now: i64) -> bool {
        exp >= 0 && exp <= now.saturating_add(self.limits.max_ahead.max(0))
    }
    /// Count one authenticated revocation POST from `caller`.
    ///
    /// # Errors
    /// `Some(retry_after)` when the caller is over its window. `None` in the
    /// error means the ledger lock was poisoned.
    pub fn charge(&self, caller: &str, now: i64) -> Result<(), Option<u64>> {
        let mut state = self.state.lock().map_err(|_| None)?;
        let window = self.limits.window();
        let hits = state.hits.entry(caller.to_owned()).or_default();
        hits.retain(|seen| now.saturating_sub(*seen) < window);
        if hits.len() as u32 >= self.limits.rate {
            return Err(Some(self.limits.retry_after));
        }
        hits.push(now);
        Ok(())
    }
    /// Remember `(iss, jti)` until `exp`. A repeat keeps the first `exp`.
    ///
    /// Returns whether this call inserted the entry. A poisoned lock inserts nothing.
    pub fn remember(&self, iss: &str, jti: &str, exp: i64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state
            .entries
            .contains_key(&(iss.to_owned(), jti.to_owned()))
        {
            return false;
        }
        state.entries.insert((iss.to_owned(), jti.to_owned()), exp);
        true
    }
    /// Stored `exp`, including an entry that presentation no longer honors.
    pub fn expiration(&self, iss: &str, jti: &str) -> Option<i64> {
        self.state
            .lock()
            .ok()?
            .entries
            .get(&(iss.to_owned(), jti.to_owned()))
            .copied()
    }
    /// Presentation of this token is revoked at `now`, through `exp` plus skew.
    pub fn is_revoked(&self, iss: &str, jti: &str, now: i64) -> bool {
        self.expiration(iss, jti)
            .is_some_and(|exp| now <= exp.saturating_add(self.limits.skew()))
    }
}

/// One downstream revocation the recipient attempted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownstreamReport {
    /// Server identifier the revocation was sent to.
    pub recipient: String,
    /// `revocation_unsupported` or `revocation_unavailable` when it did not succeed.
    pub error: Option<&'static str>,
    /// The downstream party answered `202`; the cascade is not terminal.
    pub deferred: bool,
}
impl DownstreamReport {
    /// A downstream call finished with `outcome`.
    pub fn from_outcome(recipient: &str, outcome: CallOutcome) -> Self {
        let (error, deferred) = match outcome {
            CallOutcome::Recorded => (None, false),
            CallOutcome::Unsupported => (Some("revocation_unsupported"), false),
            CallOutcome::Unavailable => (Some("revocation_unavailable"), false),
            CallOutcome::Deferred => (None, true),
        };
        Self {
            recipient: recipient.to_owned(),
            error,
            deferred,
        }
    }
}

/// What one downstream revocation call did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallOutcome {
    /// The recipient recorded the revocation.
    Recorded,
    /// No endpoint, or `unsupported_iss`. Tokens there live until `exp`.
    Unsupported,
    /// Timeout, `5xx`, or a body the caller cannot parse. Retry later.
    Unavailable,
    /// The recipient answered `202`.
    Deferred,
}

/// The server that sends a revocation, as it signs under the `jwks_uri` scheme.
///
/// The role fills this from its own configuration, so a revocation is always
/// signed as the server whose tokens it names. `issuer` and `dwk` are the `id`
/// and `dwk` of the `Signature-Key` member; `kid` names `key` in the JWKS the
/// server publishes.
#[derive(Clone, Copy)]
pub struct RevocationSender<'a> {
    /// The sending server's `issuer`, the namespace of the revoked `jti`.
    pub issuer: &'a str,
    /// Its metadata document name, such as `aauth-person.json`.
    pub dwk: &'a str,
    /// Identifier of `key` in its published JWKS.
    pub kid: &'a str,
    /// The key it signs with.
    pub key: &'a SigningKey,
}
impl std::fmt::Debug for RevocationSender<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationSender")
            .field("issuer", &self.issuer)
            .field("dwk", &self.dwk)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// One downstream revocation: the token, in the sender's namespace, and the
/// server that is to refuse it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationTarget<'a> {
    /// The recipient's server identifier, not a URL.
    pub recipient: &'a str,
    /// The recipient's metadata document name, such as `aauth-resource.json`,
    /// whose `revocation_endpoint` receives the revocation.
    pub dwk: &'a str,
    /// The revoked token's `jti`.
    pub jti: &'a str,
    /// The revoked token's `exp`, Unix seconds.
    pub exp: i64,
}

/// Delivery of one signed revocation POST.
///
/// The role calls it once per downstream target and maps the answer into its
/// cascade. An implementation discovers the recipient's `revocation_endpoint`
/// from `{recipient}/.well-known/{dwk}`, signs as `sender`, sends, and reads the
/// answer with [`read_call_outcome`]. `aauth-rust-discovery` provides one over
/// HTTPS; without any, each target is [`CallOutcome::Unavailable`].
pub trait RevocationDirectory: Send + Sync {
    /// Revoke `target.jti` at `target.recipient`, signed as `sender`.
    fn revoke(&self, sender: &RevocationSender<'_>, target: &RevocationTarget<'_>) -> CallOutcome;
}

/// JSON object for a non-empty downstream report. `None` means an empty body.
pub fn downstream_body(reports: &[DownstreamReport]) -> Option<Vec<u8>> {
    if reports.is_empty() {
        return None;
    }
    let entries: Vec<Value> = reports
        .iter()
        .map(|report| {
            let mut entry = json!({ "recipient": report.recipient });
            if let Some(error) = report.error {
                entry["error"] = json!(error);
            }
            entry
        })
        .collect();
    Some(json!({ "downstream": entries }).to_string().into_bytes())
}

/// `200` with no body and no `Content-Type`.
pub fn empty_ok() -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = StatusCode::OK;
    response
}

/// `200` whose body is a JSON object.
pub fn json_ok(bytes: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(bytes);
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        "content-type",
        "application/json".parse().expect("static content type"),
    );
    response
}

/// Success body: empty when there is nothing to report, otherwise a JSON object.
pub fn success_response(reports: &[DownstreamReport], report: bool) -> Response<Vec<u8>> {
    if !report {
        return empty_ok();
    }
    match downstream_body(reports) {
        Some(bytes) => json_ok(bytes),
        None => empty_ok(),
    }
}

/// Problem body used by revocation errors. `retry_after` sets `Retry-After`.
///
/// A revocation endpoint answers `401` only for a signature failure, sent with
/// `Signature-Error`, so a `401` body names `error` as the type
/// `urn:ietf:params:sig-error:<error>`. Other statuses use `about:blank`.
pub fn problem(status: StatusCode, error: &str, retry_after: Option<u64>) -> Response<Vec<u8>> {
    let kind = if status == StatusCode::UNAUTHORIZED {
        format!("urn:ietf:params:sig-error:{error}")
    } else {
        "about:blank".to_owned()
    };
    let body = json!({
        "type": kind,
        "title": status.canonical_reason().unwrap_or("Request refused"),
        "status": status.as_u16(),
        "error": error,
    });
    let mut response = Response::new(body.to_string().into_bytes());
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        "application/problem+json"
            .parse()
            .expect("static content type"),
    );
    if let Some(retry_after) = retry_after {
        response.headers_mut().insert(
            "retry-after",
            retry_after
                .to_string()
                .parse()
                .expect("retry-after is decimal"),
        );
    }
    response
}

/// `202` pending revocation with no `AAuth-Requirement`.
///
/// `location` must be a valid header value. An unusable location is omitted
/// rather than panicking; callers pass an absolute HTTPS URL.
pub fn pending(location: &str, retry_after: u64) -> Response<Vec<u8>> {
    let mut response = json_ok(json!({"status":"pending"}).to_string().into_bytes());
    *response.status_mut() = StatusCode::ACCEPTED;
    if let Ok(location) = location.parse() {
        response.headers_mut().insert("location", location);
    }
    response.headers_mut().insert(
        "retry-after",
        retry_after
            .to_string()
            .parse()
            .unwrap_or_else(|_| "5".parse().expect("static retry-after")),
    );
    response.headers_mut().insert(
        "cache-control",
        "no-store".parse().expect("static cache directive"),
    );
    response
}

/// Empty `404` with no `Content-Type`, for an unknown pending URL and a poll
/// from any caller other than the one that created it.
pub fn unknown_pending() -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

/// Read a revocation HTTP result the way a cascade caller does.
///
/// An empty `200` body is recorded with nothing reported. A non-empty body that
/// is not a JSON object is `revocation_unavailable`. `downstream` may be absent.
/// Any other status is read from the problem body's `error` member, not from
/// the status: `unsupported_iss` is [`CallOutcome::Unsupported`], and any other
/// value, or a body without one, is [`CallOutcome::Unavailable`].
pub fn read_call_outcome(status: u16, body: &[u8]) -> CallOutcome {
    if status == 202 {
        return CallOutcome::Deferred;
    }
    if status != 200 {
        let unsupported = strict_json(body).is_ok_and(|value| {
            value.get("error").and_then(Value::as_str) == Some("unsupported_iss")
        });
        return if unsupported {
            CallOutcome::Unsupported
        } else {
            CallOutcome::Unavailable
        };
    }
    if body.is_empty() {
        return CallOutcome::Recorded;
    }
    match strict_json(body) {
        Ok(value) if value.is_object() => CallOutcome::Recorded,
        _ => CallOutcome::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{CallOutcome, read_call_outcome};

    #[test]
    fn a_refusal_is_read_from_its_error_member() {
        let refusal = |error: &str| format!(r#"{{"error":"{error}"}}"#).into_bytes();
        for (status, body, outcome) in [
            (403, refusal("unsupported_iss"), CallOutcome::Unsupported),
            (400, refusal("unsupported_iss"), CallOutcome::Unsupported),
            (403, refusal("access_denied"), CallOutcome::Unavailable),
            (403, Vec::new(), CallOutcome::Unavailable),
            (429, refusal("rate_limited"), CallOutcome::Unavailable),
        ] {
            assert_eq!(read_call_outcome(status, &body), outcome, "{status}");
        }
    }
}
