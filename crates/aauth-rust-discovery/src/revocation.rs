//! Delivery of signed revocations: the HTTPS `RevocationDirectory`.
use crate::client::{DiscoveryClient, DiscoveryError};
use aauth_rust_core::revocation::read_call_outcome;
use aauth_rust_core::{
    CallOutcome, RevocationDirectory, RevocationSender, RevocationTarget,
    validate_server_identifier,
};
use aauth_rust_jose::strict_json;
use aauth_rust_signature_key::{
    Error as SignatureError, KeyMaterial, RequestSignature, sign_request,
    sign_requests_with_components,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Pending revocation URLs held at once; the oldest is dropped beyond this.
const MAX_PENDING: usize = 1024;
/// Seconds past a revoked token's `exp` after which its pending URL is dropped.
const PENDING_SKEW: i64 = 60;

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Delivers a role's revocation cascade over HTTPS.
///
/// Install it on a Person Server, Access Server or Resource with
/// `with_revocation_directory`. For each downstream target it fetches
/// `{recipient}/.well-known/{dwk}` through the [`DiscoveryClient`], checks
/// its `issuer`, and reads `revocation_endpoint`; a recipient that publishes
/// none is `revocation_unsupported`. It POSTs `{"jti","exp"}` signed as the
/// calling server under the `jwks_uri` scheme, covering `content-type` and
/// `content-digest` and, for a Resource, its `additional_signature_components`,
/// with `Prefer: wait` set inside the client's timeout. The answer is read
/// as the cascade reads it: `200` recorded, `unsupported_iss` unsupported,
/// a timeout, `5xx` or malformed answer unavailable. A `202` keeps its
/// `Location`, which must be on the same host and port as the endpoint;
/// the next delivery of that revocation polls it with a signed GET instead
/// of posting again, and a poll answered `404` or `410` posts again. A
/// `429 rate_limited` is not terminal and is reported deferred.
///
/// Each delivery blocks the calling thread, at most the client's timeout per
/// exchange: one metadata fetch and one POST, or one poll.
pub struct RevocationClient {
    client: DiscoveryClient,
    clock: Clock,
    pending: Mutex<BTreeMap<PendingKey, Pending>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PendingKey {
    sender: String,
    recipient: String,
    dwk: String,
    jti: String,
}

#[derive(Clone)]
struct Pending {
    location: String,
    exp: i64,
    since: i64,
}

/// One delivery: the outcome the cascade records, and why when it is not `Recorded`.
#[derive(Debug)]
pub struct Delivery {
    /// How the cascade reads this call.
    pub outcome: CallOutcome,
    /// What kept it from being recorded, for the host's logs.
    pub cause: Option<DeliveryCause>,
}

/// Why a delivery did not end `Recorded`.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeliveryCause {
    /// Metadata, admission, connection or deadline.
    Discovery(DiscoveryError),
    /// The recipient's metadata names no `revocation_endpoint`.
    NoEndpoint,
    /// The metadata's `revocation_endpoint` or a `202` `Location` is unusable.
    InvalidUrl(String),
    /// The request could not be signed, such as for an advertised component
    /// the request does not carry.
    Signing(SignatureError),
    /// The recipient answered with this status and, when it sent one, this
    /// problem `error`.
    Answer {
        /// HTTP status.
        status: u16,
        /// The problem body's `error` member.
        error: Option<String>,
    },
}

impl fmt::Display for DeliveryCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(error) => error.fmt(f),
            Self::NoEndpoint => f.write_str("the recipient publishes no revocation_endpoint"),
            Self::InvalidUrl(url) => write!(f, "unusable revocation URL {url}"),
            Self::Signing(error) => write!(f, "could not sign the revocation: {error}"),
            Self::Answer {
                status,
                error: Some(error),
            } => write!(f, "the recipient answered {status} {error}"),
            Self::Answer {
                status,
                error: None,
            } => write!(f, "the recipient answered {status}"),
        }
    }
}

impl fmt::Debug for RevocationClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationClient")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl RevocationClient {
    /// Deliver revocations through `client`.
    pub fn new(client: DiscoveryClient) -> Self {
        Self {
            client,
            clock: Box::new(system_now),
            pending: Mutex::new(BTreeMap::new()),
        }
    }
    /// Sign with `created` from `clock`, Unix seconds, instead of the system clock.
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Deliver one revocation, reporting why when it is not recorded.
    ///
    /// [`RevocationDirectory::revoke`] is this without the cause.
    pub fn deliver(
        &self,
        sender: &RevocationSender<'_>,
        target: &RevocationTarget<'_>,
    ) -> Delivery {
        let key = PendingKey {
            sender: sender.issuer.to_owned(),
            recipient: target.recipient.to_owned(),
            dwk: target.dwk.to_owned(),
            jti: target.jti.to_owned(),
        };
        let held = self.pending().get(&key).cloned();
        if let Some(held) = held {
            match self.poll(sender, &held.location) {
                Polled::Answer(delivery, still_pending) => {
                    if !still_pending {
                        self.pending().remove(&key);
                    }
                    return delivery;
                }
                Polled::Gone => {
                    self.pending().remove(&key);
                }
            }
        }
        let (delivery, location) = self.post(sender, target);
        if let Some(location) = location {
            self.hold(key, location, target.exp);
        }
        delivery
    }

    fn post(
        &self,
        sender: &RevocationSender<'_>,
        target: &RevocationTarget<'_>,
    ) -> (Delivery, Option<String>) {
        if let Err(error) = validate_server_identifier(target.recipient) {
            return unavailable(DeliveryCause::Discovery(DiscoveryError::Document {
                url: target.recipient.to_owned(),
                error,
            }));
        }
        let metadata = match self.client.fetch_metadata(target.recipient, target.dwk) {
            Ok(metadata) => metadata,
            Err(error) => return unavailable(DeliveryCause::Discovery(error)),
        };
        let endpoint = match metadata.member("revocation_endpoint") {
            None => {
                return (
                    Delivery {
                        outcome: CallOutcome::Unsupported,
                        cause: Some(DeliveryCause::NoEndpoint),
                    },
                    None,
                );
            }
            Some(Value::String(endpoint)) => endpoint.clone(),
            Some(other) => return unavailable(DeliveryCause::InvalidUrl(other.to_string())),
        };
        // A Resource lists further components its requests must cover.
        let additional: Vec<String> = if target.dwk == "aauth-resource.json" {
            metadata
                .member("additional_signature_components")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let body = json!({ "jti": target.jti, "exp": target.exp }).to_string();
        let Ok(mut request) = Request::post(endpoint.as_str())
            .header("content-type", "application/json")
            .header("prefer", self.prefer_wait())
            .body(body.into_bytes())
        else {
            return unavailable(DeliveryCause::InvalidUrl(endpoint));
        };
        if let Err(error) = self.sign(&mut request, sender, &additional) {
            return unavailable(DeliveryCause::Signing(error));
        }
        match self.client.send(&request) {
            Ok(response) => read_answer(&endpoint, &response, None),
            Err(error) => unavailable(DeliveryCause::Discovery(error)),
        }
    }

    fn poll(&self, sender: &RevocationSender<'_>, location: &str) -> Polled {
        let Ok(mut request) = Request::get(location)
            .header("prefer", self.prefer_wait())
            .body(Vec::new())
        else {
            return Polled::Gone;
        };
        if let Err(error) = self.sign(&mut request, sender, &[]) {
            let (delivery, _) = unavailable(DeliveryCause::Signing(error));
            return Polled::Answer(delivery, true);
        }
        let response = match self.client.send(&request) {
            Ok(response) => response,
            // Keep the pending URL: the recipient may still hold the cascade.
            Err(error) => {
                let (delivery, _) = unavailable(DeliveryCause::Discovery(error));
                return Polled::Answer(delivery, true);
            }
        };
        if matches!(response.status().as_u16(), 404 | 410) {
            return Polled::Gone;
        }
        let (delivery, next) = read_answer(location, &response, Some(location));
        let still_pending = next.is_some();
        Polled::Answer(delivery, still_pending)
    }

    fn sign(
        &self,
        request: &mut Request<Vec<u8>>,
        sender: &RevocationSender<'_>,
        additional: &[String],
    ) -> Result<(), SignatureError> {
        let material = KeyMaterial::JwksUri {
            id: sender.issuer.to_owned(),
            dwk: sender.dwk.to_owned(),
            kid: sender.kid.to_owned(),
        };
        let now = (self.clock)();
        if additional.is_empty() {
            return sign_request(request, sender.key, material, now);
        }
        let additional: Vec<&str> = additional.iter().map(String::as_str).collect();
        sign_requests_with_components(
            request,
            &[RequestSignature {
                label: "sig",
                key: sender.key,
                material,
            }],
            &additional,
            now,
        )
    }

    /// `wait=N`, a little inside the client's timeout, so a recipient that
    /// honors it answers `202` before the exchange is abandoned.
    fn prefer_wait(&self) -> String {
        let seconds = self
            .client
            .limits()
            .timeout
            .as_secs()
            .saturating_sub(2)
            .max(1);
        format!("wait={seconds}")
    }

    fn hold(&self, key: PendingKey, location: String, exp: i64) {
        let now = (self.clock)();
        let mut pending = self.pending();
        pending.retain(|_, held| now <= held.exp.saturating_add(PENDING_SKEW));
        if !pending.contains_key(&key) && pending.len() >= MAX_PENDING {
            let oldest = pending
                .iter()
                .min_by_key(|(_, held)| held.since)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                pending.remove(&oldest);
            }
        }
        pending.insert(
            key,
            Pending {
                location,
                exp,
                since: now,
            },
        );
    }

    fn pending(&self) -> MutexGuard<'_, BTreeMap<PendingKey, Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl RevocationDirectory for RevocationClient {
    fn revoke(&self, sender: &RevocationSender<'_>, target: &RevocationTarget<'_>) -> CallOutcome {
        self.deliver(sender, target).outcome
    }
}

enum Polled {
    /// The poll answered; `true` while the revocation is still pending there.
    Answer(Delivery, bool),
    /// The pending URL is unknown or spent: revoke again.
    Gone,
}

/// Read a revocation answer. A `202` returns the pending URL to poll next.
///
/// `polled` is the URL a poll went to; a `202` from it must name it again.
fn read_answer(
    url: &str,
    response: &Response<Vec<u8>>,
    polled: Option<&str>,
) -> (Delivery, Option<String>) {
    let status = response.status().as_u16();
    let error = strict_json(response.body()).ok().and_then(|value| {
        value
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let answer = || DeliveryCause::Answer {
        status,
        error: error.clone(),
    };
    if status == 202 {
        let location = pending_location(url, response);
        return match (location, polled) {
            (Some(location), Some(polled)) if location != polled => {
                unavailable(DeliveryCause::InvalidUrl(location))
            }
            (Some(location), _) => (
                Delivery {
                    outcome: CallOutcome::Deferred,
                    cause: Some(answer()),
                },
                Some(location),
            ),
            (None, _) => unavailable(answer()),
        };
    }
    if status == 429 && error.as_deref() == Some("rate_limited") {
        return (
            Delivery {
                outcome: CallOutcome::Deferred,
                cause: Some(answer()),
            },
            None,
        );
    }
    let outcome = read_call_outcome(status, response.body());
    let cause = (outcome != CallOutcome::Recorded).then(answer);
    (Delivery { outcome, cause }, None)
}

/// The one `Location` of a `202`, absolute, on the same host and port as `url`.
fn pending_location(url: &str, response: &Response<Vec<u8>>) -> Option<String> {
    let values: Vec<_> = response.headers().get_all("location").iter().collect();
    let [value] = values.as_slice() else {
        return None;
    };
    let value = value.to_str().ok()?;
    let base: http::Uri = url.parse().ok()?;
    let authority = base.authority()?;
    let location = if value.starts_with('/') && !value.starts_with("//") {
        format!("https://{authority}{value}")
    } else {
        value.to_owned()
    };
    let parsed: http::Uri = location.parse().ok()?;
    (parsed.scheme_str() == Some("https")
        && parsed.authority() == Some(authority)
        && !location.contains('#'))
    .then_some(location)
}

fn unavailable(cause: DeliveryCause) -> (Delivery, Option<String>) {
    (
        Delivery {
            outcome: CallOutcome::Unavailable,
            cause: Some(cause),
        },
        None,
    )
}

fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
