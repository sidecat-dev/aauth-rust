//! AAuth Events at the Agent Provider: the published `event_endpoint`,
//! subscribe-token issuance with a retained subscription record, and the
//! inbox that validates a Resource's delivery before recording it.
//!
//! Delivery from the inbox to the Agent is the host's transport. The store
//! keeps the exact event token and body bytes, and the host hands both to the
//! Agent unchanged so that the Agent can verify `body_s256`.
use crate::{AgentProvider, IssuanceKeys};
use aauth_rust_core::events::{
    EventToken, SubscribeClaims, generate_identifier, mint_subscribe_token,
};
use aauth_rust_core::{AgentKeyResolver, AgentToken, Confirmation, TokenError};
use aauth_rust_signature_key::{
    Error, KeyMaterial, PreparedRequest, canonical_authority, required_components,
    role_signature_alg_header,
};
use http::{Method, Request, Response, StatusCode};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

mod directory;
pub use directory::DirectoryEventStore;

/// One subscription as the Agent Provider recorded it at issuance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    /// Event ID: the subscribe token's `eid` and this record's key.
    pub eid: String,
    /// Subscribing Agent: the subscribe token's `sub`. Deliveries route to it.
    pub agent: String,
    /// The one Resource allowed to deliver: the subscribe token's `aud`.
    pub resource: String,
    /// The subscribe token's `max_uses`. `None` is unlimited.
    pub max_uses: Option<u64>,
    /// The subscribe token's `jti`.
    pub token_jti: String,
    /// The subscribe token's `exp`: its registration deadline, not a
    /// subscription lifetime.
    pub token_expires_at: i64,
    /// Agent Provider policy end of the subscription, Unix seconds. `None`
    /// means the Agent Provider sets no end.
    pub expires_at: Option<i64>,
}

/// One accepted delivery, retained with the exact bytes the Resource sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedEvent {
    /// Event ID of the subscription.
    pub eid: String,
    /// Agent the event is routed to.
    pub agent: String,
    /// Delivering Resource: the event token's `iss`.
    pub resource: String,
    /// Event token `jti`. `(resource, jti)` identifies one event.
    pub jti: String,
    /// Event token `exp`, Unix seconds.
    pub expires_at: i64,
    /// Exact compact event token from the `Signature-Key` header.
    pub event_token: String,
    /// Exact request body bytes. Empty when the delivery carried none.
    pub body: Vec<u8>,
    /// `Content-Type` of a delivery that carried a body.
    pub content_type: Option<String>,
    /// Verifier time at which the delivery was accepted.
    pub received_at: i64,
}

/// Result of [`EventStore::record`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// The event is newly and durably recorded. `uses` counts it.
    Accepted {
        /// Events accepted for this Event ID, including this one.
        uses: u64,
    },
    /// The store already holds `(resource, jti)`. Nothing changed.
    Duplicate {
        /// Events accepted for this Event ID.
        uses: u64,
    },
}

/// Event store failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventStoreError {
    /// No subscription has this Event ID.
    NotFound,
    /// `max_uses` events are already accepted for this Event ID.
    Exhausted,
    /// [`EventStore::create`] found the Event ID already present.
    Conflict,
    /// The backend failed. Nothing may be assumed recorded.
    Unavailable,
}

impl std::fmt::Display for EventStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no subscription has this Event ID",
            Self::Exhausted => "the subscription has accepted max_uses events",
            Self::Conflict => "a subscription with this Event ID already exists",
            Self::Unavailable => "the event store failed; nothing was recorded",
        })
    }
}
impl std::error::Error for EventStoreError {}

/// Agent Provider subscription and delivery state.
///
/// Each successful write must be durable before it returns: the inbox
/// answers `202` only after [`EventStore::record`] succeeds.
/// [`DirectoryEventStore`] is the durable file-backed implementation;
/// [`MemoryEventStore`] is a volatile reference for tests.
pub trait EventStore: Send + Sync {
    /// Retain a new subscription before its subscribe token is released.
    ///
    /// # Errors
    /// [`EventStoreError::Conflict`] when the Event ID exists.
    /// [`EventStoreError::Unavailable`] when the write did not complete.
    fn create(&self, subscription: &Subscription) -> Result<(), EventStoreError>;

    /// The subscription for `eid`, with the number of events accepted for it.
    ///
    /// # Errors
    /// [`EventStoreError::Unavailable`] when the read failed.
    fn subscription(&self, eid: &str) -> Result<Option<(Subscription, u64)>, EventStoreError>;

    /// In one atomic step: when `(resource, jti)` is already recorded, return
    /// [`Recorded::Duplicate`]. Otherwise refuse with
    /// [`EventStoreError::Exhausted`] once `max_uses` events are accepted for
    /// the Event ID, or else count the event, record it durably for delivery
    /// to its Agent and return [`Recorded::Accepted`].
    ///
    /// # Errors
    /// `NotFound`, `Exhausted` or `Unavailable`. On any error nothing is recorded.
    fn record(&self, event: &RecordedEvent) -> Result<Recorded, EventStoreError>;

    /// Recorded events not yet acknowledged by `agent`, oldest first.
    ///
    /// # Errors
    /// [`EventStoreError::Unavailable`] when the read failed.
    fn pending(&self, agent: &str) -> Result<Vec<RecordedEvent>, EventStoreError>;

    /// Remove one delivered event from `agent`'s pending list. An event not
    /// pending is ignored. Its `(resource, jti)` stays known for deduplication.
    ///
    /// # Errors
    /// [`EventStoreError::Unavailable`] when the write did not complete.
    fn acknowledge(&self, agent: &str, resource: &str, jti: &str) -> Result<(), EventStoreError>;
}

impl<T: EventStore + ?Sized> EventStore for std::sync::Arc<T> {
    fn create(&self, subscription: &Subscription) -> Result<(), EventStoreError> {
        (**self).create(subscription)
    }
    fn subscription(&self, eid: &str) -> Result<Option<(Subscription, u64)>, EventStoreError> {
        (**self).subscription(eid)
    }
    fn record(&self, event: &RecordedEvent) -> Result<Recorded, EventStoreError> {
        (**self).record(event)
    }
    fn pending(&self, agent: &str) -> Result<Vec<RecordedEvent>, EventStoreError> {
        (**self).pending(agent)
    }
    fn acknowledge(&self, agent: &str, resource: &str, jti: &str) -> Result<(), EventStoreError> {
        (**self).acknowledge(agent, resource, jti)
    }
}

#[derive(Default)]
struct MemoryInner {
    subscriptions: BTreeMap<String, (Subscription, u64)>,
    // (resource, jti) -> event token exp. An entry is dropped once its token
    // has expired, since an expired token is refused before deduplication.
    seen: BTreeMap<(String, String), i64>,
    pending: BTreeMap<String, Vec<RecordedEvent>>,
}

/// Volatile in-memory [`EventStore`]. Its records do not survive the process,
/// so it does not meet the durability an Agent Provider needs in production.
#[derive(Default)]
pub struct MemoryEventStore {
    inner: Mutex<MemoryInner>,
}

impl MemoryEventStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryInner>, EventStoreError> {
        self.inner.lock().map_err(|_| EventStoreError::Unavailable)
    }
}

impl EventStore for MemoryEventStore {
    fn create(&self, subscription: &Subscription) -> Result<(), EventStoreError> {
        let mut inner = self.lock()?;
        if inner.subscriptions.contains_key(&subscription.eid) {
            return Err(EventStoreError::Conflict);
        }
        inner
            .subscriptions
            .insert(subscription.eid.clone(), (subscription.clone(), 0));
        Ok(())
    }
    fn subscription(&self, eid: &str) -> Result<Option<(Subscription, u64)>, EventStoreError> {
        Ok(self.lock()?.subscriptions.get(eid).cloned())
    }
    fn record(&self, event: &RecordedEvent) -> Result<Recorded, EventStoreError> {
        let mut inner = self.lock()?;
        let received_at = event.received_at;
        inner.seen.retain(|_, expires_at| *expires_at > received_at);
        let (subscription, uses) = inner
            .subscriptions
            .get(&event.eid)
            .cloned()
            .ok_or(EventStoreError::NotFound)?;
        let key = (event.resource.clone(), event.jti.clone());
        if inner.seen.contains_key(&key) {
            return Ok(Recorded::Duplicate { uses });
        }
        if subscription.max_uses.is_some_and(|max| uses >= max) {
            return Err(EventStoreError::Exhausted);
        }
        let uses = uses + 1;
        inner.seen.insert(key, event.expires_at);
        if let Some(entry) = inner.subscriptions.get_mut(&event.eid) {
            entry.1 = uses;
        }
        inner
            .pending
            .entry(event.agent.clone())
            .or_default()
            .push(event.clone());
        Ok(Recorded::Accepted { uses })
    }
    fn pending(&self, agent: &str) -> Result<Vec<RecordedEvent>, EventStoreError> {
        Ok(self.lock()?.pending.get(agent).cloned().unwrap_or_default())
    }
    fn acknowledge(&self, agent: &str, resource: &str, jti: &str) -> Result<(), EventStoreError> {
        if let Some(events) = self.lock()?.pending.get_mut(agent) {
            events.retain(|event| event.resource != resource || event.jti != jti);
        }
        Ok(())
    }
}

/// Inputs to [`AgentProvider::issue_subscribe_token`]. Times are Unix seconds.
#[derive(Clone, Debug)]
pub struct SubscribeRequest<'a> {
    /// The Agent's current Agent token from this provider. Its `sub` and
    /// `cnf.jwk` become the subscribe token's `sub` and `cnf`.
    pub agent_token: &'a str,
    /// The Resource allowed to deliver events: the subscribe token's `aud`.
    pub resource: &'a str,
    /// Subscribe-token `exp`: how long the Resource may accept it for
    /// registration. At most the Agent token's `exp`.
    pub expires_at: i64,
    /// Positive limit on accepted events. `None` is unlimited.
    pub max_uses: Option<u64>,
    /// Agent Provider policy end of the subscription. `None` sets no end.
    pub subscription_expires_at: Option<i64>,
}

/// A released subscribe token and the record retained before its release.
#[derive(Clone, Debug)]
pub struct IssuedSubscription {
    /// Compact `aa-subscribe+jwt` for the Agent to present at the Resource.
    pub token: String,
    /// The subscription as retained in the store.
    pub subscription: Subscription,
}

/// Subscribe-token issuance failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscribeError {
    /// The Agent token, Resource identifier, lifetime or use limit is invalid.
    Token(TokenError),
    /// The store did not retain the subscription. No token was released.
    Store(EventStoreError),
}

impl std::fmt::Display for SubscribeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(error) => error.fmt(f),
            Self::Store(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for SubscribeError {}

impl AgentProvider {
    /// Publish `event_endpoint`, the HTTPS URL at which this provider
    /// receives event tokens. [`AgentProvider::metadata`] then carries it, and
    /// only a provider with one can construct an [`EventInbox`].
    ///
    /// # Errors
    /// `InvalidDiscoveryMetadata` unless `endpoint` is an absolute HTTPS URL
    /// with a host and valid port, and no userinfo, query or fragment.
    pub fn with_event_endpoint(mut self, endpoint: &str) -> Result<Self, TokenError> {
        aauth_rust_core::events::validate_event_endpoint(endpoint)?;
        self.event_endpoint = Some(endpoint.to_owned());
        Ok(self)
    }

    /// The published `event_endpoint`, when Events is configured.
    pub fn event_endpoint(&self) -> Option<&str> {
        self.event_endpoint.as_deref()
    }

    /// Issue a subscribe token for one Resource after the host has decided
    /// the Agent may subscribe. The Agent token is authenticated with this
    /// provider's own key at `now`, and the subscription is retained in
    /// `store` before the token is returned. The Event ID and `jti` are fresh
    /// random identifiers.
    ///
    /// # Errors
    /// [`SubscribeError::Token`] for an Agent token that does not verify, an
    /// invalid Resource identifier, an `expires_at` not after `now` or after
    /// the Agent token's `exp`, a `max_uses` of zero, or a subscription end
    /// not after `now`. [`SubscribeError::Store`] when the record was not
    /// retained.
    pub fn issue_subscribe_token(
        &self,
        store: &dyn EventStore,
        request: &SubscribeRequest<'_>,
        now: i64,
    ) -> Result<IssuedSubscription, SubscribeError> {
        let agent = AgentToken::parse(request.agent_token)
            .and_then(|token| token.verify(&IssuanceKeys(self), now))
            .map_err(SubscribeError::Token)?;
        let agent = agent.claims();
        if request.expires_at <= now
            || request.expires_at > agent.exp
            || request
                .subscription_expires_at
                .is_some_and(|end| end <= now)
        {
            return Err(SubscribeError::Token(TokenError::InvalidTokenLifetime));
        }
        let claims = SubscribeClaims {
            iss: self.issuer.clone(),
            dwk: aauth_rust_core::events::SUBSCRIBE_TOKEN_DOCUMENT.into(),
            sub: agent.sub.clone(),
            aud: request.resource.to_owned(),
            cnf: Confirmation {
                jwk: agent.cnf.jwk.clone(),
            },
            eid: generate_identifier(),
            jti: generate_identifier(),
            iat: now,
            exp: request.expires_at,
            max_uses: request.max_uses,
            extra: Default::default(),
        };
        let token =
            mint_subscribe_token(&self.key, &self.kid, &claims).map_err(SubscribeError::Token)?;
        let subscription = Subscription {
            eid: claims.eid,
            agent: claims.sub,
            resource: claims.aud,
            max_uses: claims.max_uses,
            token_jti: claims.jti,
            token_expires_at: claims.exp,
            expires_at: request.subscription_expires_at,
        };
        store.create(&subscription).map_err(SubscribeError::Store)?;
        Ok(IssuedSubscription {
            token,
            subscription,
        })
    }
}

/// Inbox configuration failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxConfigurationError {
    /// The provider publishes no `event_endpoint`; call
    /// [`AgentProvider::with_event_endpoint`] first.
    NoEventEndpoint,
}

impl std::fmt::Display for InboxConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the Agent Provider publishes no event_endpoint: configure one with with_event_endpoint before building its inbox",
        )
    }
}
impl std::error::Error for InboxConfigurationError {}

/// A delivery's proof or event token failed. Answered `401` with `Signature-Error`.
#[derive(Debug)]
pub enum DeliveryFailure {
    /// HTTP proof, target binding or scheme failure.
    Proof(Error),
    /// Event-token verification, body digest or audience failure.
    Token(TokenError),
    /// Missing coverage, with the complete component list for this request.
    Input(Vec<&'static str>),
    /// Signature `created` or token `iat` is too far ahead of the verifier clock.
    ClockSkew,
}

impl DeliveryFailure {
    /// Stable `Signature-Error` code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Proof(error) => error.code(),
            Self::Token(error) => error.code(),
            Self::Input(_) => "invalid_input",
            Self::ClockSkew => "clock_skew",
        }
    }
}

impl std::fmt::Display for DeliveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(error) => error.fmt(f),
            Self::Token(error) => error.fmt(f),
            Self::Input(required) => {
                write!(f, "signature coverage is incomplete: cover {required:?}")
            }
            Self::ClockSkew => Error::ClockSkew.fmt(f),
        }
    }
}

/// Outcome of one delivery at the inbox. Convert with [`Self::into_response`].
#[derive(Debug)]
pub enum InboxDecision {
    /// The event is durably recorded for its Agent: `202 Accepted`.
    Accepted {
        /// Events the provider will still accept for this Event ID, when the
        /// subscription has `max_uses`. Sent as the `remaining_uses` body.
        remaining_uses: Option<u64>,
        /// The store already held `(iss, jti)`; this delivery was dropped.
        duplicate: bool,
    },
    /// The inbox accepts only POST: `405`.
    MethodNotAllowed,
    /// Proof or event-token failure: `401` with `Signature-Error`.
    SignatureFailure(DeliveryFailure),
    /// The delivering Resource is not the subscription's Resource: `403`.
    Forbidden,
    /// No subscription will accept this event: unknown Event ID, an ended
    /// subscription or `max_uses` reached. `404`.
    NotFound,
    /// The store failed. Nothing was recorded: `503`.
    Unavailable,
}

impl InboxDecision {
    /// HTTP response. Failures carry RFC 9457 Problem Details. Only a
    /// signature failure carries `Signature-Error`.
    pub fn into_response(self) -> Response<Vec<u8>> {
        let mut response = Response::new(Vec::new());
        match self {
            Self::Accepted { remaining_uses, .. } => {
                *response.status_mut() = StatusCode::ACCEPTED;
                response
                    .headers_mut()
                    .insert("cache-control", "no-store".parse().unwrap());
                if let Some(remaining) = remaining_uses {
                    response
                        .headers_mut()
                        .insert("content-type", "application/json".parse().unwrap());
                    *response.body_mut() =
                        serde_json::to_vec(&serde_json::json!({ "remaining_uses": remaining }))
                            .expect("a fixed member is serializable");
                }
            }
            Self::MethodNotAllowed => {
                *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                response
                    .headers_mut()
                    .insert("allow", "POST".parse().unwrap());
                problem(&mut response, "invalid_request", "Method not allowed", 405);
            }
            Self::SignatureFailure(failure) => {
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                let mut error = format!("error={}", failure.code());
                if let DeliveryFailure::Input(required) = &failure {
                    let components = required
                        .iter()
                        .map(|name| format!("\"{name}\""))
                        .collect::<Vec<_>>()
                        .join(" ");
                    error.push_str(&format!(", required_input=({components})"));
                }
                response
                    .headers_mut()
                    .insert("signature-error", error.parse().unwrap());
                if matches!(failure, DeliveryFailure::Proof(Error::UnsupportedScheme)) {
                    response
                        .headers_mut()
                        .insert("accept-signature-scheme", "self-jwt".parse().unwrap());
                }
                if matches!(
                    failure,
                    DeliveryFailure::Proof(Error::UnsupportedAlgorithm)
                        | DeliveryFailure::Token(TokenError::UnsupportedAlgorithm)
                ) {
                    response.headers_mut().insert(
                        "accept-signature-alg",
                        role_signature_alg_header().parse().unwrap(),
                    );
                }
                problem(
                    &mut response,
                    failure.code(),
                    "Event delivery rejected",
                    401,
                );
            }
            Self::Forbidden => {
                *response.status_mut() = StatusCode::FORBIDDEN;
                problem(&mut response, "forbidden", "Forbidden", 403);
            }
            Self::NotFound => {
                *response.status_mut() = StatusCode::NOT_FOUND;
                problem(&mut response, "not_found", "No active subscription", 404);
            }
            Self::Unavailable => {
                *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                problem(
                    &mut response,
                    "temporarily_unavailable",
                    "Not recorded",
                    503,
                );
            }
        }
        response
    }
}

fn problem(response: &mut Response<Vec<u8>>, code: &str, title: &str, status: u16) {
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    let kind = if status == 401 {
        format!("urn:ietf:params:sig-error:{code}")
    } else {
        "about:blank".to_owned()
    };
    *response.body_mut() = serde_json::to_vec(
        &serde_json::json!({"type":kind,"title":title,"status":status,"error":code}),
    )
    .expect("fixed Problem Details fields are serializable");
}

/// The Agent Provider's event endpoint.
///
/// `keys` resolves Resource keys for `aauth-resource.json`. A host that
/// accepts events from Resources it has not configured supplies a resolver
/// that applies egress admission before fetching their metadata and JWKS.
pub struct EventInbox<K, S> {
    authority: String,
    path: String,
    keys: K,
    store: S,
}

impl<K: AgentKeyResolver, S: EventStore> EventInbox<K, S> {
    /// Bind the inbox to `provider`'s published `event_endpoint`.
    ///
    /// # Errors
    /// [`InboxConfigurationError::NoEventEndpoint`] when the provider has none.
    pub fn new(
        provider: &AgentProvider,
        keys: K,
        store: S,
    ) -> Result<Self, InboxConfigurationError> {
        let endpoint = provider
            .event_endpoint()
            .ok_or(InboxConfigurationError::NoEventEndpoint)?;
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|_| InboxConfigurationError::NoEventEndpoint)?;
        let authority =
            canonical_authority(&uri).map_err(|_| InboxConfigurationError::NoEventEndpoint)?;
        let path = match uri.path() {
            "" => "/".to_owned(),
            path => path.to_owned(),
        };
        Ok(Self {
            authority,
            path,
            keys,
            store,
        })
    }

    /// The store holding subscriptions and recorded events.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Validate one buffered delivery at `now`, in Unix seconds, and record it.
    ///
    /// In order: the request is a POST to the event endpoint, signed under
    /// `self-jwt` within a 60-second window. A body needs covered
    /// `Content-Digest` and `Content-Type`. The event token verifies with
    /// `typ` `aa-event+jwt`, `dwk` `aauth-resource.json`, no `cnf` and an
    /// unexpired `exp`, and the same Resource key verifies the HTTP
    /// signature. `body_s256` matches the body, or is absent with no body.
    /// Then the subscription for `eid` must exist and not have ended, the
    /// token's `iss` must be the subscription's Resource and its `aud` the
    /// subscription's Agent. Last, the store atomically drops a recorded
    /// `(iss, jti)`, refuses an exhausted subscription, or counts the event
    /// and records its exact token and body. `202` follows only that record.
    pub fn receive(&self, request: &Request<Vec<u8>>, now: i64) -> InboxDecision {
        if request.method() != Method::POST {
            return InboxDecision::MethodNotAllowed;
        }
        let failure = InboxDecision::SignatureFailure;
        match canonical_authority(request.uri()) {
            Ok(authority) if authority == self.authority && request.uri().path() == self.path => {}
            Ok(_) => return failure(DeliveryFailure::Proof(Error::TargetMismatch)),
            Err(error) => return failure(DeliveryFailure::Proof(error)),
        }
        let proof =
            match PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["self-jwt"]) {
                Ok(proof) => proof,
                Err(Error::ClockSkew) => return failure(DeliveryFailure::ClockSkew),
                Err(Error::InvalidInput) => {
                    return failure(DeliveryFailure::Input(delivery_components(request)));
                }
                Err(error) => return failure(DeliveryFailure::Proof(error)),
            };
        // A body is what the Agent receives, so its media type is covered too.
        if !request.body().is_empty() && !request.headers().contains_key("content-type") {
            return failure(DeliveryFailure::Input(delivery_components(request)));
        }
        let KeyMaterial::SelfJwt { jwt } = proof.key() else {
            return failure(DeliveryFailure::Proof(Error::UnsupportedScheme));
        };
        let token = match EventToken::parse(jwt).and_then(|token| token.verify(&self.keys, now)) {
            Ok(token) => token,
            Err(error) => return failure(DeliveryFailure::Token(error)),
        };
        let claims = token.claims();
        if claims.iat > now.saturating_add(60) {
            return failure(DeliveryFailure::ClockSkew);
        }
        if let Err(error) = proof.verify(token.issuer_key()) {
            return failure(DeliveryFailure::Proof(error));
        }
        if let Err(error) = claims.verify_body(request.body()) {
            return failure(DeliveryFailure::Token(error));
        }
        let subscription = match self.store.subscription(&claims.eid) {
            Ok(Some((subscription, _))) => subscription,
            Ok(None) => return InboxDecision::NotFound,
            Err(_) => return InboxDecision::Unavailable,
        };
        if subscription.expires_at.is_some_and(|end| end <= now) {
            return InboxDecision::NotFound;
        }
        if claims.iss != subscription.resource {
            return InboxDecision::Forbidden;
        }
        // Checked before a use is counted, so a misaddressed delivery
        // never spends one.
        if claims.aud != subscription.agent {
            return failure(DeliveryFailure::Token(TokenError::AudienceMismatch));
        }
        let content_type = request
            .headers()
            .get("content-type")
            .filter(|_| !request.body().is_empty())
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let event = RecordedEvent {
            eid: claims.eid.clone(),
            agent: subscription.agent.clone(),
            resource: claims.iss.clone(),
            jti: claims.jti.clone(),
            expires_at: claims.exp,
            event_token: token.compact().to_owned(),
            body: request.body().clone(),
            content_type,
            received_at: now,
        };
        let (uses, duplicate) = match self.store.record(&event) {
            Ok(Recorded::Accepted { uses }) => (uses, false),
            Ok(Recorded::Duplicate { uses }) => (uses, true),
            Err(EventStoreError::NotFound | EventStoreError::Exhausted) => {
                return InboxDecision::NotFound;
            }
            Err(_) => return InboxDecision::Unavailable,
        };
        let remaining_uses = match subscription.max_uses {
            None => None,
            Some(max) if uses <= max => Some(max - uses),
            // A store reporting more uses than allowed is not trusted to have
            // enforced the limit.
            Some(_) => return InboxDecision::Unavailable,
        };
        InboxDecision::Accepted {
            remaining_uses,
            duplicate,
        }
    }
}

/// Components a delivery must cover: the base set, plus `content-digest`
/// and `content-type` when it carries a body.
fn delivery_components(request: &Request<Vec<u8>>) -> Vec<&'static str> {
    let mut required: BTreeSet<&'static str> = required_components(request).into_iter().collect();
    if !request.body().is_empty() {
        required.insert("content-digest");
        required.insert("content-type");
    }
    let mut ordered = vec!["@method", "@authority", "@path", "signature-key"];
    for name in ["@query", "authorization", "content-digest", "content-type"] {
        if required.contains(name) {
            ordered.push(name);
        }
    }
    ordered
}
