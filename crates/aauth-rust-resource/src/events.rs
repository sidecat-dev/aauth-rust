//! AAuth Events at the Resource: verified subscription registration, public
//! or through a single-use subscription ticket; event tokens; and signed
//! deliveries to the Agent Provider's `event_endpoint`.
//!
//! The library performs no network I/O. The host fetches the Agent Provider's
//! metadata, applies egress admission, sends the prepared delivery and hands
//! back the response.
use crate::{AuthAuthorized, Deny, SignatureFailure};
use aauth_rust_core::events::{
    EVENT_TOKEN_DOCUMENT, EventClaims, SubscribeToken, VerifiedSubscribeToken, body_s256,
    event_endpoint, generate_identifier, mint_event_token,
};
use aauth_rust_core::{
    AgentKeyResolver, TokenError, VerifiedAuthToken, VerifiedPersonToken,
    validate_server_identifier,
};
use aauth_rust_jose::{Jwk, SigningKey, strict_json};
use aauth_rust_signature_key::{
    DiscoveryFetch, EgressLimits, Error, KeyMaterial, PinnedFetch, PreparedRequest, admit_fetch,
    canonical_authority, required_components, role_signature_alg_header, sign_request,
};
use http::{Method, Request, Response, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Name of the AsyncAPI security scheme for subscribe tokens.
pub const SUBSCRIBE_SECURITY_SCHEME: &str = "aauth_subscribe";

/// The AsyncAPI security scheme object a Resource declares as
/// `components.securitySchemes.aauth_subscribe`.
pub fn subscribe_security_scheme() -> Value {
    json!({
        "type": "http",
        "scheme": "aauth-subscribe",
        "description": "AAuth Subscribe Token (typ: aa-subscribe+jwt), issued by the agent's Agent Provider, presented as the Signature-Key JWT with HTTP Message Signatures. See draft-hardt-aauth-events."
    })
}

/// An AsyncAPI document does not declare the subscribe-token security scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncApiDeclarationError {
    /// The document is not one strict JSON object.
    Malformed,
    /// `components.securitySchemes.aauth_subscribe` is absent.
    Missing,
    /// `aauth_subscribe` is not `type: http` with `scheme: aauth-subscribe`.
    Mismatch,
}

impl std::fmt::Display for AsyncApiDeclarationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the AsyncAPI document must be one strict JSON object",
            Self::Missing => {
                "declare components.securitySchemes.aauth_subscribe with type http and scheme aauth-subscribe"
            }
            Self::Mismatch => {
                "components.securitySchemes.aauth_subscribe must have type http and scheme aauth-subscribe"
            }
        })
    }
}
impl std::error::Error for AsyncApiDeclarationError {}

/// Check that an AsyncAPI JSON document declares the subscribe-token
/// security scheme: `components.securitySchemes.aauth_subscribe` with `type`
/// `http` and `scheme` `aauth-subscribe`. Its description is free text.
///
/// # Errors
/// See [`AsyncApiDeclarationError`].
pub fn check_subscribe_security_scheme(document: &[u8]) -> Result<(), AsyncApiDeclarationError> {
    let document = strict_json(document).map_err(|_| AsyncApiDeclarationError::Malformed)?;
    if !document.is_object() {
        return Err(AsyncApiDeclarationError::Malformed);
    }
    let scheme = document
        .get("components")
        .and_then(|components| components.get("securitySchemes"))
        .and_then(|schemes| schemes.get(SUBSCRIBE_SECURITY_SCHEME))
        .ok_or(AsyncApiDeclarationError::Missing)?;
    if scheme.get("type").and_then(Value::as_str) != Some("http")
        || scheme.get("scheme").and_then(Value::as_str) != Some("aauth-subscribe")
    {
        return Err(AsyncApiDeclarationError::Mismatch);
    }
    Ok(())
}

/// One subscription as the Resource registered it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceSubscription {
    /// Agent Provider: the subscribe token's `iss`. Its `event_endpoint` is
    /// resolved from its metadata at delivery time.
    pub agent_provider: String,
    /// Event ID: the subscribe token's `eid`. `(agent_provider, eid)` keys the record.
    pub eid: String,
    /// Subscribing Agent: the subscribe token's `sub`, and each event token's `aud`.
    pub agent: String,
    /// The subscribe token's `max_uses`. The Agent Provider enforces it.
    pub max_uses: Option<u64>,
    /// The subscribe token's `jti`.
    pub token_jti: String,
    /// Verifier time of the registration.
    pub registered_at: i64,
    /// Host context returned by registration policy, such as the channel.
    pub context: Vec<u8>,
}

/// One subscription ticket as the Resource retained it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionTicket {
    /// Opaque ticket: the last path segment of the ticket URL.
    pub id: String,
    /// RFC 7638 thumbprint of the key the Resource verified when it issued
    /// the ticket. Only a subscribe token whose `cnf.jwk` has this
    /// thumbprint can use the ticket.
    pub key_thumbprint: String,
    /// Host context of the authenticated interaction that issued the ticket.
    pub context: Vec<u8>,
    /// Issue time, Unix seconds.
    pub issued_at: i64,
    /// Expiry, Unix seconds. The ticket is refused from this time on.
    pub expires_at: i64,
}

/// Resource subscription store failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionStoreError {
    /// No such subscription, or no unused ticket with this id.
    NotFound,
    /// The subscription or ticket id already exists.
    Conflict,
    /// The backend failed. Nothing may be assumed written.
    Unavailable,
}

impl std::fmt::Display for SubscriptionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such subscription or unused ticket",
            Self::Conflict => "the subscription or ticket already exists",
            Self::Unavailable => "the subscription store failed; nothing was written",
        })
    }
}
impl std::error::Error for SubscriptionStoreError {}

/// Resource subscriptions and subscription tickets.
///
/// [`MemorySubscriptionStore`] is the volatile reference. A durable
/// implementation must make each successful write durable before it returns.
pub trait SubscriptionStore: Send + Sync {
    /// Retain a new subscription.
    ///
    /// # Errors
    /// `Conflict` when `(agent_provider, eid)` is already registered.
    fn register(&self, subscription: &ResourceSubscription) -> Result<(), SubscriptionStoreError>;

    /// The subscription for `(agent_provider, eid)`.
    ///
    /// # Errors
    /// `Unavailable` when the read failed.
    fn subscription(
        &self,
        agent_provider: &str,
        eid: &str,
    ) -> Result<Option<ResourceSubscription>, SubscriptionStoreError>;

    /// Remove a subscription. An absent one is ignored.
    ///
    /// # Errors
    /// `Unavailable` when the write did not complete.
    fn remove(&self, agent_provider: &str, eid: &str) -> Result<(), SubscriptionStoreError>;

    /// Retain a new ticket before its URL is released.
    ///
    /// # Errors
    /// `Conflict` when the id exists.
    fn create_ticket(&self, ticket: &SubscriptionTicket) -> Result<(), SubscriptionStoreError>;

    /// The unused ticket with this id.
    ///
    /// # Errors
    /// `Unavailable` when the read failed.
    fn ticket(&self, id: &str) -> Result<Option<SubscriptionTicket>, SubscriptionStoreError>;

    /// In one atomic step, consume the unused ticket `id` and register
    /// `subscription`. On any error the ticket stays unused and nothing is
    /// registered.
    ///
    /// # Errors
    /// `NotFound` when no unused ticket has this id. `Conflict` when the
    /// subscription is already registered.
    fn redeem_ticket(
        &self,
        id: &str,
        subscription: &ResourceSubscription,
    ) -> Result<(), SubscriptionStoreError>;
}

impl<T: SubscriptionStore + ?Sized> SubscriptionStore for std::sync::Arc<T> {
    fn register(&self, subscription: &ResourceSubscription) -> Result<(), SubscriptionStoreError> {
        (**self).register(subscription)
    }
    fn subscription(
        &self,
        agent_provider: &str,
        eid: &str,
    ) -> Result<Option<ResourceSubscription>, SubscriptionStoreError> {
        (**self).subscription(agent_provider, eid)
    }
    fn remove(&self, agent_provider: &str, eid: &str) -> Result<(), SubscriptionStoreError> {
        (**self).remove(agent_provider, eid)
    }
    fn create_ticket(&self, ticket: &SubscriptionTicket) -> Result<(), SubscriptionStoreError> {
        (**self).create_ticket(ticket)
    }
    fn ticket(&self, id: &str) -> Result<Option<SubscriptionTicket>, SubscriptionStoreError> {
        (**self).ticket(id)
    }
    fn redeem_ticket(
        &self,
        id: &str,
        subscription: &ResourceSubscription,
    ) -> Result<(), SubscriptionStoreError> {
        (**self).redeem_ticket(id, subscription)
    }
}

#[derive(Default)]
struct MemoryInner {
    subscriptions: BTreeMap<(String, String), ResourceSubscription>,
    tickets: BTreeMap<String, SubscriptionTicket>,
}

/// Volatile in-memory [`SubscriptionStore`]. A used ticket is deleted.
#[derive(Default)]
pub struct MemorySubscriptionStore {
    inner: Mutex<MemoryInner>,
}

impl MemorySubscriptionStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryInner>, SubscriptionStoreError> {
        self.inner
            .lock()
            .map_err(|_| SubscriptionStoreError::Unavailable)
    }
}

fn subscription_key(subscription: &ResourceSubscription) -> (String, String) {
    (
        subscription.agent_provider.clone(),
        subscription.eid.clone(),
    )
}

impl SubscriptionStore for MemorySubscriptionStore {
    fn register(&self, subscription: &ResourceSubscription) -> Result<(), SubscriptionStoreError> {
        let mut inner = self.lock()?;
        let key = subscription_key(subscription);
        if inner.subscriptions.contains_key(&key) {
            return Err(SubscriptionStoreError::Conflict);
        }
        inner.subscriptions.insert(key, subscription.clone());
        Ok(())
    }
    fn subscription(
        &self,
        agent_provider: &str,
        eid: &str,
    ) -> Result<Option<ResourceSubscription>, SubscriptionStoreError> {
        Ok(self
            .lock()?
            .subscriptions
            .get(&(agent_provider.to_owned(), eid.to_owned()))
            .cloned())
    }
    fn remove(&self, agent_provider: &str, eid: &str) -> Result<(), SubscriptionStoreError> {
        self.lock()?
            .subscriptions
            .remove(&(agent_provider.to_owned(), eid.to_owned()));
        Ok(())
    }
    fn create_ticket(&self, ticket: &SubscriptionTicket) -> Result<(), SubscriptionStoreError> {
        let mut inner = self.lock()?;
        if inner.tickets.contains_key(&ticket.id) {
            return Err(SubscriptionStoreError::Conflict);
        }
        inner.tickets.insert(ticket.id.clone(), ticket.clone());
        Ok(())
    }
    fn ticket(&self, id: &str) -> Result<Option<SubscriptionTicket>, SubscriptionStoreError> {
        Ok(self.lock()?.tickets.get(id).cloned())
    }
    fn redeem_ticket(
        &self,
        id: &str,
        subscription: &ResourceSubscription,
    ) -> Result<(), SubscriptionStoreError> {
        let mut inner = self.lock()?;
        if !inner.tickets.contains_key(id) {
            return Err(SubscriptionStoreError::NotFound);
        }
        let key = subscription_key(subscription);
        if inner.subscriptions.contains_key(&key) {
            return Err(SubscriptionStoreError::Conflict);
        }
        inner.tickets.remove(id);
        inner.subscriptions.insert(key, subscription.clone());
        Ok(())
    }
}

/// Verified credential from the authenticated interaction that establishes
/// a subscription ticket. The ticket binds to its `cnf.jwk`.
///
/// Implemented for the person and auth tokens a Resource verifies. Pass the
/// one whose HTTP proof the Resource verified on that request.
pub trait TicketHolder: sealed::Sealed {
    /// The confirmation key the Resource verified.
    fn confirmation_key(&self) -> &Jwk;
}
mod sealed {
    pub trait Sealed {}
    impl Sealed for aauth_rust_core::VerifiedPersonToken {}
    impl Sealed for aauth_rust_core::VerifiedAuthToken {}
    impl<T> Sealed for crate::AuthAuthorized<T> {}
}
impl TicketHolder for VerifiedPersonToken {
    fn confirmation_key(&self) -> &Jwk {
        &self.claims().cnf.jwk
    }
}
impl TicketHolder for VerifiedAuthToken {
    fn confirmation_key(&self) -> &Jwk {
        &self.claims().cnf.jwk
    }
}
impl<T> TicketHolder for AuthAuthorized<T> {
    fn confirmation_key(&self) -> &Jwk {
        &self.token().claims().cnf.jwk
    }
}

/// Configuration of an [`EventsResource`].
pub struct EventsConfig {
    /// Canonical published Resource identity: each subscribe token's `aud`
    /// and each event token's `iss`.
    pub issuer: String,
    /// Actual HTTPS request origin; a configured nondefault port is allowed.
    pub signed_origin: String,
    /// Nonempty JWKS identifier of the Resource signing key.
    pub kid: String,
    /// Resource signing key. It signs event tokens and their deliveries.
    pub signing_key: SigningKey,
    /// Path prefix of subscription ticket URLs, starting and ending with `/`.
    pub ticket_path: String,
    /// Longest ticket lifetime, in seconds: 1..=3600.
    pub max_ticket_lifetime: i64,
}

/// Invalid [`EventsConfig`] or AsyncAPI document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventsConfigurationError {
    /// Published identity is not a canonical HTTPS DNS origin.
    InvalidIssuer,
    /// Signed origin has an invalid authority, path, query or fragment.
    InvalidOrigin,
    /// The signing key identifier is empty.
    InvalidKeyId,
    /// The ticket path does not start and end with `/`, or is not a plain path.
    InvalidTicketPath,
    /// The longest ticket lifetime is outside 1..=3600 seconds.
    InvalidTicketLifetime,
    /// The AsyncAPI document does not declare the subscribe-token security scheme.
    AsyncApi(AsyncApiDeclarationError),
}

impl std::fmt::Display for EventsConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIssuer => f.write_str(
                "Resource issuer must be a canonical HTTPS DNS origin without port or path",
            ),
            Self::InvalidOrigin => f.write_str(
                "signed_origin must be an absolute HTTPS origin without path, query or fragment",
            ),
            Self::InvalidKeyId => f.write_str("Resource kid must name its published signing key"),
            Self::InvalidTicketPath => f.write_str(
                "ticket_path must be a plain path that starts and ends with /, such as /subscriptions/",
            ),
            Self::InvalidTicketLifetime => {
                f.write_str("max_ticket_lifetime must be 1..=3600 seconds")
            }
            Self::AsyncApi(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for EventsConfigurationError {}

/// Registration policy input. Policy runs only after the subscribe token and
/// the request proof verified.
pub struct SubscriptionRequest<'a> {
    /// Verified subscribe token whose `aud` is this Resource and whose
    /// `cnf.jwk` signed the request.
    pub token: &'a VerifiedSubscribeToken,
    /// The registration request, including any AsyncAPI channel parameters.
    pub request: &'a Request<Vec<u8>>,
    /// The ticket being redeemed, on a protected registration.
    pub ticket: Option<&'a SubscriptionTicket>,
}

/// Outcome of a registration. Convert with [`Self::into_response`].
#[derive(Debug)]
pub enum RegistrationDecision {
    /// The subscription is registered: `200`.
    Registered(ResourceSubscription),
    /// The request is not a POST: `405`.
    MethodNotAllowed,
    /// Proof or subscribe-token failure: `401` with `Signature-Error`.
    SignatureFailure(SignatureFailure),
    /// Policy refused, or the ticket is unknown, used, expired or bound to
    /// another key: `403`.
    Forbidden,
    /// `(iss, eid)` is already registered: `409`.
    Conflict,
    /// The store failed. Nothing was registered: `503`.
    Unavailable,
}

impl RegistrationDecision {
    /// HTTP response. Failures carry RFC 9457 Problem Details. Only a
    /// signature failure carries `Signature-Error`.
    pub fn into_response(self) -> Response<Vec<u8>> {
        let mut response = Response::new(Vec::new());
        match self {
            Self::Registered(_) => {
                response
                    .headers_mut()
                    .insert("cache-control", "no-store".parse().unwrap());
            }
            Self::MethodNotAllowed => {
                *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                response
                    .headers_mut()
                    .insert("allow", "POST".parse().unwrap());
                events_problem(&mut response, "invalid_request", "Method not allowed", 405);
            }
            Self::SignatureFailure(failure) => {
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                let mut error = format!("error={}", failure.code());
                if let SignatureFailure::Input(required) = &failure {
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
                if matches!(failure, SignatureFailure::Proof(Error::UnsupportedScheme)) {
                    response
                        .headers_mut()
                        .insert("accept-signature-scheme", "jwt".parse().unwrap());
                }
                if matches!(
                    failure,
                    SignatureFailure::Proof(Error::UnsupportedAlgorithm)
                        | SignatureFailure::Token(TokenError::UnsupportedAlgorithm)
                ) {
                    response.headers_mut().insert(
                        "accept-signature-alg",
                        role_signature_alg_header().parse().unwrap(),
                    );
                }
                events_problem(
                    &mut response,
                    failure.code(),
                    "Subscription request rejected",
                    401,
                );
            }
            Self::Forbidden => {
                *response.status_mut() = StatusCode::FORBIDDEN;
                events_problem(&mut response, "forbidden", "Forbidden", 403);
            }
            Self::Conflict => {
                *response.status_mut() = StatusCode::CONFLICT;
                events_problem(&mut response, "conflict", "Already subscribed", 409);
            }
            Self::Unavailable => {
                *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                events_problem(
                    &mut response,
                    "temporarily_unavailable",
                    "Not registered",
                    503,
                );
            }
        }
        response
    }
}

fn events_problem(response: &mut Response<Vec<u8>>, code: &str, title: &str, status: u16) {
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    let kind = if status == 401 {
        format!("urn:ietf:params:sig-error:{code}")
    } else {
        "about:blank".to_owned()
    };
    *response.body_mut() =
        serde_json::to_vec(&json!({"type":kind,"title":title,"status":status,"error":code}))
            .expect("fixed Problem Details fields are serializable");
}

/// A released subscription ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedTicket {
    /// HTTPS ticket URL for the Agent to POST its subscribe token to.
    pub url: String,
    /// The retained ticket.
    pub ticket: SubscriptionTicket,
}

/// Ticket issuance failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketError {
    /// The lifetime is outside 1..=`max_ticket_lifetime`, or `now` is invalid.
    InvalidLifetime,
    /// The verified key has no thumbprint.
    InvalidKey,
    /// The store did not retain the ticket. No URL was released.
    Store(SubscriptionStoreError),
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLifetime => {
                f.write_str("ticket lifetime must be 1..=max_ticket_lifetime seconds")
            }
            Self::InvalidKey => f.write_str("the verified key has no RFC 7638 thumbprint"),
            Self::Store(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for TicketError {}

/// Body of one event delivery: the AsyncAPI-defined payload and its media type.
#[derive(Clone, Copy, Debug)]
pub struct EventPayload<'a> {
    /// `Content-Type` of the body. Covered by the delivery signature.
    pub content_type: &'a str,
    /// Exact nonempty body bytes.
    pub body: &'a [u8],
}

/// One event token with the body it binds. Reuse it to retry the delivery:
/// the same `jti` lets the Agent Provider drop a duplicate.
#[derive(Clone, Debug)]
pub struct PreparedEvent {
    agent_provider: String,
    eid: String,
    agent: String,
    max_uses: Option<u64>,
    token: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl PreparedEvent {
    /// The Agent Provider that receives the delivery.
    pub fn agent_provider(&self) -> &str {
        &self.agent_provider
    }
    /// Event ID of the subscription.
    pub fn eid(&self) -> &str {
        &self.eid
    }
    /// The Agent the event token is addressed to.
    pub fn agent(&self) -> &str {
        &self.agent
    }
    /// Exact compact `aa-event+jwt`.
    pub fn token(&self) -> &str {
        &self.token
    }
    /// Exact body bytes. Empty when the event has no payload.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Event preparation or delivery failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDeliveryError {
    /// No registered subscription for this Agent Provider and Event ID.
    UnknownSubscription,
    /// A payload's body is empty or its content type is not a header value.
    InvalidPayload,
    /// Token claims or lifetime, or the Agent Provider metadata, are invalid.
    Token(TokenError),
    /// The delivery request could not be signed.
    Proof(Error),
    /// A `202` without the `remaining_uses` a limited subscription requires.
    InvalidAcceptance,
    /// The store failed.
    Store(SubscriptionStoreError),
}

impl std::fmt::Display for EventDeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSubscription => f.write_str("no subscription for this Event ID"),
            Self::InvalidPayload => f.write_str(
                "an event payload needs nonempty body bytes and a valid Content-Type value; omit the payload for none",
            ),
            Self::Token(error) => error.fmt(f),
            Self::Proof(error) => error.fmt(f),
            Self::InvalidAcceptance => f.write_str(
                "a 202 for a subscription with max_uses must carry a JSON remaining_uses below max_uses",
            ),
            Self::Store(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for EventDeliveryError {}

/// The Agent Provider's answer to one delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// `202`: the Agent Provider recorded the event.
    Accepted {
        /// Events it will still accept, for a subscription with `max_uses`.
        /// At `0` the subscription is exhausted and has been removed here.
        remaining_uses: Option<u64>,
    },
    /// `404`: no subscription will accept events. It has been removed here;
    /// the Agent must subscribe again.
    Ended,
    /// Any other status. The subscription is kept.
    Rejected {
        /// HTTP status code.
        status: u16,
    },
}

/// Egress admission for a delivery POST to an `event_endpoint`: HTTPS and a
/// globally routable address unless `limits` allows otherwise. The host
/// connects only to the pinned address and follows no redirect. Admit the
/// metadata fetch separately with `admit_fetch`.
///
/// # Errors
/// As `admit_fetch`.
pub fn admit_event_endpoint(
    limits: &EgressLimits,
    endpoint: &str,
    address: std::net::IpAddr,
) -> Result<PinnedFetch, Error> {
    admit_fetch(limits, DiscoveryFetch::Metadata { url: endpoint }, address)
}

/// URL of an Agent Provider's metadata, from which a delivery resolves
/// `event_endpoint`: `{agent_provider}/.well-known/aauth-agent.json`.
pub fn agent_provider_metadata_url(agent_provider: &str) -> String {
    format!("{agent_provider}/.well-known/aauth-agent.json")
}

/// The Resource side of AAuth Events.
///
/// `keys` resolves Agent Provider keys for `aauth-agent.json`. A host that
/// accepts subscribe tokens from providers it has not configured supplies a
/// resolver that applies egress admission before fetching their metadata.
pub struct EventsResource<K, S> {
    issuer: String,
    authority: String,
    origin: String,
    kid: String,
    signing_key: SigningKey,
    ticket_path: String,
    max_ticket_lifetime: i64,
    asyncapi: Option<Vec<u8>>,
    keys: K,
    store: S,
}

impl<K: AgentKeyResolver, S: SubscriptionStore> EventsResource<K, S> {
    /// Configure a Resource's Events surface.
    ///
    /// # Errors
    /// See [`EventsConfigurationError`].
    pub fn new(config: EventsConfig, keys: K, store: S) -> Result<Self, EventsConfigurationError> {
        validate_server_identifier(&config.issuer)
            .map_err(|_| EventsConfigurationError::InvalidIssuer)?;
        let uri: http::Uri = config
            .signed_origin
            .parse()
            .map_err(|_| EventsConfigurationError::InvalidOrigin)?;
        if uri.query().is_some()
            || config.signed_origin.contains('#')
            || (!uri.path().is_empty() && uri.path() != "/")
        {
            return Err(EventsConfigurationError::InvalidOrigin);
        }
        let authority =
            canonical_authority(&uri).map_err(|_| EventsConfigurationError::InvalidOrigin)?;
        if config.kid.is_empty() {
            return Err(EventsConfigurationError::InvalidKeyId);
        }
        let path = &config.ticket_path;
        if !path.starts_with('/')
            || !path.ends_with('/')
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b))
            || path.contains("//")
        {
            return Err(EventsConfigurationError::InvalidTicketPath);
        }
        if !(1..=3600).contains(&config.max_ticket_lifetime) {
            return Err(EventsConfigurationError::InvalidTicketLifetime);
        }
        Ok(Self {
            issuer: config.issuer,
            origin: format!("https://{authority}"),
            authority,
            kid: config.kid,
            signing_key: config.signing_key,
            ticket_path: config.ticket_path,
            max_ticket_lifetime: config.max_ticket_lifetime,
            asyncapi: None,
            keys,
            store,
        })
    }

    /// Publish an AsyncAPI JSON document describing the event channels. It
    /// must declare the subscribe-token security scheme, as
    /// [`check_subscribe_security_scheme`] checks. Serve [`Self::asyncapi`]
    /// at the URL named for `urn:aauth:vocabulary:asyncapi`.
    ///
    /// # Errors
    /// [`EventsConfigurationError::AsyncApi`] when the declaration is missing or differs.
    pub fn with_asyncapi(mut self, document: Vec<u8>) -> Result<Self, EventsConfigurationError> {
        check_subscribe_security_scheme(&document).map_err(EventsConfigurationError::AsyncApi)?;
        self.asyncapi = Some(document);
        Ok(self)
    }

    /// The published AsyncAPI document bytes, unchanged.
    pub fn asyncapi(&self) -> Option<&[u8]> {
        self.asyncapi.as_deref()
    }

    /// The subscription store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Public Resource signing key with its configured kid. The Resource's
    /// metadata names it in `jwks_uri`, since delivering events is a signed call.
    ///
    /// # Errors
    /// Returns a serialization error as InvalidJwt.
    pub fn jwks(&self) -> Result<Vec<u8>, TokenError> {
        let mut jwk = serde_json::to_value(self.signing_key.public_jwk())
            .map_err(|_| TokenError::InvalidJwt)?;
        jwk["kid"] = json!(self.kid);
        serde_json::to_vec(&json!({"keys":[jwk]})).map_err(|_| TokenError::InvalidJwt)
    }

    /// Verify a subscribe token presented as the `Signature-Key` JWT on a
    /// signed request to this Resource's origin.
    ///
    /// Any failure is a signature failure: the token must verify with `typ`
    /// `aa-subscribe+jwt` and `dwk` `aauth-agent.json` and an unexpired
    /// `exp`, its `aud` must be this Resource's issuer, its `cnf.jwk` must
    /// verify the HTTP signature, and its `eid` must be nonempty.
    fn verify_subscription(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<VerifiedSubscribeToken, SignatureFailure> {
        match canonical_authority(request.uri()) {
            Ok(authority) if authority == self.authority => {}
            Ok(_) => return Err(SignatureFailure::Proof(Error::TargetMismatch)),
            Err(error) => return Err(SignatureFailure::Proof(error)),
        }
        let proof = match PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwt"]) {
            Ok(proof) => proof,
            Err(Error::ClockSkew) => {
                return Err(SignatureFailure::ClockSkew { server_time: now });
            }
            Err(Error::InvalidInput) => {
                return Err(SignatureFailure::Input(required_components(request)));
            }
            Err(error) => return Err(SignatureFailure::Proof(error)),
        };
        let KeyMaterial::Jwt { jwt: compact, .. } = proof.key() else {
            return Err(SignatureFailure::Proof(Error::UnsupportedScheme));
        };
        let token = SubscribeToken::parse(compact)
            .and_then(|token| token.verify(&self.keys, now))
            .map_err(SignatureFailure::Token)?;
        let claims = token.claims();
        if claims.iat > now.saturating_add(60) {
            return Err(SignatureFailure::ClockSkew { server_time: now });
        }
        if claims.aud != self.issuer {
            return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
        }
        proof
            .verify(&claims.cnf.jwk)
            .map_err(SignatureFailure::Proof)?;
        Ok(token)
    }

    fn subscription_record(
        token: &VerifiedSubscribeToken,
        context: Vec<u8>,
        now: i64,
    ) -> ResourceSubscription {
        let claims = token.claims();
        ResourceSubscription {
            agent_provider: claims.iss.clone(),
            eid: claims.eid.clone(),
            agent: claims.sub.clone(),
            max_uses: claims.max_uses,
            token_jti: claims.jti.clone(),
            registered_at: now,
            context,
        }
    }

    /// Register a public subscription from one buffered request at `now`.
    ///
    /// The subscribe token and request proof verify first. `policy` then
    /// decides whether this Agent may subscribe; the bytes it returns are kept
    /// as the subscription's context. A repeated `(iss, eid)` is refused.
    pub fn register<P>(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        policy: P,
    ) -> RegistrationDecision
    where
        P: FnOnce(&SubscriptionRequest<'_>) -> Result<Vec<u8>, Deny>,
    {
        if request.method() != Method::POST {
            return RegistrationDecision::MethodNotAllowed;
        }
        let token = match self.verify_subscription(request, now) {
            Ok(token) => token,
            Err(failure) => return RegistrationDecision::SignatureFailure(failure),
        };
        let context = match policy(&SubscriptionRequest {
            token: &token,
            request,
            ticket: None,
        }) {
            Ok(context) => context,
            Err(Deny) => return RegistrationDecision::Forbidden,
        };
        let subscription = Self::subscription_record(&token, context, now);
        match self.store.register(&subscription) {
            Ok(()) => RegistrationDecision::Registered(subscription),
            Err(SubscriptionStoreError::Conflict) => RegistrationDecision::Conflict,
            Err(_) => RegistrationDecision::Unavailable,
        }
    }

    /// Issue a subscription ticket after an authenticated interaction.
    ///
    /// `holder` is the person or auth token the Resource verified on that
    /// request. The ticket records the RFC 7638 thumbprint of its `cnf.jwk`,
    /// expires `lifetime` seconds after `now`, and is retained before its URL
    /// is returned. `context` is the interaction's context, returned to
    /// registration policy.
    ///
    /// # Errors
    /// See [`TicketError`].
    pub fn issue_ticket(
        &self,
        holder: &impl TicketHolder,
        context: &[u8],
        lifetime: i64,
        now: i64,
    ) -> Result<IssuedTicket, TicketError> {
        if !(1..=self.max_ticket_lifetime).contains(&lifetime)
            || !(0..=(1_i64 << 33) - 1 - lifetime).contains(&now)
        {
            return Err(TicketError::InvalidLifetime);
        }
        let key_thumbprint = holder
            .confirmation_key()
            .thumbprint()
            .map_err(|_| TicketError::InvalidKey)?;
        let ticket = SubscriptionTicket {
            id: generate_identifier(),
            key_thumbprint,
            context: context.to_vec(),
            issued_at: now,
            expires_at: now + lifetime,
        };
        self.store
            .create_ticket(&ticket)
            .map_err(TicketError::Store)?;
        Ok(IssuedTicket {
            url: format!("{}{}{}", self.origin, self.ticket_path, ticket.id),
            ticket,
        })
    }

    /// Register a protected subscription at a ticket URL, at `now`.
    ///
    /// The subscribe token and request proof verify first, over the request
    /// path that carries the ticket. The ticket must be retained, unused and
    /// unexpired, and the thumbprint of the subscribe token's `cnf.jwk` must
    /// equal the one recorded when it was issued. `policy` then decides. The
    /// ticket is consumed in the same store step that registers the
    /// subscription, so it is used at most once. Any ticket failure is `403`.
    pub fn register_with_ticket<P>(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        policy: P,
    ) -> RegistrationDecision
    where
        P: FnOnce(&SubscriptionRequest<'_>) -> Result<Vec<u8>, Deny>,
    {
        if request.method() != Method::POST {
            return RegistrationDecision::MethodNotAllowed;
        }
        let token = match self.verify_subscription(request, now) {
            Ok(token) => token,
            Err(failure) => return RegistrationDecision::SignatureFailure(failure),
        };
        let Some(id) = request
            .uri()
            .path()
            .strip_prefix(self.ticket_path.as_str())
            .filter(|id| !id.is_empty() && !id.contains('/'))
        else {
            return RegistrationDecision::Forbidden;
        };
        let ticket = match self.store.ticket(id) {
            Ok(Some(ticket)) if ticket.id == id => ticket,
            Ok(_) => return RegistrationDecision::Forbidden,
            Err(_) => return RegistrationDecision::Unavailable,
        };
        let thumbprint = token.claims().cnf.jwk.thumbprint().ok();
        if ticket.expires_at <= now || thumbprint.as_deref() != Some(ticket.key_thumbprint.as_str())
        {
            return RegistrationDecision::Forbidden;
        }
        let context = match policy(&SubscriptionRequest {
            token: &token,
            request,
            ticket: Some(&ticket),
        }) {
            Ok(context) => context,
            Err(Deny) => return RegistrationDecision::Forbidden,
        };
        let subscription = Self::subscription_record(&token, context, now);
        match self.store.redeem_ticket(id, &subscription) {
            Ok(()) => RegistrationDecision::Registered(subscription),
            Err(SubscriptionStoreError::NotFound) => RegistrationDecision::Forbidden,
            Err(SubscriptionStoreError::Conflict) => RegistrationDecision::Conflict,
            Err(SubscriptionStoreError::Unavailable) => RegistrationDecision::Unavailable,
        }
    }

    /// Mint the event token for one event on a registered subscription.
    ///
    /// The token carries this Resource as `iss`, `aauth-resource.json` as
    /// `dwk`, the subscribed Agent as `aud`, the subscription's `eid`, a
    /// fresh `jti`, `iat` of `now` and `exp` of `expires_at`. With a payload
    /// it carries `body_s256` of the exact body; without one it carries none.
    /// It never carries `cnf`.
    ///
    /// # Errors
    /// [`EventDeliveryError::UnknownSubscription`], `InvalidPayload`, or
    /// `Token` for an `expires_at` not after `now`.
    pub fn prepare_event(
        &self,
        agent_provider: &str,
        eid: &str,
        payload: Option<EventPayload<'_>>,
        expires_at: i64,
        now: i64,
    ) -> Result<PreparedEvent, EventDeliveryError> {
        let subscription = self
            .store
            .subscription(agent_provider, eid)
            .map_err(EventDeliveryError::Store)?
            .ok_or(EventDeliveryError::UnknownSubscription)?;
        if let Some(payload) = payload
            && (payload.body.is_empty()
                || payload.content_type.is_empty()
                || http::HeaderValue::from_str(payload.content_type).is_err())
        {
            return Err(EventDeliveryError::InvalidPayload);
        }
        let claims = EventClaims {
            iss: self.issuer.clone(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: subscription.agent.clone(),
            eid: subscription.eid.clone(),
            jti: generate_identifier(),
            iat: now,
            exp: expires_at,
            body_s256: payload.map(|payload| body_s256(payload.body)),
            extra: Default::default(),
        };
        let token = mint_event_token(&self.signing_key, &self.kid, &claims)
            .map_err(EventDeliveryError::Token)?;
        Ok(PreparedEvent {
            agent_provider: subscription.agent_provider,
            eid: subscription.eid,
            agent: subscription.agent,
            max_uses: subscription.max_uses,
            token,
            content_type: payload.map(|payload| payload.content_type.to_owned()),
            body: payload
                .map(|payload| payload.body.to_vec())
                .unwrap_or_default(),
        })
    }

    /// Build and sign the delivery POST for `event` at `now`.
    ///
    /// `agent_provider_metadata` is the document the host fetched from
    /// [`agent_provider_metadata_url`] for this delivery; its `issuer` must be
    /// the subscribe token's `iss`. The request goes to its `event_endpoint`,
    /// presents the event token under `self-jwt` and is signed with this
    /// Resource's key. With a body it carries `Content-Type`, and the
    /// signature covers `content-digest` and `content-type`.
    ///
    /// # Errors
    /// `Token` for metadata without a valid issuer or `event_endpoint`;
    /// `Proof` when signing fails.
    pub fn delivery_request(
        &self,
        event: &PreparedEvent,
        agent_provider_metadata: &[u8],
        now: i64,
    ) -> Result<Request<Vec<u8>>, EventDeliveryError> {
        let endpoint = event_endpoint(&event.agent_provider, agent_provider_metadata)
            .map_err(EventDeliveryError::Token)?;
        let mut builder = Request::builder().method(Method::POST).uri(endpoint);
        if let Some(content_type) = &event.content_type {
            builder = builder.header("content-type", content_type);
        }
        let mut request = builder
            .body(event.body.clone())
            .map_err(|_| EventDeliveryError::Proof(Error::InvalidUri))?;
        sign_request(
            &mut request,
            &self.signing_key,
            KeyMaterial::SelfJwt {
                jwt: event.token.clone(),
            },
            now,
        )
        .map_err(EventDeliveryError::Proof)?;
        Ok(request)
    }

    /// Read the Agent Provider's answer to a delivery of `event`.
    ///
    /// On `202` for a subscription with `max_uses`, the body must be JSON with
    /// a `remaining_uses` below `max_uses`. A subscription the Agent Provider
    /// reports exhausted (`remaining_uses` of `0`) or ended (`404`) is removed.
    ///
    /// # Errors
    /// `InvalidAcceptance` for a `202` without valid `remaining_uses`;
    /// `Store` when removal failed.
    pub fn delivery_outcome(
        &self,
        event: &PreparedEvent,
        response: &Response<Vec<u8>>,
    ) -> Result<DeliveryOutcome, EventDeliveryError> {
        let outcome = match response.status() {
            StatusCode::ACCEPTED => {
                let remaining_uses = match event.max_uses {
                    None => None,
                    Some(max) => {
                        let remaining = strict_json(response.body())
                            .ok()
                            .and_then(|body| body.get("remaining_uses").and_then(Value::as_u64))
                            .filter(|remaining| *remaining < max)
                            .ok_or(EventDeliveryError::InvalidAcceptance)?;
                        Some(remaining)
                    }
                };
                DeliveryOutcome::Accepted { remaining_uses }
            }
            StatusCode::NOT_FOUND => DeliveryOutcome::Ended,
            status => DeliveryOutcome::Rejected {
                status: status.as_u16(),
            },
        };
        if matches!(
            outcome,
            DeliveryOutcome::Ended
                | DeliveryOutcome::Accepted {
                    remaining_uses: Some(0)
                }
        ) {
            self.store
                .remove(&event.agent_provider, &event.eid)
                .map_err(EventDeliveryError::Store)?;
        }
        Ok(outcome)
    }
}
