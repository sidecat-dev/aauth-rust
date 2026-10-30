//! AAuth Events at the Agent: a subscription registration signed with a
//! subscribe token, and verification of an event token and its body after
//! the Agent Provider delivers them. How the provider delivers is the host's
//! transport; the Agent receives the exact token and body bytes.
use crate::Agent;
use aauth_rust_core::events::{EventToken, SubscribeToken, VerifiedEventToken};
use aauth_rust_core::{AgentKeyResolver, TokenError, validate_agent_identifier};
use aauth_rust_signature_key::{
    Error, KeyMaterial, RequestSignature, sign_requests_with_components,
};
use http::Request;
use std::collections::BTreeMap;

impl Agent {
    /// Sign a subscription registration at `now`, presenting `subscribe_token`
    /// as the `Signature-Key` JWT in place of this Agent's token. Sign after
    /// the URI, `Content-Type` and body are final. Components set with
    /// [`Self::with_additional_signature_components`] are covered too.
    ///
    /// # Errors
    /// `InvalidKey` when the subscribe token does not parse or its `cnf.jwk`
    /// is not this Agent's key. Otherwise as [`Self::sign`].
    pub fn sign_subscription(
        &self,
        request: &mut Request<Vec<u8>>,
        subscribe_token: &str,
        now: i64,
    ) -> Result<(), Error> {
        let token = SubscribeToken::parse(subscribe_token).map_err(|_| Error::InvalidKey)?;
        let presented = token
            .unverified_claims()
            .cnf
            .jwk
            .thumbprint()
            .map_err(|_| Error::InvalidKey)?;
        if self.key.public_jwk().thumbprint().ok() != Some(presented) {
            return Err(Error::InvalidKey);
        }
        let components: Vec<&str> = self.components.iter().map(String::as_str).collect();
        sign_requests_with_components(
            request,
            &[RequestSignature {
                label: "sig",
                key: &self.key,
                material: KeyMaterial::Jwt(subscribe_token.to_owned()),
            }],
            &components,
            now,
        )
    }
}

/// An event the Agent must not act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventError {
    /// The event token failed verification, including an `exp` that has
    /// passed: the response window has closed.
    Token(TokenError),
    /// The token's `aud` is not this Agent's identifier.
    Audience,
    /// The body does not match `body_s256`, or one is present without the other.
    Body,
    /// No local subscription has the token's `eid`.
    UnknownSubscription,
    /// The token's `iss` is not the Resource this Agent subscribed at.
    ResourceMismatch,
    /// This Agent already processed `(iss, jti)`.
    Duplicate,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(error) => error.fmt(f),
            Self::Audience => f.write_str("event token aud is not this Agent's identifier"),
            Self::Body => f.write_str("event body does not match body_s256"),
            Self::UnknownSubscription => f.write_str("no local subscription has this eid"),
            Self::ResourceMismatch => {
                f.write_str("event token iss is not the Resource this subscription names")
            }
            Self::Duplicate => f.write_str("this event (iss, jti) was already processed"),
        }
    }
}
impl std::error::Error for EventError {}

/// Verify an event token and the body the Agent Provider delivered with it.
///
/// In order: the token verifies with `typ` `aa-event+jwt`, `dwk`
/// `aauth-resource.json`, the Resource key `keys` resolves and an `exp` after
/// `now`; its `aud` equals `agent` exactly, with no case folding; and the
/// body matches `body_s256`, or is empty when `body_s256` is absent. Only a
/// returned token may be acted on. Pass the body bytes exactly as delivered.
///
/// # Errors
/// See [`EventError`].
pub fn verify_event(
    event_token: &str,
    body: &[u8],
    agent: &str,
    keys: &dyn AgentKeyResolver,
    now: i64,
) -> Result<VerifiedEventToken, EventError> {
    let token = EventToken::parse(event_token)
        .and_then(|token| token.verify(keys, now))
        .map_err(EventError::Token)?;
    if token.claims().aud != agent {
        return Err(EventError::Audience);
    }
    token
        .claims()
        .verify_body(body)
        .map_err(|_| EventError::Body)?;
    Ok(token)
}

/// An event that verified, with the local context of its subscription.
#[derive(Debug)]
pub struct ReceivedEvent<'a, T> {
    /// The verified event token.
    pub token: VerifiedEventToken,
    /// Context recorded for the token's `eid`.
    pub context: &'a T,
}

/// The Agent's local mapping from `eid` to its own context, with
/// deduplication on `(iss, jti)`. Volatile: a host that must not act twice
/// across restarts keeps the processed set durably.
pub struct EventSubscriptions<T> {
    agent: String,
    subscriptions: BTreeMap<String, (String, T)>,
    // (iss, jti) -> exp. Dropped once exp passes, since an expired token is
    // refused before deduplication.
    processed: BTreeMap<(String, String), i64>,
}

impl<T> EventSubscriptions<T> {
    /// An empty mapping for the Agent `agent`.
    ///
    /// # Errors
    /// `InvalidAgentIdentifier` when `agent` is not an Agent identifier.
    pub fn new(agent: &str) -> Result<Self, TokenError> {
        validate_agent_identifier(agent)?;
        Ok(Self {
            agent: agent.to_owned(),
            subscriptions: BTreeMap::new(),
            processed: BTreeMap::new(),
        })
    }

    /// Record `context` for a subscribe token this Agent's provider issued
    /// to it, before presenting the token. Returns its `eid`.
    ///
    /// # Errors
    /// `Token` when the token does not parse or its `sub` is not this Agent.
    pub fn remember(&mut self, subscribe_token: &str, context: T) -> Result<String, EventError> {
        let token = SubscribeToken::parse(subscribe_token).map_err(EventError::Token)?;
        let claims = token.unverified_claims();
        if claims.sub != self.agent {
            return Err(EventError::Token(TokenError::InvalidJwt));
        }
        self.subscriptions
            .insert(claims.eid.clone(), (claims.aud.clone(), context));
        Ok(claims.eid.clone())
    }

    /// Drop the context for `eid`, returning it.
    pub fn forget(&mut self, eid: &str) -> Option<T> {
        self.subscriptions.remove(eid).map(|(_, context)| context)
    }

    /// Verify a delivered event as [`verify_event`] does, then look up its
    /// `eid`, require its `iss` to be the Resource that subscription names,
    /// and refuse an `(iss, jti)` already processed. A returned event is
    /// marked processed.
    ///
    /// # Errors
    /// See [`EventError`].
    pub fn receive(
        &mut self,
        event_token: &str,
        body: &[u8],
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<ReceivedEvent<'_, T>, EventError> {
        let token = verify_event(event_token, body, &self.agent, keys, now)?;
        let claims = token.claims();
        let (resource, context) = self
            .subscriptions
            .get(&claims.eid)
            .ok_or(EventError::UnknownSubscription)?;
        if claims.iss != *resource {
            return Err(EventError::ResourceMismatch);
        }
        self.processed.retain(|_, expires_at| *expires_at > now);
        let key = (claims.iss.clone(), claims.jti.clone());
        if self.processed.contains_key(&key) {
            return Err(EventError::Duplicate);
        }
        self.processed.insert(key, claims.exp);
        Ok(ReceivedEvent { token, context })
    }
}
