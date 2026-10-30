//! AAuth Events subscribe and event tokens: claim syntax, minting and common
//! JWT verification.
//!
//! The Agent Provider mints an `aa-subscribe+jwt` for one Resource. The
//! Resource verifies it, then binds `aud` to itself and `cnf` to the key that
//! signed the registration request. The Resource mints an `aa-event+jwt`; the
//! Agent Provider verifies it together with the delivery's HTTP signature
//! under the `self-jwt` scheme, and the Agent verifies it and the delivered
//! body. These types do not bind audience, request key, subscription state or
//! routing. The role crates do.
use crate::tokens::{mint, parse_claims, reject_reserved, validate_digest};
use crate::{
    AgentKeyResolver, Confirmation, TokenError, present_claim, validate_agent_identifier,
    validate_server_identifier,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey, strict_json};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// JWT `typ` of an Agent Provider subscribe token.
pub const SUBSCRIBE_TOKEN_TYPE: &str = "aa-subscribe+jwt";
/// JWT `typ` of a Resource event token.
pub const EVENT_TOKEN_TYPE: &str = "aa-event+jwt";
/// `dwk` of a subscribe token: the Agent Provider's metadata document.
pub const SUBSCRIBE_TOKEN_DOCUMENT: &str = "aauth-agent.json";
/// `dwk` of an event token: the Resource's metadata document.
pub const EVENT_TOKEN_DOCUMENT: &str = "aauth-resource.json";

/// Claims of an `aa-subscribe+jwt`. Times are Unix seconds.
///
/// `exp` bounds how long a Resource may accept the token for registration.
/// It is not the subscription's lifetime.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscribeClaims {
    /// Agent Provider identifier. The Resource resolves `event_endpoint` from it.
    pub iss: String,
    /// Exactly `aauth-agent.json`.
    pub dwk: String,
    /// Identifier of the subscribing Agent, in the Agent Provider's domain.
    pub sub: String,
    /// The one Resource authorized to deliver events for this subscription.
    pub aud: String,
    /// The Agent's current request-signing key.
    pub cnf: Confirmation,
    /// Opaque Event ID, unique at this Agent Provider. Never empty.
    pub eid: String,
    /// Token identifier assigned uniquely by the issuer.
    pub jti: String,
    /// Issued-at time. A future `iat` is not invalidity.
    pub iat: i64,
    /// Expiry time. Verification requires `exp > now`, without clock leeway.
    pub exp: i64,
    /// Most event tokens the Agent Provider accepts for `eid`. Absent means
    /// unlimited; when present it is a positive integer.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_uses: Option<u64>,
    /// Retained additive claims; they confer no authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl SubscribeClaims {
    /// Validate subscribe-token syntax without authenticating its issuer.
    ///
    /// # Errors
    /// Rejects an invalid issuer, Agent or Resource identifier, an Agent
    /// outside the issuer's domain, a wrong `dwk`, an empty `eid` or `jti`,
    /// `exp` not after `iat`, `max_uses` of zero, a reserved extra member or a
    /// confirmation key that is not a public Ed25519 key.
    pub fn validate(&self) -> Result<(), TokenError> {
        validate_server_identifier(&self.iss)?;
        if self.dwk != SUBSCRIBE_TOKEN_DOCUMENT {
            return Err(TokenError::InvalidDiscoveryDocument);
        }
        validate_agent_identifier(&self.sub)?;
        if self.sub.rsplit_once('@').map(|(_, domain)| domain) != self.iss.strip_prefix("https://")
        {
            return Err(TokenError::AgentIssuerMismatch);
        }
        validate_server_identifier(&self.aud)?;
        if self.eid.is_empty() || self.jti.is_empty() || self.max_uses == Some(0) {
            return Err(TokenError::InvalidJwt);
        }
        if self.iat < 0 || self.exp <= self.iat {
            return Err(TokenError::InvalidTokenLifetime);
        }
        reject_reserved(
            &self.extra,
            &[
                "iss", "dwk", "sub", "aud", "cnf", "eid", "jti", "iat", "exp", "max_uses",
            ],
        )?;
        crate::require_ed25519(&self.cnf.jwk)
    }
}

/// Claims of an `aa-event+jwt`. Times are Unix seconds.
///
/// The token is the delivery's routing and security envelope. Event data is
/// the request body, which `body_s256` binds. A `cnf` claim is never valid.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventClaims {
    /// Resource identifier: the issuer and the delivery's HTTP signer.
    pub iss: String,
    /// Exactly `aauth-resource.json`.
    pub dwk: String,
    /// Identifier of the subscribing Agent, compared exactly.
    pub aud: String,
    /// The `eid` of the subscribe token this subscription was registered with.
    pub eid: String,
    /// Event identifier. `(iss, jti)` identifies one event.
    pub jti: String,
    /// Issued-at time. A future `iat` is not invalidity.
    pub iat: i64,
    /// Expiry time and the event's response window. Verification requires `exp > now`.
    pub exp: i64,
    /// Unpadded base64url SHA-256 of the delivery body. Present exactly when
    /// the delivery carries a body.
    #[serde(
        default,
        deserialize_with = "present_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_s256: Option<String>,
    /// Retained additive claims; they confer no authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl EventClaims {
    /// Validate event-token syntax without authenticating its issuer.
    ///
    /// # Errors
    /// Rejects an invalid Resource or Agent identifier, a wrong `dwk`, an empty
    /// `eid` or `jti`, `exp` not after `iat`, a `body_s256` that is not an
    /// unpadded base64url SHA-256 digest, a `cnf` claim or another reserved
    /// extra member.
    pub fn validate(&self) -> Result<(), TokenError> {
        validate_server_identifier(&self.iss)?;
        if self.dwk != EVENT_TOKEN_DOCUMENT {
            return Err(TokenError::InvalidDiscoveryDocument);
        }
        validate_agent_identifier(&self.aud)?;
        if self.eid.is_empty() || self.jti.is_empty() {
            return Err(TokenError::InvalidJwt);
        }
        if self.iat < 0 || self.exp <= self.iat {
            return Err(TokenError::InvalidTokenLifetime);
        }
        if let Some(digest) = &self.body_s256 {
            validate_digest(digest)?;
        }
        // `cnf` is reserved here: the `self-jwt` scheme forbids it, so it can
        // never be an additive claim.
        reject_reserved(
            &self.extra,
            &[
                "iss",
                "dwk",
                "aud",
                "eid",
                "jti",
                "iat",
                "exp",
                "body_s256",
                "cnf",
            ],
        )
    }

    /// Check the delivered body against `body_s256`.
    ///
    /// A nonempty body needs `body_s256` equal to its SHA-256 digest. An empty
    /// body needs `body_s256` absent. Zero bytes is no body.
    ///
    /// # Errors
    /// `InvalidJwt` when the body and `body_s256` disagree.
    pub fn verify_body(&self, body: &[u8]) -> Result<(), TokenError> {
        let matches = match &self.body_s256 {
            Some(digest) => !body.is_empty() && *digest == body_s256(body),
            None => body.is_empty(),
        };
        if matches {
            Ok(())
        } else {
            Err(TokenError::InvalidJwt)
        }
    }
}

/// `body_s256` value for `body`: unpadded base64url SHA-256 of the exact bytes.
pub fn body_s256(body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(body))
}

/// A fresh opaque identifier: 128 bits from the operating system's
/// cryptographically secure random source, as 22 unpadded base64url
/// characters. The roles draw Event IDs, token `jti` values and subscription
/// tickets from it.
pub fn generate_identifier() -> String {
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

/// Unverified subscribe token. Parsing preserves exact bytes and grants no authority.
pub struct SubscribeToken {
    jws: Jws,
    claims: SubscribeClaims,
    kid: String,
}

impl SubscribeToken {
    /// Parse strict JSON and validate subscribe-token syntax.
    ///
    /// # Errors
    /// `UnexpectedTokenType` unless `typ` is `aa-subscribe+jwt`. Also rejects
    /// a missing `kid`, malformed JSON, explicit null optionals and the
    /// [`SubscribeClaims::validate`] failures.
    pub fn parse(compact: &str) -> Result<Self, TokenError> {
        let (jws, claims, kid) = parse_claims::<SubscribeClaims>(compact, SUBSCRIBE_TOKEN_TYPE)?;
        claims.validate()?;
        Ok(Self { jws, claims, kid })
    }

    /// Inspect unauthenticated claims only for routing, never policy.
    pub fn unverified_claims(&self) -> &SubscribeClaims {
        &self.claims
    }

    /// Authenticate the Agent Provider signature, then `exp`, at `now`.
    ///
    /// The key comes from `keys` for this exact `iss`, `aauth-agent.json` and
    /// `kid`. This does not check `aud` or `cnf` against a request.
    ///
    /// # Errors
    /// Resolver trust and key errors, a failed signature, then `ExpiredJwt`
    /// when `exp` is not after `now`.
    pub fn verify(
        &self,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedSubscribeToken, TokenError> {
        if now < 0 {
            return Err(TokenError::InvalidJwt);
        }
        let key = keys.key(&self.claims.iss, &self.claims.dwk, &self.kid)?;
        self.jws.verify(&key)?;
        if self.claims.exp <= now {
            return Err(TokenError::ExpiredJwt);
        }
        Ok(VerifiedSubscribeToken {
            claims: self.claims.clone(),
            compact: self.jws.compact().into(),
        })
    }
}

impl std::fmt::Debug for SubscribeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscribeToken")
            .field("unverified_issuer", &self.claims.iss)
            .finish_non_exhaustive()
    }
}

/// Authenticated subscribe-token claims and exact bytes.
#[derive(Clone)]
pub struct VerifiedSubscribeToken {
    claims: SubscribeClaims,
    compact: String,
}

impl VerifiedSubscribeToken {
    /// Issuer-authenticated claims. Audience and request-key binding are separate.
    pub fn claims(&self) -> &SubscribeClaims {
        &self.claims
    }
    /// Exact authenticated compact bytes.
    pub fn compact(&self) -> &str {
        &self.compact
    }
}

impl std::fmt::Debug for VerifiedSubscribeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedSubscribeToken")
            .field("issuer", &self.claims.iss)
            .field("eid", &self.claims.eid)
            .finish_non_exhaustive()
    }
}

/// Unverified event token. Parsing preserves exact bytes and grants no authority.
pub struct EventToken {
    jws: Jws,
    claims: EventClaims,
    kid: String,
}

impl EventToken {
    /// Parse strict JSON and validate event-token syntax.
    ///
    /// # Errors
    /// `UnexpectedTokenType` unless `typ` is `aa-event+jwt`. Also rejects a
    /// missing `kid`, malformed JSON, explicit null optionals, a `cnf` claim
    /// and the other [`EventClaims::validate`] failures.
    pub fn parse(compact: &str) -> Result<Self, TokenError> {
        // A `cnf` member, even `null`, lands in `extra`, which `validate` refuses.
        let (jws, claims, kid) = parse_claims::<EventClaims>(compact, EVENT_TOKEN_TYPE)?;
        claims.validate()?;
        Ok(Self { jws, claims, kid })
    }

    /// Inspect unauthenticated claims only for routing, never policy.
    pub fn unverified_claims(&self) -> &EventClaims {
        &self.claims
    }

    /// Authenticate the Resource signature, then `exp`, at `now`.
    ///
    /// The key comes from `keys` for this exact `iss`, `aauth-resource.json`
    /// and `kid`. Under `self-jwt` the same key verifies the delivery's HTTP
    /// signature; [`VerifiedEventToken::issuer_key`] returns it. This does not
    /// check `aud`, `eid` or the body.
    ///
    /// # Errors
    /// Resolver trust and key errors, a failed signature, then `ExpiredJwt`
    /// when `exp` is not after `now`.
    pub fn verify(
        &self,
        keys: &dyn AgentKeyResolver,
        now: i64,
    ) -> Result<VerifiedEventToken, TokenError> {
        if now < 0 {
            return Err(TokenError::InvalidJwt);
        }
        let key = keys.key(&self.claims.iss, &self.claims.dwk, &self.kid)?;
        self.jws.verify(&key)?;
        if self.claims.exp <= now {
            return Err(TokenError::ExpiredJwt);
        }
        Ok(VerifiedEventToken {
            claims: self.claims.clone(),
            compact: self.jws.compact().into(),
            key,
        })
    }
}

impl std::fmt::Debug for EventToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventToken")
            .field("unverified_issuer", &self.claims.iss)
            .finish_non_exhaustive()
    }
}

/// Authenticated event-token claims, exact bytes and the Resource key that verified them.
#[derive(Clone)]
pub struct VerifiedEventToken {
    claims: EventClaims,
    compact: String,
    key: Jwk,
}

impl VerifiedEventToken {
    /// Issuer-authenticated claims. Audience, subscription and body checks are separate.
    pub fn claims(&self) -> &EventClaims {
        &self.claims
    }
    /// Exact authenticated compact bytes.
    pub fn compact(&self) -> &str {
        &self.compact
    }
    /// The Resource key, selected by `kid`, that verified the token.
    pub fn issuer_key(&self) -> &Jwk {
        &self.key
    }
}

impl std::fmt::Debug for VerifiedEventToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedEventToken")
            .field("issuer", &self.claims.iss)
            .field("eid", &self.claims.eid)
            .finish_non_exhaustive()
    }
}

/// Mint a subscribe token after Agent Provider policy has approved its claims.
/// Local `iat`/`exp` must be Unix seconds in 0..=8589934591.
///
/// # Errors
/// Rejects invalid claims, an empty `kid`, out-of-range times or signing errors.
pub fn mint_subscribe_token(
    key: &SigningKey,
    kid: &str,
    claims: &SubscribeClaims,
) -> Result<String, TokenError> {
    claims.validate()?;
    mint(
        key,
        kid,
        SUBSCRIBE_TOKEN_TYPE,
        claims,
        (claims.iat, claims.exp),
    )
}

/// Mint an event token after Resource policy has selected its subscription.
/// Local `iat`/`exp` must be Unix seconds in 0..=8589934591.
///
/// # Errors
/// Rejects invalid claims, including any `cnf`, an empty `kid`, out-of-range
/// times or signing errors.
pub fn mint_event_token(
    key: &SigningKey,
    kid: &str,
    claims: &EventClaims,
) -> Result<String, TokenError> {
    claims.validate()?;
    mint(key, kid, EVENT_TOKEN_TYPE, claims, (claims.iat, claims.exp))
}

/// Read `event_endpoint` from Agent Provider metadata fetched from
/// `{expected_issuer}/.well-known/aauth-agent.json`.
///
/// The document's `issuer` must equal `expected_issuer` byte for byte. The
/// endpoint must be an absolute HTTPS URL with a host and valid port, and no
/// userinfo, query or fragment. Fetching and egress admission belong to the host.
///
/// # Errors
/// `IssuerMissing` or `IssuerMismatch` for the issuer check.
/// `InvalidDiscoveryMetadata` for a missing or invalid `event_endpoint`.
/// `InvalidJwt` for oversized or malformed metadata.
pub fn event_endpoint(expected_issuer: &str, metadata: &[u8]) -> Result<String, TokenError> {
    validate_server_identifier(expected_issuer)?;
    if metadata.len() > 65536 {
        return Err(TokenError::InvalidJwt);
    }
    let document = strict_json(metadata).map_err(|_| TokenError::InvalidJwt)?;
    let issuer = document
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(TokenError::IssuerMissing)?;
    if issuer != expected_issuer {
        return Err(TokenError::IssuerMismatch);
    }
    let endpoint = document
        .get("event_endpoint")
        .and_then(Value::as_str)
        .ok_or(TokenError::InvalidDiscoveryMetadata)?;
    validate_event_endpoint(endpoint)?;
    Ok(endpoint.to_owned())
}

/// Validate an `event_endpoint` URL: absolute HTTPS with a host and valid
/// port, and no userinfo, query or fragment.
///
/// # Errors
/// `InvalidDiscoveryMetadata` for any other spelling.
pub fn validate_event_endpoint(endpoint: &str) -> Result<(), TokenError> {
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|_| TokenError::InvalidDiscoveryMetadata)?;
    let authority = uri
        .authority()
        .ok_or(TokenError::InvalidDiscoveryMetadata)?;
    let suffix = &authority.as_str()[authority.host().len()..];
    let port_valid = suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0);
    if uri.scheme_str() != Some("https")
        || authority.host().is_empty()
        || authority.as_str().contains('@')
        || uri.query().is_some()
        || endpoint.contains('#')
        || !port_valid
    {
        return Err(TokenError::InvalidDiscoveryMetadata);
    }
    Ok(())
}
