//! AAuth supervision server (`draft-hardt-aauth-supervision`).
//!
//! A person connects this server to their Person Server, and the Person
//! Server puts every act of the agents routed here to it: mission proposals,
//! updates and completions, person tokens, auth tokens and permissions. The
//! server answers `allow`, `deny` or `ask`, or asks the agent a question
//! first, and records what the Person Server reports afterwards. It issues
//! nothing and calls no one: everything it says is a response.
//!
//! The host supplies the policy, the keys of the Person Servers it admits,
//! one atomic [`ContinuationStore`] for every record, and a clock. With a
//! signing key the server publishes `jwks_uri` and signs every terminal
//! answer, so the Person Server's log shows who decided what.
//!
//! ```
//! use aauth_rust_core::continuation::MemoryContinuations;
//! use aauth_rust_core::supervision::Allowance;
//! use aauth_rust_core::{AgentKeyResolver, TokenError};
//! use aauth_rust_jose::{Jwk, SigningKey};
//! use aauth_rust_supervision_server::{
//!     Case, Config, ConnectAnswer, ConnectRequest, Policy, SupervisionServer, Verdict,
//! };
//!
//! struct Standing;
//! impl Policy for Standing {
//!     fn connect(&self, request: &ConnectRequest) -> ConnectAnswer {
//!         if request.tenant.as_deref() == Some("acme.example") {
//!             ConnectAnswer::Connected
//!         } else {
//!             ConnectAnswer::Refused
//!         }
//!     }
//!     fn decide(&self, case: &Case) -> Verdict {
//!         match case.action() {
//!             Some("SendEmail") => Verdict::Ask(Default::default()),
//!             _ => Verdict::Allow(Allowance::default()),
//!         }
//!     }
//! }
//! struct NoPersonServers;
//! impl AgentKeyResolver for NoPersonServers {
//!     fn key(&self, _: &str, _: &str, _: &str) -> Result<Jwk, TokenError> {
//!         Err(TokenError::UntrustedIssuer)
//!     }
//! }
//! let server = SupervisionServer::new(
//!     Config::new("https://ss.example").with_signing("ss-1", SigningKey::generate()),
//!     NoPersonServers,
//!     Standing,
//!     MemoryContinuations::new(10_000),
//!     || 1_790_600_000,
//! )?;
//! let metadata: serde_json::Value = serde_json::from_slice(&server.metadata())?;
//! assert_eq!(metadata["decision_endpoint"], "https://ss.example/decision");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![deny(missing_docs)]
mod connect;
mod decisions;
mod events;
mod policy;
mod records;

pub use connect::PendingConnection;
pub use decisions::StandingAnswer;
pub use policy::{
    Case, ConnectAnswer, ConnectRequest, MissionView, Observation, Policy, Round, Verdict,
    default_kind,
};

use aauth_rust_core::continuation::ContinuationStore;
use aauth_rust_core::supervision::{
    DECISION_COMPONENTS, POLL_DECISION_COMPONENTS, REQUIRED_DECISION_COMPONENTS, SupervisionError,
    SupervisorMetadata,
};
use aauth_rust_core::{AgentKeyResolver, MetadataDisplay, TokenError, validate_server_identifier};
use aauth_rust_jose::{SigningKey, strict_json};
use aauth_rust_signature_key::{
    Error as ProofError, KeyMaterial, PreparedRequest, accept_signature_components,
    canonical_authority, role_signature_alg_header, sign_response,
};
use http::{Request, Response, StatusCode};
use serde_json::{Map, Value, json};

/// The key this server signs its decisions with.
pub struct Signing {
    /// Key identifier published in the JWKS.
    pub kid: String,
    /// Host-owned signing key: Ed25519 or ES256, in this process or behind an
    /// external signer.
    pub key: SigningKey,
}

/// Host configuration of one supervision server.
pub struct Config {
    /// Canonical HTTPS server identifier: the `issuer` a person registers.
    pub issuer: String,
    /// Actual HTTPS origin requests arrive at; ports are allowed here only.
    pub signed_origin: String,
    /// Display name the Person Server may show the person.
    pub name: Option<String>,
    /// Sign every terminal decision and publish `jwks_uri`.
    pub signing: Option<Signing>,
    /// HTTPS page where a person confirms a connect, without query or
    /// fragment. Required for [`ConnectAnswer::Confirm`].
    pub interaction_url: Option<String>,
    /// Seconds a Person Server waits between polls, 0..=3600; default five.
    pub retry_after: u64,
    /// Seconds a pending decision or connect stays answerable, 1..=86400;
    /// default 3600.
    pub pending_lifetime: i64,
}

impl Config {
    /// An unsigned server at `issuer` with five-second polls and one-hour pending records.
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.into(),
            signed_origin: issuer.into(),
            name: None,
            signing: None,
            interaction_url: None,
            retry_after: 5,
            pending_lifetime: 3600,
        }
    }
    /// Sign decisions with `key`, published as `kid`.
    pub fn with_signing(mut self, kid: &str, key: SigningKey) -> Self {
        self.signing = Some(Signing {
            kid: kid.into(),
            key,
        });
        self
    }
}

/// Invalid local configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid_configuration: use a canonical issuer, an HTTPS signed origin, a nonempty kid, an HTTPS interaction URL and bounded intervals"
)]
pub struct ConfigurationError;

/// A host action named something this server does not hold, or the store failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// No such pending connect or decision, or it was already answered.
    #[error("nothing pending under that reference")]
    NotFound,
    /// The verdict cannot answer this act, such as a proposal allowed without terms.
    #[error("the verdict does not fit the pending act")]
    InvalidVerdict,
    /// The store failed.
    #[error("supervision server storage is unavailable")]
    Unavailable,
}

impl From<records::Fault> for HostError {
    fn from(_: records::Fault) -> Self {
        HostError::Unavailable
    }
}

/// Buffered supervision server. It performs no network I/O.
pub struct SupervisionServer<K, P, S, C> {
    config: Config,
    authority: String,
    metadata: SupervisorMetadata,
    display: MetadataDisplay,
    keys: K,
    policy: P,
    store: S,
    clock: C,
}

/// A refusal, boxed so every answer stays small.
pub(crate) type Refusal = Box<Response<Vec<u8>>>;
/// What a request becomes before it is answered.
pub(crate) type Answer = Result<Response<Vec<u8>>, Refusal>;

impl<K: AgentKeyResolver, P: Policy, S: ContinuationStore, C: Fn() -> i64>
    SupervisionServer<K, P, S, C>
{
    /// Validate the configuration and keep the host's dependencies.
    ///
    /// `keys` resolves Person Server keys for `(issuer, "aauth-person.json",
    /// kid)`. Answering [`TokenError::UntrustedIssuer`] for an issuer refuses
    /// that Person Server with `unsupported_iss`. Egress admission and
    /// caching of fetched Person Server documents belong to it.
    ///
    /// # Errors
    /// [`ConfigurationError`] for a malformed issuer, origin, kid,
    /// interaction URL, interval or lifetime.
    pub fn new(
        config: Config,
        keys: K,
        policy: P,
        store: S,
        clock: C,
    ) -> Result<Self, ConfigurationError> {
        validate_server_identifier(&config.issuer).map_err(|_| ConfigurationError)?;
        let uri: http::Uri = config
            .signed_origin
            .parse()
            .map_err(|_| ConfigurationError)?;
        if config.signed_origin.contains('#')
            || uri.query().is_some()
            || (!uri.path().is_empty() && uri.path() != "/")
            || config.retry_after > 3600
            || !(1..=86_400).contains(&config.pending_lifetime)
            || config.signing.as_ref().is_some_and(|s| s.kid.is_empty())
            || config
                .name
                .as_ref()
                .is_some_and(|n| n.is_empty() || n.len() > 256)
        {
            return Err(ConfigurationError);
        }
        if let Some(url) = &config.interaction_url {
            let parsed: http::Uri = url.parse().map_err(|_| ConfigurationError)?;
            canonical_authority(&parsed).map_err(|_| ConfigurationError)?;
            if parsed.query().is_some() || url.contains('#') {
                return Err(ConfigurationError);
            }
        }
        let authority = canonical_authority(&uri).map_err(|_| ConfigurationError)?;
        let metadata = SupervisorMetadata::for_issuer(
            &config.issuer,
            config.name.as_deref(),
            config.signing.is_some(),
        );
        Ok(Self {
            config,
            authority,
            metadata,
            display: MetadataDisplay::new(),
            keys,
            policy,
            store,
            clock,
        })
    }

    /// Publish `description`, `logo_uri` and the other common display
    /// members beside the protocol fields. `name` stays [`Config::name`].
    pub fn with_display(mut self, display: MetadataDisplay) -> Self {
        self.display = display;
        self
    }

    /// The `aauth-supervisor.json` document.
    pub fn metadata(&self) -> Vec<u8> {
        let mut value = self.metadata.to_value();
        for (member, display) in self.display.members() {
            if member != "name" {
                value[member] = json!(display);
            }
        }
        value.to_string().into_bytes()
    }

    /// The public JWKS, when this server signs.
    pub fn jwks(&self) -> Option<Vec<u8>> {
        let signing = self.config.signing.as_ref()?;
        let mut key = serde_json::to_value(signing.key.public_jwk()).ok()?;
        key["kid"] = json!(signing.kid);
        Some(json!({ "keys": [key] }).to_string().into_bytes())
    }

    /// Handle one buffered request at this server's origin. The host bounds
    /// collection; bodies over 1 MiB are refused.
    pub fn handle(&self, request: &Request<Vec<u8>>) -> Response<Vec<u8>> {
        match self.route(request) {
            Ok(response) => response,
            Err(refusal) => *refusal,
        }
    }

    fn route(&self, request: &Request<Vec<u8>>) -> Answer {
        if canonical_authority(request.uri()).ok().as_deref() != Some(&self.authority) {
            return Err(signature_error(ProofError::TargetMismatch));
        }
        let path = request.uri().path().to_owned();
        let method = request.method().as_str().to_owned();
        match (method.as_str(), path.as_str()) {
            ("GET", "/.well-known/aauth-supervisor.json") => {
                return Ok(json_bytes(StatusCode::OK, self.metadata()));
            }
            ("GET", "/.well-known/jwks.json") => {
                return match self.jwks() {
                    Some(jwks) => Ok(json_bytes(StatusCode::OK, jwks)),
                    None => Err(not_found()),
                };
            }
            _ => {}
        }
        if request.uri().query().is_some() {
            return Err(refuse(SupervisionError::InvalidRequest));
        }
        let now = (self.clock)();
        match (method.as_str(), path.as_str()) {
            ("POST", "/connect") => self.connect(request, now),
            ("GET", p) if p.starts_with("/connect/pending/") => {
                self.poll_connect(request, now, &p["/connect/pending/".len()..])
            }
            ("POST", "/decision") => self.decision(request, now),
            ("POST", "/mission") => self.mission(request, now, None),
            ("POST", p) if p.starts_with("/mission/") => {
                self.mission(request, now, Some(&p["/mission/".len()..]))
            }
            ("POST", "/event") => self.event(request, now),
            ("GET" | "POST" | "DELETE", p) if p.starts_with("/pending/") => {
                self.pending(request, now, &p["/pending/".len()..])
            }
            _ => Err(not_found()),
        }
    }

    /// Authenticate the Person Server that signed `request` and return its identity.
    fn authenticate(&self, request: &Request<Vec<u8>>, now: i64) -> Result<String, Refusal> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"])
            .map_err(signature_error)?;
        if !request.body().is_empty() {
            let base = std::str::from_utf8(proof.signature_base())
                .map_err(|_| signature_error(ProofError::InvalidInput))?;
            if !["\"content-type\":", "\"content-digest\":"]
                .iter()
                .all(|name| base.lines().any(|line| line.starts_with(name)))
            {
                return Err(signature_error(ProofError::InvalidInput));
            }
        }
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return Err(signature_error(ProofError::UnsupportedScheme));
        };
        if dwk != "aauth-person.json" || validate_server_identifier(id).is_err() {
            return Err(signature_error(ProofError::InvalidKey));
        }
        let verified = aauth_rust_core::verify_with_refresh(
            &self.keys,
            (id, dwk, kid),
            |key| proof.verify(key),
            |error| *error == ProofError::InvalidSignature,
        );
        let verified = match verified {
            Ok(verified) => verified,
            Err(TokenError::UntrustedIssuer) => {
                return Err(refuse(SupervisionError::UnsupportedIss));
            }
            // A key type or algorithm this server does not implement is
            // unsupported_algorithm; a metadata document failing its issuer
            // check is issuer_missing or issuer_mismatch (protocol
            // Verification (Server), steps 5 and 6).
            Err(error) => {
                return Err(signature_error(match error {
                    TokenError::UnknownKey => ProofError::UnknownKey,
                    TokenError::UnsupportedAlgorithm => ProofError::UnsupportedAlgorithm,
                    TokenError::IssuerMissing => ProofError::IssuerMissing,
                    TokenError::IssuerMismatch => ProofError::IssuerMismatch,
                    _ => ProofError::InvalidKey,
                }));
            }
        };
        verified.map_err(signature_error)?;
        Ok(id.clone())
    }

    /// The JSON object body of an authenticated POST.
    fn object(request: &Request<Vec<u8>>) -> Result<Map<String, Value>, Refusal> {
        let json = request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return Err(refuse(SupervisionError::InvalidRequest));
        }
        match strict_json(request.body()) {
            Ok(Value::Object(object)) => Ok(object),
            _ => Err(refuse(SupervisionError::InvalidRequest)),
        }
    }

    /// Whether `(ps, sub)` is connected, answering `unknown_sub` when not.
    fn require_connection(&self, ps: &str, sub: &str) -> Result<(), Refusal> {
        let record = records::load(&self.store, &records::key(records::CONNECTION, &[ps, sub]))
            .map_err(|_| server_error())?;
        if record.is_none() {
            return Err(refuse(SupervisionError::UnknownSub));
        }
        Ok(())
    }

    /// Sign a terminal answer to `request` when this server signs. The
    /// components are those the Person Server asked for in `Accept-Signature`
    /// that this server can cover, after the three every decision covers.
    fn sign(&self, mut response: Response<Vec<u8>>, request: &Request<Vec<u8>>) -> Answer {
        let Some(signing) = &self.config.signing else {
            return Ok(response);
        };
        let requested = request
            .headers()
            .get("accept-signature")
            .and_then(|v| v.to_str().ok())
            .and_then(|field| accept_signature_components(field, "sig").ok());
        let defaults = if request.method() == "GET" {
            &POLL_DECISION_COMPONENTS[..]
        } else {
            &DECISION_COMPONENTS[..]
        };
        let mut components: Vec<String> = REQUIRED_DECISION_COMPONENTS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let asked = requested.unwrap_or_else(|| defaults.iter().map(|c| (*c).to_owned()).collect());
        for component in asked {
            let coverable = match component.as_str() {
                "@status" | "content-type" | "content-digest" | "signature-key" => true,
                "@method;req" | "@authority;req" | "@path;req" => true,
                "@query;req" => request.uri().query().is_some(),
                "content-digest;req" | "content-type;req" => request
                    .headers()
                    .contains_key(component.trim_end_matches(";req")),
                _ => false,
            };
            if coverable && !components.contains(&component) {
                components.push(component);
            }
        }
        let components: Vec<&str> = components.iter().map(String::as_str).collect();
        sign_response(
            &mut response,
            request,
            &signing.key,
            KeyMaterial::JwksUri {
                id: self.config.issuer.clone(),
                dwk: aauth_rust_core::supervision::SUPERVISOR_DOCUMENT.into(),
                kid: signing.kid.clone(),
            },
            &components,
            (self.clock)(),
        )
        .map_err(|_| server_error())?;
        Ok(response)
    }

    fn pending_url(&self, path: &str, id: &str) -> String {
        format!("{}{path}{id}", self.config.signed_origin)
    }
}

pub(crate) fn json_bytes(status: StatusCode, body: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    response
}

pub(crate) fn json_response(status: StatusCode, value: Value) -> Response<Vec<u8>> {
    json_bytes(status, value.to_string().into_bytes())
}

pub(crate) fn refuse(error: SupervisionError) -> Refusal {
    Box::new(error.response(None))
}

pub(crate) fn server_error() -> Refusal {
    refuse(SupervisionError::ServerError)
}

pub(crate) fn not_found() -> Refusal {
    let mut response = json_response(StatusCode::NOT_FOUND, json!({ "error": "not_found" }));
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/problem+json"),
    );
    Box::new(response)
}

/// A polling error from the protocol's table (Polling Error Codes).
pub(crate) fn polling_error(status: StatusCode, code: &str) -> Refusal {
    let mut response = json_response(
        status,
        json!({ "type": "about:blank", "status": status.as_u16(), "error": code }),
    );
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/problem+json"),
    );
    Box::new(response)
}

/// `401` with `Signature-Error`, as for every signature failure.
pub(crate) fn signature_error(error: ProofError) -> Refusal {
    let code = error.code();
    let mut response = json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "type": format!("urn:ietf:params:sig-error:{code}"),
            "status": 401,
            "error": code,
        }),
    );
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/problem+json"),
    );
    if let Ok(value) = format!("error={code}").parse() {
        response.headers_mut().insert("signature-error", value);
    }
    if matches!(error, ProofError::UnsupportedScheme) {
        response.headers_mut().insert(
            "accept-signature-scheme",
            http::HeaderValue::from_static("jwks_uri"),
        );
    }
    if matches!(error, ProofError::UnsupportedAlgorithm)
        && let Ok(value) = role_signature_alg_header().parse()
    {
        response.headers_mut().insert("accept-signature-alg", value);
    }
    Box::new(response)
}

/// A deferred answer: `202` with `Location`, `Retry-After` and `no-store`.
pub(crate) fn deferred(
    location: &str,
    retry_after: u64,
    requirement: Option<String>,
    body: Value,
) -> Response<Vec<u8>> {
    let mut response = json_response(StatusCode::ACCEPTED, body);
    let headers = response.headers_mut();
    if let Ok(value) = location.parse() {
        headers.insert("location", value);
    }
    headers.insert("retry-after", http::HeaderValue::from(retry_after));
    headers.insert("cache-control", http::HeaderValue::from_static("no-store"));
    if let Some(requirement) = requirement
        && let Ok(value) = requirement.parse()
    {
        headers.insert("aauth-requirement", value);
    }
    response
}

/// A Structured Field String, for an `AAuth-Requirement` parameter.
pub(crate) fn sf_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
