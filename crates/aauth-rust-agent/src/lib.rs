//! Buffered request signing and immediate PS credential-context verification.
//! AAuth Events: subscription requests signed with a subscribe token, and
//! verification of delivered event tokens and bodies.
//! AAuth Bootstrap: [`BootstrapClient`] enrolls an install's durable key and
//! refreshes its Agent token, and [`Agent::subagent_request`] asks the Agent
//! Provider for a sub-agent token.
//! Transport, response-header extraction and retries belong to hosts.
#![deny(missing_docs)]
mod access;
mod bootstrap;
pub use bootstrap::{
    BootstrapClient, BootstrapError, NAMING_JWT_LIFETIME, PendingRefresh, issued_agent_token,
};
mod components;
mod credentials;
mod events;
pub use credentials::FederatedContext;
pub use events::{EventError, EventSubscriptions, ReceivedEvent, verify_event};
mod subagents;
pub use subagents::Subagent;

mod polling;
pub use polling::{PollError, PollSession};
mod r3;
pub use r3::{R3AgentError, R3TransportError};
mod attempts;
mod governance;
mod missions;
mod person;
mod requirements;
use aauth_rust_core::{AgentToken, TokenError};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{
    Error, KeyMaterial, RequestSignature, sign_requests_with_components,
};
pub use access::AccessSession;
pub use attempts::ResourceTokenAttempts;
pub use components::SignatureComponentsError;
pub use governance::{ChannelError, InteractionCompletion, PermissionDecision};
use http::Request;
pub use missions::{MissionTerminated, Missions};
pub use requirements::{Requirement, RequirementError};
use std::sync::Arc;

/// Caller-owned proof key and exact issuer token; no transport or refresh loop.
pub struct Agent {
    key: Arc<SigningKey>,
    token: String,
    components: Vec<String>,
    missions: Missions,
}
impl Agent {
    /// Retain exact issuer-provided bytes and ensure the local proof key matches.
    /// This is not issuer authentication; the Resource verifies issuer authority.
    ///
    /// # Errors
    /// Returns token-profile errors or `ConfirmationKeyMismatch` if the local
    /// signing key differs from cnf.jwk. This does not verify the issuer signature.
    pub fn new(key: SigningKey, token: String) -> Result<Self, TokenError> {
        Self::from_shared_key(Arc::new(key), token)
    }
    /// Retain an Agent, Person or Auth token with the existing proof key. Earlier
    /// values remain usable for in-flight requests; secret bytes are never exported.
    /// Parsing and matching cnf are not issuer authentication. Use the credential
    /// verification helpers or let the accepting role authenticate the issuer.
    ///
    /// # Errors
    /// Rejects malformed tokens or a new cnf.jwk that differs from this Agent key.
    /// Issuer authentication still belongs to the caller or receiving Resource.
    pub fn with_token(&self, token: String) -> Result<Self, TokenError> {
        let confirmation = credentials::credential_key(&token)?;
        if confirmation.thumbprint()? != self.key.public_jwk().thumbprint()? {
            return Err(TokenError::ConfirmationKeyMismatch);
        }
        Ok(Self {
            key: self.key.clone(),
            token,
            components: self.components.clone(),
            missions: self.missions.clone(),
        })
    }
    /// Cover a Resource's `additional_signature_components` on every request
    /// this Agent signs, including R3 authorization requests and polls. The
    /// list replaces any earlier one, and [`Self::with_token`] keeps it.
    /// The Agent does not fetch Resource metadata: pass the published array,
    /// or the fetched document to [`Self::with_resource_metadata`], which
    /// checks its `issuer` first. [`Self::with_required_input`] adds what an
    /// `invalid_input` refusal lists.
    ///
    /// Use the returned Agent only for that Resource. Signing fails with
    /// `InvalidInput` rather than omit a listed component: an entry must be a
    /// lowercase field name present on the request, or `@method`,
    /// `@authority`, `@path` or `@query`. A listed `content-digest` is always
    /// computed from the actual content.
    pub fn with_additional_signature_components<I, S>(&self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            key: self.key.clone(),
            token: self.token.clone(),
            components: components
                .into_iter()
                .map(|component| component.as_ref().to_owned())
                .collect(),
            missions: self.missions.clone(),
        }
    }
    /// Missions the Person Server reported terminated, shared by every Agent
    /// derived from this one. Feed it each response to a request that named
    /// a mission; [`Self::post_audit`] then refuses a terminated mission.
    pub fn missions(&self) -> &Missions {
        &self.missions
    }
    /// Share `missions` with this Agent, for example across Agents built
    /// separately for the same agent identity. Earlier state on this Agent is
    /// replaced by the given handle.
    pub fn with_missions(&self, missions: Missions) -> Self {
        Self {
            key: self.key.clone(),
            token: self.token.clone(),
            components: self.components.clone(),
            missions,
        }
    }
    fn from_shared_key(key: Arc<SigningKey>, token: String) -> Result<Self, TokenError> {
        let parsed = AgentToken::parse(&token)?;
        if parsed.unverified_claims().cnf.jwk.thumbprint()? != key.public_jwk().thumbprint()? {
            return Err(TokenError::ConfirmationKeyMismatch);
        }
        Ok(Self {
            key,
            token,
            components: Vec::new(),
            missions: Missions::new(),
        })
    }
    /// Return an owned copy of the retained proof key's public JWK.
    /// Use it for enrollment or renewed token claims without parsing an old token.
    /// Mutating the returned public value never changes this Agent's signing key.
    pub fn public_jwk(&self) -> Jwk {
        self.key.public_jwk()
    }
    /// Retained compact token; treat it as a credential when logging.
    pub fn token(&self) -> &str {
        &self.token
    }
    /// Sign once, last, after URI and headers are final. `now` is Unix seconds.
    /// This replaces any signature headers; it never sends or retries a request.
    /// The signature also covers any components set with
    /// [`Self::with_additional_signature_components`].
    ///
    /// # Errors
    /// Nonempty content is digest-covered (up to 1 MiB), including Content-Type
    /// when present. Hosts must pass actual bytes and bound body collection.
    /// Rejects oversized/non-HTTPS requests, invalid clocks and malformed
    /// signing material. A listed component that cannot be covered is
    /// `InvalidInput`. See the Signature-Key error explanation for a remedy.
    pub fn sign(&self, request: &mut Request<Vec<u8>>, now: i64) -> Result<(), Error> {
        let components: Vec<&str> = self.components.iter().map(String::as_str).collect();
        sign_requests_with_components(
            request,
            &[RequestSignature {
                label: "sig",
                key: &self.key,
                material: KeyMaterial::Jwt {
                    jwt: self.token.clone(),
                    cache: false,
                },
            }],
            &components,
            now,
        )
    }
}
