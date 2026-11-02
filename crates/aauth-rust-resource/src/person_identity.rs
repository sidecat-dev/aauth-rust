//! Person identity access: a Resource that serves on the person's identity
//! alone (protocol, Person Identity Access and Person Token Required).
use crate::ps_authorization::refusal;
use crate::{Authorized, Decision, Deny, PolicyOutcome, SignatureFailure, Target};
use aauth_rust_core::{
    AgentKeyResolver, PersonToken, TokenError, VerifiedPersonToken, validate_server_identifier,
};
use aauth_rust_jose::Jws;
use aauth_rust_signature_key::{Error, KeyMaterial};
use http::{Request, Response, StatusCode};

/// A named policy type for person-identity Resources stored in application
/// state. A boxed closure can capture application state while remaining
/// Send + Sync.
pub type BoxedPersonPolicy =
    Box<dyn Fn(&VerifiedPersonToken, &Request<Vec<u8>>) -> bool + Send + Sync>;

/// Person-identity outcome. Convert to HTTP only after inspecting application needs.
#[derive(Debug)]
pub enum PersonDecision<T = ()> {
    /// No Person token was verified on the request: it was unsigned, or
    /// signed with an Agent or Auth token. Send a 401 Person-token challenge.
    PersonTokenRequired,
    /// Proof/token verification failed: 401 with a stable Signature-Error code.
    SignatureFailure(SignatureFailure),
    /// The verified person failed host policy: 403 without signature diagnostics.
    Forbidden,
    /// Proof and Person token verified and host policy allowed the person.
    Granted(Box<Authorized<T, VerifiedPersonToken>>),
}
impl<T> PersonDecision<T> {
    /// Extract the verified Person token and admitted context for an
    /// application handler, or an HTTP refusal.
    ///
    /// # Errors
    /// Returns the mapped 401/403 response if target, authentication or policy refused.
    pub fn into_result(self) -> Result<(VerifiedPersonToken, T), Box<Response<Vec<u8>>>> {
        match self {
            Self::Granted(value) => Ok((*value).into_parts()),
            other => Err(Box::new(other.into_response())),
        }
    }
    /// HTTP mapping with safe RFC 9457 Problem Details for failures.
    /// Granted writes the person's directed subject as the response body.
    /// Match Granted directly when handing control to an application handler.
    pub fn into_response(self) -> Response<Vec<u8>> {
        match self {
            Self::PersonTokenRequired => {
                let mut response = refusal(StatusCode::UNAUTHORIZED, "person_token_required");
                response.headers_mut().insert(
                    "aauth-requirement",
                    "requirement=person-token"
                        .parse()
                        .expect("static requirement"),
                );
                response
            }
            Self::SignatureFailure(failure) => {
                let mut response = Decision::<()>::SignatureFailure(failure).into_response();
                // The shared Agent diagnostics must not advertise Agent-only access.
                response.headers_mut().remove("aauth-requirement");
                response
            }
            Self::Forbidden => Decision::<()>::Forbidden.into_response(),
            Self::Granted(value) => Response::new(value.claims().sub.as_bytes().to_vec()),
        }
    }
}

/// Person identity access: the agent signs with a Person token from its
/// Person Server, and host policy decides on the person it names. No
/// Resource token or Auth token is involved, and the Person Server is not
/// called.
///
/// A request that carries no verified Person token is answered
/// [`PersonDecision::PersonTokenRequired`], as a Resource that needs the
/// person's identity must (protocol, Person Token Required). An Agent or
/// Auth token is not verified for that answer. A Person token must be
/// issued for this Resource's identifier, the HTTPS origin of its endpoint.
/// A `mission_s256` or `tenant` claim reaches policy unchanged; this
/// Resource keeps no mission state. Every signature must cover the profile's
/// components under the `jwt` scheme.
pub struct PersonIdentityResource<K, P> {
    keys: K,
    policy: P,
    identifier: String,
    authority: String,
    path: String,
}
impl<K: AgentKeyResolver, P, O> PersonIdentityResource<K, P>
where
    P: Fn(&VerifiedPersonToken, &Request<Vec<u8>>) -> O,
    O: PolicyOutcome,
{
    /// Bind this Resource to one HTTPS endpoint, the keys of the Person
    /// Servers it trusts (`aauth-person.json`) and its policy. Configure the
    /// endpoint from server configuration, never from a client's Host.
    ///
    /// # Errors
    /// Rejects an endpoint whose origin is not a server identifier (HTTPS,
    /// lowercase DNS name, no port or userinfo), or one with a query or
    /// fragment.
    pub fn new(endpoint: &str, keys: K, policy: P) -> Result<Self, Error> {
        let uri: http::Uri = endpoint.parse().map_err(|_| Error::InvalidUri)?;
        if uri.query().is_some() || endpoint.contains('#') {
            return Err(Error::InvalidUri);
        }
        let authority = aauth_rust_signature_key::canonical_authority(&uri)?;
        let identifier = format!("https://{authority}");
        validate_server_identifier(&identifier).map_err(|_| Error::InvalidUri)?;
        Ok(Self {
            keys,
            policy,
            identifier,
            authority,
            path: uri.path().to_owned(),
        })
    }
    /// Check a buffered absolute HTTPS request at `now` in Unix seconds.
    /// The proof window is ±60 seconds. Token expiry has no leeway; a future
    /// `iat` beyond 60 seconds is refused. Policy receives the verified
    /// Person token and the request only after verification.
    pub fn authorize(&self, request: &Request<Vec<u8>>, now: i64) -> PersonDecision<O::Context> {
        match self.verify(request, now) {
            Ok(Some(token)) => match (self.policy)(&token, request).into_admission() {
                Ok(admitted) => PersonDecision::Granted(Box::new(Authorized { token, admitted })),
                Err(Deny) => PersonDecision::Forbidden,
            },
            Ok(None) => PersonDecision::PersonTokenRequired,
            Err(failure) => PersonDecision::SignatureFailure(failure),
        }
    }
    /// The verified Person token, or `None` when the request carries none.
    fn verify(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Option<VerifiedPersonToken>, SignatureFailure> {
        let target = Target {
            authority: &self.authority,
            path: Some(&self.path),
            accepted: &["jwt"],
            additional: &[],
        };
        let Some(proof) = target.arrive(request, now)? else {
            return Ok(None);
        };
        let KeyMaterial::Jwt { jwt: compact, .. } = proof.key() else {
            return Err(SignatureFailure::UnsupportedScheme(vec!["jwt"]));
        };
        let parsed = Jws::parse(compact).map_err(|error| SignatureFailure::Token(error.into()))?;
        if parsed.header().get("typ").and_then(|value| value.as_str()) != Some("aa-person+jwt") {
            return Ok(None);
        }
        let token = PersonToken::parse(compact)
            .and_then(|token| token.verify(&self.keys, now))
            .map_err(SignatureFailure::Token)?;
        let claims = token.claims();
        proof
            .verify(&claims.cnf.jwk)
            .map_err(SignatureFailure::Proof)?;
        if claims.iat > now.saturating_add(60) {
            return Err(SignatureFailure::ClockSkew { server_time: now });
        }
        if claims.aud != self.identifier {
            return Err(SignatureFailure::Token(TokenError::AudienceMismatch));
        }
        Ok(Some(token))
    }
}
