//! Direct Agent-identity Resource. Proof and token checks precede host policy.
#![deny(missing_docs)]
use aauth_rust_core::{AgentKeyResolver, AgentToken, TokenError, VerifiedAgentToken};
use aauth_rust_signature_key::{Error, KeyMaterial, PreparedRequest, required_components};
use http::{Request, Response, StatusCode};

#[derive(Debug)]
/// Failed proof/token verification or the required coverage needed to retry.
pub enum SignatureFailure {
    /// HTTP proof or target binding failed.
    Proof(Error),
    /// Issuer JWT or trusted discovery failed.
    Token(TokenError),
    /// Missing coverage, with the complete request-specific component list.
    Input(Vec<&'static str>),
}
impl SignatureFailure {
    /// Machine-readable wire code, separate from local error explanations.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Proof(error) => error.code(),
            Self::Token(error) => error.code(),
            Self::Input(_) => "invalid_input",
        }
    }
}
impl std::fmt::Display for SignatureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(e) => e.fmt(f),
            Self::Token(e) => e.fmt(f),
            Self::Input(required) => {
                write!(f, "signature coverage is incomplete: cover {required:?}")
            }
        }
    }
}
/// Resource outcome. Convert to HTTP only after inspecting application needs.
#[derive(Debug)]
pub enum Decision {
    /// No proof was supplied: send a 401 Agent-token challenge.
    AgentTokenRequired,
    /// Proof/token verification failed: 401 with a stable Signature-Error code.
    SignatureFailure(SignatureFailure),
    /// Verified identity failed host policy: 403 without signature diagnostics.
    Forbidden,
    /// Proof and issuer token verified and host policy allowed the identity.
    Granted(Box<VerifiedAgentToken>),
}
impl Decision {
    /// HTTP mapping with safe RFC 9457 Problem Details for failures.
    /// Granted writes the authenticated subject as the response body. Match
    /// Granted directly when handing control to an application handler instead.
    pub fn into_response(self) -> Response<Vec<u8>> {
        let mut response = Response::new(Vec::new());
        match self {
            Self::AgentTokenRequired => {
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                response.headers_mut().insert(
                    "aauth-requirement",
                    "requirement=agent-token".parse().unwrap(),
                );
                problem(&mut response, "about:blank", "Agent token required", 401);
            }
            Self::Forbidden => {
                *response.status_mut() = StatusCode::FORBIDDEN;
                problem(&mut response, "about:blank", "Forbidden", 403);
            }
            Self::Granted(token) => {
                *response.body_mut() = token.claims().sub.as_bytes().to_vec();
            }
            Self::SignatureFailure(failure) => {
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                let mut error = format!("error={}", failure.code());
                if let SignatureFailure::Input(required) = &failure {
                    let components = required
                        .iter()
                        .map(|s| format!("\"{s}\""))
                        .collect::<Vec<_>>()
                        .join(" ");
                    error.push_str(&format!(", required_input=({components})"));
                }
                if matches!(failure, SignatureFailure::Proof(Error::InvalidInput)) {
                    error.push_str(
                        ", required_input=(\"@method\" \"@authority\" \"@path\" \"signature-key\")",
                    );
                }
                response
                    .headers_mut()
                    .insert("signature-error", error.parse().unwrap());
                problem(
                    &mut response,
                    &format!("urn:ietf:params:sig-error:{}", failure.code()),
                    "Request signature rejected",
                    401,
                );
                if matches!(
                    failure,
                    SignatureFailure::Token(TokenError::UnexpectedTokenType)
                ) {
                    response.headers_mut().insert(
                        "aauth-requirement",
                        "requirement=agent-token".parse().unwrap(),
                    );
                }
                if matches!(
                    failure,
                    SignatureFailure::Proof(Error::UnsupportedAlgorithm)
                        | SignatureFailure::Token(TokenError::UnsupportedAlgorithm)
                ) {
                    response
                        .headers_mut()
                        .insert("accept-signature-alg", "Ed25519".parse().unwrap());
                }
                if matches!(failure, SignatureFailure::Proof(Error::UnsupportedScheme)) {
                    response
                        .headers_mut()
                        .insert("accept-signature-scheme", "jwt".parse().unwrap());
                }
            }
        }
        response
    }
}

fn problem(response: &mut Response<Vec<u8>>, kind: &str, title: &str, status: u16) {
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    let code = kind
        .strip_prefix("urn:ietf:params:sig-error:")
        .unwrap_or(if status == 403 {
            "forbidden"
        } else {
            "agent_token_required"
        });
    *response.body_mut() = serde_json::to_vec(
        &serde_json::json!({"type":kind,"title":title,"status":status,"error":code}),
    )
    .expect("fixed Problem Details fields are serializable");
}

/// A named policy type for Resource values stored in application state.
/// A boxed closure can capture application state while remaining Send + Sync.
pub type BoxedPolicy = Box<dyn Fn(&VerifiedAgentToken, &Request<Vec<u8>>) -> bool + Send + Sync>;

/// Direct Agent identity: trusted issuer token, holder proof, then host policy.
pub struct AgentIdentityResource<K, P> {
    keys: K,
    policy: P,
    authority: String,
    path: String,
}
impl<K: AgentKeyResolver, P: Fn(&VerifiedAgentToken, &Request<Vec<u8>>) -> bool>
    AgentIdentityResource<K, P>
{
    /// Bind this Resource to one HTTPS endpoint, plus trusted keys and policy.
    /// Configure authority/path from server configuration, never from client Host.
    /// Queries vary per request and are covered by the request signature.
    ///
    /// # Errors
    /// Rejects non-HTTPS/relative targets, userinfo, invalid ports, queries and
    /// fragments. The endpoint authority/path must come from server configuration.
    pub fn new(endpoint: &str, keys: K, policy: P) -> Result<Self, Error> {
        let uri: http::Uri = endpoint.parse().map_err(|_| Error::InvalidUri)?;
        if uri.query().is_some() || endpoint.contains('#') {
            return Err(Error::InvalidUri);
        }
        Ok(Self {
            keys,
            policy,
            authority: aauth_rust_signature_key::canonical_authority(&uri)?,
            path: uri.path().to_owned(),
        })
    }
    /// Replace admission policy while retaining the configured target and keys.
    pub fn with_policy<Q: Fn(&VerifiedAgentToken, &Request<Vec<u8>>) -> bool>(
        self,
        policy: Q,
    ) -> AgentIdentityResource<K, Q> {
        AgentIdentityResource {
            keys: self.keys,
            policy,
            authority: self.authority,
            path: self.path,
        }
    }
    /// Check a bodyless absolute HTTPS request at `now` in Unix seconds.
    /// The proof window is ±60 seconds. Token expiry has no leeway; future
    /// `iat` beyond 60 seconds is refused. Policy receives token and request only
    /// after verification. Supply actual body bytes or reject bodies at transport;
    /// an empty placeholder does not authenticate an unread downstream body.
    ///
    /// ```
    /// use aauth_rust_core::{AgentProviderKeys, VerifiedAgentToken};
    /// use aauth_rust_resource::{AgentIdentityResource, Decision};
    /// use http::Request;
    /// let keys = AgentProviderKeys::from_documents("https://ap.example",
    ///     br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/keys"}"#,
    ///     br#"{"keys":[]}"#)?;
    /// let resource = AgentIdentityResource::new("https://resource.example/", keys, |_: &VerifiedAgentToken, _request: &Request<Vec<u8>>| true)?;
    /// let request = http::Request::builder().uri("https://resource.example/")
    ///     .body(Vec::new())?;
    /// assert!(matches!(resource.authorize(&request, 1000), Decision::AgentTokenRequired));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn authorize(&self, request: &Request<Vec<u8>>, now: i64) -> Decision {
        let authority = match aauth_rust_signature_key::canonical_authority(request.uri()) {
            Ok(authority) => authority,
            Err(error) => return Decision::SignatureFailure(SignatureFailure::Proof(error)),
        };
        if authority != self.authority || request.uri().path() != self.path {
            return Decision::SignatureFailure(SignatureFailure::Proof(Error::TargetMismatch));
        }
        if ["signature-key", "signature-input", "signature"]
            .iter()
            .all(|h| !request.headers().contains_key(*h))
        {
            return Decision::AgentTokenRequired;
        }
        let proof = match PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwt"]) {
            Ok(v) => v,
            Err(Error::InvalidInput) => {
                return Decision::SignatureFailure(SignatureFailure::Input(required_components(
                    request,
                )));
            }
            Err(e) => return Decision::SignatureFailure(SignatureFailure::Proof(e)),
        };
        let KeyMaterial::Jwt(compact) = proof.key() else {
            return Decision::SignatureFailure(SignatureFailure::Proof(Error::UnsupportedScheme));
        };
        let token = match AgentToken::parse(compact).and_then(|t| t.verify(&self.keys, now)) {
            Ok(v) => v,
            Err(e) => return Decision::SignatureFailure(SignatureFailure::Token(e)),
        };
        if token.claims().iat > now.saturating_add(60) {
            return Decision::SignatureFailure(SignatureFailure::Proof(Error::ClockSkew));
        }
        if let Err(e) = proof.verify(&token.claims().cnf.jwk) {
            return Decision::SignatureFailure(SignatureFailure::Proof(e));
        }
        if !(self.policy)(&token, request) {
            return Decision::Forbidden;
        }
        Decision::Granted(Box::new(token))
    }
}
