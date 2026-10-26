//! One bounded, role-authenticated R3 artifact GET.
//!
//! The host supplies trusted HTTPS transport and egress policy. Unlike the
//! buffered role transports, this boundary reads incrementally and retains at
//! most `maximum_document_bytes + 1` response bytes. A blocking I/O deadline
//! cannot be enforced by checks after the call: the injected admission,
//! transport and body MUST honor the supplied absolute monotonic deadline.
//! No token verification, entitlement decision, account binding, caching,
//! retries, audit storage, or role endpoint wiring is performed here.
use crate::{Document, Error, Proposal, Reference, ReferencedArtifact, Registry};
use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use std::{
    fmt, io,
    time::{Duration, Instant},
};

/// Default maximum artifact size: one MiB, matching the Go fetcher.
pub const DEFAULT_MAXIMUM_DOCUMENT_BYTES: usize = 1 << 20;
/// Default total fetch budget, including admission and the response body.
pub const DEFAULT_ARTIFACT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Caller-selected limits for one fetch.
#[derive(Clone, Copy, Debug)]
pub struct FetchLimits {
    /// Maximum retained artifact bytes; one additional byte detects overflow.
    pub maximum_document_bytes: usize,
    /// Total monotonic budget. Every injected operation receives the same deadline.
    pub timeout: Duration,
}
impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            maximum_document_bytes: DEFAULT_MAXIMUM_DOCUMENT_BYTES,
            timeout: DEFAULT_ARTIFACT_FETCH_TIMEOUT,
        }
    }
}

/// Identity used in the signed `jwks_uri` Signature-Key member.
#[derive(Clone, Debug)]
pub struct FetchIdentity {
    /// Trusted Person Server or Access Server identifier.
    pub issuer: String,
    /// Exactly `aauth-person.json` or `aauth-access.json`.
    pub discovery_document: String,
    /// Published signing-key identifier.
    pub key_id: String,
}

/// Explicit host admission, called before transport or signing.
///
/// Implementations must enforce the deadline while resolving/admitting the
/// HTTPS target and bind the transport to approved addresses. An `Ok` is the
/// host's egress decision, not proof that a token entitled this issuer to fetch.
pub trait FetchEgress: Send + Sync {
    /// Admit this exact URI or fail before network transport is invoked.
    ///
    /// # Errors
    /// Returns host refusal, resolution, or timeout errors.
    fn admit(&self, uri: &str, deadline: Instant) -> io::Result<()>;
}
impl<F> FetchEgress for F
where
    F: Fn(&str, Instant) -> io::Result<()> + Send + Sync,
{
    fn admit(&self, uri: &str, deadline: Instant) -> io::Result<()> {
        self(uri, deadline)
    }
}

/// Incremental, deadline-aware response body from a trusted transport.
/// Dropping it must close/cancel this response without another request.
pub trait FetchBody {
    /// Read at most `output.len()` bytes; zero means EOF.
    /// Implementations must bound their own buffering and interrupt blocking
    /// reads at `deadline`, including while waiting for the first byte.
    ///
    /// # Errors
    /// Returns transport/read failure, with `TimedOut` for an elapsed deadline.
    fn read(&mut self, output: &mut [u8], deadline: Instant) -> io::Result<usize>;
}
/// Status and unchanged response headers with an incremental body.
pub type FetchResponse = Response<Box<dyn FetchBody>>;

/// Host-owned HTTPS transport, analogous to the existing Federation adapter.
///
/// Send exactly one request to the admitted peer over certificate-verified
/// HTTPS. Preserve the URI, signed fields and body. Do not retry, follow
/// redirects, add cookies/authentication, use a cookie jar, decode content
/// coding, or silently rewrite response headers. Enforce `deadline` across
/// connection, TLS, response headers and body; bound headers independently.
/// Return the first response, including redirects, with its original headers.
/// The library cannot enforce these obligations inside a hostile adapter.
pub trait FetchTransport: Send + Sync {
    /// Send the finalized signed GET once, after egress admission.
    ///
    /// # Errors
    /// Returns network, TLS, or timeout failure.
    fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> io::Result<FetchResponse>;
}

/// Dependencies for one PS/AS fetch identity. All callbacks are mandatory.
pub struct FetchConfig<'a> {
    /// Immutable allowlist of vocabulary registrations.
    pub registry: &'a Registry,
    /// Key published under this identity's `key_id`.
    pub signing_key: &'a SigningKey,
    /// Configured PS/AS identity, never inferred from a received URI.
    pub identity: FetchIdentity,
    /// Current trusted Unix seconds, invoked separately for every request.
    pub clock: &'a (dyn Fn() -> i64 + Send + Sync),
    /// Explicit egress admission before transport.
    pub admit: &'a dyn FetchEgress,
    /// Trusted deadline-aware HTTPS adapter.
    pub transport: &'a dyn FetchTransport,
    /// Positive size and timeout limits; use `Default` for Go defaults.
    pub limits: FetchLimits,
}

/// Error classification needed by callers deciding whether an artifact is invalid.
#[derive(Debug)]
pub enum FetchError {
    /// Invalid local fetch configuration.
    Configuration(String),
    /// Admission, network, deadline, service status, or incremental read failure.
    Transport(io::Error),
    /// Request could not be signed under the configured identity/current clock.
    Signing(aauth_rust_signature_key::Error),
    /// Invalid reference, response metadata, size, exact digest, or artifact shape.
    Document(Error),
}
impl FetchError {
    /// Whether the fetched response/reference cannot name the expected artifact.
    pub fn is_document_error(&self) -> bool {
        matches!(self, Self::Document(_))
    }
}
impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(e) => write!(f, "r3fetch: configuration: {e}"),
            Self::Transport(e) => write!(f, "r3fetch: transport: {e}"),
            Self::Signing(e) => write!(f, "r3fetch: signing: {e}"),
            Self::Document(e) => write!(f, "r3fetch: document: {e}"),
        }
    }
}
impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(_) => None,
            Self::Transport(e) => Some(e),
            Self::Signing(e) => Some(e),
            Self::Document(e) => Some(e),
        }
    }
}

/// One configured role-authenticated artifact fetcher. It performs no retries.
pub struct FetchClient<'a> {
    config: FetchConfig<'a>,
}
impl<'a> FetchClient<'a> {
    /// Validate registry, signing identity and limits before use.
    ///
    /// # Errors
    /// Rejects empty registry/key id, non-PS/AS discovery role, malformed issuer,
    /// zero limits, and an overflowing byte bound or monotonic timeout.
    pub fn new(config: FetchConfig<'a>) -> Result<Self, FetchError> {
        let invalid = |s: &str| FetchError::Configuration(s.into());
        if config.registry.is_empty() {
            return Err(invalid("vocabulary registry is required"));
        }
        aauth_rust_core::validate_server_identifier(&config.identity.issuer)
            .map_err(|e| invalid(&e.to_string()))?;
        config
            .signing_key
            .public_jwk()
            .validate()
            .map_err(|e| invalid(&e.to_string()))?;
        if !matches!(
            config.identity.discovery_document.as_str(),
            "aauth-person.json" | "aauth-access.json"
        ) {
            return Err(invalid(
                "Person or Access Server discovery role is required",
            ));
        }
        if config.identity.key_id.is_empty() {
            return Err(invalid("key id is required"));
        }
        if config.limits.maximum_document_bytes == 0
            || config
                .limits
                .maximum_document_bytes
                .checked_add(1)
                .is_none()
        {
            return Err(invalid(
                "positive, nonoverflowing document byte limit is required",
            ));
        }
        if config.limits.timeout.is_zero()
            || Instant::now().checked_add(config.limits.timeout).is_none()
        {
            return Err(invalid("positive, representable timeout is required"));
        }
        Ok(Self { config })
    }
    /// Fetch one exact class document and retain its original bytes.
    ///
    /// # Errors
    /// Returns typed transport/signing failures or an invalid document error.
    pub fn fetch_document(&self, reference: &Reference) -> Result<(Document, Vec<u8>), FetchError> {
        let exact = self.fetch_exact(reference)?;
        let document = self
            .config
            .registry
            .parse_referenced_document(reference, &exact)
            .map_err(FetchError::Document)?;
        Ok((document, exact))
    }
    /// Fetch one exact proposal; a class document never satisfies this method.
    ///
    /// # Errors
    /// Returns typed transport/signing failures or an invalid proposal error.
    pub fn fetch_proposal(&self, reference: &Reference) -> Result<(Proposal, Vec<u8>), FetchError> {
        let exact = self.fetch_exact(reference)?;
        let proposal = self
            .config
            .registry
            .parse_referenced_proposal(reference, &exact)
            .map_err(FetchError::Document)?;
        Ok((proposal, exact))
    }
    /// Fetch once and classify exact bytes as a class document or proposal.
    ///
    /// # Errors
    /// Returns typed transport/signing failures or an invalid artifact error.
    pub fn fetch_artifact(&self, reference: &Reference) -> Result<ReferencedArtifact, FetchError> {
        let exact = self.fetch_exact(reference)?;
        self.config
            .registry
            .parse_referenced_artifact(reference, &exact)
            .map_err(FetchError::Document)
    }
    fn fetch_exact(&self, reference: &Reference) -> Result<Vec<u8>, FetchError> {
        reference.validate().map_err(FetchError::Document)?;
        let c = &self.config;
        let deadline = Instant::now()
            .checked_add(c.limits.timeout)
            .ok_or_else(|| FetchError::Configuration("timeout overflow".into()))?;
        c.admit
            .admit(reference.uri(), deadline)
            .map_err(FetchError::Transport)?;
        check_deadline(deadline)?;
        let mut request = Request::builder()
            .method("GET")
            .uri(reference.uri())
            .header("accept", "application/json")
            .header("accept-encoding", "identity")
            .body(Vec::new())
            .map_err(|e| FetchError::Configuration(e.to_string()))?;
        sign_request(
            &mut request,
            c.signing_key,
            KeyMaterial::JwksUri {
                id: c.identity.issuer.clone(),
                dwk: c.identity.discovery_document.clone(),
                kid: c.identity.key_id.clone(),
            },
            (c.clock)(),
        )
        .map_err(FetchError::Signing)?;
        check_deadline(deadline)?;
        let mut response = c
            .transport
            .send(request, deadline)
            .map_err(FetchError::Transport)?;
        check_deadline(deadline)?;
        let status = response.status().as_u16();
        if status != 200 {
            let message = format!("response status is {status}");
            return Err(
                if (200..400).contains(&status) || status == 404 || status == 410 {
                    document_error(&message)
                } else {
                    FetchError::Transport(io::Error::other(message))
                },
            );
        }
        let types: Vec<_> = response.headers().get_all("content-type").iter().collect();
        if types.len() != 1 {
            return Err(document_error("exactly one Content-Type is required"));
        }
        let media = types[0]
            .to_str()
            .ok()
            .and_then(|v| v.parse::<mime::Mime>().ok());
        if !media.is_some_and(|v| v.type_() == mime::APPLICATION && v.subtype() == mime::JSON) {
            return Err(document_error("Content-Type must be application/json"));
        }
        let codings: Vec<_> = response
            .headers()
            .get_all("content-encoding")
            .iter()
            .collect();
        if codings.len() > 1 {
            return Err(document_error("ambiguous Content-Encoding"));
        }
        if let Some(coding) = codings.first() {
            let coding = coding
                .to_str()
                .map_err(|_| document_error("invalid Content-Encoding"))?
                .trim();
            if !coding.is_empty() && !coding.eq_ignore_ascii_case("identity") {
                return Err(document_error("content coding is not identity"));
            }
        }
        let maximum = c.limits.maximum_document_bytes;
        let mut exact = Vec::with_capacity(maximum.min(8192));
        let mut buffer = [0u8; 8192];
        loop {
            check_deadline(deadline)?;
            let allowed = buffer.len().min(maximum + 1 - exact.len());
            let count = response
                .body_mut()
                .read(&mut buffer[..allowed], deadline)
                .map_err(FetchError::Transport)?;
            check_deadline(deadline)?;
            if count > allowed {
                return Err(FetchError::Transport(io::Error::other(
                    "body violated read bound",
                )));
            }
            if count == 0 {
                break;
            }
            exact.extend_from_slice(&buffer[..count]);
            if exact.len() > maximum {
                return Err(document_error("document exceeds configured byte limit"));
            }
        }
        Ok(exact)
    }
}
fn document_error(message: &str) -> FetchError {
    FetchError::Document(Error::new(format!("r3fetch: {message}")))
}
fn check_deadline(deadline: Instant) -> Result<(), FetchError> {
    if Instant::now() >= deadline {
        Err(FetchError::Transport(io::Error::new(
            io::ErrorKind::TimedOut,
            "artifact fetch deadline elapsed",
        )))
    } else {
        Ok(())
    }
}
