//! The admitted HTTPS client every fetch and revocation goes through.
use crate::http1::{self, WireError};
use aauth_rust_core::{TokenError, validate_server_identifier};
use aauth_rust_jose::strict_json;
use aauth_rust_signature_key::{
    DiscoveryFetch, EgressLimits, Error as AdmissionError, FetchedHeaders, MAX_DISCOVERY_RESPONSE,
    PinnedFetch, accept_pinned_peer, accept_response, admit_fetch, admit_redirect, admit_target,
    canonical_authority,
};
use http::{HeaderMap, Request, Response};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Timeout [`DiscoveryClient::new`] applies to each fetch, redirects included.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Name resolution for the client. The client admits every address returned.
///
/// The default uses the operating system resolver. A closure
/// `Fn(&str, u16) -> io::Result<Vec<SocketAddr>>` is a resolver, which lets a
/// test or a development setup send a name to a local listener; the
/// addresses it returns still pass admission, so a loopback address also
/// needs [`DiscoveryClientBuilder::allow_restricted_addresses`].
pub trait Resolve: Send + Sync {
    /// Socket addresses for `host` and `port`.
    ///
    /// # Errors
    /// Any I/O error; the fetch then fails as unavailable.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

impl<F> Resolve for F
where
    F: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync,
{
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self(host, port)
    }
}

struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        (host, port).to_socket_addrs().map(Iterator::collect)
    }
}

/// One exchange the client has admitted, handed to a [`Transport`].
#[non_exhaustive]
pub struct Exchange<'a> {
    /// The request. Its URI names the host the server certificate must match.
    pub request: &'a Request<Vec<u8>>,
    /// The admission this exchange runs under: URL, address and body limit.
    pub pin: &'a PinnedFetch,
    /// `pin.address` with the port to connect to.
    pub address: SocketAddr,
    /// The exchange is abandoned at this instant.
    pub deadline: Instant,
}

/// Why a [`Transport`] did not return a response.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// No connection to this address; the client tries the next admitted one.
    Connect(io::Error),
    /// The response body is larger than `pin.max_response_bytes`.
    TooLarge,
    /// The deadline passed.
    Timeout,
    /// TLS, I/O or HTTP failed after connecting.
    Failed(String),
}

/// Sends one admitted HTTPS exchange.
///
/// The built-in transport is rustls with the ring provider over a
/// `std::net::TcpStream`, one HTTP/1.1 request per connection. A host
/// transport replaces it: it must connect only to `exchange.address`,
/// verify the server certificate for the request's host, read at most
/// `exchange.pin.max_response_bytes` of body before `exchange.deadline`,
/// and return redirects as they are rather than following them.
pub trait Transport: Send + Sync {
    /// Send `exchange.request` and return the response.
    ///
    /// # Errors
    /// [`TransportError`].
    fn send(&self, exchange: Exchange<'_>) -> Result<Response<Vec<u8>>, TransportError>;
}

/// The fetch was refused before a connection opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The URL is not `https`.
    NotHttps,
    /// The URL has userinfo, a fragment, or no usable host.
    InvalidUrl,
    /// The host resolved to an address that is not globally routable unicast.
    RestrictedAddress(IpAddr),
    /// A `jwks_uri` on a different host than its metadata document.
    CrossOriginJwks,
    /// A redirect to a different host.
    CrossHostRedirect,
    /// More redirects than `MAX_DISCOVERY_REDIRECTS`.
    TooManyRedirects,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHttps => f.write_str("discovery fetches only https URLs"),
            Self::InvalidUrl => {
                f.write_str("the URL has userinfo, a fragment, or no usable host and port")
            }
            Self::RestrictedAddress(address) => write!(
                f,
                "{address} is not a globally routable unicast address; for loopback or a private \
                 network, build the client with allow_restricted_addresses"
            ),
            Self::CrossOriginJwks => f.write_str(
                "jwks_uri is on another host than its metadata; admit it with \
                 EgressLimits::allow_cross_origin_jwks",
            ),
            Self::CrossHostRedirect => f.write_str("a redirect to another host is not followed"),
            Self::TooManyRedirects => f.write_str("too many redirects"),
        }
    }
}

/// A discovery fetch, metadata check or exchange that did not succeed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// Refused before connecting.
    #[error("refused {url}: {reason}")]
    Refused {
        /// The URL refused.
        url: String,
        /// Which admission rule refused it.
        reason: Refusal,
    },
    /// The response body exceeds the client's limit.
    #[error("{url}: response body is larger than {limit} bytes")]
    TooLarge {
        /// The URL fetched.
        url: String,
        /// The limit, `EgressLimits::max_response_bytes`.
        limit: usize,
    },
    /// Name resolution, connection, TLS, the exchange or the deadline failed.
    #[error("{url} could not be fetched: {detail}")]
    Unavailable {
        /// The URL fetched.
        url: String,
        /// What failed.
        detail: String,
    },
    /// A fetch answered something other than `200`.
    #[error("{url} answered HTTP {status}")]
    Status {
        /// The URL fetched.
        url: String,
        /// The status.
        status: u16,
    },
    /// The document is not the one asked for, or not usable.
    #[error("{url}: {error}")]
    Document {
        /// The document's URL, or the issuer it was asked for.
        url: String,
        /// `issuer_missing`, `issuer_mismatch`, `unknown_key` and the other
        /// document checks.
        error: TokenError,
    },
    /// The host trusts no such issuer and role, so nothing was fetched.
    #[error(
        "{issuer} is not trusted for {dwk}: add it with KeyResolver::trust before discovery fetches it"
    )]
    Untrusted {
        /// The issuer asked for.
        issuer: String,
        /// The role document asked for.
        dwk: String,
    },
    /// The client was built with unusable settings.
    #[error("invalid discovery client configuration: {0}")]
    Configuration(String),
}

impl DiscoveryError {
    /// The token error a verifier reports for this failure.
    ///
    /// Untrusted issuers are `UntrustedIssuer`, document checks keep their own
    /// error, and an issuer whose keys cannot be fetched is `InvalidKey`. All
    /// of them are `401` with a `Signature-Error` at the role.
    pub fn token_error(&self) -> TokenError {
        match self {
            Self::Untrusted { .. } => TokenError::UntrustedIssuer,
            Self::Document { error, .. } => *error,
            _ => TokenError::InvalidKey,
        }
    }
}

/// A `200` answer to [`DiscoveryClient::get`].
#[derive(Clone, Debug)]
pub struct Fetched {
    url: String,
    body: Vec<u8>,
    cache_control: Option<String>,
    age: Option<String>,
    expires: Option<String>,
    date: Option<String>,
}

impl Fetched {
    fn new(url: String, response: Response<Vec<u8>>) -> Self {
        let headers = response.headers();
        let first = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let cache_control = headers
            .get_all("cache-control")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        Self {
            url,
            cache_control: (!cache_control.is_empty()).then(|| cache_control.join(", ")),
            age: first("age"),
            expires: first("expires"),
            date: first("date"),
            body: response.into_body(),
        }
    }
    /// The URL that answered, after any same-host redirect.
    pub fn url(&self) -> &str {
        &self.url
    }
    /// The body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// The body, without copying.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
    /// `Cache-Control`, `Age`, `Expires` and `Date`, for `KeyCache::store_response`.
    pub fn cache_headers(&self) -> FetchedHeaders<'_> {
        FetchedHeaders {
            cache_control: self.cache_control.as_deref(),
            age: self.age.as_deref(),
            expires: self.expires.as_deref(),
            date: self.date.as_deref(),
        }
    }
}

/// A metadata document whose `issuer` is the identifier it was fetched under.
#[derive(Clone, Debug)]
pub struct Metadata {
    issuer: String,
    fetched: Fetched,
    document: Value,
}

impl Metadata {
    /// The verified `issuer`.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// The exact document bytes.
    pub fn bytes(&self) -> &[u8] {
        self.fetched.body()
    }
    /// A top-level member.
    pub fn member(&self, name: &str) -> Option<&Value> {
        self.document.get(name)
    }
    /// A top-level member that is a string.
    pub fn string(&self, name: &str) -> Option<&str> {
        self.member(name).and_then(Value::as_str)
    }
    /// The response it came from.
    pub fn fetched(&self) -> &Fetched {
        &self.fetched
    }
}

/// HTTPS client for metadata, JWKS and server-to-server requests, safe by default.
///
/// Every URL passes the Signature-Key egress admission in
/// `aauth-rust-signature-key` before a connection opens: `https` only;
/// the host is resolved once and every address it resolves to must be
/// globally routable unicast; the connection goes to an admitted address and
/// the peer is checked against it, so a second DNS answer cannot move it. A
/// response body is at most 65536 bytes and each fetch, redirects included,
/// finishes within ten seconds. Redirects are followed only on the same host,
/// at most three. Proxy settings in the environment are not read. TLS is
/// rustls with the ring provider and the platform's root certificates.
///
/// Every call blocks the calling thread until it finishes or times out.
/// Name resolution runs on a short-lived thread so the deadline covers it;
/// a resolver that hangs past the deadline leaves that thread to finish on
/// its own. The client is cheap to clone and safe to share between threads.
///
/// Relaxing a rule is explicit: [`DiscoveryClientBuilder::allow_restricted_addresses`]
/// for loopback in development and tests, [`DiscoveryClientBuilder::limits`]
/// for other limits, [`DiscoveryClientBuilder::resolver`] and
/// [`DiscoveryClientBuilder::transport`] to replace name resolution or the
/// connection itself.
#[derive(Clone)]
pub struct DiscoveryClient {
    inner: Arc<Inner>,
}

struct Inner {
    limits: EgressLimits,
    resolver: Arc<dyn Resolve>,
    transport: Arc<dyn Transport>,
}

impl fmt::Debug for DiscoveryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryClient")
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

/// Settings for a [`DiscoveryClient`]. Start from [`DiscoveryClient::builder`].
pub struct DiscoveryClientBuilder {
    limits: EgressLimits,
    roots: Option<Vec<Vec<u8>>>,
    resolver: Option<Arc<dyn Resolve>>,
    transport: Option<Arc<dyn Transport>>,
}

impl DiscoveryClientBuilder {
    /// Replace the egress limits: size, timeout, and the two explicit relaxations.
    ///
    /// The size must be at most `MAX_DISCOVERY_RESPONSE` and the timeout at
    /// most `MAX_FETCH_TIMEOUT`; [`Self::build`] refuses anything else.
    pub fn limits(mut self, limits: EgressLimits) -> Self {
        self.limits = limits;
        self
    }
    /// Admit addresses that are not globally routable, such as loopback and
    /// private networks. For development and tests; an Internet-facing
    /// verifier keeps them refused.
    pub fn allow_restricted_addresses(mut self) -> Self {
        self.limits.allow_restricted_addresses = true;
        self
    }
    /// Trust only these DER-encoded root certificates, instead of the platform's.
    pub fn root_certificates(mut self, roots: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.roots = Some(roots.into_iter().collect());
        self
    }
    /// Resolve names with `resolver` instead of the operating system.
    pub fn resolver(mut self, resolver: impl Resolve + 'static) -> Self {
        self.resolver = Some(Arc::new(resolver));
        self
    }
    /// Send exchanges with `transport` instead of the built-in rustls one.
    pub fn transport(mut self, transport: impl Transport + 'static) -> Self {
        self.transport = Some(Arc::new(transport));
        self
    }
    /// Build the client.
    ///
    /// # Errors
    /// [`DiscoveryError::Configuration`] for limits outside the profile, no
    /// usable root certificate, or root certificates given with a custom
    /// transport.
    pub fn build(self) -> Result<DiscoveryClient, DiscoveryError> {
        EgressLimits::bounded(self.limits.max_response_bytes, self.limits.timeout).map_err(
            |_| {
                DiscoveryError::Configuration(
                    "limits must be a nonzero size of at most 65536 bytes and a nonzero timeout \
                     of at most 30 seconds"
                        .into(),
                )
            },
        )?;
        let transport: Arc<dyn Transport> = match (self.transport, self.roots) {
            (Some(_), Some(_)) => {
                return Err(DiscoveryError::Configuration(
                    "root certificates configure the built-in transport; a custom transport \
                     verifies certificates itself"
                        .into(),
                ));
            }
            (Some(transport), None) => transport,
            (None, roots) => Arc::new(TlsTransport::new(roots)?),
        };
        Ok(DiscoveryClient {
            inner: Arc::new(Inner {
                limits: self.limits,
                resolver: self.resolver.unwrap_or_else(|| Arc::new(SystemResolver)),
                transport,
            }),
        })
    }
}

impl DiscoveryClient {
    /// The default client: platform root certificates, the system resolver,
    /// 65536 bytes, ten seconds, globally routable addresses only.
    ///
    /// # Errors
    /// [`DiscoveryError::Configuration`] when the platform has no usable
    /// root certificate.
    pub fn new() -> Result<Self, DiscoveryError> {
        Self::builder().build()
    }
    /// Start from the default settings.
    pub fn builder() -> DiscoveryClientBuilder {
        DiscoveryClientBuilder {
            limits: EgressLimits {
                max_response_bytes: MAX_DISCOVERY_RESPONSE,
                timeout: DEFAULT_TIMEOUT,
                allow_restricted_addresses: false,
                allow_cross_origin_jwks: false,
            },
            roots: None,
            resolver: None,
            transport: None,
        }
    }
    /// The limits every exchange runs under.
    pub fn limits(&self) -> &EgressLimits {
        &self.inner.limits
    }

    /// GET an admitted discovery document, following same-host redirects.
    ///
    /// # Errors
    /// [`DiscoveryError::Refused`] before connecting, [`DiscoveryError::Status`]
    /// for any final status but `200`, and the other variants for size,
    /// transport and deadline failures.
    pub fn get(&self, target: DiscoveryFetch<'_>) -> Result<Fetched, DiscoveryError> {
        let deadline = Instant::now() + self.inner.limits.timeout;
        let mut pins = self.admitted(target, deadline)?;
        loop {
            let url = pins[0].0.url.clone();
            let request = Request::get(url.as_str())
                .header("accept", "application/json")
                .body(Vec::new())
                .map_err(|_| refused(&url, Refusal::InvalidUrl))?;
            let (response, pin) = self.exchange(&pins, &request, deadline)?;
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let location = location(&url, response.headers())?;
                let from = pin.clone();
                pins = self.redirected(&from, &location, deadline)?;
                continue;
            }
            if status != 200 {
                return Err(DiscoveryError::Status { url, status });
            }
            return Ok(Fetched::new(url, response));
        }
    }

    /// Fetch `{issuer}/.well-known/{dwk}` and check that its `issuer` is `issuer`.
    ///
    /// This is the Metadata Documents check every role document shares. It
    /// does not decide that `issuer` is trusted.
    ///
    /// # Errors
    /// [`DiscoveryError::Document`] with `invalid_server_identifier` or
    /// `invalid_discovery_document` before fetching, and `issuer_missing`,
    /// `issuer_mismatch` or `invalid_discovery_metadata` for the document;
    /// otherwise as [`Self::get`].
    pub fn fetch_metadata(&self, issuer: &str, dwk: &str) -> Result<Metadata, DiscoveryError> {
        let document_error = |error| DiscoveryError::Document {
            url: format!("{issuer}/.well-known/{dwk}"),
            error,
        };
        validate_server_identifier(issuer).map_err(document_error)?;
        if !document_name(dwk) {
            return Err(document_error(TokenError::InvalidDiscoveryDocument));
        }
        let url = format!("{issuer}/.well-known/{dwk}");
        let fetched = self.get(DiscoveryFetch::Metadata { url: &url })?;
        let document = strict_json(fetched.body())
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| document_error(TokenError::InvalidDiscoveryMetadata))?;
        match document.get("issuer").and_then(Value::as_str) {
            Some(found) if found == issuer => {}
            Some(_) => return Err(document_error(TokenError::IssuerMismatch)),
            None => return Err(document_error(TokenError::IssuerMissing)),
        }
        Ok(Metadata {
            issuer: issuer.to_owned(),
            fetched,
            document,
        })
    }

    /// Send one admitted request, such as a signed POST, and return its answer.
    ///
    /// The URL passes the same admission as a fetch. Redirects are returned,
    /// not followed: a signed request covers its path, and a body is never
    /// sent anywhere it was not admitted for.
    ///
    /// # Errors
    /// As [`Self::get`], except that every status is returned as a response.
    pub fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, DiscoveryError> {
        let deadline = Instant::now() + self.inner.limits.timeout;
        let url = request.uri().to_string();
        let pins = self.admitted(DiscoveryFetch::Endpoint { url: &url }, deadline)?;
        self.exchange(&pins, request, deadline)
            .map(|(response, _)| response)
    }

    /// Admit `target`, resolve its host, and admit every address.
    fn admitted(
        &self,
        target: DiscoveryFetch<'_>,
        deadline: Instant,
    ) -> Result<Vec<(PinnedFetch, SocketAddr)>, DiscoveryError> {
        let limits = &self.inner.limits;
        let url = admit_target(limits, target).map_err(|_| self.refused_target(target))?;
        let (host, port) = host_port(&url)?;
        self.addresses(&url, &host, port, deadline)?
            .into_iter()
            .map(|address| {
                admit_fetch(limits, target, address.ip())
                    .map(|pin| (pin, address))
                    .map_err(|_| refused(&url, Refusal::RestrictedAddress(address.ip())))
            })
            .collect()
    }

    /// Admit a redirect from `from` to `location`, then its addresses.
    fn redirected(
        &self,
        from: &PinnedFetch,
        location: &str,
        deadline: Instant,
    ) -> Result<Vec<(PinnedFetch, SocketAddr)>, DiscoveryError> {
        // The pinned address was admitted already, so this asks only about
        // the redirect count and the URL.
        if let Err(error) = admit_redirect(from, location, from.address) {
            let reason = match error {
                AdmissionError::InvalidInput => Refusal::TooManyRedirects,
                _ if !is_https(location) => Refusal::NotHttps,
                _ => match (host_port(location), host_port(&from.url)) {
                    (Ok((to, _)), Ok((at, _))) if to != at => Refusal::CrossHostRedirect,
                    _ => Refusal::InvalidUrl,
                },
            };
            return Err(refused(location, reason));
        }
        let (host, port) = host_port(location)?;
        self.addresses(location, &host, port, deadline)?
            .into_iter()
            .map(|address| {
                admit_redirect(from, location, address.ip())
                    .map(|pin| (pin, address))
                    .map_err(|_| refused(location, Refusal::RestrictedAddress(address.ip())))
            })
            .collect()
    }

    fn refused_target(&self, target: DiscoveryFetch<'_>) -> DiscoveryError {
        let url = match target {
            DiscoveryFetch::Metadata { url }
            | DiscoveryFetch::Jwks { url }
            | DiscoveryFetch::Endpoint { url } => url,
            DiscoveryFetch::JwksFromMetadata { jwks_url, .. } => jwks_url,
        };
        let cross_origin_allowed = EgressLimits {
            allow_cross_origin_jwks: true,
            ..self.inner.limits.clone()
        };
        let reason = if !is_https(url) {
            Refusal::NotHttps
        } else if matches!(target, DiscoveryFetch::JwksFromMetadata { .. })
            && admit_target(&cross_origin_allowed, target).is_ok()
        {
            Refusal::CrossOriginJwks
        } else {
            Refusal::InvalidUrl
        };
        refused(url, reason)
    }

    fn addresses(
        &self,
        url: &str,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, DiscoveryError> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, port)]);
        }
        let resolver = self.inner.resolver.clone();
        let name = host.to_owned();
        let (answer, answered) = mpsc::channel();
        thread::Builder::new()
            .name("aauth-discovery-dns".into())
            .spawn(move || {
                let _ = answer.send(resolver.resolve(&name, port));
            })
            .map_err(|error| {
                unavailable(url, format!("could not start name resolution: {error}"))
            })?;
        let left = remaining(deadline).ok_or_else(|| timed_out(url))?;
        let mut addresses = match answered.recv_timeout(left) {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(error)) => {
                return Err(unavailable(
                    url,
                    format!("could not resolve {host}: {error}"),
                ));
            }
            Err(_) => return Err(timed_out(url)),
        };
        let mut seen = Vec::with_capacity(addresses.len());
        addresses.retain(|address| {
            let new = !seen.contains(address);
            seen.push(*address);
            new
        });
        if addresses.is_empty() {
            return Err(unavailable(url, format!("{host} has no address")));
        }
        Ok(addresses)
    }

    /// Try each admitted address in turn until one connects.
    fn exchange<'p>(
        &self,
        pins: &'p [(PinnedFetch, SocketAddr)],
        request: &Request<Vec<u8>>,
        deadline: Instant,
    ) -> Result<(Response<Vec<u8>>, &'p PinnedFetch), DiscoveryError> {
        let url = request.uri().to_string();
        let mut failures = Vec::new();
        for (pin, address) in pins {
            let exchange = Exchange {
                request,
                pin,
                address: *address,
                deadline,
            };
            match self.inner.transport.send(exchange) {
                Ok(response) => {
                    accept_response(pin, response.body().len()).map_err(|_| {
                        DiscoveryError::TooLarge {
                            url: url.clone(),
                            limit: pin.max_response_bytes,
                        }
                    })?;
                    return Ok((response, pin));
                }
                Err(TransportError::Connect(error)) => failures.push(format!("{address}: {error}")),
                Err(TransportError::TooLarge) => {
                    return Err(DiscoveryError::TooLarge {
                        url,
                        limit: pin.max_response_bytes,
                    });
                }
                Err(TransportError::Timeout) => return Err(timed_out(&url)),
                Err(TransportError::Failed(detail)) => return Err(unavailable(&url, detail)),
            }
        }
        Err(unavailable(
            &url,
            format!("could not connect ({})", failures.join("; ")),
        ))
    }
}

/// rustls over `std::net`, one HTTP/1.1 request per connection.
struct TlsTransport {
    config: Arc<ClientConfig>,
}

impl TlsTransport {
    fn new(roots: Option<Vec<Vec<u8>>>) -> Result<Self, DiscoveryError> {
        let mut store = RootCertStore::empty();
        match roots {
            Some(roots) => {
                for der in roots {
                    store.add(CertificateDer::from(der)).map_err(|error| {
                        DiscoveryError::Configuration(format!(
                            "a root certificate is not usable: {error}"
                        ))
                    })?;
                }
            }
            None => {
                let found = rustls_native_certs::load_native_certs();
                let (_added, _unusable) = store.add_parsable_certificates(found.certs);
            }
        }
        if store.is_empty() {
            return Err(DiscoveryError::Configuration(
                "no root certificate: install the platform's CA certificates, or pass \
                 root_certificates"
                    .into(),
            ));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| DiscoveryError::Configuration(error.to_string()))?
            .with_root_certificates(store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

impl Transport for TlsTransport {
    fn send(&self, exchange: Exchange<'_>) -> Result<Response<Vec<u8>>, TransportError> {
        let left = remaining(exchange.deadline).ok_or(TransportError::Timeout)?;
        let tcp =
            TcpStream::connect_timeout(&exchange.address, left).map_err(TransportError::Connect)?;
        let peer = tcp.peer_addr().map_err(TransportError::Connect)?;
        accept_pinned_peer(exchange.pin, peer.ip()).map_err(|_| {
            TransportError::Failed(format!(
                "connected to {peer}, not the admitted {}",
                exchange.address
            ))
        })?;
        let _ = tcp.set_nodelay(true);
        let uri = exchange.request.uri();
        let host = canonical_authority(uri)
            .map_err(|_| TransportError::Failed("request URI has no usable authority".into()))?;
        let name = uri
            .host()
            .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
            .ok_or_else(|| TransportError::Failed("request URI has no host".into()))?;
        let name = ServerName::try_from(name.to_ascii_lowercase())
            .map_err(|_| TransportError::Failed(format!("{name} is not a TLS server name")))?;
        let connection = ClientConnection::new(self.config.clone(), name)
            .map_err(|error| TransportError::Failed(format!("TLS: {error}")))?;
        let mut stream = Timed {
            stream: StreamOwned::new(connection, tcp),
            deadline: exchange.deadline,
        };
        let wire = |error: WireError| match error {
            WireError::TooLarge => TransportError::TooLarge,
            WireError::Timeout => TransportError::Timeout,
            WireError::Io(error) => TransportError::Failed(error.to_string()),
            WireError::Malformed(detail) => TransportError::Failed(detail.into()),
        };
        http1::write_request(&mut stream, exchange.request, &host).map_err(wire)?;
        http1::read_response(&mut stream, exchange.pin.max_response_bytes).map_err(wire)
    }
}

/// A TLS stream whose socket timeouts track one deadline.
struct Timed {
    stream: StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
}

impl Timed {
    fn arm(&mut self) -> io::Result<()> {
        let left = remaining(self.deadline).ok_or(io::ErrorKind::TimedOut)?;
        self.stream.sock.set_read_timeout(Some(left))?;
        self.stream.sock.set_write_timeout(Some(left))
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.stream.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.arm()?;
        self.stream.flush()
    }
}

/// The `Location` of a redirect, made absolute against `current`.
fn location(current: &str, headers: &HeaderMap) -> Result<String, DiscoveryError> {
    let values: Vec<_> = headers.get_all("location").iter().collect();
    let [value] = values.as_slice() else {
        return Err(unavailable(current, "redirect without one Location".into()));
    };
    let value = value
        .to_str()
        .map_err(|_| unavailable(current, "unreadable redirect Location".into()))?;
    if value.contains("://") {
        return Ok(value.to_owned());
    }
    if let Some(rest) = value.strip_prefix("//") {
        return Ok(format!("https://{rest}"));
    }
    if value.starts_with('/') {
        let uri: http::Uri = current
            .parse()
            .map_err(|_| refused(current, Refusal::InvalidUrl))?;
        let authority = uri
            .authority()
            .ok_or_else(|| refused(current, Refusal::InvalidUrl))?;
        return Ok(format!("https://{authority}{value}"));
    }
    Err(refused(value, Refusal::InvalidUrl))
}

/// Lowercase host without IPv6 brackets, and the port (443 by default).
fn host_port(url: &str) -> Result<(String, u16), DiscoveryError> {
    let uri: http::Uri = url.parse().map_err(|_| refused(url, Refusal::InvalidUrl))?;
    let authority = uri
        .authority()
        .ok_or_else(|| refused(url, Refusal::InvalidUrl))?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    Ok((host, authority.port_u16().unwrap_or(443)))
}

/// The Signature-Key `dwk` grammar: one safe path segment under `/.well-known/`.
pub(crate) fn document_name(dwk: &str) -> bool {
    !dwk.is_empty()
        && dwk != "."
        && dwk != ".."
        && dwk
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn is_https(url: &str) -> bool {
    url.get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
}

fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

fn refused(url: &str, reason: Refusal) -> DiscoveryError {
    DiscoveryError::Refused {
        url: url.to_owned(),
        reason,
    }
}

fn unavailable(url: &str, detail: String) -> DiscoveryError {
    DiscoveryError::Unavailable {
        url: url.to_owned(),
        detail,
    }
}

fn timed_out(url: &str) -> DiscoveryError {
    unavailable(url, "no answer before the deadline".into())
}
