//! Admission for a discovery fetch the host is about to make.
//!
//! This module does not open a connection. It checks the URL, the resolved
//! address, redirect targets, and the response size, and it pins the address
//! the host must connect to. Only a globally routable unicast address is
//! admitted. IPv4 embedded in a mapped, compatible, well-known NAT64
//! (`64:ff9b::/96`), 6to4, or Teredo form is classified as that IPv4 address.
//! The local-use NAT64 prefix `64:ff9b:1::/48` is refused as a whole. A parsed
//! `jwks_uri` origin is a name, not an authorization decision.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::Error;

/// Largest discovery response this profile will accept.
pub const MAX_DISCOVERY_RESPONSE: usize = 65_536;
/// Longest fetch timeout this profile will accept.
pub const MAX_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Most redirects one discovery fetch may follow.
pub const MAX_DISCOVERY_REDIRECTS: u8 = 3;

/// Limits the host must apply to one outbound discovery fetch.
#[derive(Clone, Debug)]
pub struct EgressLimits {
    /// Response bodies larger than this are refused. At most [`MAX_DISCOVERY_RESPONSE`].
    pub max_response_bytes: usize,
    /// Finite timeout the host applies to the connection. At most [`MAX_FETCH_TIMEOUT`].
    pub timeout: Duration,
    /// When set, addresses that are not globally routable unicast may be fetched.
    pub allow_restricted_addresses: bool,
    /// When set, a `jwks_uri` whose host differs from the metadata host may be fetched.
    pub allow_cross_origin_jwks: bool,
}

/// A fetch the host may perform, bound to one resolved address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedFetch {
    /// URL that was admitted.
    pub url: String,
    /// Address the host must connect to. A different peer is a failed pin.
    pub address: IpAddr,
    /// Maximum response body, in bytes.
    pub max_response_bytes: usize,
    /// Timeout the host applies.
    pub timeout: Duration,
    allow_restricted_addresses: bool,
    /// Redirects already followed. The next one is refused at [`MAX_DISCOVERY_REDIRECTS`].
    redirects: u8,
}

/// Which discovery document the host is about to fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryFetch<'a> {
    /// Issuer metadata, such as `{iss}/.well-known/{dwk}`.
    Metadata {
        /// Absolute HTTPS URL.
        url: &'a str,
    },
    /// JWKS named by a metadata document.
    JwksFromMetadata {
        /// Metadata URL whose host is the origin of the document.
        metadata_url: &'a str,
        /// JWKS URL taken from that document.
        jwks_url: &'a str,
    },
    /// Direct `jwks` URL. The presenter chose it.
    Jwks {
        /// Absolute HTTPS URL.
        url: &'a str,
    },
    /// An endpoint a metadata document names, such as `revocation_endpoint`,
    /// or a pending URL that endpoint answered with.
    Endpoint {
        /// Absolute HTTPS URL.
        url: &'a str,
    },
}

/// A `jwks_uri` `id`. Parsing it does not mean the origin authorized the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginPseudonym {
    id: String,
}

impl OriginPseudonym {
    /// The `id` bytes as presented.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl EgressLimits {
    /// Limits with restricted addresses and cross-origin JWKS refused.
    ///
    /// # Errors
    /// `invalid_input` when the size is zero or above [`MAX_DISCOVERY_RESPONSE`],
    /// or the timeout is zero or above [`MAX_FETCH_TIMEOUT`].
    pub fn bounded(max_response_bytes: usize, timeout: Duration) -> Result<Self, Error> {
        bounded_budget(max_response_bytes, timeout)?;
        Ok(Self {
            max_response_bytes,
            timeout,
            allow_restricted_addresses: false,
            allow_cross_origin_jwks: false,
        })
    }
}

/// Admit one fetch to `address`.
///
/// The returned pin is the only address the host may connect to for this URL.
///
/// # Errors
/// `invalid_key` for a non-HTTPS URL, an address that is not globally routable
/// unicast, or a cross-origin JWKS URL the limits do not allow. `invalid_input`
/// when the size or timeout is zero or above the profile cap, including when a
/// struct literal bypasses [`EgressLimits::bounded`].
pub fn admit_fetch(
    limits: &EgressLimits,
    target: DiscoveryFetch<'_>,
    address: IpAddr,
) -> Result<PinnedFetch, Error> {
    let url = admit_target(limits, target)?;
    if restricted(address) && !limits.allow_restricted_addresses {
        return Err(Error::InvalidKey);
    }
    Ok(PinnedFetch {
        url,
        address,
        max_response_bytes: limits.max_response_bytes,
        timeout: limits.timeout,
        allow_restricted_addresses: limits.allow_restricted_addresses,
        redirects: 0,
    })
}

/// Check the URL rules of [`admit_fetch`] before resolving its host.
///
/// Returns the URL to resolve. Each resolved address still goes through
/// [`admit_fetch`], which repeats this check.
///
/// # Errors
/// As for [`admit_fetch`], without the address check.
pub fn admit_target(limits: &EgressLimits, target: DiscoveryFetch<'_>) -> Result<String, Error> {
    bounded_budget(limits.max_response_bytes, limits.timeout)?;
    let url = match target {
        DiscoveryFetch::Metadata { url }
        | DiscoveryFetch::Jwks { url }
        | DiscoveryFetch::Endpoint { url } => url.to_owned(),
        DiscoveryFetch::JwksFromMetadata {
            metadata_url,
            jwks_url,
        } => {
            let metadata_host = https_host(metadata_url)?;
            let jwks_host = https_host(jwks_url)?;
            if metadata_host != jwks_host && !limits.allow_cross_origin_jwks {
                return Err(Error::InvalidKey);
            }
            jwks_url.to_owned()
        }
    };
    https_host(&url)?;
    Ok(url)
}

/// Admit a redirect that stays on the pinned host and pins `address`.
///
/// A different host is refused even when cross-origin JWKS is allowed. A
/// different port on the same host is the same host. At most
/// [`MAX_DISCOVERY_REDIRECTS`] redirects are admitted.
///
/// # Errors
/// `invalid_key` when `location` is not HTTPS, names another host, or resolves
/// to a restricted address the original pin did not allow. `invalid_input`
/// when this pin has already followed [`MAX_DISCOVERY_REDIRECTS`] redirects.
pub fn admit_redirect(
    pinned: &PinnedFetch,
    location: &str,
    address: IpAddr,
) -> Result<PinnedFetch, Error> {
    bounded_budget(pinned.max_response_bytes, pinned.timeout)?;
    if pinned.redirects >= MAX_DISCOVERY_REDIRECTS {
        return Err(Error::InvalidInput);
    }
    if https_host(&pinned.url)? != https_host(location)? {
        return Err(Error::InvalidKey);
    }
    if restricted(address) && !pinned.allow_restricted_addresses {
        return Err(Error::InvalidKey);
    }
    Ok(PinnedFetch {
        url: location.to_owned(),
        address,
        max_response_bytes: pinned.max_response_bytes,
        timeout: pinned.timeout,
        allow_restricted_addresses: pinned.allow_restricted_addresses,
        redirects: pinned.redirects + 1,
    })
}

/// Require the connected peer to be the pinned address.
///
/// # Errors
/// `invalid_key` when `connected` differs from the pin.
pub fn accept_pinned_peer(pinned: &PinnedFetch, connected: IpAddr) -> Result<(), Error> {
    if connected != pinned.address {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// Require the response body to fit the admitted size.
///
/// # Errors
/// `invalid_input` when `body_len` is greater than the pin's limit.
pub fn accept_response(pinned: &PinnedFetch, body_len: usize) -> Result<(), Error> {
    bounded_budget(pinned.max_response_bytes, pinned.timeout)?;
    if body_len > pinned.max_response_bytes {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Name carried by a well-formed `id`. An empty allowlist does not authorize it.
///
/// # Errors
/// `invalid_key` when `id` is not an HTTPS origin without a path, query, or fragment.
pub fn origin_pseudonym(id: &str) -> Result<OriginPseudonym, Error> {
    let uri: http::Uri = id.parse().map_err(|_| Error::InvalidKey)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidKey)?;
    let authority = uri.authority().ok_or(Error::InvalidKey)?;
    if uri.query().is_some() || id.contains('#') || id != format!("https://{authority}") {
        return Err(Error::InvalidKey);
    }
    Ok(OriginPseudonym { id: id.to_owned() })
}

/// Byte-exact membership of `origin` in a host-supplied allowlist.
pub fn origin_is_allowed(origin: &OriginPseudonym, allowed: &[&str]) -> bool {
    allowed.iter().any(|item| *item == origin.id())
}

fn https_host(url: &str) -> Result<String, Error> {
    if url.contains('#') || url.contains('@') || url.contains(' ') {
        return Err(Error::InvalidKey);
    }
    let uri: http::Uri = url.parse().map_err(|_| Error::InvalidKey)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidKey)?;
    Ok(uri.host().ok_or(Error::InvalidKey)?.to_ascii_lowercase())
}

fn bounded_budget(max_response_bytes: usize, timeout: Duration) -> Result<(), Error> {
    if max_response_bytes == 0 || max_response_bytes > MAX_DISCOVERY_RESPONSE {
        return Err(Error::InvalidInput);
    }
    if timeout.is_zero() || timeout > MAX_FETCH_TIMEOUT {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn restricted(address: IpAddr) -> bool {
    !globally_routable(address)
}

fn globally_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => routable_v4(ip),
        IpAddr::V6(ip) => {
            if local_nat64(ip) {
                return false;
            }
            embedded_v4(ip)
                .map(routable_v4)
                .unwrap_or_else(|| routable_v6(ip))
        }
    }
}

fn local_nat64(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]
}

fn routable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if a == 0 || a == 10 || a == 127 || a >= 224 {
        return false;
    }
    if a == 100 && (b & 0xc0) == 0x40 {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    if a == 192 && b == 0 && (c == 0 || c == 2) {
        return false;
    }
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    true
}

fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return Some(mapped);
    }
    let o = ip.octets();
    if o[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if o[0] == 0x20 && o[1] == 0x02 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    if o[0] == 0x20 && o[1] == 0x01 && o[2] == 0 && o[3] == 0 {
        return Some(Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]));
    }
    if o[..12] == [0; 12] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

fn routable_v6(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    if o[0] == 0xff || (o[0] & 0xfe) == 0xfc {
        return false;
    }
    if o[0] == 0xfe && ((o[1] & 0xc0) == 0x80 || (o[1] & 0xc0) == 0xc0) {
        return false;
    }
    if o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8 {
        return false;
    }
    (o[0] & 0xe0) == 0x20
}
