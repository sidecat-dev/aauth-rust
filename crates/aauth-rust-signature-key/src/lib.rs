//! Buffered RFC 9421 request proofs with `hwk`, `jwt`, `jkt-jwt`, `self-jwt`, direct `jwks`, `x509`, `cached`, and explicit `jwks_uri` schemes,
//! and response signatures that name their signer in a `Signature-Key` response field.
//! Verification proves a key; the accepting role supplies identity and policy.
#![deny(missing_docs)]
mod cache;
mod client;
mod content_digest;
mod egress;
mod jkt;
mod jwks;
mod jwt_discovery;
mod key_cache;
mod response;
mod self_jwt;
mod server_keys;
mod x509;
pub use cache::{
    AssertionCache, CacheGrant, CacheRequest, CachedAssertion, MAX_CACHEABLE_LIFETIME,
    present_issued_cid, select_presented_scheme,
};
pub use client::{choose_presented_scheme, recognized_tokens, signature_error_code};
pub use egress::{
    DiscoveryFetch, EgressLimits, MAX_DISCOVERY_REDIRECTS, MAX_DISCOVERY_RESPONSE,
    MAX_FETCH_TIMEOUT, OriginPseudonym, PinnedFetch, accept_pinned_peer, accept_response,
    admit_fetch, admit_redirect, admit_target, origin_is_allowed, origin_pseudonym,
};
pub use jkt::JktDelegation;
pub use jwks::{JwksIdentity, JwksResolver};
pub use jwt_discovery::{DiscoveredJwt, verify_application_jwt, verify_discovered_jwt};
pub use key_cache::{
    CachedDocument, DEFAULT_KEY_TTL, FetchedHeaders, KeyCache, KeyCacheAnswer, KeyCacheStore,
    MIN_REFETCH_INTERVAL,
};
pub use response::{PreparedResponse, accept_signature_components, sign_response};
pub use self_jwt::{IssuerKeyResolver, SelfJwtAssertion};
pub use server_keys::ServerKeyBinding;
pub use x509::X509Identity;

use aauth_rust_jose::{Jwk, SigningKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::Request;
use sfv::{BareItem, Dictionary, FieldType, InnerList, List, ListEntry, Parameters, Parser};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
/// Proof failure with an actionable local explanation and stable protocol code.
pub enum Error {
    #[error(
        "invalid request signature: check selected labels, Signature-Input syntax, created time in Unix seconds, covered values and signing key"
    )]
    /// Malformed framing, stale proof, unsupported component or failed signature.
    InvalidSignature,
    #[error(
        "signature coverage is incomplete: include method, authority, path, Signature-Key, query/Authorization when present, Content-Digest plus Content-Type when content requires them, and every field the server lists; a listed field must be a lowercase name present on the request"
    )]
    /// The selected signature omits required covered components, or a listed
    /// additional component cannot be covered.
    InvalidInput,
    #[error(
        "created is too far in the future: synchronize the clock and use Unix seconds rather than milliseconds"
    )]
    /// Signature creation is too far ahead of the verifier clock.
    ClockSkew,
    #[error(
        "invalid Signature-Key: check the selected scheme's parameter types, a public-only key whose kty and crv match its alg, and that the signer owns that key"
    )]
    /// Selected key material is malformed, private or inconsistent.
    InvalidKey,
    #[error(
        "unsupported Signature-Key scheme: use a scheme accepted by this verifier; Direct Agent Identity requires jwt"
    )]
    /// The selected key-conveyance scheme is not accepted.
    UnsupportedScheme,
    #[error(
        "unsupported or missing key alg: use Ed25519, ES256, ES384, RS256, or PS256; algorithms are not inferred from key shape"
    )]
    /// The key algorithm is absent or unsupported.
    UnsupportedAlgorithm,
    /// Actual buffered content exceeds the shared local 1 MiB profile.
    #[error(
        "request body exceeds 1048576 bytes: bound and collect actual content before signing or verification"
    )]
    BodyTooLarge,
    /// Covered Content-Digest is malformed or does not match actual content bytes.
    #[error("Content-Digest must be a single sha-256 byte sequence matching the actual body bytes")]
    InvalidDigest,
    #[error(
        "request URI must be an absolute HTTPS URI with a valid authority and port, without userinfo"
    )]
    /// Request URI is not an absolute HTTPS target with a usable authority.
    InvalidUri,
    #[error(
        "invalid clock: supply Unix seconds in 0..=8589934591, not contemporary milliseconds, and a non-negative verification window"
    )]
    /// Clock or verification window is outside the nonnegative Unix-second profile.
    InvalidClock,
    /// `keyid` does not name the same key Signature-Key already carries.
    #[error(
        "keyid must equal the kid of the Signature-Key member; the verifier takes the key from Signature-Key, and hwk has no kid"
    )]
    UnsupportedKeyId,
    #[error(
        "request target differs from this Resource endpoint: sign for its configured HTTPS authority and path"
    )]
    /// Signed request target differs from the configured Resource endpoint.
    TargetMismatch,
    #[error(
        "invalid Signature-Key JWT: check compact serialization, required claims, and the assertion signature"
    )]
    /// JWT carried by Signature-Key is malformed or its signature failed.
    InvalidJwt,
    #[error(
        "Signature-Key JWT has expired: mint a new assertion whose exp is after the verifier clock"
    )]
    /// JWT `exp` is not strictly after the verifier clock.
    ExpiredJwt,
    #[error(
        "discovery metadata has no issuer: pass the document named by dwk before resolving a key"
    )]
    /// Discovery metadata has no `issuer` member.
    IssuerMissing,
    #[error(
        "discovery metadata issuer differs from the assertion iss: refuse a key from a different document"
    )]
    /// Discovery metadata `issuer` is not the assertion `iss`.
    IssuerMismatch,
    #[error("Signature-Key kid is not in the issuer's JWKS: refresh that set or correct kid")]
    /// Selected `kid` is absent from the issuer's key set.
    UnknownKey,
    #[error("Signature-Key cache identifier could not be resolved: resend the assertion in full")]
    /// The cache identifier is unknown, evicted, or failed to open.
    CacheMiss,
}
impl Error {
    /// Stable Signature-Error code; Display is a local explanation.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidSignature
            | Self::InvalidDigest
            | Self::InvalidUri
            | Self::InvalidClock
            | Self::UnsupportedKeyId
            | Self::TargetMismatch => "invalid_signature",
            Self::InvalidInput => "invalid_input",
            Self::BodyTooLarge => "invalid_request",
            Self::ClockSkew => "clock_skew",
            Self::InvalidKey => "invalid_key",
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::InvalidJwt => "invalid_jwt",
            Self::ExpiredJwt => "expired_jwt",
            Self::IssuerMissing => "issuer_missing",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::UnknownKey => "unknown_key",
            Self::CacheMiss => "cache_miss",
        }
    }
}

#[derive(Clone, Debug)]
/// Unverified selected key conveyance; extraction alone establishes no identity.
pub enum KeyMaterial {
    /// Header Web Key: inline public key, sufficient for pseudonymous proof only.
    /// To sign, pass the signing key's own [`SigningKey::public_jwk`].
    Hwk(Jwk),
    /// Compact JWT carrying a confirmation key; the accepting role verifies it.
    /// `cache` is the bare `cache` flag; it requires `jti` and `exp`.
    Jwt {
        /// Compact JWT.
        jwt: String,
        /// Caller asked for a cache identifier. Issuance is a separate step.
        cache: bool,
    },
    /// Unverified service identity/key reference. Host must admit the identity
    /// before resolving metadata/JWKS; this value alone grants no authority.
    JwksUri {
        /// HTTPS signer origin; the AAuth role further restricts server identifiers.
        id: String,
        /// Safe dot-well-known document name, without path separators.
        dwk: String,
        /// Nonempty exact key identifier in the admitted issuer's JWKS.
        kid: String,
    },
    /// Self-issued `jkt-jwt` delegation. `jwt` is the compact assertion.
    /// `cache` is the bare `cache` flag; it requires `jti` at verification.
    JktJwt {
        /// Compact `jkt-s256+jwt` assertion.
        jwt: String,
        /// Caller asked for a cache identifier. Issuance is a separate step.
        cache: bool,
    },
    /// Self-issued JWT. The discovered issuer key signs both the assertion and the request.
    SelfJwt {
        /// Compact JWT. It must not carry `cnf`, and this scheme has no `cache` parameter.
        jwt: String,
    },
    /// Direct JWKS. `url` is the signer identity and is compared as presented.
    Jwks {
        /// Exact HTTPS JWKS URL. Not canonicalized.
        url: String,
        /// Key identifier inside that JWKS.
        kid: String,
    },
    /// X.509 certificate. The host resolves `x5u`; this value does not fetch it.
    X509 {
        /// Exact HTTPS PEM URL. Not canonicalized.
        x5u: String,
        /// SHA-256 of the DER-encoded end-entity certificate.
        x5t: Vec<u8>,
    },
    /// Reference to an assertion this verifier previously cached.
    Cached {
        /// Cache identifier exactly as issued. It is not parsed here.
        cid: String,
    },
}

/// Algorithms an `hwk` member may name. Compact JWS and the `jwt`, `jkt-jwt`,
/// `self-jwt`, `jwks`, and `jwks_uri` schemes accept only Ed25519. Resource,
/// person server, and access server advertise only Ed25519.
pub const ACCEPTED_SIGNATURE_ALGS: &[&str] = &["Ed25519", "ES256", "ES384", "RS256", "PS256"];

/// `Accept-Signature-Alg` value for the `hwk` algorithm set, in preference order.
pub fn accept_signature_alg_header() -> String {
    ACCEPTED_SIGNATURE_ALGS.join(", ")
}

/// `Accept-Signature-Alg` value sent by the Resource, Person Server, and Access Server.
/// Those roles accept Ed25519 proofs only.
pub fn role_signature_alg_header() -> &'static str {
    "Ed25519"
}

/// Maximum actual content bytes signed or verified by this buffered profile.
/// Hosts must also bound collection before allocating a request body.
pub const MAX_BODY_BYTES: usize = 1_048_576;

/// Components required by the local buffered request profile.
/// Nonempty bodies or a supplied Content-Digest require covered digest.
/// Content-Type is additionally required when present on nonempty content.
/// A supplied empty-content digest is also checked.
pub fn required_components(req: &Request<Vec<u8>>) -> Vec<&'static str> {
    let mut required = vec!["@method", "@authority", "@path", "signature-key"];
    if req.uri().query().is_some() {
        required.push("@query")
    }
    if req.headers().contains_key("authorization") {
        required.push("authorization")
    }
    if content_digest::needed(req) {
        required.push("content-digest");
        if !req.body().is_empty() && req.headers().contains_key("content-type") {
            required.push("content-type");
        }
    }
    required
}

fn header(req: &Request<Vec<u8>>, name: &str) -> Result<String, Error> {
    field_value(req.headers(), name)
}
/// One field's combined value, at most 16 KiB, as RFC 9421 Section 2.1 joins it.
pub(crate) fn field_value(headers: &http::HeaderMap, name: &str) -> Result<String, Error> {
    let mut combined = String::new();
    let mut present = false;
    for value in headers.get_all(name) {
        if value.as_bytes().len() > 16384 - combined.len() {
            return Err(Error::InvalidSignature);
        }
        if present {
            if combined.len() + value.as_bytes().len() + 2 > 16384 {
                return Err(Error::InvalidSignature);
            }
            combined.push_str(", ");
        }
        combined.push_str(value.to_str().map_err(|_| Error::InvalidSignature)?.trim());
        present = true;
        if combined.len() > 16384 {
            return Err(Error::InvalidSignature);
        }
    }
    if !present {
        return Err(Error::InvalidSignature);
    }
    Ok(combined)
}
fn dictionary(req: &Request<Vec<u8>>, name: &str) -> Result<Dictionary, Error> {
    let error = if name == "signature-key" {
        Error::InvalidKey
    } else {
        Error::InvalidSignature
    };
    Parser::new(&header(req, name).map_err(|_| error)?)
        .parse()
        .map_err(|_| error)
}
fn text<'a>(params: &'a Parameters, name: &str) -> Result<&'a str, Error> {
    optional_text(params, name)?.ok_or(Error::InvalidKey)
}
fn byte_sequence(params: &Parameters, name: &str) -> Result<Vec<u8>, Error> {
    match params.get(name) {
        Some(BareItem::ByteSequence(bytes)) => Ok(bytes.clone()),
        _ => Err(Error::InvalidKey),
    }
}
fn optional_text<'a>(params: &'a Parameters, name: &str) -> Result<Option<&'a str>, Error> {
    match params.get(name) {
        None => Ok(None),
        Some(BareItem::String(s)) => Ok(Some(s.as_str())),
        _ => Err(Error::InvalidKey),
    }
}
fn parse_key(entry: &ListEntry, header: &str, label: &str) -> Result<(KeyMaterial, bool), Error> {
    let ListEntry::Item(item) = entry else {
        return Err(Error::InvalidKey);
    };
    let BareItem::Token(scheme) = &item.bare_item else {
        return Err(Error::InvalidKey);
    };
    match scheme.as_str() {
        "hwk" => Ok((parse_hwk(item)?, false)),
        "jwt" => {
            let jwt = text(&item.params, "jwt")?.to_owned();
            let cache = jkt::cache_flag(header, label, &item.params)?;
            if cache {
                cache::require_cacheable_jwt(&jwt)?;
            }
            Ok((KeyMaterial::Jwt { jwt, cache }, cache))
        }
        "jkt-jwt" => {
            let jwt = text(&item.params, "jwt")?.to_owned();
            let cache = jkt::cache_flag(header, label, &item.params)?;
            Ok((KeyMaterial::JktJwt { jwt, cache }, cache))
        }
        "self-jwt" => {
            if item.params.contains_key("cache") {
                return Err(Error::InvalidKey);
            }
            Ok((
                KeyMaterial::SelfJwt {
                    jwt: text(&item.params, "jwt")?.to_owned(),
                },
                false,
            ))
        }
        "jwks" => {
            let url = text(&item.params, "url")?.to_owned();
            let kid = text(&item.params, "kid")?.to_owned();
            jwks::validate(&url, &kid)?;
            Ok((KeyMaterial::Jwks { url, kid }, false))
        }
        "x509" => {
            let x5u = text(&item.params, "x5u")?.to_owned();
            let x5t = byte_sequence(&item.params, "x5t")?;
            x509::validate(&x5u, &x5t)?;
            Ok((KeyMaterial::X509 { x5u, x5t }, false))
        }
        "cached" => {
            let cid = text(&item.params, "cid")?.to_owned();
            quoted(&cid)?;
            Ok((KeyMaterial::Cached { cid }, false))
        }
        "jwks_uri" => {
            let id = text(&item.params, "id")?;
            let dwk = text(&item.params, "dwk")?;
            let kid = text(&item.params, "kid")?;
            validate_reference(id, dwk, kid)?;
            Ok((
                KeyMaterial::JwksUri {
                    id: id.into(),
                    dwk: dwk.into(),
                    kid: kid.into(),
                },
                false,
            ))
        }
        _ => Err(Error::UnsupportedScheme),
    }
}
/// Identifier the Signature-Key member itself carries. `hwk` has none.
fn key_identifier(key: &KeyMaterial) -> Result<Option<String>, Error> {
    match key {
        KeyMaterial::Hwk(_) | KeyMaterial::X509 { .. } | KeyMaterial::Cached { .. } => Ok(None),
        KeyMaterial::JwksUri { kid, .. } | KeyMaterial::Jwks { kid, .. } => Ok(Some(kid.clone())),
        KeyMaterial::Jwt { jwt: compact, .. }
        | KeyMaterial::JktJwt { jwt: compact, .. }
        | KeyMaterial::SelfJwt { jwt: compact } => {
            let header = aauth_rust_jose::Jws::parse(compact)
                .map_err(|_| Error::InvalidKey)?
                .header()
                .get("kid")
                .and_then(|value| value.as_str())
                .filter(|kid| !kid.is_empty())
                .map(str::to_owned);
            Ok(header)
        }
    }
}
fn parse_hwk(item: &sfv::Item) -> Result<KeyMaterial, Error> {
    if item.params.contains_key("kid") {
        return Err(Error::InvalidKey);
    }
    if ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
        .iter()
        .any(|name| item.params.contains_key(*name))
    {
        return Err(Error::InvalidKey);
    }
    let alg = match item.params.get("alg") {
        None => return Err(Error::UnsupportedAlgorithm),
        Some(BareItem::String(value)) => value.as_str(),
        _ => return Err(Error::InvalidKey),
    };
    let kty = match item.params.get("kty") {
        Some(BareItem::String(value)) => value.as_str(),
        _ => return Err(Error::InvalidKey),
    };
    // `none` and symmetric MAC algorithms are prohibited. An unrecognized key
    // type, including AKP, is `unsupported_algorithm` rather than a parse failure.
    if kty == "oct" || matches!(alg, "none" | "HS256" | "HS384" | "HS512") {
        return Err(Error::UnsupportedAlgorithm);
    }
    if !matches!(kty, "OKP" | "EC" | "RSA") {
        return Err(Error::UnsupportedAlgorithm);
    }
    let key = Jwk {
        kty: kty.into(),
        crv: optional_text(&item.params, "crv")?.unwrap_or("").into(),
        x: optional_text(&item.params, "x")?.unwrap_or("").into(),
        y: optional_text(&item.params, "y")?.unwrap_or("").into(),
        n: optional_text(&item.params, "n")?.unwrap_or("").into(),
        e: optional_text(&item.params, "e")?.unwrap_or("").into(),
        alg: alg.into(),
        extra: Default::default(),
    };
    key.validate().map_err(|err| match err {
        aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
        _ => Error::InvalidKey,
    })?;
    Ok(KeyMaterial::Hwk(key))
}

fn quoted(value: &str) -> Result<String, Error> {
    if value.is_empty() || !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Error::InvalidKey);
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
fn validate_reference(id: &str, dwk: &str, kid: &str) -> Result<(), Error> {
    let uri: http::Uri = id.parse().map_err(|_| Error::InvalidKey)?;
    canonical_authority(&uri).map_err(|_| Error::InvalidKey)?;
    if uri.query().is_some()
        || id.contains('#')
        || id != format!("https://{}", uri.authority().ok_or(Error::InvalidKey)?)
        || dwk.is_empty()
        || dwk == "."
        || dwk == ".."
        || !discovery_name(dwk)
    {
        return Err(Error::InvalidKey);
    }
    quoted(kid)?;
    Ok(())
}
pub(crate) fn discovery_name(dwk: &str) -> bool {
    !dwk.is_empty()
        && dwk != "."
        && dwk != ".."
        && dwk
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Derived components this profile reconstructs.
const DERIVED_COMPONENTS: &[&str] = &["@method", "@authority", "@path", "@query"];

/// A lowercase HTTP field name that a signature may cover. `signature` and
/// `signature-input` carry the proof itself and are never covered.
fn field_component(name: &str) -> bool {
    !name.is_empty()
        && !matches!(name, "signature" | "signature-input")
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}

fn components(input: &InnerList) -> Result<Vec<&str>, Error> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for item in &input.items {
        let BareItem::String(name) = &item.bare_item else {
            return Err(Error::InvalidSignature);
        };
        if !item.params.is_empty() || !seen.insert(name.as_str()) {
            return Err(Error::InvalidSignature);
        }
        result.push(name.as_str());
    }
    Ok(result)
}
/// RFC 9421 authority for an absolute HTTPS URI: lowercase host, omit port 443.
/// Hosts use this same normalization when binding proofs to a configured target.
///
/// # Errors
/// Rejects non-HTTPS/relative URIs, empty hosts, userinfo and ports outside 1..=65535.
pub fn canonical_authority(uri: &http::Uri) -> Result<String, Error> {
    if uri.scheme_str() != Some("https") {
        return Err(Error::InvalidUri);
    }
    let authority = uri.authority().ok_or(Error::InvalidUri)?;
    if authority.as_str().contains('@') {
        return Err(Error::InvalidUri);
    }
    let raw_host = authority.host();
    if raw_host.is_empty() {
        return Err(Error::InvalidUri);
    }
    let suffix = &authority.as_str()[raw_host.len()..];
    let port = if suffix.is_empty() {
        None
    } else {
        Some(
            suffix
                .strip_prefix(':')
                .ok_or(Error::InvalidUri)?
                .parse::<u16>()
                .map_err(|_| Error::InvalidUri)?,
        )
    };
    let host = raw_host.to_ascii_lowercase();
    if port == Some(0) {
        return Err(Error::InvalidUri);
    }
    let normalized = match port {
        None | Some(443) => host,
        Some(port) => format!("{host}:{port}"),
    };
    Ok(normalized)
}
fn build_base(req: &Request<Vec<u8>>, input: &InnerList) -> Result<Vec<u8>, Error> {
    let names = components(input)?;
    let mut lines = Vec::new();
    for name in names {
        let value = match name {
            "@method" => req.method().as_str(),
            "@authority" => {
                let normalized = canonical_authority(req.uri())?;
                lines.push(format!("\"@authority\": {normalized}"));
                continue;
            }
            "@path" => {
                let path = req.uri().path();
                if path.is_empty() { "/" } else { path }
            }
            "@query" => {
                lines.push(format!("\"@query\": ?{}", req.uri().query().unwrap_or("")));
                continue;
            }
            field if field_component(field) => {
                lines.push(format!("\"{field}\": {}", header(req, field)?));
                continue;
            }
            _ => return Err(Error::InvalidSignature),
        };
        lines.push(format!("\"{name}\": {value}"));
    }
    let params = List::from([ListEntry::InnerList(input.clone())])
        .serialize()
        .ok_or(Error::InvalidSignature)?;
    lines.push(format!("\"@signature-params\": {params}"));
    Ok(lines.join("\n").into_bytes())
}

/// Captured request bytes and selected assertion. No assertion is trusted yet.
pub struct PreparedRequest {
    key: KeyMaterial,
    base: Vec<u8>,
    signature: Vec<u8>,
    window: i64,
    cache: bool,
}
impl PreparedRequest {
    /// Capture a selected hwk/jwt assertion at `now` with a window in Unix seconds.
    /// Local clocks are limited to 0..=8589934591 (through 2242).
    /// Beyond the required set, a signature may cover any lowercase header
    /// field present on the request, such as one a server lists in
    /// `additional_signature_components`. Derived components other than
    /// `@method`, `@authority`, `@path` and `@query` are refused.
    ///
    /// # Errors
    /// Returns profile, syntax, coverage, time or key-conveyance errors. A
    /// request without `Signature`, `Signature-Input` or `Signature-Key` is
    /// `InvalidSignature`. No proof is authenticated until
    /// [`PreparedRequest::verify`] succeeds.
    pub fn prepare(
        req: &Request<Vec<u8>>,
        label: &str,
        now: i64,
        window: i64,
    ) -> Result<Self, Error> {
        Self::prepare_with_schemes(req, label, now, window, &["hwk", "jwt"])
    }
    /// Apply the accepting protocol's scheme profile before key resolution.
    ///
    /// # Errors
    /// As for [`PreparedRequest::prepare`], also rejects a selected scheme outside
    /// `accepted`. Unselected dictionary members do not impose scheme support.
    pub fn prepare_with_schemes(
        req: &Request<Vec<u8>>,
        label: &str,
        now: i64,
        window: i64,
        accepted: &[&str],
    ) -> Result<Self, Error> {
        if req.body().len() > MAX_BODY_BYTES {
            return Err(Error::BodyTooLarge);
        }
        if req.uri().scheme_str() != Some("https") {
            return Err(Error::InvalidUri);
        }
        if window < 0 || !(0..=(1_i64 << 33) - 1).contains(&now) {
            return Err(Error::InvalidClock);
        }
        // A request missing any of the three fields is not signed, so this is
        // `invalid_signature` before coverage or key material is read.
        if ["signature", "signature-input", "signature-key"]
            .iter()
            .any(|name| !req.headers().contains_key(*name))
        {
            return Err(Error::InvalidSignature);
        }
        let inputs = dictionary(req, "signature-input")?;
        let Some(ListEntry::InnerList(input)) = inputs.get(label) else {
            return Err(Error::InvalidSignature);
        };
        let covered = components(input)?;
        let required = required_components(req);
        if required.iter().any(|s| !covered.contains(s)) {
            return Err(Error::InvalidInput);
        }
        if covered.contains(&"content-digest") {
            content_digest::verify(req)?;
        }
        let created = match input.params.get("created") {
            Some(BareItem::Integer(n)) => i64::from(*n),
            _ => return Err(Error::InvalidSignature),
        };
        if created < 0 || created < now.saturating_sub(window) {
            return Err(Error::InvalidSignature);
        }
        if created > now.saturating_add(window) {
            return Err(Error::ClockSkew);
        }
        if let Some(expires) = input.params.get("expires") {
            match expires {
                BareItem::Integer(n) if i64::from(*n) > now && i64::from(*n) > created => {}
                _ => return Err(Error::InvalidSignature),
            }
        }
        let key_header = header(req, "signature-key").map_err(|_| Error::InvalidKey)?;
        let keys = Parser::new(&key_header)
            .parse::<Dictionary>()
            .map_err(|_| Error::InvalidKey)?;
        let entry = keys.get(label).ok_or(Error::InvalidSignature)?;
        let ListEntry::Item(item) = entry else {
            return Err(Error::InvalidKey);
        };
        let BareItem::Token(scheme) = &item.bare_item else {
            return Err(Error::InvalidKey);
        };
        if !accepted.contains(&scheme.as_str()) {
            return Err(Error::UnsupportedScheme);
        }
        let (key, cache) = parse_key(entry, &key_header, label)?;
        if let Some(keyid) = input.params.get("keyid") {
            let BareItem::String(keyid) = keyid else {
                return Err(Error::InvalidSignature);
            };
            match key_identifier(&key)? {
                Some(kid) if kid == keyid.as_str() => {}
                _ => return Err(Error::UnsupportedKeyId),
            }
        }
        let signatures = dictionary(req, "signature")?;
        let Some(ListEntry::Item(signature)) = signatures.get(label) else {
            return Err(Error::InvalidSignature);
        };
        let BareItem::ByteSequence(bytes) = &signature.bare_item else {
            return Err(Error::InvalidSignature);
        };
        if !signature.params.is_empty() {
            return Err(Error::InvalidSignature);
        }
        // `x509` names its HTTP algorithm only after the certificate is
        // checked. Ed25519 and ES256 are 64 bytes, ES384 is 96, and a
        // modulus-sized signature is accepted here so an RSA certificate can
        // still be classified as `unsupported_algorithm`. The other schemes
        // name no algorithm until their key is resolved, so a key of a type
        // this verifier does not implement is `unsupported_algorithm` then,
        // not a length failure now; `verify` checks the length.
        let accepted_len = match &key {
            KeyMaterial::Hwk(jwk) => {
                bytes.len()
                    == jwk.signature_len().map_err(|err| match err {
                        aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
                        _ => Error::InvalidKey,
                    })?
            }
            KeyMaterial::X509 { .. } => {
                matches!(bytes.len(), 64 | 96) || (256..=1024).contains(&bytes.len())
            }
            _ => true,
        };
        if !accepted_len {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            key,
            base: build_base(req, input)?,
            signature: bytes.clone(),
            window,
            cache,
        })
    }
    /// Selected unverified material for role-specific token/key resolution.
    pub fn key(&self) -> &KeyMaterial {
        &self.key
    }
    /// Exact RFC 9421 base reconstructed from the captured request components.
    pub fn signature_base(&self) -> &[u8] {
        &self.base
    }
    /// Verify the captured request proof with the resolved public key.
    ///
    /// # Errors
    /// Returns algorithm/key errors or `InvalidSignature` for a bad proof.
    pub fn verify(&self, key: &Jwk) -> Result<(), Error> {
        let allowed = match &self.key {
            KeyMaterial::Hwk(header) => header.alg == key.alg,
            KeyMaterial::X509 { .. } => matches!(key.alg.as_str(), "Ed25519" | "ES256" | "ES384"),
            _ => key.alg == "Ed25519",
        };
        if !allowed {
            return Err(Error::UnsupportedAlgorithm);
        }
        key.verify(&self.base, &self.signature)
            .map_err(|e| match e {
                aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
                aauth_rust_jose::Error::InvalidKey => Error::InvalidKey,
                _ => Error::InvalidSignature,
            })
    }
}

/// One labeled signature. The Signature-Key member and the HTTP signature
/// share `label`.
pub struct RequestSignature<'a> {
    /// Dictionary key shared by Signature-Key, Signature-Input, and Signature.
    pub label: &'a str,
    /// Key that signs this label's signature base.
    pub key: &'a SigningKey,
    /// Signature-Key member for this label.
    pub material: KeyMaterial,
}

/// Sign once, without sending, retrying or obtaining credentials.
/// `now` is Unix seconds in 0..=8589934591 (through 2242). Contemporary
/// millisecond timestamps are outside this local profile. This replaces
/// signature headers; call after URI and
/// other headers are final.
///
/// The signature uses `key`'s own algorithm. An `hwk` member carries that
/// key's public JWK, for any algorithm in [`ACCEPTED_SIGNATURE_ALGS`]. A `jwt`
/// or `jkt-jwt` member with `cache` set ends in the bare `;cache` flag.
///
/// # Errors
/// Computes and covers SHA-256 Content-Digest on nonempty content or when a
/// digest field was supplied; covers Content-Type when present on nonempty content.
/// Existing digest bytes are replaced from actual content before signing.
/// Rejects bodies over 1 MiB, non-HTTPS/invalid targets, invalid clocks, malformed
/// JWT/key material, an inline public key that differs from the signer's key or
/// algorithm, or `cache` on an assertion without `jti` and `exp` (`invalid_jwt`).
pub fn sign_request(
    req: &mut Request<Vec<u8>>,
    key: &SigningKey,
    material: KeyMaterial,
    now: i64,
) -> Result<(), Error> {
    sign_requests(
        req,
        &[RequestSignature {
            label: "sig",
            key,
            material,
        }],
        now,
    )
}

/// Sign every label after the complete Signature-Key dictionary is in place.
///
/// Each signature covers `signature-key`, so each one protects every member,
/// not only its own. `now` is Unix seconds in 0..=8589934591.
///
/// # Errors
/// As for [`sign_request`]. Also rejects an empty set or a repeated label.
pub fn sign_requests(
    req: &mut Request<Vec<u8>>,
    parts: &[RequestSignature<'_>],
    now: i64,
) -> Result<(), Error> {
    sign_requests_with_components(req, parts, &[], now)
}

/// Sign every label, also covering the components a server lists in its
/// `additional_signature_components` metadata.
///
/// Each entry is a lowercase HTTP field name or one of `@method`,
/// `@authority`, `@path` and `@query`. Entries the base components do not
/// already cover follow them in list order, and `signature-key` stays last.
/// A repeated entry is covered once. A listed `content-digest` is computed
/// from the actual content, even when it is empty, and keeps its base position.
///
/// # Errors
/// As for [`sign_requests`]. Returns [`Error::InvalidInput`], before the
/// request is changed, for any other derived component, a name that is not a
/// lowercase field name, `signature`, `signature-input`, or a listed field
/// the request does not carry. The signer never omits a listed component.
pub fn sign_requests_with_components(
    req: &mut Request<Vec<u8>>,
    parts: &[RequestSignature<'_>],
    additional: &[&str],
    now: i64,
) -> Result<(), Error> {
    for name in additional {
        let derived = DERIVED_COMPONENTS.contains(name);
        if !derived && !field_component(name) {
            return Err(Error::InvalidInput);
        }
        let generated = matches!(*name, "content-digest" | "signature-key");
        if !derived && !generated && !req.headers().contains_key(*name) {
            return Err(Error::InvalidInput);
        }
    }
    if parts.is_empty() || req.body().len() > MAX_BODY_BYTES {
        return Err(if parts.is_empty() {
            Error::InvalidInput
        } else {
            Error::BodyTooLarge
        });
    }
    if req.uri().scheme_str() != Some("https") {
        return Err(Error::InvalidUri);
    }
    if !(0..=(1_i64 << 33) - 1).contains(&now) {
        return Err(Error::InvalidClock);
    }
    let mut seen = BTreeSet::new();
    let mut members = Vec::with_capacity(parts.len());
    for part in parts {
        if !seen.insert(part.label) {
            return Err(Error::InvalidInput);
        }
        cache::token(part.label).map_err(|_| Error::InvalidInput)?;
        members.push(signature_member(part)?);
    }
    let mut covered = vec!["@method", "@authority", "@path"];
    if req.uri().query().is_some() {
        covered.push("@query");
    }
    if req.headers().contains_key("authorization") {
        covered.push("authorization");
    }
    if content_digest::needed(req) || additional.contains(&"content-digest") {
        let digest = content_digest::field(req.body());
        req.headers_mut().insert(
            "content-digest",
            digest.parse().map_err(|_| Error::InvalidDigest)?,
        );
        covered.push("content-digest");
        if !req.body().is_empty() && req.headers().contains_key("content-type") {
            covered.push("content-type");
        }
    }
    for name in additional {
        if *name != "signature-key" && !covered.contains(name) {
            covered.push(*name);
        }
    }
    covered.push("signature-key");
    let covered = covered
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(" ");
    req.headers_mut().insert(
        "signature-key",
        members
            .join(", ")
            .parse()
            .map_err(|_| Error::InvalidInput)?,
    );
    let input = parts
        .iter()
        .map(|part| format!("{}=({covered});created={now}", part.label))
        .collect::<Vec<_>>()
        .join(", ");
    req.headers_mut().insert(
        "signature-input",
        input.parse().map_err(|_| Error::InvalidInput)?,
    );
    let mut signatures = Vec::with_capacity(parts.len());
    for part in parts {
        let inputs = dictionary(req, "signature-input")?;
        let Some(ListEntry::InnerList(inner)) = inputs.get(part.label) else {
            return Err(Error::InvalidInput);
        };
        let base = build_base(req, inner)?;
        signatures.push(format!(
            "{}=:{}:",
            part.label,
            STANDARD.encode(part.key.sign(&base))
        ));
    }
    req.headers_mut().insert(
        "signature",
        signatures
            .join(", ")
            .parse()
            .map_err(|_| Error::InvalidInput)?,
    );
    Ok(())
}

fn signature_member(part: &RequestSignature<'_>) -> Result<String, Error> {
    cache::token(part.label)?;
    let body = match &part.material {
        KeyMaterial::Hwk(jwk) => {
            let signer = part.key.public_jwk();
            let thumbprint = |key: &Jwk| key.thumbprint().map_err(|_| Error::InvalidKey);
            if jwk.alg != signer.alg || thumbprint(jwk)? != thumbprint(&signer)? {
                return Err(Error::InvalidKey);
            }
            hwk_member(jwk)
        }
        KeyMaterial::JwksUri { id, dwk, kid } => {
            validate_reference(id, dwk, kid)?;
            format!(
                "jwks_uri;id={};dwk={};kid={}",
                quoted(id)?,
                quoted(dwk)?,
                quoted(kid)?
            )
        }
        KeyMaterial::Jwks { url, kid } => {
            jwks::validate(url, kid)?;
            format!("jwks;url={};kid={}", quoted(url)?, quoted(kid)?)
        }
        KeyMaterial::Jwt { jwt, cache } => {
            aauth_rust_jose::Jws::parse(jwt).map_err(|_| Error::InvalidKey)?;
            let mut header = format!("jwt;jwt=\"{jwt}\"");
            if *cache {
                cache::require_cacheable_jwt(jwt)?;
                header.push_str(";cache");
            }
            header
        }
        KeyMaterial::JktJwt { jwt, cache } => {
            let delegation = jkt::parse_jkt(jwt, *cache)?;
            if delegation.confirmation.thumbprint().ok() != part.key.public_jwk().thumbprint().ok()
            {
                return Err(Error::InvalidKey);
            }
            let mut header = format!("jkt-jwt;jwt=\"{jwt}\"");
            if *cache {
                header.push_str(";cache");
            }
            header
        }
        KeyMaterial::SelfJwt { jwt } => {
            self_jwt::assert_signable(jwt, part.key)?;
            format!("self-jwt;jwt=\"{jwt}\"")
        }
        KeyMaterial::X509 { x5u, x5t } => {
            x509::validate(x5u, x5t)?;
            format!("x509;x5u={};x5t=:{}:", quoted(x5u)?, STANDARD.encode(x5t))
        }
        KeyMaterial::Cached { cid } => {
            quoted(cid)?;
            format!("cached;cid={}", quoted(cid)?)
        }
    };
    Ok(format!("{}={body}", part.label))
}

/// `hwk` member for a validated key: the JWK members its key type requires,
/// in the draft's order, and never `kid`. Validated values need no escaping.
fn hwk_member(jwk: &Jwk) -> String {
    match jwk.kty.as_str() {
        "EC" => format!(
            "hwk;kty=\"EC\";crv=\"{}\";x=\"{}\";y=\"{}\";alg=\"{}\"",
            jwk.crv, jwk.x, jwk.y, jwk.alg
        ),
        "RSA" => format!(
            "hwk;kty=\"RSA\";n=\"{}\";e=\"{}\";alg=\"{}\"",
            jwk.n, jwk.e, jwk.alg
        ),
        _ => format!(
            "hwk;kty=\"OKP\";crv=\"{}\";x=\"{}\";alg=\"{}\"",
            jwk.crv, jwk.x, jwk.alg
        ),
    }
}

impl std::fmt::Debug for PreparedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = match &self.key {
            KeyMaterial::Hwk(_) => "hwk",
            KeyMaterial::Jwt { .. } => "jwt",
            KeyMaterial::JwksUri { .. } => "jwks_uri",
            KeyMaterial::Jwks { .. } => "jwks",
            KeyMaterial::JktJwt { .. } => "jkt-jwt",
            KeyMaterial::SelfJwt { .. } => "self-jwt",
            KeyMaterial::X509 { .. } => "x509",
            KeyMaterial::Cached { .. } => "cached",
        };
        f.debug_struct("PreparedRequest")
            .field("scheme", &scheme)
            .field("base_length", &self.base.len())
            .finish_non_exhaustive()
    }
}
