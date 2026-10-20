//! Buffered RFC 9421 request proofs with Ed25519 `hwk`, `jwt` and explicit `jwks_uri` schemes.
//! Verification proves a key; the accepting role supplies identity and policy.
#![deny(missing_docs)]
mod content_digest;

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
        "signature coverage is incomplete: include method, authority, path, Signature-Key, query/Authorization when present, and Content-Digest plus Content-Type when content requires them"
    )]
    /// The selected signature omits required covered components.
    InvalidInput,
    #[error(
        "created is too far in the future: synchronize the clock and use Unix seconds rather than milliseconds"
    )]
    /// Signature creation is too far ahead of the verifier clock.
    ClockSkew,
    #[error(
        "invalid Signature-Key: check the selected scheme's parameter types, public-only OKP/Ed25519 key, and that the signer owns that key"
    )]
    /// Selected key material is malformed, private or inconsistent.
    InvalidKey,
    #[error(
        "unsupported Signature-Key scheme: use a scheme accepted by this verifier; Direct Agent Identity requires jwt"
    )]
    /// The selected key-conveyance scheme is not accepted.
    UnsupportedScheme,
    #[error(
        "unsupported or missing key alg: set alg to the string Ed25519; algorithms are not inferred from key shape"
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
    /// keyid is unsupported by this profile: identify the key in Signature-Key instead.
    #[error("keyid is unsupported by this profile: identify the key in Signature-Key instead")]
    UnsupportedKeyId,
    #[error(
        "request target differs from this Resource endpoint: sign for its configured HTTPS authority and path"
    )]
    /// Signed request target differs from the configured Resource endpoint.
    TargetMismatch,
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
        }
    }
}

#[derive(Clone, Debug)]
/// Unverified selected key conveyance; extraction alone establishes no identity.
pub enum KeyMaterial {
    /// Header Web Key: inline public key, sufficient for pseudonymous proof only.
    Hwk(Jwk),
    /// Compact JWT carrying a confirmation key; the accepting role verifies it.
    Jwt(String),
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
    let mut combined = String::new();
    let mut present = false;
    for value in req.headers().get_all(name) {
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
    match params.get(name) {
        Some(BareItem::String(s)) => Ok(s.as_str()),
        _ => Err(Error::InvalidKey),
    }
}
fn parse_key(entry: &ListEntry) -> Result<KeyMaterial, Error> {
    let ListEntry::Item(item) = entry else {
        return Err(Error::InvalidKey);
    };
    let BareItem::Token(scheme) = &item.bare_item else {
        return Err(Error::InvalidKey);
    };
    match scheme.as_str() {
        "hwk" => {
            if item.params.contains_key("kid") {
                return Err(Error::InvalidKey);
            }
            let alg = match item.params.get("alg") {
                None => return Err(Error::UnsupportedAlgorithm),
                Some(BareItem::String(value)) => value.as_str(),
                _ => return Err(Error::InvalidKey),
            };
            if alg != "Ed25519" {
                return Err(Error::UnsupportedAlgorithm);
            }
            let key = Jwk {
                kty: text(&item.params, "kty")?.into(),
                crv: text(&item.params, "crv")?.into(),
                x: text(&item.params, "x")?.into(),
                alg: alg.into(),
                extra: Default::default(),
            };
            if ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
                .iter()
                .any(|name| item.params.contains_key(*name))
            {
                return Err(Error::InvalidKey);
            }
            key.validate().map_err(|_| Error::InvalidKey)?;
            Ok(KeyMaterial::Hwk(key))
        }
        "jwt" => Ok(KeyMaterial::Jwt(text(&item.params, "jwt")?.into())),
        "jwks_uri" => {
            let id = text(&item.params, "id")?;
            let dwk = text(&item.params, "dwk")?;
            let kid = text(&item.params, "kid")?;
            validate_reference(id, dwk, kid)?;
            Ok(KeyMaterial::JwksUri {
                id: id.into(),
                dwk: dwk.into(),
                kid: kid.into(),
            })
        }
        _ => Err(Error::UnsupportedScheme),
    }
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
        || !dwk
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(Error::InvalidKey);
    }
    quoted(kid)?;
    Ok(())
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
            "signature-key" | "authorization" | "content-digest" | "content-type" => {
                lines.push(format!("\"{name}\": {}", header(req, name)?));
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
}
impl PreparedRequest {
    /// Capture a selected hwk/jwt assertion at `now` with a window in Unix seconds.
    /// Local clocks are limited to 0..=8589934591 (through 2242).
    ///
    /// # Errors
    /// Returns profile, syntax, coverage, time or key-conveyance errors. No proof
    /// is authenticated until [`PreparedRequest::verify`] succeeds.
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
        if input.params.contains_key("keyid") {
            return Err(Error::UnsupportedKeyId);
        }
        if let Some(expires) = input.params.get("expires") {
            match expires {
                BareItem::Integer(n) if i64::from(*n) > now && i64::from(*n) > created => {}
                _ => return Err(Error::InvalidSignature),
            }
        }
        let keys = dictionary(req, "signature-key")?;
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
        let key = parse_key(entry)?;
        let signatures = dictionary(req, "signature")?;
        let Some(ListEntry::Item(signature)) = signatures.get(label) else {
            return Err(Error::InvalidSignature);
        };
        let BareItem::ByteSequence(bytes) = &signature.bare_item else {
            return Err(Error::InvalidSignature);
        };
        if bytes.len() != 64 || !signature.params.is_empty() {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            key,
            base: build_base(req, input)?,
            signature: bytes.clone(),
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
        key.verify(&self.base, &self.signature)
            .map_err(|e| match e {
                aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
                aauth_rust_jose::Error::InvalidKey => Error::InvalidKey,
                _ => Error::InvalidSignature,
            })
    }
}

/// Sign once, without sending, retrying or obtaining credentials.
/// `now` is Unix seconds in 0..=8589934591 (through 2242). Contemporary
/// millisecond timestamps are outside this local profile. This replaces
/// signature headers; call after URI and
/// other headers are final.
///
/// # Errors
/// Computes and covers SHA-256 Content-Digest on nonempty content or when a
/// digest field was supplied; covers Content-Type when present on nonempty content.
/// Existing digest bytes are replaced from actual content before signing.
/// Rejects bodies over 1 MiB, non-HTTPS/invalid targets, invalid clocks, malformed
/// JWT/key material or an inline public key that differs from the signer.
pub fn sign_request(
    req: &mut Request<Vec<u8>>,
    key: &SigningKey,
    material: KeyMaterial,
    now: i64,
) -> Result<(), Error> {
    if req.body().len() > MAX_BODY_BYTES {
        return Err(Error::BodyTooLarge);
    }
    if req.uri().scheme_str() != Some("https") {
        return Err(Error::InvalidUri);
    }
    if !(0..=(1_i64 << 33) - 1).contains(&now) {
        return Err(Error::InvalidClock);
    }
    let key_header = match material {
        KeyMaterial::Hwk(jwk) => {
            jwk.validate().map_err(|_| Error::InvalidKey)?;
            if jwk.thumbprint().ok() != key.public_jwk().thumbprint().ok() {
                return Err(Error::InvalidKey);
            }
            format!(
                "sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"{}\";alg=\"Ed25519\"",
                jwk.x
            )
        }
        KeyMaterial::JwksUri { id, dwk, kid } => {
            validate_reference(&id, &dwk, &kid)?;
            format!(
                "sig=jwks_uri;id={};dwk={};kid={}",
                quoted(&id)?,
                quoted(&dwk)?,
                quoted(&kid)?
            )
        }
        KeyMaterial::Jwt(jwt) => {
            aauth_rust_jose::Jws::parse(&jwt).map_err(|_| Error::InvalidKey)?;
            format!("sig=jwt;jwt=\"{jwt}\"")
        }
    };
    let mut covered = vec!["@method", "@authority", "@path"];
    if req.uri().query().is_some() {
        covered.push("@query")
    }
    if req.headers().contains_key("authorization") {
        covered.push("authorization")
    }
    if content_digest::needed(req) {
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
    covered.push("signature-key");
    let input = format!(
        "sig=({});created={now}",
        covered
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(" ")
    );
    req.headers_mut().insert(
        "signature-key",
        key_header.parse().map_err(|_| Error::InvalidInput)?,
    );
    req.headers_mut().insert(
        "signature-input",
        input.parse().map_err(|_| Error::InvalidInput)?,
    );
    let inputs = dictionary(req, "signature-input")?;
    let Some(ListEntry::InnerList(inner)) = inputs.get("sig") else {
        return Err(Error::InvalidInput);
    };
    let base = build_base(req, inner)?;
    req.headers_mut().insert(
        "signature",
        format!("sig=:{}:", STANDARD.encode(key.sign(&base)))
            .parse()
            .map_err(|_| Error::InvalidInput)?,
    );
    Ok(())
}

impl std::fmt::Debug for PreparedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = match &self.key {
            KeyMaterial::Hwk(_) => "hwk",
            KeyMaterial::Jwt(_) => "jwt",
            KeyMaterial::JwksUri { .. } => "jwks_uri",
        };
        f.debug_struct("PreparedRequest")
            .field("scheme", &scheme)
            .field("base_length", &self.base.len())
            .finish_non_exhaustive()
    }
}
