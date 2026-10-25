//! `jkt-jwt` self-issued delegation. The enclave key signs the assertion;
//! the ephemeral `cnf.jwk` signs the HTTP request.
use super::{Error, KeyMaterial, PreparedRequest};
use aauth_rust_jose::{Jwk, Jws};
use serde_json::{Map, Value};
use sfv::{BareItem, Parameters};

/// Verified `jkt-s256+jwt` delegation. The HTTP signature has already been
/// checked against `confirmation`.
#[derive(Clone, Debug)]
pub struct JktDelegation {
    /// `urn:jkt:sha-256:` plus the RFC 7638 thumbprint of `identity`.
    pub issuer: String,
    /// Assertion `iat`, Unix seconds.
    pub issued_at: i64,
    /// Assertion `exp`, Unix seconds. Verification requires this to be after `now`.
    pub expires_at: i64,
    /// Assertion `jti` when present. Required when the member set `cache`.
    pub jti: Option<String>,
    /// Enclave public key from the JWT header `jwk`. It signed the assertion.
    pub identity: Jwk,
    /// Ephemeral public key from `cnf.jwk`. It signed the HTTP request.
    pub confirmation: Jwk,
    /// The Signature-Key member carried a bare `cache` flag.
    pub cache: bool,
}

pub(crate) fn cache_flag(header: &str, label: &str, params: &Parameters) -> Result<bool, Error> {
    let member = dictionary_member(header, label)?;
    let shape = cache_shape(member)?;
    match (params.get("cache"), shape) {
        (None, CacheShape::Absent) => Ok(false),
        (Some(BareItem::Boolean(true)), CacheShape::Bare) => Ok(true),
        _ => Err(Error::InvalidKey),
    }
}

enum CacheShape {
    Absent,
    Bare,
    Assigned,
}

fn dictionary_member<'a>(header: &'a str, label: &str) -> Result<&'a str, Error> {
    let mut start = 0;
    let mut in_string = false;
    let bytes = header.as_bytes();
    let mut i = 0;
    let mut found = None;
    let end_member = |slice: &'a str, found: &mut Option<&'a str>| {
        let member = slice.trim();
        let Some((key, _)) = member.split_once('=') else {
            return;
        };
        if key.trim() == label {
            *found = Some(member);
        }
    };
    while i < bytes.len() {
        if in_string {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match bytes[i] {
            b'"' => {
                in_string = true;
                i += 1;
            }
            b',' => {
                end_member(&header[start..i], &mut found);
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    end_member(&header[start..], &mut found);
    found.ok_or(Error::InvalidKey)
}

fn cache_shape(member: &str) -> Result<CacheShape, Error> {
    let bytes = member.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut shape = CacheShape::Absent;
    while i < bytes.len() {
        if in_string {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if bytes[i] == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if bytes[i] != b';' {
            i += 1;
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_param_name(bytes[i]) {
            i += 1;
        }
        let name = &member[start..i];
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if name == "cache" {
            if !matches!(shape, CacheShape::Absent) {
                return Err(Error::InvalidKey);
            }
            shape = if i < bytes.len() && bytes[i] == b'=' {
                CacheShape::Assigned
            } else {
                CacheShape::Bare
            };
        }
    }
    Ok(shape)
}

fn is_param_name(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

pub(crate) fn parse_jkt(jwt: &str, cache: bool) -> Result<JktDelegation, Error> {
    let parsed = Jws::parse(jwt).map_err(map_jws)?;
    let header = parsed.header();
    let typ = header
        .get("typ")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidJwt)?;
    if typ != "jkt-s256+jwt" {
        return Err(Error::InvalidJwt);
    }
    let header_alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(Error::UnsupportedAlgorithm)?;
    let jwk_value = header.get("jwk").ok_or(Error::InvalidJwt)?;
    if !jwk_value.is_object() {
        return Err(Error::InvalidJwt);
    }
    let identity: Jwk = serde_json::from_value(jwk_value.clone()).map_err(|_| Error::InvalidJwt)?;
    identity.validate().map_err(map_jose)?;
    if identity.alg != header_alg {
        return Err(Error::InvalidKey);
    }
    let expected = format!(
        "urn:jkt:sha-256:{}",
        identity.thumbprint().map_err(map_jose)?
    );
    let payload = aauth_rust_jose::strict_json(parsed.payload()).map_err(|_| Error::InvalidJwt)?;
    let claims = payload.as_object().ok_or(Error::InvalidJwt)?;
    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidJwt)?;
    if issuer != expected {
        return Err(Error::InvalidJwt);
    }
    let issued_at = unix_claim(claims, "iat")?;
    let expires_at = unix_claim(claims, "exp")?;
    let confirmation = confirmation_jwk(claims.get("cnf"))?;
    let jti = optional_jti(claims.get("jti"))?;
    if cache && jti.is_none() {
        return Err(Error::InvalidJwt);
    }
    parsed.verify(&identity).map_err(map_jws)?;
    if expires_at <= issued_at {
        return Err(Error::InvalidJwt);
    }
    confirmation.validate().map_err(map_jose)?;
    Ok(JktDelegation {
        issuer: issuer.to_owned(),
        issued_at,
        expires_at,
        jti,
        identity,
        confirmation,
        cache,
    })
}

fn unix_claim(claims: &Map<String, Value>, name: &str) -> Result<i64, Error> {
    match claims.get(name) {
        Some(Value::Number(n)) => n.as_i64().filter(|n| *n >= 0).ok_or(Error::InvalidJwt),
        _ => Err(Error::InvalidJwt),
    }
}

fn confirmation_jwk(cnf: Option<&Value>) -> Result<Jwk, Error> {
    let cnf = cnf.and_then(Value::as_object).ok_or(Error::InvalidJwt)?;
    let jwk = cnf.get("jwk").ok_or(Error::InvalidJwt)?;
    if !jwk.is_object() {
        return Err(Error::InvalidJwt);
    }
    let parsed: Jwk = serde_json::from_value(jwk.clone()).map_err(|_| Error::InvalidJwt)?;
    if parsed.alg != "Ed25519" {
        return Err(Error::UnsupportedAlgorithm);
    }
    Ok(parsed)
}

fn optional_jti(value: Option<&Value>) -> Result<Option<String>, Error> {
    match value {
        None => Ok(None),
        Some(Value::String(jti)) if !jti.is_empty() => Ok(Some(jti.clone())),
        _ => Err(Error::InvalidJwt),
    }
}

fn map_jws(err: aauth_rust_jose::Error) -> Error {
    match err {
        aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
        aauth_rust_jose::Error::InvalidKey => Error::InvalidKey,
        _ => Error::InvalidJwt,
    }
}

fn map_jose(err: aauth_rust_jose::Error) -> Error {
    match err {
        aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
        aauth_rust_jose::Error::InvalidKey => Error::InvalidKey,
        _ => Error::InvalidJwt,
    }
}

impl PreparedRequest {
    /// Verify a selected `jkt-jwt` member, then the HTTP signature under `cnf.jwk`.
    ///
    /// `now` is the verifier clock in Unix seconds. `iat` uses the same window
    /// `prepare` applied to `created`. Only `typ` `jkt-s256+jwt` is accepted.
    /// A bare `cache` parameter requires `jti`. This method does not issue a
    /// cache identifier.
    ///
    /// # Errors
    /// `invalid_jwt` for a malformed assertion, a thumbprint mismatch, or a bad
    /// enclave signature. `expired_jwt` when `exp` is not after `now`.
    /// `clock_skew` when `iat` is further ahead than the signature window.
    /// `unsupported_algorithm` when the enclave or confirmation key names an
    /// algorithm this profile does not implement.
    pub fn verify_jkt_jwt(&self, now: i64) -> Result<JktDelegation, Error> {
        if !(0..=(1_i64 << 33) - 1).contains(&now) {
            return Err(Error::InvalidClock);
        }
        let KeyMaterial::JktJwt { jwt, cache } = &self.key else {
            return Err(Error::InvalidKey);
        };
        let delegation = parse_jkt(jwt, *cache)?;
        if delegation.issued_at > now.saturating_add(self.window) {
            return Err(Error::ClockSkew);
        }
        if delegation.expires_at <= now {
            return Err(Error::ExpiredJwt);
        }
        self.verify(&delegation.confirmation)?;
        Ok(delegation)
    }
}
