//! `jwt` discovery when `iss` and `dwk` are both present.
//!
//! This module does not fetch. The host fetches `{iss}/.well-known/{dwk}` and
//! the metadata document's `jwks_uri`, then passes those bytes here.
use aauth_rust_jose::{Jwk, Jws};
use serde_json::{Map, Value};

use super::Error;

/// Issuer key and confirmation key from a discovered `jwt` assertion.
#[derive(Clone, Debug)]
pub struct DiscoveredJwt {
    /// `{iss}/.well-known/{dwk}`, using the claim bytes unchanged.
    pub metadata_url: String,
    /// `jwks_uri` from the metadata document, unchanged.
    pub jwks_uri: String,
    /// Key from that JWKS whose `kid` matches the JWT header.
    pub issuer_key: Jwk,
    /// `cnf.jwk`. It is returned only after the issuer key verifies the assertion.
    pub confirmation: Jwk,
}

/// Check metadata and JWKS bytes for an assertion that carries both `iss` and `dwk`.
///
/// `exp` equal to `now` is expired and is reported before the documents are read.
/// `issuer` must equal `iss` byte for byte.
///
/// # Errors
/// `invalid_jwt` when the assertion is malformed, `iss` is not a bare origin,
/// either discovery claim is absent, or the issuer key does not verify it.
/// `issuer_missing` and `issuer_mismatch` come from the metadata document.
/// `unknown_key` when `kid` is not in the JWKS. `unsupported_algorithm` when
/// the issuer key or `cnf.jwk` is not Ed25519, or the key `alg` differs from
/// the header `alg`. `expired_jwt` when `exp` is not after `now`.
pub fn verify_discovered_jwt(
    compact: &str,
    metadata: &[u8],
    jwks: &[u8],
    now: i64,
) -> Result<DiscoveredJwt, Error> {
    let checked = check(compact, now)?;
    let (issuer, dwk, kid) = checked.discovery.ok_or(Error::InvalidJwt)?;
    let metadata_url = format!("{issuer}/.well-known/{dwk}");
    let jwks_uri = metadata_jwks_uri(&issuer, metadata)?;
    let issuer_key = select_kid(jwks, &kid)?;
    require_issuer_alg(&issuer_key, checked.parsed.header())?;
    checked.parsed.verify(&issuer_key).map_err(map_jws)?;
    Ok(DiscoveredJwt {
        metadata_url,
        jwks_uri,
        issuer_key,
        confirmation: checked.confirmation,
    })
}

/// Verify an assertion whose `iss` or `dwk` is absent with a key the host already holds.
///
/// # Errors
/// `invalid_jwt` when both discovery claims are present, the assertion is
/// malformed, or `issuer_key` does not verify it. `unsupported_algorithm`
/// when `issuer_key` or `cnf.jwk` is not Ed25519, or the key `alg` differs
/// from the header `alg`. `expired_jwt` when `exp` is not after `now`.
pub fn verify_application_jwt(compact: &str, issuer_key: &Jwk, now: i64) -> Result<Jwk, Error> {
    let checked = check(compact, now)?;
    if checked.discovery.is_some() {
        return Err(Error::InvalidJwt);
    }
    require_issuer_alg(issuer_key, checked.parsed.header())?;
    issuer_key.validate().map_err(map_jose)?;
    checked.parsed.verify(issuer_key).map_err(map_jws)?;
    Ok(checked.confirmation)
}

struct Checked {
    parsed: Jws,
    confirmation: Jwk,
    discovery: Option<(String, String, String)>,
}

fn check(compact: &str, now: i64) -> Result<Checked, Error> {
    if !(0..=(1_i64 << 33) - 1).contains(&now) {
        return Err(Error::InvalidClock);
    }
    let parsed = Jws::parse(compact).map_err(map_jws)?;
    let claims = claims(parsed.payload())?;
    let expires_at = unix_claim(&claims, "exp")?;
    if expires_at <= now {
        return Err(Error::ExpiredJwt);
    }
    let confirmation = confirmation_jwk(claims.get("cnf"))?;
    confirmation.validate().map_err(map_jose)?;
    let issuer = optional_string(&claims, "iss")?;
    let dwk = optional_string(&claims, "dwk")?;
    let discovery = match (issuer, dwk) {
        (Some(issuer), Some(dwk)) => {
            https_origin(&issuer)?;
            if !super::discovery_name(&dwk) {
                return Err(Error::InvalidJwt);
            }
            let kid = parsed
                .header()
                .get("kid")
                .and_then(Value::as_str)
                .filter(|kid| !kid.is_empty())
                .ok_or(Error::InvalidJwt)?
                .to_owned();
            Some((issuer, dwk, kid))
        }
        (issuer, dwk) => {
            if let Some(issuer) = issuer {
                https_origin(&issuer)?;
            }
            if let Some(dwk) = dwk
                && !super::discovery_name(&dwk)
            {
                return Err(Error::InvalidJwt);
            }
            None
        }
    };
    Ok(Checked {
        parsed,
        confirmation,
        discovery,
    })
}

fn metadata_jwks_uri(expected_issuer: &str, bytes: &[u8]) -> Result<String, Error> {
    if bytes.len() > 65_536 {
        return Err(Error::InvalidKey);
    }
    let metadata = aauth_rust_jose::strict_json(bytes).map_err(|_| Error::InvalidKey)?;
    let issuer = match metadata.get("issuer") {
        Some(Value::String(value)) if !value.is_empty() => value,
        Some(Value::String(_)) => return Err(Error::IssuerMismatch),
        _ => return Err(Error::IssuerMissing),
    };
    if issuer != expected_issuer {
        return Err(Error::IssuerMismatch);
    }
    let uri = metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidKey)?;
    https_location(uri)?;
    Ok(uri.to_owned())
}

fn select_kid(bytes: &[u8], kid: &str) -> Result<Jwk, Error> {
    if bytes.len() > 65_536 {
        return Err(Error::InvalidKey);
    }
    let document = aauth_rust_jose::strict_json(bytes).map_err(|_| Error::InvalidKey)?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() <= 128)
        .ok_or(Error::InvalidKey)?;
    let mut matches = keys
        .iter()
        .filter(|value| value.get("kid").and_then(Value::as_str) == Some(kid));
    let value = matches.next().ok_or(Error::UnknownKey)?;
    if matches.next().is_some() {
        return Err(Error::InvalidKey);
    }
    let key: Jwk = serde_json::from_value(value.clone()).map_err(|_| Error::InvalidKey)?;
    if key.alg != "Ed25519" {
        return Err(Error::UnsupportedAlgorithm);
    }
    key.validate().map_err(map_jose)?;
    Ok(key)
}

fn confirmation_jwk(cnf: Option<&Value>) -> Result<Jwk, Error> {
    let cnf = cnf.and_then(Value::as_object).ok_or(Error::InvalidJwt)?;
    let jwk = cnf.get("jwk").ok_or(Error::InvalidJwt)?;
    if !jwk.is_object() {
        return Err(Error::InvalidJwt);
    }
    let key: Jwk = serde_json::from_value(jwk.clone()).map_err(|_| Error::InvalidJwt)?;
    if key.alg != "Ed25519" {
        return Err(Error::UnsupportedAlgorithm);
    }
    Ok(key)
}

fn require_issuer_alg(key: &Jwk, header: &Value) -> Result<(), Error> {
    let header_alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if key.alg != "Ed25519" || header_alg != key.alg {
        return Err(Error::UnsupportedAlgorithm);
    }
    Ok(())
}

fn claims(payload: &[u8]) -> Result<Map<String, Value>, Error> {
    let value = aauth_rust_jose::strict_json(payload).map_err(|_| Error::InvalidJwt)?;
    value.as_object().cloned().ok_or(Error::InvalidJwt)
}

fn optional_string(claims: &Map<String, Value>, name: &str) -> Result<Option<String>, Error> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        _ => Err(Error::InvalidJwt),
    }
}

fn unix_claim(claims: &Map<String, Value>, name: &str) -> Result<i64, Error> {
    match claims.get(name) {
        Some(Value::Number(number)) => number
            .as_i64()
            .filter(|number| *number >= 0)
            .ok_or(Error::InvalidJwt),
        _ => Err(Error::InvalidJwt),
    }
}

fn https_origin(value: &str) -> Result<(), Error> {
    if value.contains('#') || value.contains('?') || value.contains('@') {
        return Err(Error::InvalidJwt);
    }
    let uri: http::Uri = value.parse().map_err(|_| Error::InvalidJwt)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidJwt)?;
    let authority = uri.authority().ok_or(Error::InvalidJwt)?;
    if value != format!("https://{authority}") || uri.query().is_some() {
        return Err(Error::InvalidJwt);
    }
    Ok(())
}

fn https_location(value: &str) -> Result<(), Error> {
    if value.contains('#') || value.contains('@') || value.contains(' ') {
        return Err(Error::InvalidKey);
    }
    let uri: http::Uri = value.parse().map_err(|_| Error::InvalidKey)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidKey)?;
    Ok(())
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
