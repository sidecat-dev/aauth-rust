//! `self-jwt`: one discovered issuer key signs both the assertion and the HTTP request.
//! This crate does not fetch metadata. The host resolves `iss`, `dwk`, and `kid`
//! only after the JWT has parsed and the pre-signature checks have passed.
//! The scheme has no `cache` parameter and this verifier issues no cache identifier.
use super::{Error, KeyMaterial, PreparedRequest};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use serde_json::{Map, Value};

/// Host lookup of the issuer key named by a `self-jwt` header `kid`.
///
/// Called only after the JWT parses, `typ` matches, `exp` is still in the
/// future, `iss` and `dwk` and `kid` are present, and `cnf` is absent.
/// The host owns the JWKS fetch, HTTPS, and egress admission (`admit_fetch`
/// once that helper exists). This library checks that the metadata document's
/// `issuer` equals `iss` before calling the resolver, and does not fetch.
/// Return [`Error::UnknownKey`] when `kid` is not in that set.
pub trait IssuerKeyResolver {
    /// Resolve the public key for this exact issuer, discovery name, and `kid`.
    ///
    /// `issuer` is the `iss` claim with its original bytes, not a canonicalized host.
    ///
    /// # Errors
    /// [`Error::UnknownKey`] when the kid is absent. Other [`Error`] values
    /// propagate unchanged.
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, Error>;

    /// Resolve `kid` again from a fresh fetch, because the assertion's
    /// signature failed under the key [`Self::key`] answered (Signature-Key
    /// line 1218 and unknown_key, line 1054). Called at most once per
    /// verification.
    ///
    /// `Ok(None)` means no fresher key is available and the failure stands:
    /// the resolver does not fetch, or fetched this issuer within the last
    /// minute. The default answers `Ok(None)`.
    ///
    /// # Errors
    /// As for [`Self::key`].
    fn refreshed_key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Option<Jwk>, Error> {
        let _ = (issuer, dwk, kid);
        Ok(None)
    }
}

impl<F> IssuerKeyResolver for F
where
    F: Fn(&str, &str, &str) -> Result<Jwk, Error>,
{
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, Error> {
        self(issuer, dwk, kid)
    }
}

/// Verified self-issued assertion. The HTTP signature used `key_id`'s key.
/// There is no cache identifier: self-jwt is not a cacheable scheme.
#[derive(Clone, Debug)]
pub struct SelfJwtAssertion {
    /// Exact `iss` claim bytes.
    pub issuer: String,
    /// Exact `dwk` claim.
    pub discovery_document: String,
    /// JWT header `kid` passed to the resolver.
    pub key_id: String,
    /// Assertion `exp`, Unix seconds. Verification requires this to be after `now`.
    pub expires_at: i64,
    /// Exact compact serialization.
    pub compact: String,
    payload: Vec<u8>,
}

impl SelfJwtAssertion {
    /// Independent copy of the verified JWT payload bytes.
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// Self-jwt never receives a cache identifier.
    pub fn cache_identifier(&self) -> Option<&str> {
        None
    }
}

pub(crate) fn assert_signable(jwt: &str, key: &SigningKey) -> Result<(), Error> {
    let checked = check(jwt, None, 0, 0, false)?;
    checked
        .parsed
        .verify(&key.public_jwk())
        .map_err(|_| Error::InvalidKey)?;
    Ok(())
}

struct Checked {
    parsed: Jws,
    issuer: String,
    discovery_document: String,
    key_id: String,
    expires_at: i64,
}

fn check(
    jwt: &str,
    expected_typ: Option<&str>,
    now: i64,
    window: i64,
    enforce_time: bool,
) -> Result<Checked, Error> {
    let parsed = Jws::parse(jwt).map_err(map_jws)?;
    let header = parsed.header();
    if let Some(expected) = expected_typ {
        let typ = header.get("typ").and_then(Value::as_str);
        if typ != Some(expected) {
            return Err(Error::InvalidJwt);
        }
    }
    let claims = claims(parsed.payload())?;
    let expires_at = unix_claim(&claims, "exp")?;
    if enforce_time && expires_at <= now {
        return Err(Error::ExpiredJwt);
    }
    if let Some(issued_at) = optional_unix(&claims, "iat")? {
        if enforce_time && issued_at > now.saturating_add(window) {
            return Err(Error::ClockSkew);
        }
        if expires_at <= issued_at {
            return Err(Error::InvalidJwt);
        }
    }
    let issuer = required_string(&claims, "iss")?;
    https_origin(&issuer)?;
    let discovery_document = required_string(&claims, "dwk")?;
    if !super::discovery_name(&discovery_document) {
        return Err(Error::InvalidJwt);
    }
    let key_id = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.is_empty())
        .ok_or(Error::InvalidJwt)?
        .to_owned();
    if claims.contains_key("cnf") {
        return Err(Error::InvalidJwt);
    }
    Ok(Checked {
        parsed,
        issuer,
        discovery_document,
        key_id,
        expires_at,
    })
}

fn claims(payload: &[u8]) -> Result<Map<String, Value>, Error> {
    let value = aauth_rust_jose::strict_json(payload).map_err(|_| Error::InvalidJwt)?;
    value.as_object().cloned().ok_or(Error::InvalidJwt)
}

fn required_string(claims: &Map<String, Value>, name: &str) -> Result<String, Error> {
    match claims.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(Error::InvalidJwt),
    }
}

fn unix_claim(claims: &Map<String, Value>, name: &str) -> Result<i64, Error> {
    match claims.get(name) {
        Some(Value::Number(n)) => n.as_i64().filter(|n| *n >= 0).ok_or(Error::InvalidJwt),
        _ => Err(Error::InvalidJwt),
    }
}

fn optional_unix(claims: &Map<String, Value>, name: &str) -> Result<Option<i64>, Error> {
    match claims.get(name) {
        None => Ok(None),
        Some(_) => unix_claim(claims, name).map(Some),
    }
}

/// `iss` must be an HTTPS origin. The original claim bytes are kept: the host
/// is not lowercased and an explicit port is not stripped.
fn https_origin(value: &str) -> Result<(), Error> {
    if value.contains('#') || value.contains('?') || value.contains('@') {
        return Err(Error::InvalidJwt);
    }
    let uri: http::Uri = value.parse().map_err(|_| Error::InvalidJwt)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidJwt)?;
    let authority = uri.authority().ok_or(Error::InvalidJwt)?;
    // `http::Uri` reports `/` for an origin written without a path. Require the
    // claim bytes to be exactly `https://` plus that authority, so a real path
    // is rejected and the host is not rewritten.
    if value != format!("https://{authority}") || uri.query().is_some() {
        return Err(Error::InvalidJwt);
    }
    Ok(())
}

fn metadata_issuer(metadata: &[u8]) -> Result<String, Error> {
    let value = aauth_rust_jose::strict_json(metadata).map_err(|_| Error::IssuerMissing)?;
    match value
        .as_object()
        .and_then(|object| object.get("issuer"))
        .and_then(Value::as_str)
    {
        Some(issuer) if !issuer.is_empty() => Ok(issuer.to_owned()),
        _ => Err(Error::IssuerMissing),
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
    /// Verify a selected `self-jwt`, resolve its issuer key, then verify the HTTP signature.
    ///
    /// `metadata` is the discovery document bytes. Its `issuer` member must
    /// equal `iss` or the resolver is not called. `expected_typ` is the
    /// deployment policy for the JWT `typ` header. The draft registers none.
    /// A mismatch is `invalid_jwt` and does not call `resolver`. `exp` equal
    /// to `now` is expired. `iss` is passed to the resolver unchanged.
    ///
    /// # Errors
    /// `invalid_jwt` for a malformed assertion, a `cnf` claim, a bad `iss` or
    /// `dwk`, a missing `kid`, or a JWT signature that fails under the resolved
    /// key. `expired_jwt` when `exp` is not after `now`, before resolution.
    /// `unknown_key` when the resolver reports that `kid`. `invalid_signature`
    /// when the JWT verifies and the HTTP signature does not.
    /// `issuer_missing` when metadata has no issuer. `issuer_mismatch` when
    /// that issuer differs from `iss`.
    pub fn verify_self_jwt(
        &self,
        metadata: &[u8],
        resolver: &impl IssuerKeyResolver,
        now: i64,
        expected_typ: &str,
    ) -> Result<SelfJwtAssertion, Error> {
        if expected_typ.is_empty() {
            return Err(Error::InvalidKey);
        }
        if !(0..=(1_i64 << 33) - 1).contains(&now) {
            return Err(Error::InvalidClock);
        }
        let KeyMaterial::SelfJwt { jwt } = &self.key else {
            return Err(Error::InvalidKey);
        };
        let checked = check(jwt, Some(expected_typ), now, self.window, true)?;
        let documented = metadata_issuer(metadata)?;
        if documented != checked.issuer {
            return Err(Error::IssuerMismatch);
        }
        let header_alg = checked
            .parsed
            .header()
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(Error::UnsupportedAlgorithm)?;
        let check = |key: &Jwk| {
            key.validate().map_err(map_jose)?;
            if key.alg != header_alg {
                return Err(Error::InvalidKey);
            }
            checked.parsed.verify(key).map_err(map_jws)
        };
        let names = (
            checked.issuer.as_str(),
            checked.discovery_document.as_str(),
            checked.key_id.as_str(),
        );
        let mut key = resolver.key(names.0, names.1, names.2)?;
        // A failed assertion signature may mean a replaced key under the
        // same kid: one refresh, then `invalid_jwt` stands.
        match check(&key) {
            Err(Error::InvalidJwt) => match resolver.refreshed_key(names.0, names.1, names.2)? {
                Some(fresh) => {
                    check(&fresh)?;
                    key = fresh;
                }
                None => return Err(Error::InvalidJwt),
            },
            other => other?,
        }
        self.verify(&key)?;
        Ok(SelfJwtAssertion {
            issuer: checked.issuer,
            discovery_document: checked.discovery_document,
            key_id: checked.key_id,
            expires_at: checked.expires_at,
            compact: jwt.clone(),
            payload: checked.parsed.payload().to_vec(),
        })
    }
}
