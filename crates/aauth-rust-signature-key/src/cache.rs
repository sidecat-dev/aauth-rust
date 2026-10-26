//! Assertion cache for `jwt` and `jkt-jwt`.
//!
//! The identifier is an XChaCha20-Poly1305 seal under a verifier key. It carries
//! 192 random bits plus the scheme, issuer, optional subject, the SHA-256 of
//! the verified compact assertion, both expiries, and the confirmation key.
//! Another node that holds the same key can open it. A local index records
//! what this process has not evicted. Opening the seal is not authentication:
//! the HTTP signature is still checked against the confirmation key.
use super::{Error, KeyMaterial, PreparedRequest};
use aauth_rust_jose::{Jwk, Jws};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Longest remaining assertion lifetime this cache will accept.
/// The draft does not define "long-lived". Beyond this, caching is refused
/// and no separate revocation list is consulted.
pub const MAX_CACHEABLE_LIFETIME: i64 = 86_400;

const NONCE_LEN: usize = 24;

/// A cache request built only from an assertion this library has verified.
#[derive(Debug)]
pub struct CacheRequest {
    label: String,
    scheme: &'static str,
    issuer: String,
    subject: Option<String>,
    assertion_sha256: [u8; 32],
    confirmation: Jwk,
    jti: String,
    assertion_exp: i64,
    retain_until: i64,
    now: i64,
}

impl CacheRequest {
    /// Verify `compact` under `issuer_key`, then retain its identity.
    ///
    /// The confirmation key is `cnf.jwk` from the verified payload. A host
    /// cannot substitute a different key, issuer, or `jti`.
    ///
    /// # Errors
    /// `invalid_jwt` when the compact assertion, `iss`, `jti`, `exp`, or
    /// confirmation is unusable. `unsupported_algorithm` when `cnf.jwk` is
    /// not Ed25519. `invalid_key` when the issuer signature fails as a key
    /// error.
    pub fn verified_jwt(
        label: &str,
        compact: &str,
        issuer_key: &Jwk,
        retain_until: i64,
        now: i64,
    ) -> Result<Self, Error> {
        let parsed = Jws::parse(compact).map_err(map_jws)?;
        parsed.verify(issuer_key).map_err(map_jws)?;
        let payload =
            aauth_rust_jose::strict_json(parsed.payload()).map_err(|_| Error::InvalidJwt)?;
        Self::from_verified("jwt", label, compact, &payload, retain_until, now)
    }

    /// Verify a `jkt-s256+jwt` under its header key, then retain its identity.
    ///
    /// # Errors
    /// Same classes as [`CacheRequest::verified_jwt`]. `jti` is required.
    pub fn verified_jkt(
        label: &str,
        compact: &str,
        retain_until: i64,
        now: i64,
    ) -> Result<Self, Error> {
        let delegation = super::jkt::parse_jkt(compact, true)?;
        if delegation.jti.is_none() {
            return Err(Error::InvalidJwt);
        }
        let parsed = Jws::parse(compact).map_err(map_jws)?;
        let payload =
            aauth_rust_jose::strict_json(parsed.payload()).map_err(|_| Error::InvalidJwt)?;
        let request = Self::from_verified("jkt-jwt", label, compact, &payload, retain_until, now)?;
        if request.issuer != delegation.issuer
            || request.confirmation.x != delegation.confirmation.x
        {
            return Err(Error::InvalidJwt);
        }
        Ok(request)
    }

    /// Move the verifier clock used for retention checks. Issuance still
    /// requires `retain_until` after this clock.
    pub fn at(mut self, now: i64) -> Self {
        self.now = now;
        self
    }

    fn from_verified(
        scheme: &'static str,
        label: &str,
        compact: &str,
        payload: &Value,
        retain_until: i64,
        now: i64,
    ) -> Result<Self, Error> {
        let issuer = payload
            .get("iss")
            .and_then(Value::as_str)
            .filter(|issuer| !issuer.is_empty())
            .ok_or(Error::InvalidJwt)?
            .to_owned();
        let subject = match payload.get("sub") {
            None => None,
            Some(Value::String(subject)) if !subject.is_empty() => Some(subject.clone()),
            _ => return Err(Error::InvalidJwt),
        };
        let jti = payload
            .get("jti")
            .and_then(Value::as_str)
            .filter(|jti| !jti.is_empty())
            .ok_or(Error::InvalidJwt)?
            .to_owned();
        let assertion_exp = payload
            .get("exp")
            .and_then(Value::as_i64)
            .filter(|exp| *exp >= 0)
            .ok_or(Error::InvalidJwt)?;
        let confirmation = confirmation_jwk(payload.get("cnf"))?;
        confirmation.validate().map_err(|_| Error::InvalidKey)?;
        if confirmation.alg != "Ed25519" {
            return Err(Error::UnsupportedAlgorithm);
        }
        let digested = Sha256::digest(compact.as_bytes());
        let mut assertion_sha256 = [0u8; 32];
        assertion_sha256.copy_from_slice(&digested);
        Ok(Self {
            label: label.to_owned(),
            scheme,
            issuer,
            subject,
            assertion_sha256,
            confirmation,
            jti,
            assertion_exp,
            retain_until,
            now,
        })
    }
}

/// Identifier issued for one cached assertion.
#[derive(Clone, Debug)]
pub struct CacheGrant {
    /// Signature label the identifier was issued for.
    pub label: String,
    /// Opaque `cid`. Present this string unchanged.
    pub cid: String,
    /// Assertion `jti` echoed for the caller.
    pub jti: String,
    /// Advisory retention time. It is not later than the assertion `exp`.
    pub expires: i64,
}

impl CacheGrant {
    /// `Signature-Key-Cache` field value for this grant.
    ///
    /// # Errors
    /// Returns `invalid_key` when the label or `jti` cannot be serialized.
    pub fn field_value(&self) -> Result<String, Error> {
        token(&self.label)?;
        Ok(format!(
            "{}={};jti={};expires={}",
            self.label,
            super::quoted(&self.cid)?,
            super::quoted(&self.jti)?,
            self.expires
        ))
    }
}

/// Assertion recovered from a cache identifier. The HTTP signature is not
/// checked yet. The identity fields are the ones sealed at issuance.
#[derive(Clone, Debug)]
pub struct CachedAssertion {
    /// `jwt` or `jkt-jwt`.
    pub scheme: String,
    /// Assertion `iss`.
    pub issuer: String,
    /// Assertion `sub` when the verified payload carried one.
    pub subject: Option<String>,
    /// SHA-256 of the compact assertion that was verified before issuance.
    pub assertion_sha256: [u8; 32],
    /// Assertion `jti`.
    pub jti: String,
    /// Confirmation key that must verify the HTTP signature.
    pub confirmation: Jwk,
    /// Assertion `exp`.
    pub assertion_exp: i64,
    /// Verifier retention deadline.
    pub retain_until: i64,
}

struct Slot {
    bucket: String,
    retain_until: i64,
}

/// Verifier-side assertion cache. The AEAD key is shared by a verifier fleet,
/// is not readable from [`Debug`](std::fmt::Debug), and is overwritten with
/// zeros when the cache is dropped.
pub struct AssertionCache {
    key: [u8; 32],
    entries: BTreeMap<String, Slot>,
    by_key: BTreeMap<String, usize>,
    max_entries: usize,
    per_key: usize,
}

impl std::fmt::Debug for AssertionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssertionCache")
            .field("entries", &self.entries.len())
            .field("max_entries", &self.max_entries)
            .field("per_key", &self.per_key)
            .finish_non_exhaustive()
    }
}

impl Drop for AssertionCache {
    fn drop(&mut self) {
        zero_key(&mut self.key);
    }
}

impl AssertionCache {
    /// Empty cache. `max_entries` bounds the index. `per_key` bounds entries
    /// that share one confirmation key.
    ///
    /// # Errors
    /// Returns `invalid_key` when either bound is zero.
    pub fn open(mut key: [u8; 32], max_entries: usize, per_key: usize) -> Result<Self, Error> {
        if max_entries == 0 || per_key == 0 {
            zero_key(&mut key);
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            key,
            entries: BTreeMap::new(),
            by_key: BTreeMap::new(),
            max_entries,
            per_key,
        })
    }

    /// Issue a grant when `requested` is set.
    ///
    /// `request` comes from [`CacheRequest::verified_jwt`] or
    /// [`CacheRequest::verified_jkt`]. A retention time later than
    /// `assertion_exp` is `invalid_key`. An assertion with more than
    /// [`MAX_CACHEABLE_LIFETIME`] seconds left, or a full index, stores
    /// nothing and returns `None`. Index slots whose retention has passed
    /// are dropped before that capacity check.
    ///
    /// # Errors
    /// `invalid_key` when retention exceeds the assertion.
    /// `invalid_clock` when a time is negative. `expired_jwt` when the
    /// assertion is already expired.
    pub fn issue_requested(
        &mut self,
        requested: bool,
        request: CacheRequest,
    ) -> Result<Option<CacheGrant>, Error> {
        if !requested {
            return Ok(None);
        }
        let CacheRequest {
            label,
            scheme,
            issuer,
            subject,
            assertion_sha256,
            confirmation,
            jti,
            assertion_exp,
            retain_until,
            now,
        } = request;
        if jti.is_empty() {
            return Err(Error::InvalidJwt);
        }
        if now < 0 || assertion_exp < 0 || retain_until < 0 {
            return Err(Error::InvalidClock);
        }
        if assertion_exp <= now {
            return Err(Error::ExpiredJwt);
        }
        if retain_until > assertion_exp || retain_until <= now {
            return Err(Error::InvalidKey);
        }
        if assertion_exp - now > MAX_CACHEABLE_LIFETIME {
            return Ok(None);
        }
        token(&label)?;
        self.drop_expired(now);
        let bucket = confirmation.thumbprint().map_err(|_| Error::InvalidKey)?;
        if self.entries.len() >= self.max_entries
            || self.by_key.get(&bucket).copied().unwrap_or(0) >= self.per_key
        {
            return Ok(None);
        }
        let mut plain = json!({
            "scheme": scheme,
            "iss": issuer,
            "sha256": URL_SAFE_NO_PAD.encode(assertion_sha256),
            "jti": jti,
            "exp": assertion_exp,
            "retain": retain_until,
            "x": confirmation.x,
        });
        if let Some(subject) = &subject {
            plain["sub"] = json!(subject);
        }
        let cid = seal(&self.key, &plain.to_string())?;
        self.entries.insert(
            cid.clone(),
            Slot {
                bucket: bucket.clone(),
                retain_until,
            },
        );
        *self.by_key.entry(bucket).or_insert(0) += 1;
        Ok(Some(CacheGrant {
            label,
            cid,
            jti,
            expires: retain_until,
        }))
    }

    /// Drop a local index entry. A peer that shares the AEAD key can still
    /// open the seal until its retention time.
    pub fn evict(&mut self, cid: &str) -> bool {
        let Some(slot) = self.entries.remove(cid) else {
            return false;
        };
        if let Some(count) = self.by_key.get_mut(&slot.bucket) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.by_key.remove(&slot.bucket);
            }
        }
        true
    }

    fn drop_expired(&mut self, now: i64) {
        let stale: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, slot)| slot.retain_until <= now)
            .map(|(cid, _)| cid.clone())
            .collect();
        for cid in stale {
            self.evict(&cid);
        }
    }

    /// Resolve `cid` only when this process still indexes it.
    ///
    /// # Errors
    /// `cache_miss` when the identifier is unknown, evicted, expired as a
    /// cache entry, or fails to open. An assertion that is still retained and
    /// past its own `exp` is returned so the caller can reject it as
    /// `expired_jwt`.
    pub fn resolve(&self, cid: &str, now: i64) -> Result<CachedAssertion, Error> {
        if !self.entries.contains_key(cid) {
            return Err(Error::CacheMiss);
        }
        self.open_shared(cid, now)
    }

    /// Open a seal with this fleet key, ignoring the local index.
    ///
    /// # Errors
    /// `cache_miss` when the seal does not open or retention has passed.
    pub fn open_shared(&self, cid: &str, now: i64) -> Result<CachedAssertion, Error> {
        if now < 0 {
            return Err(Error::InvalidClock);
        }
        let opened = unseal(&self.key, cid)?;
        // `expires` is honored through that second. A miss begins after it,
        // so an entry retained until the assertion `exp` can still fail as
        // `expired_jwt` at that second.
        if now > opened.retain_until {
            return Err(Error::CacheMiss);
        }
        Ok(opened)
    }
}

impl PreparedRequest {
    /// Whether the selected `jwt` or `jkt-jwt` member carried a bare `cache` flag.
    pub fn cache_requested(&self) -> bool {
        self.cache
    }

    /// Resolve a local cache entry and verify the HTTP signature.
    ///
    /// # Errors
    /// `invalid_key` when this request is not `cached`. `cache_miss` when the
    /// identifier does not resolve. `invalid_signature` when it resolves but
    /// the HTTP signature does not match the confirmation key.
    /// `expired_jwt` when the signature matches and the assertion `exp` is not
    /// after `now`.
    pub fn verify_cached(
        &self,
        cache: &AssertionCache,
        now: i64,
    ) -> Result<CachedAssertion, Error> {
        let KeyMaterial::Cached { cid } = &self.key else {
            return Err(Error::InvalidKey);
        };
        self.finish_cached(cache.resolve(cid, now), now)
    }

    /// Resolve a self-contained identifier with the fleet key and verify the
    /// HTTP signature. The issuing process's local index is not required.
    ///
    /// # Errors
    /// Same as [`PreparedRequest::verify_cached`].
    pub fn verify_cached_sealed(
        &self,
        cache: &AssertionCache,
        now: i64,
    ) -> Result<CachedAssertion, Error> {
        let KeyMaterial::Cached { cid } = &self.key else {
            return Err(Error::InvalidKey);
        };
        self.finish_cached(cache.open_shared(cid, now), now)
    }

    fn finish_cached(
        &self,
        resolved: Result<CachedAssertion, Error>,
        now: i64,
    ) -> Result<CachedAssertion, Error> {
        let resolved = resolved?;
        self.verify(&resolved.confirmation)?;
        if resolved.assertion_exp <= now {
            return Err(Error::ExpiredJwt);
        }
        Ok(resolved)
    }
}

/// Scheme a client may present. `cached` is skipped until `issued` is set,
/// including when `cached` is the first accepted token.
pub fn select_presented_scheme<'a>(accepted: &'a [&str], issued: Option<&str>) -> Option<&'a str> {
    let mut fallback = None;
    for scheme in accepted {
        if *scheme == "cached" {
            if issued.is_some() {
                return Some(*scheme);
            }
            continue;
        }
        if fallback.is_none() {
            fallback = Some(*scheme);
        }
    }
    fallback
}

/// Accept `cid` only when it is the exact identifier a verifier issued.
///
/// # Errors
/// `invalid_key` when nothing was issued or `cid` differs by any byte.
pub fn present_issued_cid(issued: Option<&str>, cid: &str) -> Result<(), Error> {
    match issued {
        Some(expected) if expected == cid => Ok(()),
        _ => Err(Error::InvalidKey),
    }
}

pub(crate) fn require_cacheable_jwt(compact: &str) -> Result<(), Error> {
    let jws = Jws::parse(compact).map_err(|err| match err {
        aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
        _ => Error::InvalidJwt,
    })?;
    let payload = aauth_rust_jose::strict_json(jws.payload()).map_err(|_| Error::InvalidJwt)?;
    let jti = payload.get("jti").and_then(Value::as_str).unwrap_or("");
    if jti.is_empty() {
        return Err(Error::InvalidJwt);
    }
    match payload.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp >= 0 => Ok(()),
        _ => Err(Error::InvalidJwt),
    }
}

fn confirmation_jwk(cnf: Option<&Value>) -> Result<Jwk, Error> {
    let cnf = cnf.and_then(Value::as_object).ok_or(Error::InvalidJwt)?;
    let jwk = cnf.get("jwk").ok_or(Error::InvalidJwt)?;
    serde_json::from_value(jwk.clone()).map_err(|_| Error::InvalidJwt)
}

fn map_jws(err: aauth_rust_jose::Error) -> Error {
    match err {
        aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
        aauth_rust_jose::Error::InvalidKey => Error::InvalidKey,
        _ => Error::InvalidJwt,
    }
}

fn zero_key(key: &mut [u8; 32]) {
    for byte in key.iter_mut() {
        // Volatile so the wipe is not deleted as a dead store.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn seal(key: &[u8; 32], plain: &str) -> Result<String, Error> {
    let aead = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = aead
        .encrypt(XNonce::from_slice(&nonce_bytes), plain.as_bytes())
        .map_err(|_| Error::InvalidKey)?;
    let mut sealed = nonce_bytes.to_vec();
    sealed.extend(ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(sealed))
}

fn unseal(key: &[u8; 32], cid: &str) -> Result<CachedAssertion, Error> {
    let bytes = URL_SAFE_NO_PAD.decode(cid).map_err(|_| Error::CacheMiss)?;
    if bytes.len() <= NONCE_LEN {
        return Err(Error::CacheMiss);
    }
    let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
    let aead = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::CacheMiss)?;
    let plain = aead
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| Error::CacheMiss)?;
    let value: Value = serde_json::from_slice(&plain).map_err(|_| Error::CacheMiss)?;
    let scheme = value
        .get("scheme")
        .and_then(Value::as_str)
        .filter(|scheme| *scheme == "jwt" || *scheme == "jkt-jwt")
        .ok_or(Error::CacheMiss)?
        .to_owned();
    let issuer = value
        .get("iss")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty())
        .ok_or(Error::CacheMiss)?
        .to_owned();
    let subject = match value.get("sub") {
        None => None,
        Some(Value::String(subject)) if !subject.is_empty() => Some(subject.clone()),
        _ => return Err(Error::CacheMiss),
    };
    let digest = value
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or(Error::CacheMiss)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(digest)
        .map_err(|_| Error::CacheMiss)?;
    let assertion_sha256: [u8; 32] = decoded.try_into().map_err(|_| Error::CacheMiss)?;
    let jti = value
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty())
        .ok_or(Error::CacheMiss)?
        .to_owned();
    let assertion_exp = value
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(Error::CacheMiss)?;
    let retain_until = value
        .get("retain")
        .and_then(Value::as_i64)
        .ok_or(Error::CacheMiss)?;
    let x = value
        .get("x")
        .and_then(Value::as_str)
        .ok_or(Error::CacheMiss)?;
    let confirmation = Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: x.to_owned(),
        y: String::new(),
        n: String::new(),
        e: String::new(),
        alg: "Ed25519".into(),
        extra: Default::default(),
    };
    confirmation.validate().map_err(|_| Error::CacheMiss)?;
    Ok(CachedAssertion {
        scheme,
        issuer,
        subject,
        assertion_sha256,
        jti,
        confirmation,
        assertion_exp,
        retain_until,
    })
}

pub(crate) fn token(label: &str) -> Result<(), Error> {
    let mut chars = label.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '*' => {}
        _ => return Err(Error::InvalidKey),
    }
    if !sf_key(label) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn sf_key(label: &str) -> bool {
    let mut chars = label.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first == '*' => {}
        _ => return false,
    }
    chars
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.' | '*'))
}
