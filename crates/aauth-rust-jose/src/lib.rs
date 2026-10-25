//! Ed25519 JWKs, thumbprints and compact JWS. No HTTP, discovery or role policy.
#![deny(missing_docs)]
mod json;
pub use json::strict_json;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
/// JOSE parsing, algorithm, key-shape or signature failure.
pub enum Error {
    /// unsupported signature algorithm.
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    /// invalid public key.
    #[error("invalid public key")]
    InvalidKey,
    /// invalid compact JWS.
    #[error("invalid compact JWS")]
    InvalidJws,
    /// invalid JSON: the JSON parser reason.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Public-only Ed25519 profile. Validate at every cryptographic use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type; this profile requires `OKP`.
    pub kty: String,
    #[serde(default)]
    /// Curve name; this profile requires `Ed25519`.
    pub crv: String,
    #[serde(default)]
    /// Canonical unpadded base64url encoding of the 32-byte public key.
    pub x: String,
    #[serde(default)]
    /// Fully specified algorithm; `Ed25519`, never polymorphic `EdDSA`.
    pub alg: String,
    #[serde(flatten)]
    /// Additive public metadata. Known private members are rejected at use.
    pub extra: BTreeMap<String, Value>,
}

impl Jwk {
    /// Validate algorithm, shape, public-only members and non-weak key bytes.
    ///
    /// # Errors
    /// Returns `UnsupportedAlgorithm` for an unsupported alg, or `InvalidKey`
    /// for inconsistent fields, private material or invalid/noncanonical bytes.
    pub fn validate(&self) -> Result<(), Error> {
        self.verifying_key().map(|_| ())
    }

    fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, Error> {
        if self.alg.is_empty()
            || self.kty == "oct"
            || matches!(self.alg.as_str(), "none" | "HS256" | "HS384" | "HS512")
        {
            return Err(Error::UnsupportedAlgorithm);
        }
        // AKP and any other unrecognized key type take the unsupported-algorithm
        // path, including when `alg` itself is a known name. A known type that
        // disagrees with `alg` is an inconsistent key, not an unknown one.
        if !matches!(self.kty.as_str(), "OKP" | "EC" | "RSA") {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.alg != "Ed25519" {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.kty != "OKP"
            || self.crv != "Ed25519"
            || ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
                .iter()
                .any(|name| self.extra.contains_key(*name))
        {
            return Err(Error::InvalidKey);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|_| Error::InvalidKey)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| Error::InvalidKey)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidKey)?;
        if key.is_weak() {
            return Err(Error::InvalidKey);
        }
        Ok(key)
    }

    /// Verify an Ed25519 signature over these exact message bytes.
    ///
    /// # Errors
    /// Returns a key/algorithm error or `InvalidJws` if signature verification fails.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::InvalidJws)?;
        self.verifying_key()?
            .verify_strict(message, &signature)
            .map_err(|_| Error::InvalidJws)
    }

    /// RFC 7638: only required public members, ordered lexicographically.
    ///
    /// # Errors
    /// Returns the same key/algorithm errors as [`Jwk::validate`].
    pub fn thumbprint(&self) -> Result<String, Error> {
        self.validate()?;
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, self.x);
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
    }
}

/// Caller-owned key. Secret material is deliberately absent from Debug/Serialize.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Generate a fresh Ed25519 signing key using the operating system RNG.
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
    }
    /// Import a caller-owned seed. Examples/tests use fixed seeds only as fixtures.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }
    /// Export public material only, including its fully specified algorithm.
    pub fn public_jwk(&self) -> Jwk {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(self.0.verifying_key().as_bytes()),
            alg: "Ed25519".into(),
            extra: BTreeMap::new(),
        }
    }
    /// Sign exact bytes; callers supply domain separation and protocol framing.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

/// Parsed bytes are not authenticated until `verify` succeeds.
pub struct Jws {
    compact: String,
    header: Value,
    payload: Vec<u8>,
    input: String,
    signature: Vec<u8>,
}

fn check_header(header: &Value) -> Result<(), Error> {
    if !header.is_object() {
        return Err(Error::InvalidJws);
    }
    if header.get("alg").and_then(Value::as_str) != Some("Ed25519") {
        return Err(Error::UnsupportedAlgorithm);
    }
    if !header.is_object() || header.get("crit").is_some() || header.get("b64").is_some() {
        return Err(Error::InvalidJws);
    }
    Ok(())
}

impl Jws {
    /// Create compact JWS with an Ed25519 protected header and arbitrary payload.
    /// Issuer-specific typ, kid and claim requirements belong to the token profile.
    ///
    /// # Errors
    /// Returns algorithm/header errors for an unsupported alg, crit or b64
    /// profile, or JSON serialization errors.
    pub fn sign(header: &Value, payload: &[u8], key: &SigningKey) -> Result<String, Error> {
        check_header(header)?;
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?),
            URL_SAFE_NO_PAD.encode(payload)
        );
        Ok(format!(
            "{}.{}",
            input,
            URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()))
        ))
    }
    /// Retain the original signed segments of a bounded compact JWS.
    /// Parsing never authenticates its claims.
    ///
    /// # Errors
    /// Rejects oversized/malformed compact data, noncanonical base64url, duplicate
    /// header members, non-object headers, unsupported alg, crit or b64 profiles.
    pub fn parse(compact: &str) -> Result<Self, Error> {
        if compact.len() > 16384 {
            return Err(Error::InvalidJws);
        }
        let parts: Vec<_> = compact.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|s| s.is_empty()) {
            return Err(Error::InvalidJws);
        }
        let decode = |s| URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::InvalidJws);
        let header = strict_json(&decode(parts[0])?)?;
        check_header(&header)?;
        Ok(Self {
            compact: compact.into(),
            header,
            payload: decode(parts[1])?,
            input: format!("{}.{}", parts[0], parts[1]),
            signature: decode(parts[2])?,
        })
    }
    /// Parsed protected header; untrusted until signature verification succeeds.
    pub fn header(&self) -> &Value {
        &self.header
    }
    /// Decoded payload bytes; not necessarily JSON and not yet authenticated.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Original compact serialization, unchanged after parsing.
    pub fn compact(&self) -> &str {
        &self.compact
    }
    /// Verify an Ed25519 signature over these exact message bytes.
    ///
    /// # Errors
    /// Returns a key/algorithm error or `InvalidJws` if signature verification fails.
    pub fn verify(&self, key: &Jwk) -> Result<(), Error> {
        key.verify(self.input.as_bytes(), &self.signature)
    }
}
