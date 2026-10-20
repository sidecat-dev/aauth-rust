//! Ed25519 JWKs, thumbprints and compact JWS. No HTTP, discovery or role policy.
mod json;
pub use json::strict_json;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid public key")]
    InvalidKey,
    #[error("invalid compact JWS")]
    InvalidJws,
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Public-only Ed25519 profile. Validate at every cryptographic use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub crv: String,
    #[serde(default)]
    pub x: String,
    #[serde(default)]
    pub alg: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Jwk {
    pub fn validate(&self) -> Result<(), Error> {
        self.verifying_key().map(|_| ())
    }

    fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, Error> {
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

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::InvalidJws)?;
        self.verifying_key()?
            .verify_strict(message, &signature)
            .map_err(|_| Error::InvalidJws)
    }

    /// RFC 7638: only required public members, ordered lexicographically.
    pub fn thumbprint(&self) -> Result<String, Error> {
        self.validate()?;
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, self.x);
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
    }
}

/// Caller-owned key. Secret material is deliberately absent from Debug/Serialize.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
    }
    /// Import a caller-owned seed. Examples/tests use fixed seeds only as fixtures.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }
    pub fn public_jwk(&self) -> Jwk {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(self.0.verifying_key().as_bytes()),
            alg: "Ed25519".into(),
            extra: BTreeMap::new(),
        }
    }
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
    pub fn header(&self) -> &Value {
        &self.header
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn compact(&self) -> &str {
        &self.compact
    }
    pub fn verify(&self, key: &Jwk) -> Result<(), Error> {
        key.verify(self.input.as_bytes(), &self.signature)
    }
}
