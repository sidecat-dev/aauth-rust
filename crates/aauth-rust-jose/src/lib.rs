//! Ed25519, P-256, P-384 and RSA JWKs, plus Ed25519 compact JWS. No HTTP, discovery or role policy.
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

/// Public JWK for Ed25519, ES256, ES384, RS256, or PS256. Validate at every use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: `OKP`, `EC`, or `RSA`.
    pub kty: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    /// Curve name. Required for `OKP` and `EC`.
    pub crv: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    /// Public key or EC X coordinate, unpadded base64url.
    pub x: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    /// EC Y coordinate, unpadded base64url. Required for `EC`.
    pub y: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    /// RSA modulus, unpadded base64url. Required for `RSA`.
    pub n: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    /// RSA public exponent, unpadded base64url. Required for `RSA`.
    pub e: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    /// Fully specified algorithm. `EdDSA` and names that omit padding or hash are rejected.
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
        self.classify().map(|_| ())
    }

    /// Byte length of a signature this key accepts.
    ///
    /// # Errors
    /// Same as [`Jwk::validate`].
    pub fn signature_len(&self) -> Result<usize, Error> {
        Ok(match self.classify()? {
            Material::Ed25519(_) | Material::Ecdsa { coord_len: 32, .. } => 64,
            Material::Ecdsa { coord_len: 48, .. } => 96,
            Material::Rsa { n, .. } => n.len(),
            Material::Ecdsa { .. } => return Err(Error::InvalidKey),
        })
    }

    fn classify(&self) -> Result<Material, Error> {
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
        if ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
            .iter()
            .any(|name| self.extra.contains_key(*name))
        {
            return Err(Error::InvalidKey);
        }
        match (self.kty.as_str(), self.alg.as_str()) {
            ("OKP", "Ed25519") => {
                if self.crv != "Ed25519"
                    || !self.y.is_empty()
                    || !self.n.is_empty()
                    || !self.e.is_empty()
                {
                    return Err(Error::InvalidKey);
                }
                let raw = b64(&self.x)?;
                let bytes: [u8; 32] = raw.try_into().map_err(|_| Error::InvalidKey)?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| Error::InvalidKey)?;
                if key.is_weak() {
                    return Err(Error::InvalidKey);
                }
                Ok(Material::Ed25519(key))
            }
            ("EC", "ES256") => self.ecdsa("P-256", 32),
            ("EC", "ES384") => self.ecdsa("P-384", 48),
            ("RSA", "RS256") => self.rsa(RsaPadding::Pkcs1),
            ("RSA", "PS256") => self.rsa(RsaPadding::Pss),
            ("OKP", "ES256" | "ES384" | "RS256" | "PS256")
            | ("EC", "Ed25519" | "RS256" | "PS256")
            | ("RSA", "Ed25519" | "ES256" | "ES384") => Err(Error::InvalidKey),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

    fn ecdsa(&self, crv: &str, coord_len: usize) -> Result<Material, Error> {
        if self.crv != crv || !self.n.is_empty() || !self.e.is_empty() {
            return Err(Error::InvalidKey);
        }
        let x = b64(&self.x)?;
        let y = b64(&self.y)?;
        if x.len() != coord_len || y.len() != coord_len {
            return Err(Error::InvalidKey);
        }
        Ok(Material::Ecdsa { x, y, coord_len })
    }

    fn rsa(&self, padding: RsaPadding) -> Result<Material, Error> {
        if !self.crv.is_empty() || !self.x.is_empty() || !self.y.is_empty() {
            return Err(Error::InvalidKey);
        }
        let n = unsigned(&self.n)?;
        let e = unsigned(&self.e)?;
        if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 5 || e[0] == 0 {
            return Err(Error::InvalidKey);
        }
        let mut value = 0u64;
        for byte in &e {
            value = value
                .checked_shl(8)
                .and_then(|shifted| shifted.checked_add(u64::from(*byte)))
                .ok_or(Error::InvalidKey)?;
        }
        if value < 3 || value & 1 == 0 {
            return Err(Error::InvalidKey);
        }
        Ok(Material::Rsa { n, e, padding })
    }

    fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, Error> {
        match self.classify()? {
            Material::Ed25519(key) => Ok(key),
            _ => Err(Error::InvalidKey),
        }
    }

    /// Verify a signature over these exact message bytes.
    ///
    /// Ed25519, ES256, and ES384 use the raw signature. RS256 is RSASSA-PKCS1-v1_5
    /// with SHA-256. PS256 is RSASSA-PSS with SHA-256. `n` and `e` are minimal
    /// unsigned integers: no leading zero octet, a modulus of 256 to 1024 bytes,
    /// and an odd exponent of at least 3. The `alg` member selects the operation;
    /// key type alone does not.
    ///
    /// # Errors
    /// Returns a key/algorithm error or `InvalidJws` if signature verification fails.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match self.classify()? {
            Material::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| Error::InvalidJws)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| Error::InvalidJws)
            }
            Material::Ecdsa { x, y, coord_len } => {
                verify_ecdsa(coord_len, &x, &y, message, signature)
            }
            Material::Rsa { n, e, padding } => verify_rsa(&n, &e, padding, message, signature),
        }
    }

    /// RFC 7638 thumbprint of an Ed25519 public key.
    ///
    /// # Errors
    /// Returns the same key/algorithm errors as [`Jwk::validate`]. Other
    /// accepted algorithms do not use this thumbprint.
    pub fn thumbprint(&self) -> Result<String, Error> {
        self.verifying_key()?;
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, self.x);
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
    }
}

enum Material {
    Ed25519(ed25519_dalek::VerifyingKey),
    Ecdsa {
        x: Vec<u8>,
        y: Vec<u8>,
        coord_len: usize,
    },
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
        padding: RsaPadding,
    },
}

#[derive(Clone, Copy)]
enum RsaPadding {
    Pkcs1,
    Pss,
}

fn b64(value: &str) -> Result<Vec<u8>, Error> {
    if value.is_empty() {
        return Err(Error::InvalidKey);
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::InvalidKey)
}

fn unsigned(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = b64(value)?;
    // RFC 7518 Base64urlUInt requires the minimum number of octets.
    if bytes.is_empty() || bytes[0] == 0 {
        return Err(Error::InvalidKey);
    }
    Ok(bytes)
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
            y: String::new(),
            n: String::new(),
            e: String::new(),
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

fn verify_ecdsa(
    coord_len: usize,
    x: &[u8],
    y: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    match coord_len {
        32 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| Error::InvalidKey)?;
            let signature =
                p256::ecdsa::Signature::from_slice(signature).map_err(|_| Error::InvalidJws)?;
            p256::ecdsa::signature::Verifier::verify(&key, message, &signature)
                .map_err(|_| Error::InvalidJws)
        }
        48 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| Error::InvalidKey)?;
            let signature =
                p384::ecdsa::Signature::from_slice(signature).map_err(|_| Error::InvalidJws)?;
            p384::ecdsa::signature::Verifier::verify(&key, message, &signature)
                .map_err(|_| Error::InvalidJws)
        }
        _ => Err(Error::InvalidKey),
    }
}

fn verify_rsa(
    n: &[u8],
    e: &[u8],
    padding: RsaPadding,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use rsa::signature::Verifier;
    let key = rsa::RsaPublicKey::new_with_max_size(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
        8192,
    )
    .map_err(|_| Error::InvalidKey)?;
    match padding {
        RsaPadding::Pkcs1 => {
            let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
            let signature =
                rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| Error::InvalidJws)?;
            verifier
                .verify(message, &signature)
                .map_err(|_| Error::InvalidJws)
        }
        RsaPadding::Pss => {
            let verifier = rsa::pss::VerifyingKey::<sha2::Sha256>::new(key);
            let signature =
                rsa::pss::Signature::try_from(signature).map_err(|_| Error::InvalidJws)?;
            verifier
                .verify(message, &signature)
                .map_err(|_| Error::InvalidJws)
        }
    }
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
    /// Verify the compact JWS. The key `alg` must equal the header `alg`.
    ///
    /// # Errors
    /// `unsupported_algorithm` when the key names a different algorithm than
    /// the header. Other failures are key errors or `InvalidJws`.
    pub fn verify(&self, key: &Jwk) -> Result<(), Error> {
        let header_alg = self
            .header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(Error::UnsupportedAlgorithm)?;
        if key.alg != header_alg {
            return Err(Error::UnsupportedAlgorithm);
        }
        key.verify(self.input.as_bytes(), &self.signature)
    }
}
