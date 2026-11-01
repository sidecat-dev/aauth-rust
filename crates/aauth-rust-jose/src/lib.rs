//! Ed25519, P-256, P-384 and RSA JWKs and signing keys, Ed25519 and ES256
//! compact JWS, and signing through a caller's [`ExternalSigner`]. No HTTP,
//! discovery or role policy.
#![deny(missing_docs)]
mod json;
pub use json::strict_json;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, SecretDocument};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
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
    /// The signer failed, or an external signer returned a signature its
    /// public JWK does not verify. Nothing was signed.
    #[error("signing failed: {0}")]
    Signer(Box<dyn std::error::Error + Send + Sync>),
    /// The private key is held by an external signer, so it cannot be exported.
    #[error(
        "this key is held by an external signer: its private key is not in this process and cannot be exported"
    )]
    NotExportable,
}

/// Algorithms of the compact JWS profile, in preference order: `Ed25519`,
/// which every AAuth party must support, and `ES256`, which every party
/// should support (protocol, Signature Algorithms). AAuth tokens are compact
/// JWS, so their issuer keys and `cnf.jwk` confirmation keys use one of these.
pub const JWS_ALGORITHMS: &[&str] = &["Ed25519", "ES256"];

/// Every algorithm a [`Jwk`] or [`SigningKey`] may name.
const KEY_ALGORITHMS: [&str; 5] = ["Ed25519", "ES256", "ES384", "RS256", "PS256"];

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
        // The point must be on the curve, with coordinates below the field
        // modulus, before the key is accepted for any use.
        let point = sec1_point(&x, &y);
        let on_curve = match coord_len {
            32 => p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_ok(),
            _ => p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).is_ok(),
        };
        if !on_curve {
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

    /// RFC 7638 SHA-256 thumbprint of any key [`Jwk::validate`] accepts.
    ///
    /// It hashes only the members the key type requires, in lexicographic
    /// order: `crv`, `kty` and `x` for OKP; `crv`, `kty`, `x` and `y` for EC;
    /// `e`, `kty` and `n` for RSA. `alg` is not hashed, so one RSA key has the
    /// same thumbprint under RS256 and PS256.
    ///
    /// # Errors
    /// Returns the same key/algorithm errors as [`Jwk::validate`].
    pub fn thumbprint(&self) -> Result<String, Error> {
        // Every value below was decoded as unpadded base64url or matched a
        // fixed curve name, so none needs JSON escaping.
        let canonical = match self.classify()? {
            Material::Ed25519(_) => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, self.x),
            Material::Ecdsa { .. } => format!(
                r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                self.crv, self.x, self.y
            ),
            Material::Rsa { .. } => format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, self.e, self.n),
        };
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

/// Caller-owned private key for one fully specified algorithm, held in this
/// process or by an [`ExternalSigner`].
///
/// Ed25519 is the default: [`SigningKey::generate`] and
/// [`SigningKey::from_seed`] make Ed25519 keys. [`SigningKey::generate_es256`]
/// makes an ES256 key, [`SigningKey::from_pkcs8_der`] also imports ES256,
/// ES384, RS256 and PS256 keys, and
/// [`SigningKey::external`] signs with a key that a platform keystore, HSM,
/// secure enclave or remote service holds. Every key signs HTTP messages.
/// Compact JWS, and so every AAuth token, signs only with an algorithm in
/// [`JWS_ALGORITHMS`]: Ed25519 or ES256. [`SigningKey::export_pkcs8_der`]
/// writes an in-process key out. Secret material is deliberately absent from
/// Debug/Serialize.
pub struct SigningKey(Secret);

enum Secret {
    Ed25519(ed25519_dalek::SigningKey),
    Es256(p256::ecdsa::SigningKey),
    Es384(p384::ecdsa::SigningKey),
    Rs256(rsa::pkcs1v15::SigningKey<Sha256>),
    Ps256(rsa::pss::BlindedSigningKey<Sha256>),
    External(External),
}

struct External {
    signer: Box<dyn ExternalSigner>,
    public: Jwk,
    algorithm: &'static str,
}

/// A signer that holds its private key outside this library: a platform
/// keystore, an HSM, a secure enclave or a remote signing service.
///
/// [`SigningKey::external`] wraps one, and the result signs everywhere a
/// [`SigningKey`] does: HTTP message signatures, compact JWS, and the issuer
/// key of every role. The private key never passes through this library.
pub trait ExternalSigner: Send + Sync {
    /// The public key, with its fully specified `alg`. [`SigningKey::external`]
    /// reads it once and validates it like any other public JWK.
    fn public_jwk(&self) -> Jwk;
    /// Sign these exact bytes with the private key, hashing them as the
    /// algorithm requires (SHA-256 for ES256, RS256 and PS256, SHA-384 for
    /// ES384, none for Ed25519).
    ///
    /// Return the signature in the JWS form [`Jwk::verify`] accepts: 64 bytes
    /// for Ed25519, the fixed-size `R || S` for ECDSA (64 bytes for ES256, 96
    /// for ES384), not the DER `Ecdsa-Sig-Value` many keystores return, and
    /// the modulus length for RSA. [`SigningKey::sign`] verifies the result
    /// under [`Self::public_jwk`] before using it.
    ///
    /// # Errors
    /// Any failure of the keystore, device or service. It is returned to the
    /// caller as [`Error::Signer`].
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Unencrypted PKCS #8 private key DER from [`SigningKey::export_pkcs8_der`].
/// The bytes are zeroized when this value is dropped. Debug shows only the
/// length.
pub struct Pkcs8PrivateKey(SecretDocument);

impl Pkcs8PrivateKey {
    /// The DER bytes, the body of a `PRIVATE KEY` PEM block. Store them where
    /// only the key's owner can read them.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Pkcs8PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs8PrivateKey")
            .field("length", &self.0.as_bytes().len())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generate a fresh Ed25519 signing key using the operating system RNG.
    pub fn generate() -> Self {
        let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        Self(Secret::Ed25519(key))
    }
    /// Generate a fresh ES256 (ECDSA P-256 with SHA-256) signing key using the
    /// operating system RNG. AAuth tokens and agent keys may use it as well as
    /// Ed25519.
    pub fn generate_es256() -> Self {
        Self(Secret::Es256(p256::ecdsa::SigningKey::random(
            &mut rand_core::OsRng,
        )))
    }
    /// Import a caller-owned seed. Examples/tests use fixed seeds only as fixtures.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Self(Secret::Ed25519(key))
    }
    /// Import an unencrypted PKCS #8 private key (RFC 5958 DER, the body of a
    /// `PRIVATE KEY` PEM block) for one fully specified algorithm.
    ///
    /// The key must match `algorithm`: an Ed25519 key for `Ed25519`, a P-256
    /// key for `ES256`, a P-384 key for `ES384`, and an `rsaEncryption` key
    /// for `RS256` or `PS256`. An RSA key names neither padding nor hash, so
    /// the algorithm is never inferred from the key. RS256 is RSASSA-PKCS1-v1_5
    /// and PS256 is RSASSA-PSS with a 32-byte salt, both with SHA-256. An RSA
    /// modulus is 256 to 512 bytes (the `rsa` crate's limit for a private
    /// key), with an odd exponent of at least 3.
    ///
    /// # Errors
    /// `UnsupportedAlgorithm` when `algorithm` is not one of the five above.
    /// `InvalidKey` when `der` is not a key of that algorithm, or its public
    /// key would fail [`Jwk::validate`].
    pub fn from_pkcs8_der(algorithm: &str, der: &[u8]) -> Result<Self, Error> {
        let secret = match algorithm {
            "Ed25519" => ed25519_dalek::SigningKey::from_pkcs8_der(der).map(Secret::Ed25519),
            "ES256" => p256::ecdsa::SigningKey::from_pkcs8_der(der).map(Secret::Es256),
            "ES384" => p384::ecdsa::SigningKey::from_pkcs8_der(der).map(Secret::Es384),
            "RS256" => rsa::RsaPrivateKey::from_pkcs8_der(der)
                .map(|key| Secret::Rs256(rsa::pkcs1v15::SigningKey::new(key))),
            "PS256" => rsa::RsaPrivateKey::from_pkcs8_der(der)
                .map(|key| Secret::Ps256(rsa::pss::BlindedSigningKey::new(key))),
            _ => return Err(Error::UnsupportedAlgorithm),
        }
        .map_err(|_| Error::InvalidKey)?;
        let key = Self(secret);
        key.public_jwk().validate().map_err(|_| Error::InvalidKey)?;
        Ok(key)
    }
    /// Sign with a key `signer` holds. The private key stays with the signer.
    ///
    /// The signer's public JWK is read once and validated like any other:
    /// it needs a fully specified `alg` among `Ed25519`, `ES256`, `ES384`,
    /// `RS256` and `PS256`, a `kty` and `crv` that agree with it, valid public
    /// key bytes and no private members. Members other than those the key type
    /// requires, such as `kid`, are dropped from [`Self::public_jwk`]. An
    /// Ed25519 or ES256 signer also signs compact JWS and AAuth tokens.
    ///
    /// # Errors
    /// The errors of [`Jwk::validate`]: `UnsupportedAlgorithm` for an absent,
    /// polymorphic or unsupported `alg`, and `InvalidKey` for private members,
    /// a `kty` or `crv` that disagrees with `alg`, or bytes that are not a
    /// public key of that type.
    pub fn external(signer: impl ExternalSigner + 'static) -> Result<Self, Error> {
        let mut public = signer.public_jwk();
        public.validate()?;
        public.extra.clear();
        let algorithm = KEY_ALGORITHMS
            .into_iter()
            .find(|alg| *alg == public.alg)
            .ok_or(Error::UnsupportedAlgorithm)?;
        Ok(Self(Secret::External(External {
            signer: Box::new(signer),
            public,
            algorithm,
        })))
    }
    /// Export an in-process key's private material as unencrypted PKCS #8 DER
    /// (RFC 5958), the form [`Self::from_pkcs8_der`] reads with this key's
    /// [`Self::algorithm`].
    ///
    /// Use it to keep a [`Self::generate`] key across restarts, or to hand one
    /// key to two processes, such as an Agent Provider and an Agent. The
    /// returned bytes are zeroized when dropped; write them where only the
    /// key's owner can read them.
    ///
    /// # Errors
    /// [`Error::NotExportable`] for a key from [`Self::external`].
    /// [`Error::InvalidKey`] if the key cannot be encoded.
    pub fn export_pkcs8_der(&self) -> Result<Pkcs8PrivateKey, Error> {
        let document = match &self.0 {
            Secret::Ed25519(key) => key.to_pkcs8_der(),
            Secret::Es256(key) => key.to_pkcs8_der(),
            Secret::Es384(key) => key.to_pkcs8_der(),
            Secret::Rs256(key) => {
                let private: &rsa::RsaPrivateKey = key.as_ref();
                private.to_pkcs8_der()
            }
            Secret::Ps256(key) => {
                let private: &rsa::RsaPrivateKey = key.as_ref();
                private.to_pkcs8_der()
            }
            Secret::External(_) => return Err(Error::NotExportable),
        }
        .map_err(|_| Error::InvalidKey)?;
        Ok(Pkcs8PrivateKey(document))
    }
    /// Fully specified algorithm this key signs with, as its JWK `alg` names it.
    pub fn algorithm(&self) -> &'static str {
        match &self.0 {
            Secret::Ed25519(_) => "Ed25519",
            Secret::Es256(_) => "ES256",
            Secret::Es384(_) => "ES384",
            Secret::Rs256(_) => "RS256",
            Secret::Ps256(_) => "PS256",
            Secret::External(external) => external.algorithm,
        }
    }
    /// Export public material only, including its fully specified algorithm.
    pub fn public_jwk(&self) -> Jwk {
        let mut jwk = Jwk {
            kty: String::new(),
            crv: String::new(),
            x: String::new(),
            y: String::new(),
            n: String::new(),
            e: String::new(),
            alg: self.algorithm().into(),
            extra: BTreeMap::new(),
        };
        match &self.0 {
            Secret::Ed25519(key) => {
                jwk.kty = "OKP".into();
                jwk.crv = "Ed25519".into();
                jwk.x = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
            }
            Secret::Es256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                ec_coordinates(&mut jwk, "P-256", point.as_bytes());
            }
            Secret::Es384(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                ec_coordinates(&mut jwk, "P-384", point.as_bytes());
            }
            Secret::Rs256(key) => rsa_members(&mut jwk, key.as_ref()),
            Secret::Ps256(key) => rsa_members(&mut jwk, key.as_ref()),
            Secret::External(external) => return external.public.clone(),
        }
        jwk
    }
    /// Sign exact bytes; callers supply domain separation and protocol framing.
    ///
    /// The result is the JWS form [`Jwk::verify`] accepts: 64 bytes for
    /// Ed25519 and ES256, the fixed-size `R || S` of 96 bytes for ES384, and
    /// the modulus length for RS256 and PS256. ECDSA nonces are deterministic
    /// (RFC 6979). RSA signing draws its blinding factor, and PS256 its salt,
    /// from the operating system RNG. An external signer's signature is
    /// returned only after it verifies under the signer's public JWK.
    ///
    /// # Errors
    /// [`Error::Signer`] when an external signer fails or returns a signature
    /// its public JWK does not verify, or an in-process ECDSA or RSA operation
    /// fails. An in-process Ed25519 key always signs.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let failed = |error: rsa::signature::Error| Error::Signer(Box::new(error));
        Ok(match &self.0 {
            Secret::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
            Secret::Es256(key) => {
                let signature: p256::ecdsa::Signature = key.try_sign(message).map_err(failed)?;
                signature.to_bytes().to_vec()
            }
            Secret::Es384(key) => {
                let signature: p384::ecdsa::Signature = key.try_sign(message).map_err(failed)?;
                signature.to_bytes().to_vec()
            }
            Secret::Rs256(key) => key
                .try_sign_with_rng(&mut rand_core::OsRng, message)
                .map_err(failed)?
                .to_vec(),
            Secret::Ps256(key) => key
                .try_sign_with_rng(&mut rand_core::OsRng, message)
                .map_err(failed)?
                .to_vec(),
            Secret::External(external) => {
                let signature = external.signer.sign(message).map_err(Error::Signer)?;
                external.public.verify(message, &signature).map_err(|_| {
                    Error::Signer(
                        "the external signature does not verify under the signer's public JWK; an ECDSA signature is the fixed-size R || S, not DER"
                            .into(),
                    )
                })?;
                signature
            }
        })
    }
}

/// Uncompressed SEC1 point `0x04 || x || y`.
fn sec1_point(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    point
}

/// Split an uncompressed SEC1 point, `0x04 || x || y`, into JWK members.
fn ec_coordinates(jwk: &mut Jwk, crv: &str, point: &[u8]) {
    let (x, y) = point[1..].split_at(point.len() / 2);
    jwk.kty = "EC".into();
    jwk.crv = crv.into();
    jwk.x = URL_SAFE_NO_PAD.encode(x);
    jwk.y = URL_SAFE_NO_PAD.encode(y);
}

fn rsa_members(jwk: &mut Jwk, key: &rsa::RsaPrivateKey) {
    jwk.kty = "RSA".into();
    jwk.n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
    jwk.e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
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
    let point = sec1_point(x, y);
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
    let alg = header.get("alg").and_then(Value::as_str);
    if !alg.is_some_and(|alg| JWS_ALGORITHMS.contains(&alg)) {
        return Err(Error::UnsupportedAlgorithm);
    }
    if !header.is_object() || header.get("crit").is_some() || header.get("b64").is_some() {
        return Err(Error::InvalidJws);
    }
    Ok(())
}

impl Jws {
    /// Create compact JWS with an Ed25519 or ES256 protected header and an
    /// arbitrary payload. The header `alg` must name `key`'s own algorithm.
    /// Issuer-specific typ, kid and claim requirements belong to the token profile.
    ///
    /// # Errors
    /// Returns algorithm/header errors for an alg outside [`JWS_ALGORITHMS`],
    /// crit or b64 profile, or JSON serialization errors. A key whose
    /// algorithm differs from the header `alg` is `UnsupportedAlgorithm`, as
    /// is an ES384, RS256 or PS256 key. A signing failure is [`Error::Signer`].
    pub fn sign(header: &Value, payload: &[u8], key: &SigningKey) -> Result<String, Error> {
        check_header(header)?;
        if header.get("alg").and_then(Value::as_str) != Some(key.algorithm()) {
            return Err(Error::UnsupportedAlgorithm);
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = key.sign(input.as_bytes())?;
        Ok(format!("{}.{}", input, URL_SAFE_NO_PAD.encode(signature)))
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
    /// Verify the compact JWS. The key `alg` must equal the header `alg`,
    /// which parsing has already limited to [`JWS_ALGORITHMS`].
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
