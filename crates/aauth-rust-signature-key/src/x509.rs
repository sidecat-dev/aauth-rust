//! `x509` Signature-Key members.
//!
//! This crate does not fetch `x5u`. The host resolves that exact URL, passes
//! the PEM chain, and passes the trust anchors it already accepts. It also
//! fetches the certificate revocation lists (CRLs) for the chain and passes
//! them; this check verifies each CRL and refuses a certificate it revokes or
//! that no current CRL covers. OCSP is not supported. The first PEM
//! certificate is the end entity.
use super::{Error, KeyMaterial, PreparedRequest};
use aauth_rust_jose::Jwk;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls_pki_types::{
    AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm,
    TrustAnchor, UnixTime,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, EndEntityCert, ExpirationPolicy,
    ExtendedKeyUsageValidator, KeyPurposeIdIter, RevocationCheckDepth, RevocationOptionsBuilder,
    UnknownStatusPolicy,
};

/// Certificate and key that verified one `x509` proof.
#[derive(Clone, Debug)]
pub struct X509Identity {
    /// `x5u` as presented. It is not canonicalized and it was not fetched here.
    pub url: String,
    /// SHA-256 of the end-entity certificate's DER encoding. Equals `x5t`.
    pub thumbprint: Vec<u8>,
    /// Public key selected from that certificate. It verified the HTTP signature.
    pub key: Jwk,
}

const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const EC_PUBLIC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Certificate signature algorithms. The HTTP signature is verified separately.
#[derive(Clone, Copy, Debug)]
enum ChainAlg {
    Ed25519,
    P256,
    P384,
}

impl SignatureVerificationAlgorithm for ChainAlg {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match self {
            Self::Ed25519 => {
                let key: Jwk = serde_json::from_value(serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(public_key),
                }))
                .map_err(|_| InvalidSignature)?;
                key.verify(message, signature).map_err(|_| InvalidSignature)
            }
            Self::P256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let signature =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                p256::ecdsa::signature::Verifier::verify(&key, message, &signature)
                    .map_err(|_| InvalidSignature)
            }
            Self::P384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let signature =
                    p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                p384::ecdsa::signature::Verifier::verify(&key, message, &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        use rustls_pki_types::alg_id;
        match self {
            Self::Ed25519 => alg_id::ED25519,
            Self::P256 => alg_id::ECDSA_P256,
            Self::P384 => alg_id::ECDSA_P384,
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        use rustls_pki_types::alg_id;
        match self {
            Self::Ed25519 => alg_id::ED25519,
            Self::P256 => alg_id::ECDSA_SHA256,
            Self::P384 => alg_id::ECDSA_SHA384,
        }
    }
}

pub(crate) fn validate(url: &str, thumbprint: &[u8]) -> Result<(), Error> {
    https_url(url)?;
    super::quoted(url)?;
    if thumbprint.len() != 32 {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn https_url(value: &str) -> Result<(), Error> {
    if value.contains('#') || value.contains('@') || value.contains(' ') {
        return Err(Error::InvalidKey);
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(Error::InvalidKey);
    };
    if rest.is_empty() {
        return Err(Error::InvalidKey);
    }
    let uri: http::Uri = value.parse().map_err(|_| Error::InvalidKey)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidKey)?;
    let authority = uri.authority().ok_or(Error::InvalidKey)?.as_str();
    if !rest.starts_with(authority) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

struct AnyExtendedKeyUsage;

impl ExtendedKeyUsageValidator for AnyExtendedKeyUsage {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in iter {
            purpose?;
        }
        Ok(())
    }
}

impl PreparedRequest {
    /// Check the host-supplied chain, then verify the HTTP signature.
    ///
    /// `chain_pem` is the PEM the host obtained for this member's `x5u`. The
    /// first certificate is the end entity and the rest are intermediates.
    /// `trust_anchors_der` are DER trust anchors. `crls_der` are the DER
    /// RFC 5280 CRLs the host obtained for this chain. `now` is the verifier
    /// clock in Unix seconds and is compared with the certificates' validity
    /// and each CRL's `nextUpdate`.
    ///
    /// Chain validation, including revocation, runs before the thumbprint
    /// comparison and before the HTTP signature check. A leaf that matches
    /// `x5t` and whose key would verify the signature is still rejected when it
    /// does not chain to one of the supplied anchors. The end entity and every
    /// intermediate must each be covered by a supplied CRL that its issuer
    /// signed and that is not past `nextUpdate`; a certificate that one lists,
    /// or that none covers, is rejected. Pass one CRL per issuer: the first
    /// whose issuer name matches is the one checked. Delta CRLs are not
    /// supported.
    ///
    /// The end-entity subject public key selects exactly one HTTP algorithm:
    /// Ed25519, P-256 as ES256, or P-384 as ES384. `rsaEncryption` does not
    /// name a padding or a hash, so an RSA certificate is
    /// `unsupported_algorithm`.
    ///
    /// # Errors
    /// `invalid_key` when this request is not `x509`, the PEM, anchors or CRLs
    /// are unusable, the chain, validity or revocation check fails, or `x5t`
    /// does not equal the SHA-256 of the end-entity DER.
    /// `unsupported_algorithm` when the certificate key is not one of the
    /// three algorithms above.
    /// `invalid_signature` when the HTTP signature does not match that key.
    pub fn verify_x509(
        &self,
        chain_pem: &str,
        trust_anchors_der: &[&[u8]],
        crls_der: &[&[u8]],
        now: i64,
    ) -> Result<X509Identity, Error> {
        let KeyMaterial::X509 { x5u, x5t } = &self.key else {
            return Err(Error::InvalidKey);
        };
        if now < 0 {
            return Err(Error::InvalidClock);
        }
        let certs = pem_certs(chain_pem)?;
        let anchors = trust_anchors(trust_anchors_der)?;
        let lists = crls_der
            .iter()
            .map(|der| {
                BorrowedCertRevocationList::from_der(der)
                    .map(CertRevocationList::from)
                    .map_err(|_| Error::InvalidKey)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let crls: Vec<&CertRevocationList<'_>> = lists.iter().collect();
        // Every certificate in the path needs a current CRL from its issuer.
        let revocation = RevocationOptionsBuilder::new(&crls)
            .map_err(|_| Error::InvalidKey)?
            .with_depth(RevocationCheckDepth::Chain)
            .with_status_policy(UnknownStatusPolicy::Deny)
            .with_expiration_policy(ExpirationPolicy::Enforce)
            .build();
        let ee = CertificateDer::from_slice(&certs[0]);
        let end_entity = EndEntityCert::try_from(&ee).map_err(|_| Error::InvalidKey)?;
        let intermediates: Vec<CertificateDer<'_>> = certs[1..]
            .iter()
            .map(|der| CertificateDer::from_slice(der))
            .collect();
        // These algorithms verify the certificates' own signatures. Each
        // certificate names one of them. The HTTP algorithm is chosen later
        // from the end-entity key alone.
        let chain_algs: &[&dyn SignatureVerificationAlgorithm] =
            &[&ChainAlg::Ed25519, &ChainAlg::P256, &ChainAlg::P384];
        end_entity
            .verify_for_usage(
                chain_algs,
                &anchors,
                &intermediates,
                UnixTime::since_unix_epoch(Duration::from_secs(now as u64)),
                AnyExtendedKeyUsage,
                Some(revocation),
                None,
            )
            .map_err(|_| Error::InvalidKey)?;
        let thumbprint = Sha256::digest(&certs[0]);
        if thumbprint.as_slice() != x5t.as_slice() {
            return Err(Error::InvalidKey);
        }
        let key = public_key(&certs[0])?;
        let expected = key.signature_len().map_err(|_| Error::InvalidKey)?;
        if self.signature.len() != expected {
            return Err(Error::InvalidSignature);
        }
        self.verify(&key)?;
        Ok(X509Identity {
            url: x5u.clone(),
            thumbprint: thumbprint.to_vec(),
            key,
        })
    }
}

fn trust_anchors(ders: &[&[u8]]) -> Result<Vec<TrustAnchor<'static>>, Error> {
    if ders.is_empty() {
        return Err(Error::InvalidKey);
    }
    ders.iter()
        .map(|der| {
            let cert = CertificateDer::from_slice(der);
            webpki::anchor_from_trusted_cert(&cert)
                .map_err(|_| Error::InvalidKey)
                .map(|anchor| anchor.to_owned())
        })
        .collect()
}

fn pem_certs(pem: &str) -> Result<Vec<Vec<u8>>, Error> {
    let mut certs = Vec::new();
    let mut lines = pem.lines().map(str::trim).filter(|line| !line.is_empty());
    while let Some(line) = lines.next() {
        if line != "-----BEGIN CERTIFICATE-----" {
            return Err(Error::InvalidKey);
        }
        let mut encoded = String::new();
        let mut closed = false;
        for line in lines.by_ref() {
            if line == "-----END CERTIFICATE-----" {
                closed = true;
                break;
            }
            if line.starts_with("-----") {
                return Err(Error::InvalidKey);
            }
            encoded.push_str(line);
        }
        if !closed {
            return Err(Error::InvalidKey);
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| Error::InvalidKey)?;
        if der.is_empty() {
            return Err(Error::InvalidKey);
        }
        certs.push(der);
    }
    if certs.is_empty() {
        return Err(Error::InvalidKey);
    }
    Ok(certs)
}

fn public_key(der: &[u8]) -> Result<Jwk, Error> {
    let SubjectPublicKey { oid, params, raw } = subject_public_key(der)?;
    // `rsaEncryption` names neither the padding nor the hash. Choosing RS256
    // or PS256 here would be the polymorphic selection the draft forbids.
    if oid == RSA_ENCRYPTION {
        return Err(Error::UnsupportedAlgorithm);
    }
    if oid == ED25519 {
        if params.is_some() || raw.len() != 32 {
            return Err(Error::InvalidKey);
        }
        return Ok(Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(raw),
            y: String::new(),
            n: String::new(),
            e: String::new(),
            alg: "Ed25519".into(),
            extra: Default::default(),
        });
    }
    if oid == EC_PUBLIC {
        let Some((0x06, curve)) = params else {
            return Err(Error::InvalidKey);
        };
        let (coord_len, crv, alg) = if curve == P256 {
            (32, "P-256", "ES256")
        } else if curve == P384 {
            (48, "P-384", "ES384")
        } else {
            return Err(Error::UnsupportedAlgorithm);
        };
        if raw.len() != 1 + coord_len * 2 || raw[0] != 0x04 {
            return Err(Error::InvalidKey);
        }
        return Ok(Jwk {
            kty: "EC".into(),
            crv: crv.into(),
            x: URL_SAFE_NO_PAD.encode(&raw[1..1 + coord_len]),
            y: URL_SAFE_NO_PAD.encode(&raw[1 + coord_len..]),
            n: String::new(),
            e: String::new(),
            alg: alg.into(),
            extra: Default::default(),
        });
    }
    Err(Error::UnsupportedAlgorithm)
}

struct SubjectPublicKey<'a> {
    oid: &'a [u8],
    params: Option<(u8, &'a [u8])>,
    raw: &'a [u8],
}

fn subject_public_key(der: &[u8]) -> Result<SubjectPublicKey<'_>, Error> {
    let mut certificate = Reader::new(der);
    let mut certificate = certificate.sequence()?;
    let mut body = certificate.sequence()?;
    if body.input.first() == Some(&0xa0) {
        body.skip()?;
    }
    for _ in 0..5 {
        body.skip()?;
    }
    let mut spki = body.sequence()?;
    let mut algorithm = spki.sequence()?;
    let oid = algorithm.oid()?;
    let params = if algorithm.input.is_empty() {
        None
    } else {
        Some(algorithm.tlv()?)
    };
    let raw = spki.bit_string()?;
    Ok(SubjectPublicKey { oid, params, raw })
}

struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    fn sequence(&mut self) -> Result<Reader<'a>, Error> {
        let (tag, body) = self.tlv()?;
        if tag != 0x30 {
            return Err(Error::InvalidKey);
        }
        Ok(Reader { input: body })
    }

    fn oid(&mut self) -> Result<&'a [u8], Error> {
        let (tag, body) = self.tlv()?;
        if tag != 0x06 {
            return Err(Error::InvalidKey);
        }
        Ok(body)
    }

    fn bit_string(&mut self) -> Result<&'a [u8], Error> {
        let (tag, body) = self.tlv()?;
        if tag != 0x03 || body.first() != Some(&0) || body.len() < 2 {
            return Err(Error::InvalidKey);
        }
        Ok(&body[1..])
    }

    fn skip(&mut self) -> Result<(), Error> {
        self.tlv().map(|_| ())
    }

    fn tlv(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let tag = self.take(1)?[0];
        let first = self.take(1)?[0];
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 3 {
                return Err(Error::InvalidKey);
            }
            let bytes = self.take(count)?;
            let mut length = 0usize;
            for byte in bytes {
                length = (length << 8) | usize::from(*byte);
            }
            length
        };
        Ok((tag, self.take(length)?))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.input.split_at_checked(len).ok_or(Error::InvalidKey)?;
        self.input = tail;
        Ok(head)
    }
}
