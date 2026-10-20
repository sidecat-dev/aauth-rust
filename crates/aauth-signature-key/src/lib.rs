//! Bodyless RFC 9421 request proofs with the Ed25519 `hwk` and `jwt` schemes.
//! Verification proves a key; the accepting role supplies identity and policy.
use aauth_jose::{Jwk, SigningKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::Request;
use sfv::{BareItem, Dictionary, FieldType, InnerList, List, ListEntry, Parameters, Parser};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid_signature")]
    InvalidSignature,
    #[error("invalid_input")]
    InvalidInput,
    #[error("clock_skew")]
    ClockSkew,
    #[error("invalid_key")]
    InvalidKey,
    #[error("unsupported_scheme")]
    UnsupportedScheme,
    #[error("unsupported_algorithm")]
    UnsupportedAlgorithm,
}

#[derive(Clone, Debug)]
pub enum KeyMaterial {
    Hwk(Jwk),
    Jwt(String),
}

/// Components required by this bodyless request profile.
pub fn required_components(req: &Request<Vec<u8>>) -> Vec<&'static str> {
    let mut required = vec!["@method", "@authority", "@path", "signature-key"];
    if req.uri().query().is_some() {
        required.push("@query")
    }
    if req.headers().contains_key("authorization") {
        required.push("authorization")
    }
    required
}

fn header<'a>(req: &'a Request<Vec<u8>>, name: &str) -> Result<&'a str, Error> {
    let mut values = req.headers().get_all(name).iter();
    let value = values.next().ok_or(Error::InvalidSignature)?;
    if values.next().is_some() || value.as_bytes().len() > 16384 {
        return Err(Error::InvalidInput);
    }
    value
        .to_str()
        .map(str::trim)
        .map_err(|_| Error::InvalidInput)
}
fn dictionary(req: &Request<Vec<u8>>, name: &str) -> Result<Dictionary, Error> {
    Parser::new(header(req, name)?)
        .parse()
        .map_err(|_| Error::InvalidInput)
}
fn text<'a>(params: &'a Parameters, name: &str) -> Result<&'a str, Error> {
    match params.get(name) {
        Some(BareItem::String(s)) => Ok(s.as_str()),
        _ => Err(Error::InvalidKey),
    }
}
fn parse_key(entry: &ListEntry) -> Result<KeyMaterial, Error> {
    let ListEntry::Item(item) = entry else {
        return Err(Error::InvalidInput);
    };
    let BareItem::Token(scheme) = &item.bare_item else {
        return Err(Error::InvalidInput);
    };
    match scheme.as_str() {
        "hwk" => {
            if item.params.contains_key("kid") {
                return Err(Error::InvalidKey);
            }
            let alg = text(&item.params, "alg").map_err(|_| Error::UnsupportedAlgorithm)?;
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
            if item.params.contains_key("d") {
                return Err(Error::InvalidKey);
            }
            key.validate().map_err(|_| Error::InvalidKey)?;
            Ok(KeyMaterial::Hwk(key))
        }
        "jwt" => Ok(KeyMaterial::Jwt(text(&item.params, "jwt")?.into())),
        _ => Err(Error::UnsupportedScheme),
    }
}
fn components(input: &InnerList) -> Result<Vec<&str>, Error> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for item in &input.items {
        let BareItem::String(name) = &item.bare_item else {
            return Err(Error::InvalidInput);
        };
        if !item.params.is_empty() || !seen.insert(name.as_str()) {
            return Err(Error::InvalidInput);
        }
        result.push(name.as_str());
    }
    Ok(result)
}
fn build_base(req: &Request<Vec<u8>>, input: &InnerList) -> Result<Vec<u8>, Error> {
    let names = components(input)?;
    let mut lines = Vec::new();
    for name in names {
        let value = match name {
            "@method" => req.method().as_str(),
            "@authority" => {
                let authority = req.uri().authority().ok_or(Error::InvalidInput)?;
                if authority.as_str().contains('@') {
                    return Err(Error::InvalidInput);
                }
                let raw_host = authority.host();
                if raw_host.is_empty() {
                    return Err(Error::InvalidInput);
                }
                let suffix = &authority.as_str()[raw_host.len()..];
                let port = if suffix.is_empty() {
                    None
                } else {
                    Some(
                        suffix
                            .strip_prefix(':')
                            .ok_or(Error::InvalidInput)?
                            .parse::<u16>()
                            .map_err(|_| Error::InvalidInput)?,
                    )
                };
                let host = raw_host.to_ascii_lowercase();
                let normalized = match port {
                    None | Some(443) => host,
                    Some(port) => format!("{host}:{port}"),
                };
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
            "signature-key" | "authorization" => header(req, name)?,
            _ => return Err(Error::InvalidInput),
        };
        lines.push(format!("\"{name}\": {value}"));
    }
    let params = List::from([ListEntry::InnerList(input.clone())])
        .serialize()
        .ok_or(Error::InvalidInput)?;
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
    pub fn prepare(
        req: &Request<Vec<u8>>,
        label: &str,
        now: i64,
        window: i64,
    ) -> Result<Self, Error> {
        Self::prepare_with_schemes(req, label, now, window, &["hwk", "jwt"])
    }
    /// Apply the accepting protocol's scheme profile before key resolution.
    pub fn prepare_with_schemes(
        req: &Request<Vec<u8>>,
        label: &str,
        now: i64,
        window: i64,
        accepted: &[&str],
    ) -> Result<Self, Error> {
        if !req.body().is_empty()
            || req.uri().scheme_str() != Some("https")
            || window < 0
            || now < 0
        {
            return Err(Error::InvalidInput);
        }
        let inputs = dictionary(req, "signature-input")?;
        let Some(ListEntry::InnerList(input)) = inputs.get(label) else {
            return Err(Error::InvalidInput);
        };
        let covered = components(input)?;
        let required = required_components(req);
        if required.iter().any(|s| !covered.contains(s)) {
            return Err(Error::InvalidInput);
        }
        let created = match input.params.get("created") {
            Some(BareItem::Integer(n)) => i64::from(*n),
            _ => return Err(Error::InvalidInput),
        };
        if created < 0 || created < now.saturating_sub(window) {
            return Err(Error::InvalidSignature);
        }
        if created > now.saturating_add(window) {
            return Err(Error::ClockSkew);
        }
        if input.params.contains_key("keyid") {
            return Err(Error::InvalidInput);
        }
        if let Some(expires) = input.params.get("expires") {
            match expires {
                BareItem::Integer(n) if i64::from(*n) > now => {}
                _ => return Err(Error::InvalidSignature),
            }
        }
        let keys = dictionary(req, "signature-key")?;
        let entry = keys.get(label).ok_or(Error::InvalidInput)?;
        let ListEntry::Item(item) = entry else {
            return Err(Error::InvalidInput);
        };
        let BareItem::Token(scheme) = &item.bare_item else {
            return Err(Error::InvalidInput);
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
    pub fn key(&self) -> &KeyMaterial {
        &self.key
    }
    pub fn signature_base(&self) -> &[u8] {
        &self.base
    }
    pub fn verify(&self, key: &Jwk) -> Result<(), Error> {
        key.verify(&self.base, &self.signature)
            .map_err(|e| match e {
                aauth_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
                aauth_jose::Error::InvalidKey => Error::InvalidKey,
                _ => Error::InvalidSignature,
            })
    }
}

/// Sign once, without sending, retrying or obtaining credentials.
pub fn sign_request(
    req: &mut Request<Vec<u8>>,
    key: &SigningKey,
    material: KeyMaterial,
    now: i64,
) -> Result<(), Error> {
    if !req.body().is_empty()
        || req.uri().scheme_str() != Some("https")
        || !(0..=999_999_999_999_999).contains(&now)
    {
        return Err(Error::InvalidInput);
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
        KeyMaterial::Jwt(jwt) => {
            aauth_jose::Jws::parse(&jwt).map_err(|_| Error::InvalidKey)?;
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
