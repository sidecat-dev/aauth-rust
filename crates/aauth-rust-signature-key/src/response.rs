//! RFC 9421 response signatures (Sections 2.4 and 3) with a `Signature-Key`
//! response field naming the signer.
//!
//! A component is written as the signer asks for it: `@status` or a lowercase
//! response field name, or a request component with `;req` appended:
//! `@method;req`, `@authority;req`, `@path;req`, `@query;req`, or a lowercase
//! request field name such as `content-digest;req`. The request components
//! bind the response to the request it answers.
use super::{
    DERIVED_COMPONENTS, Error, KeyMaterial, MAX_BODY_BYTES, RequestSignature, canonical_authority,
    content_digest, field_component, field_value, key_identifier, parse_key, scheme_accepts,
    signature_member,
};
use aauth_rust_jose::{Jwk, SigningKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, Request, Response};
use sfv::{BareItem, Dictionary, FieldType, InnerList, List, ListEntry, Parser};
use std::collections::BTreeSet;

/// One covered component: its name and whether it is read from the request.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Component {
    name: String,
    request: bool,
}

impl Component {
    fn parse(value: &str) -> Result<Self, Error> {
        let (name, request) = match value.strip_suffix(";req") {
            Some(name) => (name, true),
            None => (value, false),
        };
        let usable = if request {
            DERIVED_COMPONENTS.contains(&name) || field_component(name)
        } else {
            name == "@status" || field_component(name)
        };
        if !usable {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            name: name.to_owned(),
            request,
        })
    }
    fn label(&self) -> String {
        if self.request {
            format!("{};req", self.name)
        } else {
            self.name.clone()
        }
    }
    fn identifier(&self) -> String {
        if self.request {
            format!("\"{}\";req", self.name)
        } else {
            format!("\"{}\"", self.name)
        }
    }
}

/// Sign `response` as the answer to `request`, covering `components` in order.
///
/// Sets `Content-Digest` from the actual response content when
/// `content-digest` is listed, then `Signature-Key`, `Signature-Input` (with
/// `created` and, when the key material names one, `keyid`) and `Signature`
/// under the label `sig`. Call after the status, body and other fields are
/// final. `now` is Unix seconds in 0..=8589934591.
///
/// # Errors
/// [`Error::InvalidInput`] for an empty list, a repeated or unusable
/// component, or a listed field that neither message carries.
/// [`Error::BodyTooLarge`] above 1 MiB, [`Error::InvalidClock`] for a clock
/// outside the profile, and the key-material errors of request signing.
/// [`Error::SigningFailed`] when the key's external signer fails; the
/// response then carries no `Signature` field.
pub fn sign_response(
    response: &mut Response<Vec<u8>>,
    request: &Request<Vec<u8>>,
    key: &SigningKey,
    material: KeyMaterial,
    components: &[&str],
    now: i64,
) -> Result<(), Error> {
    if response.body().len() > MAX_BODY_BYTES {
        return Err(Error::BodyTooLarge);
    }
    if !(0..=(1_i64 << 33) - 1).contains(&now) {
        return Err(Error::InvalidClock);
    }
    let parsed = parse_list(components)?;
    let member = signature_member(&RequestSignature {
        label: "sig",
        key,
        material: material.clone(),
    })?;
    for component in &parsed {
        let generated = !component.request
            && matches!(component.name.as_str(), "content-digest" | "signature-key");
        let headers = if component.request {
            request.headers()
        } else {
            response.headers()
        };
        if !component.name.starts_with('@')
            && !generated
            && !headers.contains_key(component.name.as_str())
        {
            return Err(Error::InvalidInput);
        }
    }
    if parsed
        .iter()
        .any(|c| !c.request && c.name == "content-digest")
    {
        let digest = content_digest::field(response.body());
        response.headers_mut().insert(
            "content-digest",
            digest.parse().map_err(|_| Error::InvalidDigest)?,
        );
    }
    response.headers_mut().insert(
        "signature-key",
        member.parse().map_err(|_| Error::InvalidInput)?,
    );
    let covered = parsed
        .iter()
        .map(Component::identifier)
        .collect::<Vec<_>>()
        .join(" ");
    let mut input = format!("sig=({covered});created={now}");
    if let Some(kid) = key_identifier(&material)? {
        input.push_str(&format!(";keyid=\"{kid}\""));
    }
    response.headers_mut().insert(
        "signature-input",
        input.parse().map_err(|_| Error::InvalidInput)?,
    );
    let inputs: Dictionary = Parser::new(&input)
        .parse()
        .map_err(|_| Error::InvalidInput)?;
    let Some(ListEntry::InnerList(inner)) = inputs.get("sig") else {
        return Err(Error::InvalidInput);
    };
    let base = response_base(response, request, inner)?;
    response.headers_mut().remove("signature");
    let signature = key.sign(&base).map_err(|_| Error::SigningFailed)?;
    let signature = format!("sig=:{}:", STANDARD.encode(signature));
    response.headers_mut().insert(
        "signature",
        signature.parse().map_err(|_| Error::InvalidInput)?,
    );
    Ok(())
}

/// Components named by an `Accept-Signature` field (RFC 9421 Section 5.1)
/// for `label`, in the form [`sign_response`] takes.
///
/// # Errors
/// [`Error::InvalidSignature`] for a field that does not parse, a missing
/// label, or an item that is not a component string with at most `;req`.
pub fn accept_signature_components(field: &str, label: &str) -> Result<Vec<String>, Error> {
    let dictionary: Dictionary = Parser::new(field)
        .parse()
        .map_err(|_| Error::InvalidSignature)?;
    let Some(ListEntry::InnerList(inner)) = dictionary.get(label) else {
        return Err(Error::InvalidSignature);
    };
    Ok(components(inner)?.iter().map(Component::label).collect())
}

/// A captured response signature. No signer is trusted until
/// [`PreparedResponse::verify`] succeeds with a key the role resolved.
pub struct PreparedResponse {
    key: KeyMaterial,
    base: Vec<u8>,
    signature: Vec<u8>,
    covered: Vec<Component>,
    created: i64,
}

impl PreparedResponse {
    /// Capture the labeled signature on `response`, the answer to `request`.
    ///
    /// The scheme of the response's `Signature-Key` member must be in
    /// `accepted`. A covered response `Content-Digest` must match the actual
    /// response content, and a covered request `Content-Digest` the request
    /// content. Freshness is the caller's: a stored exchange verifies later
    /// exactly as it did on arrival, and [`Self::created`] says when it was signed.
    ///
    /// # Errors
    /// [`Error::InvalidSignature`] for missing or malformed signature fields
    /// or components, [`Error::InvalidDigest`] for a digest that does not
    /// match, and the key-conveyance errors of request verification.
    pub fn prepare(
        response: &Response<Vec<u8>>,
        request: &Request<Vec<u8>>,
        label: &str,
        accepted: &[&str],
    ) -> Result<Self, Error> {
        if response.body().len() > MAX_BODY_BYTES || request.body().len() > MAX_BODY_BYTES {
            return Err(Error::BodyTooLarge);
        }
        let headers = response.headers();
        if ["signature", "signature-input", "signature-key"]
            .iter()
            .any(|name| !headers.contains_key(*name))
        {
            return Err(Error::InvalidSignature);
        }
        let inputs = dictionary(headers, "signature-input")?;
        let Some(ListEntry::InnerList(inner)) = inputs.get(label) else {
            return Err(Error::InvalidSignature);
        };
        let covered = components(inner)?;
        let created = match inner.params.get("created") {
            Some(BareItem::Integer(n)) if i64::from(*n) >= 0 => i64::from(*n),
            _ => return Err(Error::InvalidSignature),
        };
        if let Some(expires) = inner.params.get("expires") {
            match expires {
                BareItem::Integer(n) if i64::from(*n) > created => {}
                _ => return Err(Error::InvalidSignature),
            }
        }
        for component in &covered {
            if component.name == "content-digest" {
                let (field, body) = if component.request {
                    (
                        field_value(request.headers(), "content-digest"),
                        request.body(),
                    )
                } else {
                    (field_value(headers, "content-digest"), response.body())
                };
                content_digest::verify_field(&field.map_err(|_| Error::InvalidDigest)?, body)?;
            }
        }
        let key_header = field_value(headers, "signature-key").map_err(|_| Error::InvalidKey)?;
        let keys: Dictionary = Parser::new(&key_header)
            .parse()
            .map_err(|_| Error::InvalidKey)?;
        let entry = keys.get(label).ok_or(Error::InvalidSignature)?;
        let ListEntry::Item(item) = entry else {
            return Err(Error::InvalidKey);
        };
        let BareItem::Token(scheme) = &item.bare_item else {
            return Err(Error::InvalidKey);
        };
        if !accepted.contains(&scheme.as_str()) {
            return Err(Error::UnsupportedScheme);
        }
        let (key, _) = parse_key(entry, &key_header, label)?;
        if let Some(keyid) = inner.params.get("keyid") {
            let BareItem::String(keyid) = keyid else {
                return Err(Error::InvalidSignature);
            };
            match key_identifier(&key)? {
                Some(kid) if kid == keyid.as_str() => {}
                _ => return Err(Error::UnsupportedKeyId),
            }
        }
        let signatures = dictionary(headers, "signature")?;
        let Some(ListEntry::Item(signature)) = signatures.get(label) else {
            return Err(Error::InvalidSignature);
        };
        let BareItem::ByteSequence(bytes) = &signature.bare_item else {
            return Err(Error::InvalidSignature);
        };
        if !signature.params.is_empty() {
            return Err(Error::InvalidSignature);
        }
        // As for a request: a key resolved later is checked by `verify`, so a
        // key type this verifier does not implement is `unsupported_algorithm`.
        let accepted_len = match &key {
            KeyMaterial::Hwk(jwk) => {
                bytes.len()
                    == jwk.signature_len().map_err(|err| match err {
                        aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
                        _ => Error::InvalidKey,
                    })?
            }
            _ => true,
        };
        if !accepted_len {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            key,
            base: response_base(response, request, inner)?,
            signature: bytes.clone(),
            covered,
            created,
        })
    }
    /// Selected unverified signer reference for the role to resolve.
    pub fn key(&self) -> &KeyMaterial {
        &self.key
    }
    /// Whether the signature covers `component`, written as for [`sign_response`].
    pub fn covers(&self, component: &str) -> bool {
        Component::parse(component).is_ok_and(|wanted| self.covered.contains(&wanted))
    }
    /// The signature's `created` time in Unix seconds.
    pub fn created(&self) -> i64 {
        self.created
    }
    /// Exact RFC 9421 signature base reconstructed from both messages.
    pub fn signature_base(&self) -> &[u8] {
        &self.base
    }
    /// Verify the captured signature with the resolved public key.
    ///
    /// # Errors
    /// Returns algorithm or key errors, or `InvalidSignature` for a bad signature.
    pub fn verify(&self, key: &Jwk) -> Result<(), Error> {
        if !scheme_accepts(&self.key, key) {
            return Err(Error::UnsupportedAlgorithm);
        }
        key.verify(&self.base, &self.signature)
            .map_err(|e| match e {
                aauth_rust_jose::Error::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
                aauth_rust_jose::Error::InvalidKey => Error::InvalidKey,
                _ => Error::InvalidSignature,
            })
    }
}

impl std::fmt::Debug for PreparedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedResponse")
            .field("created", &self.created)
            .field("base_length", &self.base.len())
            .finish_non_exhaustive()
    }
}

fn parse_list(components: &[&str]) -> Result<Vec<Component>, Error> {
    if components.is_empty() {
        return Err(Error::InvalidInput);
    }
    let mut seen = BTreeSet::new();
    let mut parsed = Vec::with_capacity(components.len());
    for value in components {
        let component = Component::parse(value)?;
        if !seen.insert(component.clone()) {
            return Err(Error::InvalidInput);
        }
        parsed.push(component);
    }
    Ok(parsed)
}

fn dictionary(headers: &HeaderMap, name: &str) -> Result<Dictionary, Error> {
    Parser::new(&field_value(headers, name)?)
        .parse()
        .map_err(|_| Error::InvalidSignature)
}

fn components(input: &InnerList) -> Result<Vec<Component>, Error> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for item in &input.items {
        let BareItem::String(name) = &item.bare_item else {
            return Err(Error::InvalidSignature);
        };
        let request = match item.params.len() {
            0 => false,
            1 if item.params.get("req") == Some(&BareItem::Boolean(true)) => true,
            _ => return Err(Error::InvalidSignature),
        };
        let label = if request {
            format!("{};req", name.as_str())
        } else {
            name.as_str().to_owned()
        };
        let component = Component::parse(&label).map_err(|_| Error::InvalidSignature)?;
        if !seen.insert(component.clone()) {
            return Err(Error::InvalidSignature);
        }
        result.push(component);
    }
    if result.is_empty() {
        return Err(Error::InvalidSignature);
    }
    Ok(result)
}

fn response_base(
    response: &Response<Vec<u8>>,
    request: &Request<Vec<u8>>,
    input: &InnerList,
) -> Result<Vec<u8>, Error> {
    let mut lines = Vec::new();
    for component in components(input)? {
        let value = match (component.name.as_str(), component.request) {
            ("@status", false) => response.status().as_u16().to_string(),
            ("@method", true) => request.method().as_str().to_owned(),
            ("@authority", true) => canonical_authority(request.uri())?,
            ("@path", true) => {
                let path = request.uri().path();
                if path.is_empty() { "/" } else { path }.to_owned()
            }
            ("@query", true) => format!("?{}", request.uri().query().unwrap_or("")),
            (field, true) => field_value(request.headers(), field)?,
            (field, false) => field_value(response.headers(), field)?,
        };
        lines.push(format!("{}: {value}", component.identifier()));
    }
    let params = List::from([ListEntry::InnerList(input.clone())])
        .serialize()
        .ok_or(Error::InvalidSignature)?;
    lines.push(format!("\"@signature-params\": {params}"));
    Ok(lines.join("\n").into_bytes())
}
