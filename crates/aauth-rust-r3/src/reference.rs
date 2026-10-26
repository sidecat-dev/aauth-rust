use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize, Serializer};

use crate::error::Error;
use crate::jsonvalue::refuse_deserialize;

/// Exact R3 artifact bytes at an HTTPS URI.
///
/// A reference is not a nested JSON object. Callers carry `r3_uri` and `r3_s256`
/// as sibling claims.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reference {
    uri: String,
    digest: String,
}

impl Reference {
    /// Validate an absolute HTTPS URI and a canonical unpadded base64url SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`Error`] when the URI is not absolute HTTPS without userinfo or a
    /// fragment, or when the digest is not 32 canonical bytes.
    pub fn new(uri: impl Into<String>, digest: impl Into<String>) -> Result<Self, Error> {
        let reference = Self {
            uri: uri.into(),
            digest: digest.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Absolute HTTPS artifact URI, unchanged from construction.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Canonical unpadded base64url SHA-256 digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        validate_https_uri(&self.uri, "reference URI")?;
        validate_digest(&self.digest)
    }
}

impl Serialize for Reference {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "r3: Reference has no context-free JSON form; encode r3_uri and r3_s256 as sibling claims",
        ))
    }
}

impl<'de> Deserialize<'de> for Reference {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        refuse_deserialize(
            deserializer,
            "r3: Reference has no context-free JSON form; use Reference::new with r3_uri and r3_s256",
        )
    }
}

/// Absolute HTTPS URI with a host, no userinfo, and no fragment. `what` names
/// the value in error text.
pub(crate) fn validate_https_uri(uri: &str, what: &str) -> Result<(), Error> {
    let not_https = || Error::new(format!("r3: {what} must be an absolute HTTPS URI"));
    if uri.is_empty()
        || uri
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte < 0x20)
    {
        return Err(not_https());
    }
    let Some(scheme_end) = uri.find(':') else {
        return Err(not_https());
    };
    let scheme = &uri[..scheme_end];
    if !is_scheme(scheme) || !scheme.eq_ignore_ascii_case("https") {
        return Err(not_https());
    }
    let rest = &uri[scheme_end + 1..];
    if !rest.starts_with("//") {
        return Err(not_https());
    }
    let after = &rest[2..];
    let authority_end = after.find(['/', '?']).unwrap_or(after.len());
    let authority = &after[..authority_end];
    if authority.is_empty() {
        return Err(not_https());
    }
    if authority.contains('@') {
        return Err(Error::new(format!("r3: {what} must not contain userinfo")));
    }
    let hostname = hostname_of(authority, what)?;
    if hostname.is_empty() {
        return Err(not_https());
    }
    if uri.contains('#') {
        return Err(Error::new(format!("r3: {what} must not contain a fragment")));
    }
    Ok(())
}

fn is_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
        }
        _ => false,
    }
}

fn hostname_of<'a>(authority: &'a str, what: &str) -> Result<&'a str, Error> {
    if let Some(host) = authority.strip_prefix('[') {
        let Some(end) = host.find(']') else {
            return Err(Error::new(format!("r3: invalid {what}: missing ']'")));
        };
        let hostname = &host[..end];
        let after = &host[end + 1..];
        if after.is_empty() {
            return Ok(hostname);
        }
        let Some(port) = after.strip_prefix(':') else {
            return Err(Error::new(format!("r3: invalid {what}: invalid host")));
        };
        if !port.is_empty() && !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::new(format!("r3: invalid {what}: invalid port")));
        }
        return Ok(hostname);
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(host);
        }
        return Err(Error::new(format!("r3: invalid {what}: invalid port")));
    }
    Ok(authority)
}

fn validate_digest(digest: &str) -> Result<(), Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(digest)
        .map_err(|err| Error::new(format!("r3: invalid reference digest: {err}")))?;
    if bytes.len() != 32 {
        return Err(Error::new("r3: reference digest must encode 32 bytes"));
    }
    if URL_SAFE_NO_PAD.encode(&bytes) != digest {
        return Err(Error::new(
            "r3: reference digest is not canonical unpadded base64url",
        ));
    }
    Ok(())
}
