//! `aauth-resource` link relation.
//!
//! These helpers return metadata targets. This library fetches nothing.
//! An admissible target is a server identifier followed by
//! `/.well-known/aauth-resource.json`. A path before that suffix, a relative
//! target, and a target outside that form are omitted. The HTML scan is not
//! limited to `head`. The link is not an authorization requirement.

use aauth_rust_jose::strict_json;
use serde_json::Value;

use crate::{TokenError, validate_server_identifier};

const SUFFIX: &str = "/.well-known/aauth-resource.json";

/// One metadata document an agent may fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLink {
    /// Absolute metadata URL.
    pub target: String,
    /// `target` without the well-known suffix.
    pub issuer: String,
}

/// Links and the requirement header from one HTTP response.
///
/// `requirement` is copied from `AAuth-Requirement` only. A link never fills it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseDiscovery {
    /// Metadata targets from the `Link` header.
    pub links: Vec<ResourceLink>,
    /// `AAuth-Requirement` field value, when that header was present.
    pub requirement: Option<String>,
}

/// `Link` targets with `rel=aauth-resource` that have the required form.
pub fn links_from_header(field: &str) -> Vec<ResourceLink> {
    if field.len() > 8192 {
        return Vec::new();
    }
    split_links(field)
        .into_iter()
        .filter_map(parse_link)
        .collect()
}

/// `link` elements in an HTML document whose `rel` contains `aauth-resource`.
pub fn links_from_html(document: &str) -> Vec<ResourceLink> {
    if document.len() > 1_048_576 {
        return Vec::new();
    }
    let mut links = Vec::new();
    let bytes = document.as_bytes();
    let mut index = 0;
    while index + 5 < bytes.len() {
        if !bytes[index..].get(..5).is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case(b"<link")
                && bytes
                    .get(index + 5)
                    .is_some_and(|next| next.is_ascii_whitespace() || *next == b'/')
        }) {
            index += 1;
            continue;
        }
        let Some(end) = document[index..].find('>') else {
            break;
        };
        if let Some(link) = link_element(&document[index..index + end]) {
            links.push(link);
        }
        index += end + 1;
    }
    links
}

/// Metadata URLs a host may fetch. This function returns targets and fetches nothing.
/// Every other target is omitted.
pub fn fetch_targets<'a>(targets: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    targets
        .into_iter()
        .filter_map(admissible_target)
        .map(|link| link.target)
        .collect()
}

/// Read discovery from the two headers. The link is not a requirement.
pub fn discovery_from_headers(link: Option<&str>, requirement: Option<&str>) -> ResponseDiscovery {
    ResponseDiscovery {
        links: link.map(links_from_header).unwrap_or_default(),
        requirement: requirement
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    }
}

/// Check that metadata `issuer` is the link target minus the well-known suffix.
///
/// # Errors
/// Returns [`TokenError::IssuerMissing`] when `issuer` is absent and
/// [`TokenError::IssuerMismatch`] when it differs. Malformed JSON is
/// [`TokenError::InvalidJwt`].
pub fn metadata_matches_link(link: &ResourceLink, bytes: &[u8]) -> Result<(), TokenError> {
    if bytes.len() > 65536 {
        return Err(TokenError::InvalidJwt);
    }
    let metadata = strict_json(bytes).map_err(|_| TokenError::InvalidJwt)?;
    let issuer = metadata
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(TokenError::IssuerMissing)?;
    if issuer != link.issuer {
        return Err(TokenError::IssuerMismatch);
    }
    Ok(())
}

fn admissible_target(target: &str) -> Option<ResourceLink> {
    let issuer = target.strip_suffix(SUFFIX)?;
    validate_server_identifier(issuer).ok()?;
    Some(ResourceLink {
        target: target.to_owned(),
        issuer: issuer.to_owned(),
    })
}

fn split_links(field: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut angle = false;
    for (index, character) in field.char_indices() {
        match character {
            '"' if !angle => quoted = !quoted,
            '<' if !quoted => angle = true,
            '>' if !quoted => angle = false,
            ',' if !quoted && !angle => {
                let part = field[start..index].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    let rest = field[start..].trim();
    if !rest.is_empty() {
        parts.push(rest);
    }
    parts
}

fn parse_link(value: &str) -> Option<ResourceLink> {
    let rest = value.trim().strip_prefix('<')?;
    let (target, rest) = rest.split_once('>')?;
    let mut rel = None;
    for parameter in rest.split(';') {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            continue;
        }
        let Some((name, raw)) = parameter.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("rel") {
            rel = Some(unquote(raw.trim()));
        }
    }
    let rel = rel?;
    if !rel
        .split_whitespace()
        .any(|token| token.eq_ignore_ascii_case("aauth-resource"))
    {
        return None;
    }
    admissible_target(target)
}

fn link_element(tag: &str) -> Option<ResourceLink> {
    let mut href = None;
    let mut rel = None;
    let mut rest = tag;
    while let Some(start) = rest.find(|character: char| character.is_ascii_alphabetic()) {
        rest = &rest[start..];
        let name_end = rest
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '-')
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        rest = rest[name_end..].trim_start();
        if !rest.starts_with('=') {
            continue;
        }
        rest = rest[1..].trim_start();
        let (value, next) = quoted_or_bare(rest)?;
        if name.eq_ignore_ascii_case("href") {
            href = Some(value);
        } else if name.eq_ignore_ascii_case("rel") {
            rel = Some(value);
        }
        rest = next;
    }
    let rel = rel?;
    if !rel
        .split_whitespace()
        .any(|token| token.eq_ignore_ascii_case("aauth-resource"))
    {
        return None;
    }
    admissible_target(&href?)
}

fn quoted_or_bare(value: &str) -> Option<(String, &str)> {
    let first = value.chars().next()?;
    if first == '"' || first == '\'' {
        let end = value[1..].find(first)?;
        return Some((value[1..1 + end].to_owned(), &value[1 + end + 1..]));
    }
    let end = value
        .find(|character: char| character.is_ascii_whitespace() || character == '>')
        .unwrap_or(value.len());
    Some((value[..end].to_owned(), &value[end..]))
}

fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
        .to_owned()
}
