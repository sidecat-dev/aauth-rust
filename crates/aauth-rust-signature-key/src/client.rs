//! Client reading of advisory signature headers.
//!
//! Unknown list tokens are skipped. `Signature-Error` contributes its `error`
//! member and, for `invalid_input`, its `required_input` member. The response
//! body is not an input.
use super::{Error, select_presented_scheme};
use sfv::{BareItem, Dictionary, List, ListEntry, Parser};

/// Tokens from an `Accept-Signature-Scheme` or `Accept-Signature-Alg` list
/// that this client recognizes.
///
/// Comparison is case-sensitive. Inner lists, non-tokens, and names outside
/// `known` are ignored. An empty result means the client should not sign.
///
/// # Errors
/// Returns `invalid_input` when the field is not a Structured Field list.
pub fn recognized_tokens(field: &str, known: &[&str]) -> Result<Vec<String>, Error> {
    let list = Parser::new(field)
        .parse::<List>()
        .map_err(|_| Error::InvalidInput)?;
    let mut recognized = Vec::new();
    for entry in &list {
        let ListEntry::Item(item) = entry else {
            continue;
        };
        let BareItem::Token(token) = &item.bare_item else {
            continue;
        };
        if known.iter().any(|name| *name == token.as_str()) {
            recognized.push(token.to_string());
        }
    }
    Ok(recognized)
}

/// Scheme to present, after unknown tokens are dropped.
///
/// `cached` is skipped until `issued` is set, including when it is the first
/// recognized token. `None` means no recognized scheme can be presented.
///
/// # Errors
/// Returns `invalid_input` when `field` is not a Structured Field list.
pub fn choose_presented_scheme(
    field: &str,
    known: &[&str],
    issued: Option<&str>,
) -> Result<Option<String>, Error> {
    let recognized = recognized_tokens(field, known)?;
    let names: Vec<&str> = recognized.iter().map(String::as_str).collect();
    Ok(select_presented_scheme(&names, issued).map(str::to_owned))
}

/// `error` token from `Signature-Error`.
///
/// Other dictionary members are ignored. This function does not accept a
/// response body.
///
/// # Errors
/// Returns `invalid_input` when the field is not a dictionary or `error` is
/// missing or not a token.
pub fn signature_error_code(field: &str) -> Result<String, Error> {
    let dictionary = Parser::new(field)
        .parse::<Dictionary>()
        .map_err(|_| Error::InvalidInput)?;
    match dictionary.get("error") {
        Some(ListEntry::Item(item)) => match &item.bare_item {
            BareItem::Token(token) if !token.as_str().is_empty() => Ok(token.to_string()),
            _ => Err(Error::InvalidInput),
        },
        _ => Err(Error::InvalidInput),
    }
}

/// A `Signature-Error` field as a client reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureErrorField {
    /// The `error` token, such as `invalid_input`.
    pub code: String,
    /// For `invalid_input`, the components the server requires, in the
    /// order of its `required_input` member. `None` when the member is
    /// absent, is not an inner list of plain strings, or the code is another:
    /// the member is defined only for `invalid_input`, and a client then has
    /// to learn the components by other means, such as the server's metadata.
    pub required_input: Option<Vec<String>>,
}

/// Read `Signature-Error`: the `error` token and, for `invalid_input`, the
/// `required_input` member (`draft-hardt-httpbis-signature-key`,
/// Signature-Error, invalid_input). Other members are ignored.
///
/// # Errors
/// As for [`signature_error_code`].
pub fn parse_signature_error(field: &str) -> Result<SignatureErrorField, Error> {
    let code = signature_error_code(field)?;
    let required_input = if code == "invalid_input" {
        let dictionary = Parser::new(field)
            .parse::<Dictionary>()
            .map_err(|_| Error::InvalidInput)?;
        match dictionary.get("required_input") {
            Some(ListEntry::InnerList(list)) => list
                .items
                .iter()
                .map(|item| match &item.bare_item {
                    BareItem::String(name) if item.params.is_empty() => {
                        Some(name.as_str().to_owned())
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    } else {
        None
    };
    Ok(SignatureErrorField {
        code,
        required_input,
    })
}
