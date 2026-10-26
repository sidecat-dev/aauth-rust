//! Helpers shared by the standard JSON definition adapters.

use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinitionError, DefinitionErrorKind, DefinitionParser,
};
use crate::error::Error;
use crate::hints::{AccessMode, OperationHints};
use crate::jsonvalue::{Json, push_key, push_string};
use crate::uri::VocabularyUri;

pub(crate) fn invalid(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::InvalidSource, reason)
}

pub(crate) fn incomplete(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::IncompleteSource, reason)
}

pub(crate) fn unresolved(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::UnresolvedDependency, reason)
}

pub(crate) fn unsupported(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::SourceKindUnsupported, reason)
}

pub(crate) fn unavailable(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::IdentityUnavailable, reason)
}

pub(crate) fn ambiguous(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::IdentityAmbiguous, reason)
}

pub(crate) fn invalid_annotation(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::InvalidAnnotation, reason)
}

/// The member spelled exactly `name`. Strict JSON has already refused duplicates.
pub(crate) fn member<'a>(members: &'a [(String, Json)], name: &str) -> Option<&'a Json> {
    members
        .iter()
        .find(|(member, _)| member.as_str() == name)
        .map(|(_, value)| value)
}

/// Whether Go `encoding/json` decodes member `name` into the struct field
/// tagged `field`.
///
/// Go matches an exact name first and otherwise folds each rune with
/// `unicode.ToUpper(unicode.ToLower(r))`. Besides ASCII case, only `ſ`, `K`
/// (Kelvin), `ı`, and `İ` fold onto an ASCII letter. Every field name here is ASCII.
pub(crate) fn go_json_name_matches(name: &str, field: &str) -> bool {
    fn fold(c: char) -> char {
        match c {
            '\u{17f}' => 'S',
            '\u{212a}' => 'K',
            '\u{130}' | '\u{131}' => 'I',
            c => c.to_ascii_uppercase(),
        }
    }
    name.chars().map(fold).eq(field.chars().map(fold))
}

/// Refuse a member that the Go reference would read as one of `fields` but
/// that is not spelled exactly so.
///
/// Go decodes these objects into structs and so reads `"Tools"` or `"ſtatus"`
/// as the typed member, and a later variant overwrites an earlier exact one.
/// Reading only the exact spelling would make the two implementations derive
/// different operations from one source, so such a source is refused.
pub(crate) fn refuse_field_variants(
    members: &[(String, Json)],
    fields: &[&str],
    context: &str,
) -> Result<(), DefinitionError> {
    for (name, _) in members {
        for field in fields {
            if name.as_str() != *field && go_json_name_matches(name, field) {
                return Err(invalid(format!(
                    "{context} member \"{name}\" is a case variant of \"{field}\""
                )));
            }
        }
    }
    Ok(())
}

/// Read the two published annotations of one operation.
///
/// `Ok(None)` means neither annotation is present. An access mode must be a
/// JSON string naming an annotation mode and a budget must be a JSON boolean;
/// `null` is neither.
pub(crate) fn published_hints(
    access_mode: Option<&Json>,
    budget: Option<&Json>,
    context: &str,
) -> Result<Option<OperationHints>, DefinitionError> {
    let access_mode = match access_mode {
        None => None,
        Some(Json::String(text)) => match AccessMode::parse(text) {
            Ok(mode) => Some(mode),
            Err(err) => {
                let reason = format!("{context} access mode is not an access mode");
                return Err(invalid_annotation(reason).with_cause(err));
            }
        },
        Some(_) => {
            return Err(invalid_annotation(format!(
                "{context} access mode must be a string"
            )));
        }
    };
    let budget = match budget {
        None => None,
        Some(Json::Bool(value)) => Some(*value),
        Some(_) => {
            return Err(invalid_annotation(format!(
                "{context} budget must be a boolean"
            )));
        }
    };
    if access_mode.is_none() && budget.is_none() {
        return Ok(None);
    }
    match OperationHints::new(access_mode, budget) {
        Ok(hints) => Ok(Some(hints)),
        Err(err) => {
            let reason = format!("{context} hints are invalid");
            Err(invalid_annotation(reason).with_cause(err))
        }
    }
}

/// `{"<name>":"<value>"}`, the shape of a one-member standard operation.
pub(crate) fn single_member_operation(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![b'{'];
    push_key(&mut out, name);
    push_string(&mut out, value);
    out.push(b'}');
    out
}

/// Resolve an RFC 6901 JSON Pointer that is already percent-decoded.
pub(crate) fn json_pointer<'a>(root: &'a Json, pointer: &str) -> Option<&'a Json> {
    if pointer.is_empty() {
        return Some(root);
    }
    let rest = pointer.strip_prefix('/')?;
    let mut current = root;
    for token in rest.split('/') {
        let token = unescape_pointer_token(token)?;
        current = match current {
            Json::Object(members) => member(members, &token)?,
            Json::Array(items) => items.get(array_index(&token)?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Undo the `~0` and `~1` escapes of one JSON Pointer token.
pub(crate) fn unescape_pointer_token(token: &str) -> Option<String> {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c != '~' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            _ => return None,
        }
    }
    Some(out)
}

fn array_index(token: &str) -> Option<usize> {
    let canonical = token == "0" || (!token.starts_with('0') && !token.is_empty());
    if !canonical || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// Decode `%XX` escapes. `None` for an invalid escape or a result that is not UTF-8.
pub(crate) fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            out.push(high * 16 + low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The process-wide parser for one standard vocabulary.
pub(crate) fn cached_parser<S: ?Sized + 'static>(
    cell: &'static OnceLock<Option<DefinitionParser<S>>>,
    build: impl FnOnce() -> Result<DefinitionParser<S>, Error>,
    uri: &'static str,
) -> Result<DefinitionParser<S>, Error> {
    cell.get_or_init(|| build().ok()).clone().ok_or_else(|| {
        Error::new(format!(
            "r3: standard definition parser for \"{uri}\" did not register"
        ))
    })
}

/// Parse through a standard parser, reporting an unavailable parser as a
/// typed refusal for that vocabulary.
pub(crate) fn parse_standard<S: ?Sized + 'static>(
    parser: Result<DefinitionParser<S>, Error>,
    uri: &'static str,
    endpoint: &str,
    source: &S,
) -> Result<AuthoritativeSnapshot, DefinitionError> {
    match parser {
        Ok(parser) => parser.parse(endpoint, source),
        Err(err) => Err(invalid("standard definition parser is unavailable")
            .with_cause(err)
            .for_vocabulary(VocabularyUri::from_static(uri))),
    }
}
