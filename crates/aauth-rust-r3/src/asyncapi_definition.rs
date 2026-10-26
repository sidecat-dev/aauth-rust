//! AsyncAPI authoritative definitions: one self-contained AsyncAPI 3.0.0 or
//! 3.1.0 JSON document.
//!
//! Ported from Go `r3/vocab/asyncapi/definition.go`, a focused profile. Every
//! `$ref` anywhere in the document must be a same-document pointer. Each
//! operation's map key is its `operationId`; it must name an existing local
//! channel, carry `action` `send` or `receive`, and use no traits. An operation
//! that is itself a reference is not resolved. YAML conversion, fetching, and
//! reference resolution stay outside this parser.

use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinedOperation, DefinitionCodec, DefinitionError,
    DefinitionMaterial, DefinitionParser, DefinitionRegistration, SourceEncoding,
};
use crate::definition_support::{
    cached_parser, incomplete, invalid, member, parse_standard, percent_decode, published_hints,
    refuse_field_variants, unescape_pointer_token, unresolved, unsupported,
};
use crate::error::Error;
use crate::jsonvalue::{Json, parse_json, push_key, push_string};
use crate::standard::AsyncApiCodec;
use crate::vocabulary::{Operation, Vocabulary};

/// Exact bytes of one AsyncAPI document in its JSON form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncApiDocumentSource {
    exact: Vec<u8>,
}

impl AsyncApiDocumentSource {
    /// Receipt encoding: the exact JSON document bytes. Shared with the Go reference.
    pub const SOURCE_ENCODING: &'static str =
        "urn:aauth:source-encoding:asyncapi-application-json-focused-v1";

    /// Copy the exact document bytes.
    pub fn new(exact: &[u8]) -> Self {
        Self {
            exact: exact.to_vec(),
        }
    }

    /// The exact document bytes.
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}

struct AsyncApiDefinitionCodec;

impl DefinitionCodec<AsyncApiDocumentSource> for AsyncApiDefinitionCodec {
    fn vocabulary(&self) -> Result<Vocabulary, Error> {
        AsyncApiCodec::vocabulary()
    }

    fn parse_definition(
        &self,
        source: &AsyncApiDocumentSource,
    ) -> Result<DefinitionMaterial, DefinitionError> {
        parse_document(source)
    }
}

impl AsyncApiCodec {
    /// The process-wide AsyncAPI definition parser. Every call returns the
    /// same parser registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the AsyncAPI vocabulary is unavailable.
    pub fn definition_parser() -> Result<DefinitionParser<AsyncApiDocumentSource>, Error> {
        static PARSER: OnceLock<Option<DefinitionParser<AsyncApiDocumentSource>>> =
            OnceLock::new();
        cached_parser(
            &PARSER,
            || DefinitionParser::new(AsyncApiDefinitionCodec),
            Self::URI,
        )
    }

    /// Derive an authoritative snapshot from one AsyncAPI JSON document for
    /// the advertised discovery `endpoint`. Performs no I/O.
    ///
    /// # Errors
    /// Returns a typed [`DefinitionError`]: `source_kind_unsupported` for
    /// another version or operation traits; `incomplete_source` for missing
    /// info, channels, operations, or a channel reference;
    /// `unresolved_dependency` for an external, missing, or referenced
    /// channel or operation; `invalid_annotation` for invalid hints;
    /// `invalid_source` otherwise.
    pub fn parse_definition(
        endpoint: &str,
        source: &AsyncApiDocumentSource,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        parse_standard(Self::definition_parser(), Self::URI, endpoint, source)
    }

    /// Registration of [`Self::definition_parser`], for a [`crate::DefinitionRegistry`].
    ///
    /// # Errors
    /// Returns [`Error`] when the AsyncAPI vocabulary is unavailable.
    pub fn definition_registration() -> Result<DefinitionRegistration, Error> {
        Self::definition_parser().map(|parser| parser.registration())
    }
}

fn parse_document(source: &AsyncApiDocumentSource) -> Result<DefinitionMaterial, DefinitionError> {
    let document = match parse_json(&source.exact) {
        Ok(document) => document,
        Err(err) => return Err(invalid("invalid AsyncAPI JSON").with_cause(err)),
    };
    refuse_external_references(&document)?;
    // Go decodes the root into a struct, so `null` reads as an empty document.
    let members: &[(String, Json)] = match &document {
        Json::Object(members) => members,
        Json::Null => &[],
        _ => return Err(invalid("AsyncAPI document must be a JSON object")),
    };
    refuse_field_variants(
        members,
        &["asyncapi", "info", "channels", "operations"],
        "AsyncAPI document",
    )?;
    // Go decodes every typed member before reading any, so a type mismatch in
    // one of them is refused before the version is considered.
    let version = match member(members, "asyncapi") {
        None | Some(Json::Null) => "",
        Some(Json::String(version)) => version.as_str(),
        Some(_) => return Err(invalid("AsyncAPI asyncapi must be a string")),
    };
    let channels = object_map(member(members, "channels"), "channels")?;
    let operations = object_map(member(members, "operations"), "operations")?;
    if version != "3.0.0" && version != "3.1.0" {
        return Err(unsupported(
            "only AsyncAPI 3.0.0 and 3.1.0 JSON documents are supported",
        ));
    }
    validate_info(member(members, "info"))?;
    if channels.is_empty() {
        return Err(incomplete("AsyncAPI document has no channels"));
    }
    if operations.is_empty() {
        return Err(incomplete("AsyncAPI document has no operations"));
    }
    let vocabulary = match AsyncApiCodec::vocabulary() {
        Ok(vocabulary) => vocabulary,
        Err(err) => return Err(invalid("AsyncAPI vocabulary is unavailable").with_cause(err)),
    };
    let mut ordered: Vec<&(String, Json)> = operations.iter().collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    let mut defined = Vec::with_capacity(ordered.len());
    for (identifier, operation) in ordered {
        defined.push(parse_operation(identifier, operation, channels, &vocabulary)?);
    }
    let encoding = match SourceEncoding::new(AsyncApiDocumentSource::SOURCE_ENCODING) {
        Ok(encoding) => encoding,
        Err(err) => return Err(invalid("AsyncAPI source encoding").with_cause(err)),
    };
    DefinitionMaterial::new(encoding, source.exact.clone(), defined)
        .map_err(|err| invalid("assemble AsyncAPI definition material").with_cause(err))
}

/// A member Go decodes into a map: absent and `null` are empty.
fn object_map<'a>(
    value: Option<&'a Json>,
    name: &str,
) -> Result<&'a [(String, Json)], DefinitionError> {
    match value {
        None | Some(Json::Null) => Ok(&[]),
        Some(Json::Object(members)) => Ok(members),
        Some(_) => Err(invalid(format!("AsyncAPI {name} must be an object"))),
    }
}

/// Go reads `info` with a lenient decode and reports any failure as an
/// incomplete `info`.
fn validate_info(value: Option<&Json>) -> Result<(), DefinitionError> {
    let missing = || incomplete("AsyncAPI info requires title and version");
    let Some(Json::Object(members)) = value else {
        return Err(missing());
    };
    refuse_field_variants(members, &["title", "version"], "AsyncAPI info")?;
    let filled = |name: &str| {
        matches!(member(members, name), Some(Json::String(value)) if !value.is_empty())
    };
    if filled("title") && filled("version") {
        Ok(())
    } else {
        Err(missing())
    }
}

fn parse_operation(
    identifier: &str,
    value: &Json,
    channels: &[(String, Json)],
    vocabulary: &Vocabulary,
) -> Result<DefinedOperation, DefinitionError> {
    let Json::Object(fields) = value else {
        return Err(invalid(format!(
            "AsyncAPI operation \"{identifier}\" is not an object"
        )));
    };
    if member(fields, "$ref").is_some() {
        return Err(unresolved(format!(
            "AsyncAPI operation \"{identifier}\" is a reference"
        )));
    }
    if member(fields, "traits").is_some() {
        return Err(unsupported(format!(
            "AsyncAPI operation \"{identifier}\" uses traits outside the focused parser profile"
        )));
    }
    validate_channel(identifier, member(fields, "channel"), channels)?;
    let action = match member(fields, "action") {
        Some(Json::String(action)) if matches!(action.as_str(), "send" | "receive") => {
            action.as_str()
        }
        _ => {
            return Err(invalid(format!(
                "AsyncAPI operation \"{identifier}\" requires action send or receive"
            )));
        }
    };
    let raw = operation_json(identifier, action);
    if let Err(err) = Operation::new(vocabulary, &raw) {
        return Err(invalid("invalid AsyncAPI operation identity").with_cause(err));
    }
    let hints = published_hints(
        member(fields, "x-aauth-access-mode"),
        member(fields, "x-aauth-budget"),
        &format!("AsyncAPI operation \"{identifier}\""),
    )?;
    DefinedOperation::new(&raw, hints.as_ref())
        .map_err(|err| invalid("construct derived AsyncAPI operation").with_cause(err))
}

fn validate_channel(
    identifier: &str,
    value: Option<&Json>,
    channels: &[(String, Json)],
) -> Result<(), DefinitionError> {
    // Go decodes the channel into a struct with one string `$ref`. Anything
    // that leaves the reference empty is an incomplete operation.
    let reference = match value {
        Some(Json::Object(members)) => {
            refuse_field_variants(members, &["$ref"], "AsyncAPI channel reference")?;
            match member(members, "$ref") {
                Some(Json::String(reference)) => reference.as_str(),
                _ => "",
            }
        }
        _ => "",
    };
    if reference.is_empty() {
        return Err(incomplete(format!(
            "AsyncAPI operation \"{identifier}\" requires a channel reference"
        )));
    }
    let Some(name) = local_channel_name(reference) else {
        return Err(unresolved(format!(
            "AsyncAPI operation \"{identifier}\" uses external channel reference \"{reference}\""
        )));
    };
    let Some(channel) = member(channels, &name) else {
        return Err(unresolved(format!(
            "AsyncAPI operation \"{identifier}\" references missing channel \"{name}\""
        )));
    };
    let Json::Object(channel_fields) = channel else {
        return Err(invalid(format!("AsyncAPI channel \"{name}\" is not an object")));
    };
    if member(channel_fields, "$ref").is_some() {
        return Err(unresolved(format!(
            "AsyncAPI channel \"{name}\" requires reference resolution"
        )));
    }
    Ok(())
}

/// The one channel name a `#/channels/<token>` reference names, after URI
/// fragment percent-decoding and JSON Pointer unescaping.
fn local_channel_name(reference: &str) -> Option<String> {
    let token = percent_decode(reference.strip_prefix("#/channels/")?)?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    unescape_pointer_token(&token)
}

/// Walk the whole document in sorted member order, as Go does, refusing a
/// non-string `$ref` and any `$ref` that is not a same-document pointer.
fn refuse_external_references(value: &Json) -> Result<(), DefinitionError> {
    match value {
        Json::Object(members) => {
            if let Some(reference) = member(members, "$ref") {
                let Json::String(reference) = reference else {
                    return Err(invalid("AsyncAPI $ref must be a string"));
                };
                if !reference.starts_with("#/") {
                    return Err(unresolved(format!(
                        "AsyncAPI external reference \"{reference}\" requires caller resolution"
                    )));
                }
            }
            let mut ordered: Vec<&(String, Json)> = members.iter().collect();
            ordered.sort_by(|left, right| left.0.cmp(&right.0));
            for (_, child) in ordered {
                refuse_external_references(child)?;
            }
            Ok(())
        }
        Json::Array(items) => {
            for item in items {
                refuse_external_references(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn operation_json(operation_id: &str, action: &str) -> Vec<u8> {
    let mut out = vec![b'{'];
    push_key(&mut out, "operationId");
    push_string(&mut out, operation_id);
    out.push(b',');
    push_key(&mut out, "action");
    push_string(&mut out, action);
    out.push(b'}');
    out
}
