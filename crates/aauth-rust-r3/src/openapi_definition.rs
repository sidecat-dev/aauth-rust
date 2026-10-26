//! OpenAPI authoritative definitions: one self-contained OpenAPI 3.0 or 3.1
//! document in its JSON form.
//!
//! Ported from Go `r3/vocab/openapi/definition.go`, which loads the document
//! with kin-openapi while refusing external references, derives the
//! `operationId` of each Paths operation in sorted path and method order, and
//! then validates the document. Callback and webhook operations are not
//! derived. This port reads the JSON form with the crate's strict JSON and
//! checks the object graph that carries operations and references:
//!
//! - the fixed fields of the OpenAPI Object, Info, Paths, Path Item, Operation,
//!   Parameter, Request Body, Media Type, Encoding, Responses, Response, Header,
//!   Callback, and Components, refusing a member that is neither a fixed field
//!   nor an `x-` extension;
//! - every Reference Object, Path Item, and Schema `$ref`: a same-document JSON
//!   Pointer must resolve and must not cycle, and any other reference is an
//!   unresolved dependency;
//! - required members, response codes, component names, and the path
//!   parameters each path template needs.
//!
//! As in Go, refusals of the loaded document's shape and references come
//! first, then operation identity and annotations, then validation.
//!
//! Not ported from kin-openapi's validation: Schema Object keywords, examples
//! and defaults against their schemas, security requirements, server URL
//! templates, and the fields of Link, Example, Security Scheme, Server, Tag,
//! Contact, and License objects. The YAML form needs a YAML parser and is
//! refused as an unsupported source kind.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinedOperation, DefinitionCodec, DefinitionError,
    DefinitionMaterial, DefinitionParser, DefinitionRegistration, SourceEncoding,
};
use crate::definition_support::{
    ambiguous, cached_parser, go_json_name_matches, incomplete, invalid, json_pointer, member,
    parse_standard, percent_decode, published_hints, single_member_operation, unavailable,
    unresolved, unsupported,
};
use crate::error::Error;
use crate::jsonvalue::{Json, parse_json};
use crate::standard::OpenApiCodec;
use crate::vocabulary::{Operation, Vocabulary};

/// Exact bytes of one complete, self-contained OpenAPI document.
///
/// Acquisition and external reference resolution stay with the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenApiDocumentSource {
    exact: Vec<u8>,
}

impl OpenApiDocumentSource {
    /// Receipt encoding: the exact document bytes. Shared with the Go reference.
    pub const SOURCE_ENCODING: &'static str = "urn:aauth:source-encoding:openapi-document-exact-v1";

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

struct OpenApiDefinitionCodec;

impl DefinitionCodec<OpenApiDocumentSource> for OpenApiDefinitionCodec {
    fn vocabulary(&self) -> Result<Vocabulary, Error> {
        OpenApiCodec::vocabulary()
    }

    fn parse_definition(
        &self,
        source: &OpenApiDocumentSource,
    ) -> Result<DefinitionMaterial, DefinitionError> {
        parse_document(source)
    }
}

impl OpenApiCodec {
    /// The process-wide OpenAPI definition parser. Every call returns the same
    /// parser registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the OpenAPI vocabulary is unavailable.
    pub fn definition_parser() -> Result<DefinitionParser<OpenApiDocumentSource>, Error> {
        static PARSER: OnceLock<Option<DefinitionParser<OpenApiDocumentSource>>> =
            OnceLock::new();
        cached_parser(
            &PARSER,
            || DefinitionParser::new(OpenApiDefinitionCodec),
            Self::URI,
        )
    }

    /// Derive an authoritative snapshot from one OpenAPI document for the
    /// advertised discovery `endpoint`. Performs no I/O.
    ///
    /// # Errors
    /// Returns a typed [`DefinitionError`]: `incomplete_source` for an empty
    /// document; `source_kind_unsupported` for the YAML form or a version other
    /// than 3.0.x and 3.1.x; `unresolved_dependency` for a reference outside the
    /// document; `operation_identity_unavailable` for an invalid `operationId`
    /// or none at all; `operation_identity_ambiguous` for a repeated one;
    /// `invalid_annotation` for invalid hints; `invalid_source` otherwise.
    pub fn parse_definition(
        endpoint: &str,
        source: &OpenApiDocumentSource,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        parse_standard(Self::definition_parser(), Self::URI, endpoint, source)
    }

    /// Registration of [`Self::definition_parser`], for a [`crate::DefinitionRegistry`].
    ///
    /// # Errors
    /// Returns [`Error`] when the OpenAPI vocabulary is unavailable.
    pub fn definition_registration() -> Result<DefinitionRegistration, Error> {
        Self::definition_parser().map(|parser| parser.registration())
    }
}

/// Path Item operation fields, in the order Go derives them: sorted
/// upper-case method names.
const METHODS: [&str; 8] = [
    "delete", "get", "head", "options", "patch", "post", "put", "trace",
];

const ROOT_FIELDS_30: &[&str] = &[
    "openapi",
    "info",
    "servers",
    "paths",
    "components",
    "security",
    "tags",
    "externalDocs",
];
const ROOT_FIELDS_31: &[&str] = &[
    "openapi",
    "info",
    "jsonSchemaDialect",
    "servers",
    "paths",
    "webhooks",
    "components",
    "security",
    "tags",
    "externalDocs",
];
const INFO_FIELDS_30: &[&str] = &[
    "title",
    "description",
    "termsOfService",
    "contact",
    "license",
    "version",
];
const INFO_FIELDS_31: &[&str] = &[
    "title",
    "summary",
    "description",
    "termsOfService",
    "contact",
    "license",
    "version",
];
const PATH_ITEM_FIELDS: &[&str] = &[
    "$ref",
    "summary",
    "description",
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
    "servers",
    "parameters",
];
const OPERATION_FIELDS: &[&str] = &[
    "tags",
    "summary",
    "description",
    "externalDocs",
    "operationId",
    "parameters",
    "requestBody",
    "responses",
    "callbacks",
    "deprecated",
    "security",
    "servers",
];
const PARAMETER_FIELDS: &[&str] = &[
    "name",
    "in",
    "description",
    "required",
    "deprecated",
    "allowEmptyValue",
    "style",
    "explode",
    "allowReserved",
    "schema",
    "example",
    "examples",
    "content",
];
const HEADER_FIELDS: &[&str] = &[
    "description",
    "required",
    "deprecated",
    "allowEmptyValue",
    "style",
    "explode",
    "allowReserved",
    "schema",
    "example",
    "examples",
    "content",
];
const REQUEST_BODY_FIELDS: &[&str] = &["description", "content", "required"];
const MEDIA_TYPE_FIELDS: &[&str] = &["schema", "example", "examples", "encoding"];
const ENCODING_FIELDS: &[&str] = &["contentType", "headers", "style", "explode", "allowReserved"];
const RESPONSE_FIELDS: &[&str] = &["description", "headers", "content", "links"];

fn parse_document(source: &OpenApiDocumentSource) -> Result<DefinitionMaterial, DefinitionError> {
    let Ok(text) = std::str::from_utf8(&source.exact) else {
        return Err(invalid("OpenAPI document must be UTF-8"));
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(incomplete("OpenAPI document is empty"));
    }
    if !trimmed.starts_with(['{', '[']) {
        return Err(unsupported(
            "the YAML form of an OpenAPI document needs a YAML parser; this adapter reads the JSON form",
        ));
    }
    let document = match parse_json(&source.exact) {
        Ok(document) => document,
        Err(err) => return Err(invalid("invalid JSON document").with_cause(err)),
    };
    let Json::Object(root) = &document else {
        return Err(invalid("OpenAPI document root must be an object"));
    };
    let minor = match member(root, "openapi") {
        Some(Json::String(version)) => supported_minor(version),
        _ => None,
    };
    let Some(minor) = minor else {
        return Err(unsupported(
            "document must declare an OpenAPI 3.0.x or 3.1.x version",
        ));
    };
    let vocabulary = match OpenApiCodec::vocabulary() {
        Ok(vocabulary) => vocabulary,
        Err(err) => return Err(invalid("OpenAPI vocabulary is unavailable").with_cause(err)),
    };
    let mut walk = Walk {
        root: &document,
        v31: minor == 1,
        pending: Vec::new(),
        visited: BTreeSet::new(),
        first_invalid: None,
        side_ids: BTreeSet::new(),
    };
    walk.openapi_object(root)?;
    walk.drain()?;
    let operations = walk.derive(root, &vocabulary)?;
    if let Some(err) = walk.first_invalid.take() {
        return Err(err);
    }
    let encoding = match SourceEncoding::new(OpenApiDocumentSource::SOURCE_ENCODING) {
        Ok(encoding) => encoding,
        Err(err) => return Err(invalid("OpenAPI source encoding").with_cause(err)),
    };
    DefinitionMaterial::new(encoding, source.exact.clone(), operations)
        .map_err(|err| invalid("assemble OpenAPI definition material").with_cause(err))
}

/// `3.0.x` or `3.1.x` with a decimal patch number.
fn supported_minor(version: &str) -> Option<u8> {
    let mut parts = version.split('.');
    let (Some("3"), Some(minor @ ("0" | "1")), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if patch.is_empty() || !patch.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(if minor == "1" { 1 } else { 0 })
}

/// Where a Path Item or Callback was reached from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Origin {
    /// A Paths entry, whose operations are derived.
    Paths,
    /// A callback or webhook, whose operations are described but not derived.
    Side,
    /// A reusable component, which describes no operation until referenced.
    Component,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    PathItem(Origin),
    Callback(Origin),
    Parameter,
    RequestBody,
    MediaType,
    Encoding,
    Response,
    Header,
    Example,
    Link,
    SecurityScheme,
    Schema,
}

fn node_name(node: Node) -> &'static str {
    match node {
        Node::PathItem(_) => "Path Item",
        Node::Callback(_) => "Callback",
        Node::Parameter => "Parameter",
        Node::RequestBody => "Request Body",
        Node::MediaType => "Media Type",
        Node::Encoding => "Encoding",
        Node::Response => "Response",
        Node::Header => "Header",
        Node::Example => "Example",
        Node::Link => "Link",
        Node::SecurityScheme => "Security Scheme",
        Node::Schema => "Schema",
    }
}

/// One pass over the document. Objects reached through a member or a
/// reference are queued, so the stack depth stays within the JSON depth limit
/// however long a reference chain is.
struct Walk<'a> {
    root: &'a Json,
    v31: bool,
    pending: Vec<(&'a Json, Node)>,
    visited: BTreeSet<(usize, Node)>,
    /// The first validation refusal. Go validates only after it derives
    /// operations, so this is reported after derivation.
    first_invalid: Option<DefinitionError>,
    /// `operationId` values of callback and webhook operations.
    side_ids: BTreeSet<String>,
}

impl<'a> Walk<'a> {
    fn record(&mut self, reason: String) {
        if self.first_invalid.is_none() {
            self.first_invalid = Some(invalid(reason));
        }
    }

    /// Record an unknown member that is not an `x-` extension. Go decodes
    /// these objects into structs and so reads a case variant of a fixed field,
    /// such as `GET` or `OperationId`, as that field before it validates;
    /// such a variant is refused at once rather than read differently.
    fn fields(
        &mut self,
        members: &[(String, Json)],
        allowed: &[&str],
        what: &str,
    ) -> Result<(), DefinitionError> {
        for (name, _) in members {
            if name.starts_with("x-") || allowed.contains(&name.as_str()) {
                continue;
            }
            if let Some(field) = allowed
                .iter()
                .find(|field| go_json_name_matches(name, field))
            {
                return Err(invalid(format!(
                    "OpenAPI {what} member \"{name}\" is a case variant of \"{field}\""
                )));
            }
            self.record(format!("OpenAPI {what} has unknown member \"{name}\""));
        }
        Ok(())
    }

    /// Follow one `$ref`. Only a same-document JSON Pointer resolves here.
    fn reference(&self, value: &Json) -> Result<&'a Json, DefinitionError> {
        let Json::String(text) = value else {
            return Err(invalid("OpenAPI $ref must be a string"));
        };
        if text.is_empty() {
            return Err(invalid("OpenAPI $ref must not be empty"));
        }
        let Some(fragment) = text.strip_prefix('#') else {
            return Err(unresolved(format!(
                "external OpenAPI reference \"{text}\" requires caller resolution"
            )));
        };
        let Some(pointer) = percent_decode(fragment) else {
            return Err(invalid(format!(
                "OpenAPI reference \"{text}\" has an invalid percent escape"
            )));
        };
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return Err(invalid(format!(
                "OpenAPI reference \"{text}\" is not a JSON Pointer"
            )));
        }
        json_pointer(self.root, &pointer).ok_or_else(|| {
            invalid(format!(
                "OpenAPI reference \"{text}\" does not resolve in the document"
            ))
        })
    }

    /// Follow `$ref` until an object without one, refusing a cycle.
    fn resolve_chain(&self, value: &'a Json) -> Result<&'a Json, DefinitionError> {
        let mut current = value;
        let mut seen = BTreeSet::new();
        while let Json::Object(members) = current {
            let Some(reference) = member(members, "$ref") else {
                break;
            };
            if !seen.insert(std::ptr::from_ref(current).addr()) {
                return Err(invalid("OpenAPI references form a cycle"));
            }
            current = self.reference(reference)?;
        }
        Ok(current)
    }

    fn drain(&mut self) -> Result<(), DefinitionError> {
        while let Some((value, node)) = self.pending.pop() {
            if self
                .visited
                .insert((std::ptr::from_ref(value).addr(), node))
            {
                self.visit(value, node)?;
            }
        }
        Ok(())
    }

    fn visit(&mut self, value: &'a Json, node: Node) -> Result<(), DefinitionError> {
        match node {
            Node::PathItem(origin) => return self.path_item(value, origin),
            Node::Schema => return self.schema(value),
            Node::MediaType => return self.media_type(value),
            Node::Encoding => return self.encoding(value),
            _ => {}
        }
        let members = object(value, node_name(node))?;
        if member(members, "$ref").is_some() {
            let target = self.resolve_chain(value)?;
            self.pending.push((target, node));
            return Ok(());
        }
        match node {
            Node::Callback(origin) => {
                for (expression, item) in members {
                    if !expression.starts_with("x-") {
                        self.pending.push((item, Node::PathItem(origin)));
                    }
                }
                Ok(())
            }
            Node::Parameter => self.parameter(members),
            Node::RequestBody => self.request_body(members),
            Node::Response => self.response(members),
            Node::Header => self.header(members),
            Node::Example
            | Node::Link
            | Node::SecurityScheme
            | Node::PathItem(_)
            | Node::Schema
            | Node::MediaType
            | Node::Encoding => Ok(()),
        }
    }

    fn openapi_object(&mut self, members: &'a [(String, Json)]) -> Result<(), DefinitionError> {
        let allowed = if self.v31 {
            ROOT_FIELDS_31
        } else {
            ROOT_FIELDS_30
        };
        self.fields(members, allowed, "Object")?;
        match member(members, "info") {
            Some(info) => self.info(info)?,
            None => self.record("an OpenAPI document requires info".to_owned()),
        }
        match member(members, "paths") {
            Some(paths) => self.paths(paths)?,
            None if !self.v31 => self.record("an OpenAPI 3.0 document requires paths".to_owned()),
            None => {}
        }
        if let Some(components) = member(members, "components") {
            self.components(components)?;
        }
        if self.v31 {
            if let Some(webhooks) = member(members, "webhooks") {
                for (_, item) in object(webhooks, "webhooks")? {
                    self.pending.push((item, Node::PathItem(Origin::Side)));
                }
            }
            text(members, "jsonSchemaDialect", "Object")?;
            if ["paths", "components", "webhooks"]
                .iter()
                .all(|name| member(members, name).is_none())
            {
                self.record(
                    "an OpenAPI 3.1 document requires paths, components, or webhooks".to_owned(),
                );
            }
        }
        for name in ["servers", "security", "tags"] {
            if let Some(value) = member(members, name) {
                array(value, name)?;
            }
        }
        if let Some(docs) = member(members, "externalDocs") {
            object(docs, "externalDocs")?;
        }
        Ok(())
    }

    fn info(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        let members = object(value, "Info")?;
        let allowed = if self.v31 {
            INFO_FIELDS_31
        } else {
            INFO_FIELDS_30
        };
        self.fields(members, allowed, "Info")?;
        for name in ["title", "version", "summary", "description", "termsOfService"] {
            text(members, name, "Info")?;
        }
        for name in ["contact", "license"] {
            if let Some(value) = member(members, name) {
                object(value, name)?;
            }
        }
        for name in ["title", "version"] {
            if !matches!(member(members, name), Some(Json::String(value)) if !value.is_empty()) {
                self.record(format!("OpenAPI Info requires a non-empty {name}"));
            }
        }
        Ok(())
    }

    fn paths(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        for (path, item) in object(value, "Paths")? {
            if path.starts_with("x-") {
                continue;
            }
            if !path.starts_with('/') {
                self.record(format!(
                    "OpenAPI path \"{path}\" must begin with a forward slash"
                ));
            }
            self.pending.push((item, Node::PathItem(Origin::Paths)));
        }
        Ok(())
    }

    fn path_item(&mut self, value: &'a Json, origin: Origin) -> Result<(), DefinitionError> {
        let members = object(value, "Path Item")?;
        if let Some(reference) = member(members, "$ref") {
            // The specification leaves a field present both here and in the
            // referenced Path Item undefined; kin-openapi keeps only the
            // referenced one. An operation named on both sides is ambiguous.
            if METHODS.iter().any(|method| member(members, method).is_some()) {
                return Err(ambiguous(
                    "an OpenAPI Path Item combines $ref with operations",
                ));
            }
            if member(members, "parameters").is_some() || member(members, "servers").is_some() {
                self.record("an OpenAPI Path Item combines $ref with shared fields".to_owned());
            }
            self.resolve_chain(value)?;
            let target = self.reference(reference)?;
            self.pending.push((target, Node::PathItem(origin)));
        }
        self.fields(members, PATH_ITEM_FIELDS, "Path Item")?;
        for name in ["summary", "description"] {
            text(members, name, "Path Item")?;
        }
        if let Some(servers) = member(members, "servers") {
            array(servers, "Path Item servers")?;
        }
        if let Some(parameters) = member(members, "parameters") {
            self.parameters(parameters)?;
        }
        for method in METHODS {
            if let Some(operation) = member(members, method) {
                self.operation(operation, origin)?;
            }
        }
        Ok(())
    }

    fn operation(&mut self, value: &'a Json, origin: Origin) -> Result<(), DefinitionError> {
        let members = object(value, "Operation")?;
        self.fields(members, OPERATION_FIELDS, "Operation")?;
        for name in ["summary", "description", "operationId"] {
            text(members, name, "Operation")?;
        }
        if origin == Origin::Side
            && let Some(Json::String(id)) = member(members, "operationId")
            && !id.is_empty()
        {
            self.side_ids.insert(id.clone());
        }
        if let Some(tags) = member(members, "tags")
            && !matches!(tags, Json::Array(items) if items.iter().all(|tag| matches!(tag, Json::String(_))))
        {
            return Err(invalid("OpenAPI Operation tags must be an array of strings"));
        }
        if let Some(deprecated) = member(members, "deprecated")
            && !matches!(deprecated, Json::Bool(_))
        {
            return Err(invalid("OpenAPI Operation deprecated must be a boolean"));
        }
        for name in ["security", "servers"] {
            if let Some(value) = member(members, name) {
                array(value, name)?;
            }
        }
        if let Some(docs) = member(members, "externalDocs") {
            object(docs, "externalDocs")?;
        }
        if let Some(parameters) = member(members, "parameters") {
            self.parameters(parameters)?;
        }
        if let Some(body) = member(members, "requestBody") {
            self.pending.push((body, Node::RequestBody));
        }
        match member(members, "responses") {
            Some(responses) => self.responses(responses)?,
            None => self.record("an OpenAPI Operation requires responses".to_owned()),
        }
        if let Some(callbacks) = member(members, "callbacks") {
            for (_, callback) in object(callbacks, "Operation callbacks")? {
                self.pending.push((callback, Node::Callback(Origin::Side)));
            }
        }
        Ok(())
    }

    fn parameters(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        let Json::Array(items) = value else {
            return Err(invalid("OpenAPI parameters must be an array"));
        };
        for item in items {
            self.pending.push((item, Node::Parameter));
        }
        Ok(())
    }

    fn parameter(&mut self, members: &'a [(String, Json)]) -> Result<(), DefinitionError> {
        self.fields(members, PARAMETER_FIELDS, "Parameter")?;
        for name in ["name", "in", "description", "style"] {
            text(members, name, "Parameter")?;
        }
        for name in [
            "required",
            "deprecated",
            "allowEmptyValue",
            "explode",
            "allowReserved",
        ] {
            flag(members, name, "Parameter")?;
        }
        match (member(members, "name"), member(members, "in")) {
            (Some(_), Some(Json::String(location))) => {
                if !["query", "header", "path", "cookie"].contains(&location.as_str()) {
                    self.record(format!(
                        "OpenAPI Parameter location \"{location}\" is not query, header, path, or cookie"
                    ));
                }
                if location.as_str() == "path"
                    && !matches!(member(members, "required"), Some(Json::Bool(true)))
                {
                    self.record("an OpenAPI path Parameter must be required".to_owned());
                }
            }
            _ => self.record("an OpenAPI Parameter requires name and in".to_owned()),
        }
        self.schema_and_content(members)
    }

    fn header(&mut self, members: &'a [(String, Json)]) -> Result<(), DefinitionError> {
        self.fields(members, HEADER_FIELDS, "Header")?;
        for name in ["description", "style"] {
            text(members, name, "Header")?;
        }
        for name in [
            "required",
            "deprecated",
            "allowEmptyValue",
            "explode",
            "allowReserved",
        ] {
            flag(members, name, "Header")?;
        }
        self.schema_and_content(members)
    }

    fn schema_and_content(&mut self, members: &'a [(String, Json)]) -> Result<(), DefinitionError> {
        if let Some(schema) = member(members, "schema") {
            self.pending.push((schema, Node::Schema));
        }
        if let Some(content) = member(members, "content") {
            self.map(content, "content", Node::MediaType)?;
        }
        if let Some(examples) = member(members, "examples") {
            self.map(examples, "examples", Node::Example)?;
        }
        Ok(())
    }

    fn map(&mut self, value: &'a Json, what: &str, node: Node) -> Result<(), DefinitionError> {
        for (_, child) in object(value, what)? {
            self.pending.push((child, node));
        }
        Ok(())
    }

    fn request_body(&mut self, members: &'a [(String, Json)]) -> Result<(), DefinitionError> {
        self.fields(members, REQUEST_BODY_FIELDS, "Request Body")?;
        text(members, "description", "Request Body")?;
        flag(members, "required", "Request Body")?;
        match member(members, "content") {
            Some(content) => self.map(content, "content", Node::MediaType),
            None => {
                self.record("an OpenAPI Request Body requires content".to_owned());
                Ok(())
            }
        }
    }

    fn media_type(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        let members = object(value, "Media Type")?;
        self.fields(members, MEDIA_TYPE_FIELDS, "Media Type")?;
        if let Some(schema) = member(members, "schema") {
            self.pending.push((schema, Node::Schema));
        }
        if let Some(examples) = member(members, "examples") {
            self.map(examples, "examples", Node::Example)?;
        }
        if let Some(encoding) = member(members, "encoding") {
            self.map(encoding, "encoding", Node::Encoding)?;
        }
        Ok(())
    }

    fn encoding(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        let members = object(value, "Encoding")?;
        self.fields(members, ENCODING_FIELDS, "Encoding")?;
        if let Some(headers) = member(members, "headers") {
            self.map(headers, "headers", Node::Header)?;
        }
        Ok(())
    }

    fn responses(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        let mut codes = 0usize;
        for (code, response) in object(value, "Responses")? {
            if code.starts_with("x-") {
                continue;
            }
            codes += 1;
            if !is_response_code(code) {
                self.record(format!(
                    "OpenAPI response code \"{code}\" is not a status code, a range, or default"
                ));
            }
            self.pending.push((response, Node::Response));
        }
        if codes == 0 {
            self.record("OpenAPI Responses must contain at least one response code".to_owned());
        }
        Ok(())
    }

    fn response(&mut self, members: &'a [(String, Json)]) -> Result<(), DefinitionError> {
        self.fields(members, RESPONSE_FIELDS, "Response")?;
        text(members, "description", "Response")?;
        if member(members, "description").is_none() {
            self.record("an OpenAPI Response requires description".to_owned());
        }
        if let Some(headers) = member(members, "headers") {
            self.map(headers, "headers", Node::Header)?;
        }
        if let Some(content) = member(members, "content") {
            self.map(content, "content", Node::MediaType)?;
        }
        if let Some(links) = member(members, "links") {
            self.map(links, "links", Node::Link)?;
        }
        Ok(())
    }

    fn components(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        for (name, entries) in object(value, "Components")? {
            if name.starts_with("x-") {
                continue;
            }
            let node = match name.as_str() {
                "schemas" => Node::Schema,
                "responses" => Node::Response,
                "parameters" => Node::Parameter,
                "examples" => Node::Example,
                "requestBodies" => Node::RequestBody,
                "headers" => Node::Header,
                "securitySchemes" => Node::SecurityScheme,
                "links" => Node::Link,
                "callbacks" => Node::Callback(Origin::Component),
                "pathItems" if self.v31 => Node::PathItem(Origin::Component),
                other => {
                    self.record(format!("OpenAPI Components has unknown member \"{other}\""));
                    continue;
                }
            };
            for (component, entry) in object(entries, name)? {
                if !is_component_name(component) {
                    self.record(format!(
                        "OpenAPI component name \"{component}\" is not [A-Za-z0-9.-_]+"
                    ));
                }
                self.pending.push((entry, node));
            }
        }
        Ok(())
    }

    /// Queue every subschema and reference target. Schema keywords themselves
    /// are not validated.
    fn schema(&mut self, value: &'a Json) -> Result<(), DefinitionError> {
        let members = match value {
            Json::Object(members) => members,
            Json::Bool(_) if self.v31 => return Ok(()),
            _ => return Err(invalid("OpenAPI Schema Object must be an object")),
        };
        if let Some(reference) = member(members, "$ref") {
            self.resolve_chain(value)?;
            let target = self.reference(reference)?;
            self.pending.push((target, Node::Schema));
            // OpenAPI 3.0 ignores the siblings of `$ref`; 3.1 Schema Objects
            // evaluate them.
            if !self.v31 {
                return Ok(());
            }
        }
        for (keyword, child) in members {
            match keyword.as_str() {
                "properties" | "patternProperties" | "dependentSchemas" | "$defs" => {
                    self.map(child, keyword, Node::Schema)?;
                }
                "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                    let Json::Array(items) = child else {
                        return Err(invalid(format!(
                            "OpenAPI Schema {keyword} must be an array"
                        )));
                    };
                    for item in items {
                        self.pending.push((item, Node::Schema));
                    }
                }
                "additionalProperties" if matches!(child, Json::Bool(_)) => {}
                "items"
                | "additionalProperties"
                | "not"
                | "contains"
                | "if"
                | "then"
                | "else"
                | "propertyNames"
                | "unevaluatedItems"
                | "unevaluatedProperties"
                | "contentSchema" => self.pending.push((child, Node::Schema)),
                _ => {}
            }
        }
        Ok(())
    }

    /// Derive Paths operations in Go's order: sorted path names, then sorted
    /// method names. Validation of path templates is recorded, not returned.
    fn derive(
        &mut self,
        root: &'a [(String, Json)],
        vocabulary: &Vocabulary,
    ) -> Result<Vec<DefinedOperation>, DefinitionError> {
        let paths: &[(String, Json)] = match member(root, "paths") {
            Some(Json::Object(paths)) => paths,
            _ => &[],
        };
        let mut ordered: Vec<&'a (String, Json)> = paths
            .iter()
            .filter(|(path, _)| !path.starts_with("x-"))
            .collect();
        ordered.sort_by(|left, right| left.0.cmp(&right.0));
        let mut operations = Vec::new();
        let mut seen = BTreeSet::new();
        for (path, item) in ordered {
            let item = self.resolve_chain(item)?;
            let members = object(item, "Path Item")?;
            let path_parameters = member(members, "parameters");
            for method in METHODS {
                let Some(operation) = member(members, method) else {
                    continue;
                };
                let operation = object(operation, "Operation")?;
                let operation_parameters = member(operation, "parameters");
                self.check_path_parameters(path, method, path_parameters, operation_parameters)?;
                let id = match member(operation, "operationId") {
                    Some(Json::String(id)) => id.as_str(),
                    _ => "",
                };
                if id.is_empty() {
                    continue;
                }
                let raw = single_member_operation("operationId", id);
                if let Err(err) = Operation::new(vocabulary, &raw) {
                    let reason = format!(
                        "path \"{path}\" method {} has an invalid operationId",
                        method.to_ascii_uppercase()
                    );
                    return Err(unavailable(reason).with_cause(err));
                }
                if !seen.insert(id.to_owned()) {
                    return Err(ambiguous(format!(
                        "operationId \"{id}\" is not globally unique"
                    )));
                }
                // The specification requires an operationId to be unique among
                // all operations the document describes. A callback or webhook
                // with a derived operation's identity makes it ambiguous.
                if self.side_ids.contains(id) {
                    return Err(ambiguous(format!(
                        "operationId \"{id}\" also names a callback or webhook operation"
                    )));
                }
                let hints = published_hints(
                    member(operation, "x-aauth-access-mode"),
                    member(operation, "x-aauth-budget"),
                    &format!("OpenAPI operation \"{id}\""),
                )?;
                match DefinedOperation::new(&raw, hints.as_ref()) {
                    Ok(defined) => operations.push(defined),
                    Err(err) => {
                        return Err(invalid("construct derived OpenAPI operation").with_cause(err));
                    }
                }
            }
        }
        if operations.is_empty() {
            return Err(unavailable(
                "OpenAPI Paths contains no operation with an operationId",
            ));
        }
        Ok(operations)
    }

    /// The path parameters declared for one operation must be exactly the
    /// template names of its path, and no parameter list may repeat a name and
    /// location.
    fn check_path_parameters(
        &mut self,
        path: &str,
        method: &str,
        path_level: Option<&'a Json>,
        operation_level: Option<&'a Json>,
    ) -> Result<(), DefinitionError> {
        let Some(template) = template_names(path) else {
            self.record(format!("OpenAPI path \"{path}\" has a malformed template"));
            return Ok(());
        };
        let mut declared = BTreeSet::new();
        for list in [path_level, operation_level].into_iter().flatten() {
            let Json::Array(items) = list else {
                continue;
            };
            let mut listed = BTreeSet::new();
            for item in items {
                let Json::Object(parameter) = self.resolve_chain(item)? else {
                    continue;
                };
                let (Some(Json::String(name)), Some(Json::String(location))) =
                    (member(parameter, "name"), member(parameter, "in"))
                else {
                    continue;
                };
                if !listed.insert((name.as_str(), location.as_str())) {
                    self.record(format!(
                        "OpenAPI parameters repeat the {location} parameter \"{name}\""
                    ));
                }
                if location.as_str() == "path" {
                    declared.insert(name.clone());
                }
            }
        }
        if declared != template {
            self.record(format!(
                "OpenAPI operation {} \"{path}\" must declare exactly its path template parameters",
                method.to_ascii_uppercase()
            ));
        }
        Ok(())
    }
}

fn object<'v>(value: &'v Json, what: &str) -> Result<&'v [(String, Json)], DefinitionError> {
    match value {
        Json::Object(members) => Ok(members),
        _ => Err(invalid(format!("OpenAPI {what} must be an object"))),
    }
}

fn array(value: &Json, what: &str) -> Result<(), DefinitionError> {
    match value {
        Json::Array(_) => Ok(()),
        _ => Err(invalid(format!("OpenAPI {what} must be an array"))),
    }
}

fn text(members: &[(String, Json)], name: &str, what: &str) -> Result<(), DefinitionError> {
    match member(members, name) {
        None | Some(Json::String(_)) => Ok(()),
        Some(_) => Err(invalid(format!("OpenAPI {what} {name} must be a string"))),
    }
}

fn flag(members: &[(String, Json)], name: &str, what: &str) -> Result<(), DefinitionError> {
    match member(members, name) {
        None | Some(Json::Bool(_)) => Ok(()),
        Some(_) => Err(invalid(format!("OpenAPI {what} {name} must be a boolean"))),
    }
}

/// `default`, a status code `100`–`599`, or a range `1XX`–`5XX`.
fn is_response_code(code: &str) -> bool {
    if code == "default" {
        return true;
    }
    match code.as_bytes() {
        [b'1'..=b'5', b'X', b'X'] => true,
        [b'1'..=b'5', second, third] => second.is_ascii_digit() && third.is_ascii_digit(),
        _ => false,
    }
}

fn is_component_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// The `{name}` template expressions of a path. `None` when braces do not pair.
fn template_names(path: &str) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        if rest[..open].contains('}') {
            return None;
        }
        let after = &rest[open + 1..];
        let close = after.find('}')?;
        let name = &after[..close];
        if name.is_empty() || name.contains('{') {
            return None;
        }
        names.insert(name.to_owned());
        rest = &after[close + 1..];
    }
    if rest.contains('}') {
        return None;
    }
    Some(names)
}
