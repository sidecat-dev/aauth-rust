//! MCP authoritative definitions: one complete, ordered `tools/list` result sequence.
//!
//! Ported from Go `r3/vocab/mcp/definition.go`. The caller removes JSON-RPC
//! envelopes and supplies each page's exact `result` object with the cursor
//! its request carried. Nothing here speaks MCP or opens a transport. A tool's
//! `inputSchema` must be a self-contained JSON Schema object whose root type is
//! `object`; hints are read from the tool's `_meta`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinedOperation, DefinitionCodec, DefinitionError, DefinitionMaterial,
    DefinitionParser, DefinitionRegistration, SourceEncoding,
};
use crate::definition_support::{
    ambiguous, cached_parser, incomplete, invalid, invalid_annotation, member, parse_standard,
    published_hints, refuse_field_variants, single_member_operation, unresolved,
};
use crate::error::Error;
use crate::hints::OperationHints;
use crate::json_schema::{SchemaRefusal, check_schema_resource};
use crate::jsonvalue::{Json, parse_json};
use crate::standard::McpCodec;
use crate::vocabulary::{Operation, Vocabulary};

/// The location Go registers a tool `inputSchema` under before compiling it.
const INPUT_SCHEMA_LOCATION: &str = "urn:aauth:mcp:tool-input-schema";

const FRAME_PREFIX: &[u8] = b"aauth-r3-mcp-tools-list-cursor-result-json-frames\0";

/// One `tools/list` page: the cursor its request carried and the exact result object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolsListPage {
    requested_cursor: Option<String>,
    result_json: Vec<u8>,
}

impl ToolsListPage {
    /// The page returned for the cursor-free initial request. `result_json` is
    /// the value of the JSON-RPC `result` member, not the whole response.
    pub fn initial(result_json: &[u8]) -> Self {
        Self {
            requested_cursor: None,
            result_json: result_json.to_vec(),
        }
    }

    /// The page returned for a continuation request that carried `requested_cursor`.
    pub fn continued(requested_cursor: impl Into<String>, result_json: &[u8]) -> Self {
        Self {
            requested_cursor: Some(requested_cursor.into()),
            result_json: result_json.to_vec(),
        }
    }

    /// The cursor the request carried; `None` for the initial request.
    pub fn requested_cursor(&self) -> Option<&str> {
        self.requested_cursor.as_deref()
    }

    /// The exact result object bytes.
    pub fn result_json(&self) -> &[u8] {
        &self.result_json
    }
}

/// A complete, ordered `tools/list` result sequence.
///
/// Parsing checks that each continuation requested the prior page's
/// `nextCursor` and that the last page advertises no further page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolsListSnapshot {
    pages: Vec<ToolsListPage>,
}

impl ToolsListSnapshot {
    /// Receipt encoding of [`Self::receipt_input`], shared with the Go reference.
    pub const SOURCE_ENCODING: &'static str =
        "urn:aauth:source-encoding:mcp-tools-list-cursor-result-json-frames-v1";

    /// Own the pages in request order.
    pub fn new(pages: Vec<ToolsListPage>) -> Self {
        Self { pages }
    }

    /// Pages in request order.
    pub fn pages(&self) -> &[ToolsListPage] {
        &self.pages
    }

    /// The exact framed bytes a parsed snapshot's receipt covers.
    ///
    /// The UTF-8 text `aauth-r3-mcp-tools-list-cursor-result-json-frames` and
    /// one zero byte; the page count as an unsigned 64-bit big-endian integer;
    /// then per page one cursor-presence byte, the cursor length and bytes when
    /// present, and the result length and exact result bytes. The framing
    /// distinguishes page boundaries and cursor presence.
    pub fn receipt_input(&self) -> Vec<u8> {
        let mut framed = FRAME_PREFIX.to_vec();
        push_length(&mut framed, self.pages.len());
        for page in &self.pages {
            match &page.requested_cursor {
                None => framed.push(0),
                Some(cursor) => {
                    framed.push(1);
                    push_length(&mut framed, cursor.len());
                    framed.extend_from_slice(cursor.as_bytes());
                }
            }
            push_length(&mut framed, page.result_json.len());
            framed.extend_from_slice(&page.result_json);
        }
        framed
    }
}

fn push_length(out: &mut Vec<u8>, length: usize) {
    out.extend_from_slice(&(length as u64).to_be_bytes());
}

struct McpDefinitionCodec;

impl DefinitionCodec<ToolsListSnapshot> for McpDefinitionCodec {
    fn vocabulary(&self) -> Result<Vocabulary, Error> {
        McpCodec::vocabulary()
    }

    fn parse_definition(
        &self,
        source: &ToolsListSnapshot,
    ) -> Result<DefinitionMaterial, DefinitionError> {
        parse_tools_list(source)
    }
}

impl McpCodec {
    /// The process-wide MCP definition parser. Every call returns the same
    /// parser registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the MCP vocabulary is unavailable.
    pub fn definition_parser() -> Result<DefinitionParser<ToolsListSnapshot>, Error> {
        static PARSER: OnceLock<Option<DefinitionParser<ToolsListSnapshot>>> = OnceLock::new();
        cached_parser(
            &PARSER,
            || DefinitionParser::new(McpDefinitionCodec),
            Self::URI,
        )
    }

    /// Derive an authoritative snapshot from already-acquired `tools/list`
    /// pages for the advertised discovery `endpoint`. Performs no I/O.
    ///
    /// # Errors
    /// Returns a typed [`DefinitionError`]: `incomplete_source` for missing
    /// pages, a broken cursor chain, or no tools; `invalid_source` for a
    /// malformed page, tool, or `inputSchema`; `unresolved_dependency` for an
    /// `inputSchema` that needs an external schema; `invalid_annotation` for
    /// invalid `_meta` hints; `operation_identity_ambiguous` for a repeated tool.
    pub fn parse_definition(
        endpoint: &str,
        source: &ToolsListSnapshot,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        parse_standard(Self::definition_parser(), Self::URI, endpoint, source)
    }

    /// Registration of [`Self::definition_parser`], for a [`crate::DefinitionRegistry`].
    ///
    /// # Errors
    /// Returns [`Error`] when the MCP vocabulary is unavailable.
    pub fn definition_registration() -> Result<DefinitionRegistration, Error> {
        Self::definition_parser().map(|parser| parser.registration())
    }
}

struct DefinedTool {
    name: String,
    operation: Vec<u8>,
    hints: Option<OperationHints>,
}

struct ToolsPage {
    tools: Vec<DefinedTool>,
    next_cursor: Option<String>,
}

fn parse_tools_list(source: &ToolsListSnapshot) -> Result<DefinitionMaterial, DefinitionError> {
    if source.pages.is_empty() {
        return Err(incomplete("MCP tools/list snapshot contains no pages"));
    }
    let vocabulary = match McpCodec::vocabulary() {
        Ok(vocabulary) => vocabulary,
        Err(err) => return Err(invalid("MCP vocabulary is unavailable").with_cause(err)),
    };
    let receipt_input = source.receipt_input();
    let mut defined = Vec::new();
    let mut seen_tools = BTreeSet::new();
    let mut seen_cursors = BTreeSet::new();
    let mut expected_cursor: Option<String> = None;
    let last = source.pages.len() - 1;
    for (index, frame) in source.pages.iter().enumerate() {
        if index == 0 {
            if frame.requested_cursor.is_some() {
                return Err(incomplete(
                    "initial MCP tools/list page must not have a requested cursor",
                ));
            }
        } else if expected_cursor.is_none() || frame.requested_cursor != expected_cursor {
            return Err(incomplete(format!(
                "MCP tools/list page {index} was not requested with the prior nextCursor"
            )));
        }
        let document = match parse_json(&frame.result_json) {
            Ok(document) => document,
            Err(err) => {
                let reason = format!("invalid MCP tools/list page {index}");
                return Err(invalid(reason).with_cause(err));
            }
        };
        let page = parse_page(&document, &vocabulary, index)?;
        match (&page.next_cursor, index == last) {
            (None, true) => {}
            (Some(_), true) => {
                return Err(incomplete(format!(
                    "final MCP tools/list page {index} advertises another page"
                )));
            }
            (None, false) => {
                return Err(incomplete(format!(
                    "MCP tools/list page {index} does not identify the next page"
                )));
            }
            (Some(cursor), false) => {
                if cursor.is_empty() {
                    return Err(incomplete(format!(
                        "MCP tools/list page {index} does not identify the next page"
                    )));
                }
                if !seen_cursors.insert(cursor.clone()) {
                    return Err(incomplete(format!(
                        "MCP tools/list page {index} repeats nextCursor \"{cursor}\""
                    )));
                }
            }
        }
        expected_cursor = page.next_cursor;
        for tool in page.tools {
            if !seen_tools.insert(tool.name.clone()) {
                return Err(ambiguous(format!(
                    "MCP tool \"{}\" occurs more than once",
                    tool.name
                )));
            }
            match DefinedOperation::new(&tool.operation, tool.hints.as_ref()) {
                Ok(operation) => defined.push(operation),
                Err(err) => return Err(invalid("construct derived MCP tool").with_cause(err)),
            }
        }
    }
    if defined.is_empty() {
        return Err(incomplete("MCP tools/list snapshot defines no tools"));
    }
    let encoding = match SourceEncoding::new(ToolsListSnapshot::SOURCE_ENCODING) {
        Ok(encoding) => encoding,
        Err(err) => return Err(invalid("MCP source encoding").with_cause(err)),
    };
    DefinitionMaterial::new(encoding, receipt_input, defined)
        .map_err(|err| invalid("assemble MCP definition material").with_cause(err))
}

/// One result object. Go decodes it into a struct, so `null` reads as an
/// object with no members and a `null` cursor reads as an empty cursor.
fn parse_page(
    document: &Json,
    vocabulary: &Vocabulary,
    index: usize,
) -> Result<ToolsPage, DefinitionError> {
    let context = format!("MCP tools/list page {index}");
    let members: &[(String, Json)] = match document {
        Json::Object(members) => members,
        Json::Null => &[],
        _ => return Err(invalid(format!("{context} must be a JSON object"))),
    };
    refuse_field_variants(members, &["tools", "nextCursor"], &context)?;
    let tools = match member(members, "tools") {
        None => return Err(invalid(format!("{context} is missing tools"))),
        Some(Json::Array(tools)) => tools,
        Some(_) => return Err(invalid(format!("{context} tools must be an array"))),
    };
    let mut parsed = Vec::with_capacity(tools.len());
    for (position, tool) in tools.iter().enumerate() {
        let tool_context = format!("{context} tool {position}");
        parsed.push(parse_tool(tool, vocabulary, &tool_context)?);
    }
    let next_cursor = match member(members, "nextCursor") {
        None => None,
        Some(Json::String(cursor)) => Some(cursor.clone()),
        Some(Json::Null) => Some(String::new()),
        Some(_) => return Err(invalid(format!("{context} nextCursor must be a string"))),
    };
    Ok(ToolsPage {
        tools: parsed,
        next_cursor,
    })
}

fn parse_tool(
    tool: &Json,
    vocabulary: &Vocabulary,
    context: &str,
) -> Result<DefinedTool, DefinitionError> {
    let members: &[(String, Json)] = match tool {
        Json::Object(members) => members,
        Json::Null => &[],
        _ => return Err(invalid(format!("{context} must be a JSON object"))),
    };
    refuse_field_variants(members, &["name", "inputSchema", "_meta"], context)?;
    let name = match member(members, "name") {
        None => return Err(invalid(format!("{context} is missing name"))),
        Some(Json::String(name)) => name.clone(),
        Some(Json::Null) => String::new(),
        Some(_) => return Err(invalid(format!("{context} name must be a string"))),
    };
    let operation = single_member_operation("tool", &name);
    if let Err(err) = Operation::new(vocabulary, &operation) {
        let reason = format!("{context} name is not an R3 MCP tool name");
        return Err(invalid(reason).with_cause(err));
    }
    validate_input_schema(member(members, "inputSchema"), context)?;
    let hints = match member(members, "_meta") {
        None => None,
        Some(Json::Object(meta)) => published_hints(
            member(meta, "aauth.dev/access-mode"),
            member(meta, "aauth.dev/budget"),
            context,
        )?,
        Some(_) => {
            return Err(invalid_annotation(format!(
                "{context} _meta must be an object"
            )));
        }
    };
    Ok(DefinedTool {
        name,
        operation,
        hints,
    })
}

fn validate_input_schema(schema: Option<&Json>, context: &str) -> Result<(), DefinitionError> {
    let Some(schema) = schema else {
        return Err(invalid(format!("{context} is missing inputSchema")));
    };
    let Json::Object(members) = schema else {
        return Err(invalid(format!(
            "{context} inputSchema must be a JSON Schema object"
        )));
    };
    if !matches!(member(members, "type"), Some(Json::String(kind)) if kind.as_str() == "object") {
        return Err(invalid(format!(
            "{context} inputSchema must have object root type"
        )));
    }
    match check_schema_resource(schema, INPUT_SCHEMA_LOCATION) {
        Ok(()) => Ok(()),
        Err(SchemaRefusal::External(reference)) => Err(unresolved(format!(
            "{context} inputSchema requires external reference resolution: {reference}"
        ))),
        Err(SchemaRefusal::Invalid(reason)) => Err(invalid(format!(
            "{context} inputSchema is not a valid JSON Schema: {reason}"
        ))),
    }
}
