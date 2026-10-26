//! Self-contained JSON Schema resources, as an MCP tool `inputSchema` needs them.
//!
//! Ported from what Go `r3/vocab/mcp` asks of `santhosh-tekuri/jsonschema/v6`
//! when it compiles an `inputSchema` with external loading refused: every
//! keyword the draft's meta-schema constrains has that shape, and every
//! reference resolves inside the supplied value. Drafts 4, 6, 7, 2019-09, and
//! 2020-12 are read; 2020-12 applies when `$schema` is absent, as in Go.
//!
//! Not ported: the regular-expression syntax of `pattern` values and of
//! `patternProperties` names, which Go compiles with RE2. A pattern Go refuses
//! is accepted here. Format assertion stays off, as in Go.

use std::collections::BTreeMap;

use crate::definition_support::{json_pointer, member, percent_decode};
use crate::jsonvalue::{Json, json_equal};

/// Why a schema resource was refused.
pub(crate) enum SchemaRefusal {
    /// The schema needs a resource or meta-schema the value does not contain.
    External(String),
    /// The value is not a schema of its draft.
    Invalid(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Draft {
    V4,
    V6,
    V7,
    V2019,
    V2020,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AnchorGrammar {
    V2019,
    V2020,
}

/// What a draft's meta-schema requires of one keyword's value.
#[derive(Clone, Copy)]
enum Shape {
    Schema,
    /// Draft 4 `additionalItems` and `additionalProperties`: a schema or a boolean.
    SchemaOrFlag,
    SchemaMap,
    /// A non-empty array of schemas.
    SchemaList,
    /// A schema, or a non-empty array of schemas.
    SchemaOrList,
    /// An object whose values are schemas or unique string arrays.
    Dependencies,
    /// An object whose values are unique string arrays.
    RequiredMap,
    Text,
    Flag,
    Number,
    PositiveNumber,
    /// A non-negative integer.
    Count,
    /// A unique string array.
    Names {
        non_empty: bool,
    },
    /// A simple type, or a non-empty unique array of simple types.
    Types,
    Values {
        non_empty_unique: bool,
    },
    List,
    Anchor(AnchorGrammar),
    /// An object of booleans.
    Vocabulary,
}

const SIMPLE_TYPES: [&str; 7] = [
    "array", "boolean", "integer", "null", "number", "object", "string",
];

fn invalid(reason: impl Into<String>) -> SchemaRefusal {
    SchemaRefusal::Invalid(reason.into())
}

/// Check `root` as one schema resource retrieved from `location`.
pub(crate) fn check_schema_resource(root: &Json, location: &str) -> Result<(), SchemaRefusal> {
    let draft = match root {
        Json::Object(members) => match member(members, "$schema") {
            Some(value) => meta_schema_draft(value)?,
            None => Draft::V2020,
        },
        _ => Draft::V2020,
    };
    let mut walker = Walker {
        resources: vec![(location.to_owned(), root, draft)],
        anchors: Vec::new(),
        references: Vec::new(),
        contexts: BTreeMap::new(),
    };
    walker.visit(root, location, draft)?;
    walker.resolve_references()
}

/// The bundled draft a `$schema` names. Any other meta-schema would have to
/// be loaded, which is an unresolved dependency.
fn meta_schema_draft(value: &Json) -> Result<Draft, SchemaRefusal> {
    let Json::String(uri) = value else {
        return Err(invalid("\"$schema\" must be a string"));
    };
    let (head, fragment) = split_fragment(uri);
    let host_path = head
        .strip_prefix("http://")
        .or_else(|| head.strip_prefix("https://"))
        .unwrap_or(head);
    let draft = match (host_path, fragment.is_empty()) {
        ("json-schema.org/schema" | "json-schema.org/draft/2020-12/schema", true) => Draft::V2020,
        ("json-schema.org/draft/2019-09/schema", true) => Draft::V2019,
        ("json-schema.org/draft-07/schema", true) => Draft::V7,
        ("json-schema.org/draft-06/schema", true) => Draft::V6,
        ("json-schema.org/draft-04/schema", true) => Draft::V4,
        _ => return Err(SchemaRefusal::External(uri.clone())),
    };
    Ok(draft)
}

struct Walker<'a> {
    /// Schema resources by absolute URI without a fragment.
    resources: Vec<(String, &'a Json, Draft)>,
    /// Plain-name fragments by resource URI.
    anchors: Vec<(String, String, &'a Json)>,
    /// Every reference, resolved to an absolute URI.
    references: Vec<String>,
    /// Already checked schema nodes and their effective resource/draft context.
    /// References may revisit nodes; the JSON value itself remains acyclic.
    contexts: BTreeMap<usize, (String, Draft)>,
}

impl<'a> Walker<'a> {
    fn visit(&mut self, node: &'a Json, base: &str, mut draft: Draft) -> Result<(), SchemaRefusal> {
        if self.contexts.contains_key(&std::ptr::from_ref(node).addr()) {
            return Ok(());
        }
        let members = match node {
            Json::Object(members) => members,
            Json::Bool(_) if draft != Draft::V4 => return Ok(()),
            _ => return Err(invalid("a schema must be a JSON object or boolean")),
        };
        let mut base = base.to_owned();
        let id_keyword = if draft == Draft::V4 { "id" } else { "$id" };
        if let Some(value) = member(members, id_keyword) {
            let Json::String(id) = value else {
                return Err(invalid(format!("\"{id_keyword}\" must be a string")));
            };
            let resolved = resolve_uri(&base, id);
            let (resource, fragment) = split_fragment(&resolved);
            if draft >= Draft::V2019 && !fragment.is_empty() {
                return Err(invalid("\"$id\" must not contain a non-empty fragment"));
            }
            if resource != base.as_str()
                && let Some(schema) = member(members, "$schema")
            {
                draft = meta_schema_draft(schema)?;
            }
            // A fragment-only legacy id names an anchor, not a second resource.
            // A nonempty resource id must never identify two distinct nodes.
            if resource != base.as_str() || (!id.is_empty() && fragment.is_empty()) {
                self.add_resource(resource, node, draft)?;
            }
            base = resource.to_owned();
            if !fragment.is_empty() {
                self.add_anchor(&base, fragment, node)?;
            }
        }
        if draft >= Draft::V2019
            && let Some(value) = member(members, "$anchor")
        {
            let grammar = if draft == Draft::V2019 {
                AnchorGrammar::V2019
            } else {
                AnchorGrammar::V2020
            };
            let name = anchor_name(value, "$anchor", grammar)?;
            self.add_anchor(&base, &name, node)?;
        }
        if draft == Draft::V2020
            && let Some(value) = member(members, "$dynamicAnchor")
        {
            let name = anchor_name(value, "$dynamicAnchor", AnchorGrammar::V2020)?;
            self.add_anchor(&base, &name, node)?;
        }
        self.contexts
            .insert(std::ptr::from_ref(node).addr(), (base.clone(), draft));
        let reference_keywords: &[&str] = match draft {
            Draft::V4 | Draft::V6 | Draft::V7 => &["$ref"],
            Draft::V2019 => &["$ref", "$recursiveRef"],
            Draft::V2020 => &["$ref", "$dynamicRef"],
        };
        for keyword in reference_keywords {
            if let Some(value) = member(members, keyword) {
                let Json::String(reference) = value else {
                    return Err(invalid(format!("\"{keyword}\" must be a string")));
                };
                self.references.push(resolve_uri(&base, reference));
            }
        }
        for (keyword, value) in members {
            let Some(shape) = keyword_shape(draft, keyword) else {
                continue;
            };
            if !shape_matches(shape, value, draft) {
                return Err(invalid(format!(
                    "keyword \"{keyword}\" does not match the draft meta-schema"
                )));
            }
            self.visit_subschemas(shape, value, &base, draft)?;
        }
        if draft == Draft::V4 {
            for (dependent, required) in [
                ("exclusiveMaximum", "maximum"),
                ("exclusiveMinimum", "minimum"),
            ] {
                if member(members, dependent).is_some() && member(members, required).is_none() {
                    return Err(invalid(format!("\"{dependent}\" requires \"{required}\"")));
                }
            }
        }
        Ok(())
    }

    fn add_resource(
        &mut self,
        uri: &str,
        node: &'a Json,
        draft: Draft,
    ) -> Result<(), SchemaRefusal> {
        if let Some((_, existing, _)) = self.resources.iter().find(|(name, _, _)| name == uri) {
            if !std::ptr::eq(*existing, node) {
                return Err(invalid(format!("duplicate schema resource id \"{uri}\"")));
            }
        } else {
            self.resources.push((uri.to_owned(), node, draft));
        }
        Ok(())
    }

    fn add_anchor(&mut self, uri: &str, name: &str, node: &'a Json) -> Result<(), SchemaRefusal> {
        if let Some((_, _, existing)) = self
            .anchors
            .iter()
            .find(|(resource, anchor, _)| resource == uri && anchor == name)
        {
            if !std::ptr::eq(*existing, node) {
                return Err(invalid(format!("duplicate schema anchor \"{uri}#{name}\"")));
            }
        } else {
            self.anchors.push((uri.to_owned(), name.to_owned(), node));
        }
        Ok(())
    }

    fn visit_subschemas(
        &mut self,
        shape: Shape,
        value: &'a Json,
        base: &str,
        draft: Draft,
    ) -> Result<(), SchemaRefusal> {
        match (shape, value) {
            (Shape::Schema | Shape::SchemaOrList, Json::Object(_) | Json::Bool(_))
            | (Shape::SchemaOrFlag, Json::Object(_)) => self.visit(value, base, draft),
            (Shape::SchemaList | Shape::SchemaOrList, Json::Array(items)) => {
                for item in items {
                    self.visit(item, base, draft)?;
                }
                Ok(())
            }
            (Shape::SchemaMap, Json::Object(members)) => {
                for (_, child) in members {
                    self.visit(child, base, draft)?;
                }
                Ok(())
            }
            (Shape::Dependencies, Json::Object(members)) => {
                for (_, child) in members {
                    if !matches!(child, Json::Array(_)) {
                        self.visit(child, base, draft)?;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Close over referenced targets, including targets beneath otherwise
    /// ignored annotations. The work list grows only when a previously unseen
    /// schema is visited, so recursive references do not recurse on the stack.
    fn resolve_references(&mut self) -> Result<(), SchemaRefusal> {
        for reference in &self.references {
            let (resource, _) = split_fragment(reference);
            if !self
                .resources
                .iter()
                .any(|(uri, _, _)| uri.as_str() == resource)
            {
                return Err(SchemaRefusal::External(reference.clone()));
            }
        }
        let mut index = 0;
        while index < self.references.len() {
            let reference = self.references[index].clone();
            index += 1;
            let (resource, fragment) = split_fragment(&reference);
            let Some((_, root, draft)) = self
                .resources
                .iter()
                .find(|(uri, _, _)| uri.as_str() == resource)
            else {
                return Err(SchemaRefusal::External(reference.clone()));
            };
            let Some(fragment) = percent_decode(fragment) else {
                return Err(invalid(format!(
                    "reference \"{reference}\" has an invalid percent escape"
                )));
            };
            let mut target = *root;
            let (mut base, mut draft) = self
                .contexts
                .get(&std::ptr::from_ref(target).addr())
                .cloned()
                .unwrap_or((resource.to_owned(), *draft));
            let resolved = if fragment.is_empty() {
                true
            } else if let Some(pointer) = fragment.strip_prefix('/') {
                // Preserve the closest enclosing resource's context while
                // walking into an annotation that has not been checked before.
                let mut found = true;
                for token in pointer.split('/') {
                    let Some(child) = json_pointer(target, &format!("/{token}")) else {
                        found = false;
                        break;
                    };
                    target = child;
                    if let Some(context) = self.contexts.get(&std::ptr::from_ref(target).addr()) {
                        (base, draft) = context.clone();
                    }
                }
                found
            } else if let Some((_, _, anchored)) = self
                .anchors
                .iter()
                .find(|(uri, name, _)| *uri == base && *name == fragment)
            {
                target = *anchored;
                true
            } else {
                false
            };
            if !resolved {
                return Err(invalid(format!(
                    "reference \"{reference}\" does not identify a schema in the value"
                )));
            }
            self.visit(target, &base, draft)?;
        }
        Ok(())
    }
}

fn anchor_name(
    value: &Json,
    keyword: &str,
    grammar: AnchorGrammar,
) -> Result<String, SchemaRefusal> {
    match value {
        Json::String(name) if is_anchor(name, grammar) => Ok(name.clone()),
        _ => Err(invalid(format!("\"{keyword}\" is not an anchor name"))),
    }
}

/// The meta-schema shape of `keyword` in `draft`, when the meta-schema
/// constrains it. Unknown keywords are annotations and are not checked.
fn keyword_shape(draft: Draft, keyword: &str) -> Option<Shape> {
    let boolean_schemas = draft != Draft::V4;
    let v7 = draft >= Draft::V7;
    let v2019 = draft >= Draft::V2019;
    let v2020 = draft == Draft::V2020;
    let shape = match keyword {
        "title" | "description" | "pattern" | "$schema" => Shape::Text,
        "multipleOf" => Shape::PositiveNumber,
        "maximum" | "minimum" => Shape::Number,
        "exclusiveMaximum" | "exclusiveMinimum" if boolean_schemas => Shape::Number,
        "exclusiveMaximum" | "exclusiveMinimum" => Shape::Flag,
        "maxLength" | "minLength" | "maxItems" | "minItems" | "maxProperties" | "minProperties" => {
            Shape::Count
        }
        "uniqueItems" => Shape::Flag,
        "properties" | "patternProperties" | "definitions" => Shape::SchemaMap,
        "dependencies" => Shape::Dependencies,
        "allOf" | "anyOf" | "oneOf" => Shape::SchemaList,
        "not" => Shape::Schema,
        "additionalProperties" if boolean_schemas => Shape::Schema,
        "additionalProperties" => Shape::SchemaOrFlag,
        "items" if v2020 => Shape::Schema,
        "items" => Shape::SchemaOrList,
        "additionalItems" if v2020 => return None,
        "additionalItems" if boolean_schemas => Shape::Schema,
        "additionalItems" => Shape::SchemaOrFlag,
        "type" => Shape::Types,
        "required" => Shape::Names {
            non_empty: !boolean_schemas,
        },
        "enum" => Shape::Values {
            non_empty_unique: draft <= Draft::V6,
        },
        "examples" if boolean_schemas => Shape::List,
        "contains" | "propertyNames" if boolean_schemas => Shape::Schema,
        "format" if boolean_schemas => Shape::Text,
        "$comment" | "contentMediaType" | "contentEncoding" if v7 => Shape::Text,
        "if" | "then" | "else" if v7 => Shape::Schema,
        "readOnly" | "writeOnly" if v7 => Shape::Flag,
        "$defs" | "dependentSchemas" if v2019 => Shape::SchemaMap,
        "unevaluatedItems" | "unevaluatedProperties" | "contentSchema" if v2019 => Shape::Schema,
        "maxContains" | "minContains" if v2019 => Shape::Count,
        "dependentRequired" if v2019 => Shape::RequiredMap,
        "deprecated" if v2019 => Shape::Flag,
        "$vocabulary" if v2019 => Shape::Vocabulary,
        "$recursiveAnchor" if v2020 => Shape::Anchor(AnchorGrammar::V2020),
        "$recursiveAnchor" if v2019 => Shape::Flag,
        "$recursiveRef" if v2020 => Shape::Text,
        "prefixItems" if v2020 => Shape::SchemaList,
        _ => return None,
    };
    Some(shape)
}

fn shape_matches(shape: Shape, value: &Json, draft: Draft) -> bool {
    match shape {
        Shape::Schema => is_schema(value, draft),
        Shape::SchemaOrFlag => is_schema(value, draft) || matches!(value, Json::Bool(_)),
        Shape::SchemaMap => matches!(
            value,
            Json::Object(members) if members.iter().all(|(_, child)| is_schema(child, draft))
        ),
        Shape::SchemaList => is_schema_list(value, draft),
        Shape::SchemaOrList => is_schema(value, draft) || is_schema_list(value, draft),
        Shape::Dependencies => matches!(
            value,
            Json::Object(members) if members.iter().all(|(_, child)| {
                is_schema(child, draft) || is_name_list(child, draft == Draft::V4)
            })
        ),
        Shape::RequiredMap => matches!(
            value,
            Json::Object(members) if members.iter().all(|(_, child)| is_name_list(child, false))
        ),
        Shape::Text => matches!(value, Json::String(_)),
        Shape::Flag => matches!(value, Json::Bool(_)),
        Shape::Number => matches!(value, Json::Number(_)),
        Shape::PositiveNumber => matches!(
            value,
            Json::Number(literal) if !literal.starts_with('-') && !is_zero(literal)
        ),
        Shape::Count => matches!(value, Json::Number(literal) if is_non_negative_integer(literal)),
        Shape::Names { non_empty } => is_name_list(value, non_empty),
        Shape::Types => match value {
            Json::String(name) => SIMPLE_TYPES.contains(&name.as_str()),
            Json::Array(items) => {
                !items.is_empty()
                    && items.iter().all(|item| {
                        matches!(item, Json::String(name) if SIMPLE_TYPES.contains(&name.as_str()))
                    })
                    && all_unique(items)
            }
            _ => false,
        },
        Shape::Values { non_empty_unique } => matches!(
            value,
            Json::Array(items) if !non_empty_unique || (!items.is_empty() && all_unique(items))
        ),
        Shape::List => matches!(value, Json::Array(_)),
        Shape::Anchor(grammar) => matches!(value, Json::String(text) if is_anchor(text, grammar)),
        Shape::Vocabulary => matches!(
            value,
            Json::Object(members) if members.iter().all(|(_, child)| matches!(child, Json::Bool(_)))
        ),
    }
}

fn is_schema(value: &Json, draft: Draft) -> bool {
    match value {
        Json::Object(_) => true,
        Json::Bool(_) => draft != Draft::V4,
        _ => false,
    }
}

fn is_schema_list(value: &Json, draft: Draft) -> bool {
    matches!(
        value,
        Json::Array(items) if !items.is_empty() && items.iter().all(|item| is_schema(item, draft))
    )
}

fn is_name_list(value: &Json, non_empty: bool) -> bool {
    let Json::Array(items) = value else {
        return false;
    };
    (!non_empty || !items.is_empty())
        && items.iter().all(|item| matches!(item, Json::String(_)))
        && all_unique(items)
}

fn all_unique(items: &[Json]) -> bool {
    items.iter().enumerate().all(|(index, item)| {
        !items[..index]
            .iter()
            .any(|earlier| json_equal(earlier, item))
    })
}

/// `$anchor` grammar: 2019-09 `[A-Za-z][-A-Za-z0-9.:_]*`, 2020-12 `[A-Za-z_][-A-Za-z0-9._]*`.
fn is_anchor(text: &str, grammar: AnchorGrammar) -> bool {
    let mut bytes = text.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let first_valid =
        first.is_ascii_alphabetic() || (grammar == AnchorGrammar::V2020 && first == b'_');
    first_valid
        && bytes.all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_')
                || (grammar == AnchorGrammar::V2019 && byte == b':')
        })
}

fn is_zero(literal: &str) -> bool {
    let mantissa = literal.split(['e', 'E']).next().unwrap_or(literal);
    mantissa
        .bytes()
        .all(|byte| matches!(byte, b'0' | b'.' | b'-'))
}

/// Whether a JSON number literal is an integer of at least zero, without
/// floating point: `1e2` and `2.0` are integers, `-0` is zero.
fn is_non_negative_integer(literal: &str) -> bool {
    if is_zero(literal) {
        return true;
    }
    if literal.starts_with('-') {
        return false;
    }
    let (mantissa, exponent) = literal.split_once(['e', 'E']).unwrap_or((literal, "0"));
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = format!("{whole}{fraction}");
    let trailing_zeros = digits.len() - digits.trim_end_matches('0').len();
    let scale = exponent_value(exponent)
        .saturating_sub(fraction.len() as i64)
        .saturating_add(trailing_zeros as i64);
    scale >= 0
}

fn exponent_value(text: &str) -> i64 {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let magnitude = digits.bytes().fold(0i64, |value, byte| {
        value
            .saturating_mul(10)
            .saturating_add(i64::from(byte - b'0'))
    });
    if negative { -magnitude } else { magnitude }
}

fn split_fragment(uri: &str) -> (&str, &str) {
    uri.split_once('#').unwrap_or((uri, ""))
}

struct UriParts<'a> {
    scheme: Option<&'a str>,
    authority: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

/// RFC 3986 appendix B component split.
fn uri_parts(text: &str) -> UriParts<'_> {
    let (rest, fragment) = match text.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment)),
        None => (text, None),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((rest, query)) => (rest, Some(query)),
        None => (rest, None),
    };
    let (scheme, rest) = match rest.find([':', '/']) {
        Some(index) if index > 0 && rest.as_bytes()[index] == b':' => {
            (Some(&rest[..index]), &rest[index + 1..])
        }
        _ => (None, rest),
    };
    let (authority, path) = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find('/').unwrap_or(after.len());
            (Some(&after[..end]), &after[end..])
        }
        None => (None, rest),
    };
    UriParts {
        scheme,
        authority,
        path,
        query,
        fragment,
    }
}

/// RFC 3986 section 5.2.2 reference resolution.
fn resolve_uri(base: &str, reference: &str) -> String {
    let reference = uri_parts(reference);
    let base = uri_parts(base);
    let (scheme, authority, path, query) = if reference.scheme.is_some() {
        (
            reference.scheme,
            reference.authority,
            remove_dot_segments(reference.path),
            reference.query,
        )
    } else if reference.authority.is_some() {
        (
            base.scheme,
            reference.authority,
            remove_dot_segments(reference.path),
            reference.query,
        )
    } else if reference.path.is_empty() {
        (
            base.scheme,
            base.authority,
            base.path.to_owned(),
            reference.query.or(base.query),
        )
    } else if reference.path.starts_with('/') {
        (
            base.scheme,
            base.authority,
            remove_dot_segments(reference.path),
            reference.query,
        )
    } else {
        let merged = merge_paths(&base, reference.path);
        (
            base.scheme,
            base.authority,
            remove_dot_segments(&merged),
            reference.query,
        )
    };
    let mut out = String::new();
    if let Some(scheme) = scheme {
        out.push_str(scheme);
        out.push(':');
    }
    if let Some(authority) = authority {
        out.push_str("//");
        out.push_str(authority);
    }
    out.push_str(&path);
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }
    if let Some(fragment) = reference.fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

fn merge_paths(base: &UriParts<'_>, path: &str) -> String {
    if base.authority.is_some() && base.path.is_empty() {
        return format!("/{path}");
    }
    match base.path.rfind('/') {
        Some(index) => format!("{}{path}", &base.path[..=index]),
        None => path.to_owned(),
    }
}

fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::new();
    while !input.is_empty() {
        if let Some(rest) = input
            .strip_prefix("../")
            .or_else(|| input.strip_prefix("./"))
        {
            input = rest;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            remove_last_segment(&mut output);
        } else if input == "/.." {
            input = "/";
            remove_last_segment(&mut output);
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..]
                .find('/')
                .map_or(input.len(), |index| index + start);
            output.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    output
}

fn remove_last_segment(output: &mut String) {
    match output.rfind('/') {
        Some(index) => output.truncate(index),
        None => output.clear(),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_non_negative_integer, resolve_uri};

    #[test]
    fn json_schema_counts_are_integers_without_floating_point() {
        for literal in [
            "0",
            "-0",
            "1",
            "1.0",
            "1e2",
            "2.50e1",
            "10E-1",
            "1e999999999999999999999",
        ] {
            assert!(is_non_negative_integer(literal), "{literal}");
        }
        for literal in [
            "-1",
            "1.5",
            "1e-1",
            "-2e3",
            "15e-1",
            "1e-999999999999999999999",
        ] {
            assert!(!is_non_negative_integer(literal), "{literal}");
        }
    }

    #[test]
    fn json_schema_reference_resolution_follows_rfc_3986() {
        let base = "http://a/b/c/d;p?q";
        for (reference, want) in [
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g"),
            ("?y", "http://a/b/c/d;p?y"),
            ("#s", "http://a/b/c/d;p?q#s"),
            ("", "http://a/b/c/d;p?q"),
            ("../g", "http://a/b/g"),
            ("../../g", "http://a/g"),
            ("../../../g", "http://a/g"),
            ("g;x=1/../y", "http://a/b/c/y"),
        ] {
            assert_eq!(resolve_uri(base, reference), want, "{reference}");
        }
        assert_eq!(
            resolve_uri("urn:aauth:mcp:tool-input-schema", "#/$defs/a"),
            "urn:aauth:mcp:tool-input-schema#/$defs/a"
        );
    }
}
