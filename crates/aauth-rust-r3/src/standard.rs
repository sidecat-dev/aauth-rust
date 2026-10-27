//! The seven standard vocabularies, `urn:aauth:vocabulary:*`.
//!
//! Ported from the Go `r3/vocab/*` codecs. Each codec parses its operation
//! grammar and nothing more: it does not fetch or read a definition and does
//! not read annotations. An operation object carries only the members its
//! vocabulary defines. Every string member is non-empty and has no surrounding
//! whitespace. An optional member is either absent or valid (`null` is refused),
//! and absence never equals a present value.

use std::sync::OnceLock;

use crate::annotation::AnnotationEncoding;
use crate::error::Error;
use crate::jsonvalue::{Json, parse_json, push_key, push_string};
use crate::reference::validate_https_uri;
use crate::uri::VocabularyUri;
use crate::vocabulary::{Codec, Registry, Vocabulary};

/// The process-wide registration of each standard vocabulary, in draft order.
///
/// Every call returns the same registrations, so sets parsed through any of them
/// compare. A registration made with [`Vocabulary::new`] is a different one.
///
/// # Errors
/// Returns [`Error`] when a built-in URI or annotation encoding is refused.
pub fn standard_vocabularies() -> Result<Vec<Vocabulary>, Error> {
    Ok(vec![
        McpCodec::vocabulary()?,
        OpenApiCodec::vocabulary()?,
        GrpcCodec::vocabulary()?,
        GraphQlCodec::vocabulary()?,
        AsyncApiCodec::vocabulary()?,
        WsdlCodec::vocabulary()?,
        ODataCodec::vocabulary()?,
    ])
}

/// A new allowlist holding all seven [`standard_vocabularies`].
///
/// # Errors
/// Returns [`Error`] when a standard vocabulary cannot be registered.
pub fn standard_registry() -> Result<Registry, Error> {
    Registry::new(&standard_vocabularies()?)
}

/// Operations parsed by one standard codec, in first-seen order.
///
/// Opaque. Compare sets through the codec or a [`crate::Registry`].
#[derive(Clone, Debug)]
pub struct StandardSet<E>(Vec<E>);

/// One operation object of a standard vocabulary.
///
/// `same_slot` is what a set may hold at most once. `covered_by` and
/// `may_overlap` default to that. An entry with an optional qualifier or a
/// method list overrides them, and `may_overlap` errs toward overlap.
trait Entry: Clone + PartialEq {
    /// Members an operation object may carry.
    const MEMBERS: &'static [&'static str];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error>;

    /// Write the members, without braces, in canonical order.
    fn write(&self, out: &mut Vec<u8>);

    /// Short description for error text.
    fn label(&self) -> String;

    fn same_slot(&self, other: &Self) -> bool {
        self == other
    }

    /// Whether `other` authorizes every call `self` names.
    fn covered_by(&self, other: &Self) -> bool {
        self == other
    }

    /// Whether one call could match both entries.
    fn may_overlap(&self, other: &Self) -> bool {
        self.same_slot(other)
    }

    /// Combine two entries in the same slot for a union.
    fn merge(&self, other: &Self) -> Result<Self, Error> {
        if self == other {
            Ok(self.clone())
        } else {
            Err(Error::new(format!(
                "r3: conflicting entries for {}",
                self.label()
            )))
        }
    }
}

macro_rules! standard_codec {
    ($(#[$doc:meta])* $codec:ident, $entry:ty, $uri:literal, $annotation:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $codec;

        impl $codec {
            /// Registered vocabulary URI.
            pub const URI: &'static str = $uri;

            /// The process-wide registration of this codec. Every call returns
            /// the same registration.
            ///
            /// # Errors
            /// Returns [`Error`] when the built-in URI or annotation encoding is refused.
            pub fn vocabulary() -> Result<Vocabulary, Error> {
                static REGISTRATION: OnceLock<Option<Vocabulary>> = OnceLock::new();
                REGISTRATION
                    .get_or_init(|| Vocabulary::new($codec).ok())
                    .clone()
                    .ok_or_else(|| {
                        Error::new(format!(
                            "r3: standard vocabulary \"{}\" did not register",
                            Self::URI
                        ))
                    })
            }
        }

        impl Codec for $codec {
            type Set = StandardSet<$entry>;

            fn uri(&self) -> VocabularyUri {
                VocabularyUri::from_static(Self::URI)
            }

            fn annotation_encoding(&self) -> AnnotationEncoding {
                $annotation
            }

            fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), Error> {
                validate_standard_endpoint(endpoint)
            }

            fn parse_set(&self, raw: &[Vec<u8>]) -> Result<Self::Set, Error> {
                parse_entries(raw)
            }

            fn marshal_set(&self, set: &Self::Set) -> Result<Vec<Vec<u8>>, Error> {
                Ok(set.0.iter().map(marshal_entry).collect())
            }

            fn union_sets<'a>(
                &self,
                sets: impl IntoIterator<Item = &'a Self::Set>,
            ) -> Result<Self::Set, Error>
            where
                Self::Set: 'a,
            {
                union_entries(sets)
            }

            fn sets_equal(&self, left: &Self::Set, right: &Self::Set) -> bool {
                entries_subset(left, right) && entries_subset(right, left)
            }

            fn is_subset(&self, subset: &Self::Set, superset: &Self::Set) -> bool {
                entries_subset(subset, superset)
            }

            fn is_disjoint(&self, left: &Self::Set, right: &Self::Set) -> bool {
                entries_disjoint(left, right)
            }
        }
    };
}

standard_codec!(
    /// `urn:aauth:vocabulary:mcp`: `{"tool"}`.
    ///
    /// The tool name from MCP tool discovery, compared exactly. Annotations are
    /// published in the tool's `_meta`.
    McpCodec,
    McpTool,
    "urn:aauth:vocabulary:mcp",
    AnnotationEncoding::MCP_META
);

standard_codec!(
    /// `urn:aauth:vocabulary:openapi`: `{"operationId"}`.
    ///
    /// The OpenAPI `operationId`, compared exactly. Annotations are published as
    /// specification extensions on the Operation Object.
    OpenApiCodec,
    OpenApiOperation,
    "urn:aauth:vocabulary:openapi",
    AnnotationEncoding::SPECIFICATION_EXTENSION
);

standard_codec!(
    /// `urn:aauth:vocabulary:grpc`: `{"method"}`.
    ///
    /// `package.ServiceName/MethodName` with protobuf identifiers and a non-empty
    /// package. The draft defines no annotation encoding.
    GrpcCodec,
    GrpcMethod,
    "urn:aauth:vocabulary:grpc",
    AnnotationEncoding::UNAVAILABLE
);

standard_codec!(
    /// `urn:aauth:vocabulary:graphql`: `{"operation", "type"}`.
    ///
    /// A GraphQL name and one of `query`, `mutation`, or `subscription`. The pair
    /// is the identity: one name with two types is two operations. The draft
    /// defines no annotation encoding.
    GraphQlCodec,
    GraphQlOperation,
    "urn:aauth:vocabulary:graphql",
    AnnotationEncoding::UNAVAILABLE
);

standard_codec!(
    /// `urn:aauth:vocabulary:asyncapi`: `{"operationId", "action"?}`.
    ///
    /// `operationId` names the operation. `action`, when present, is `send` or
    /// `receive`. An entry without `action` and one with it name the same
    /// operation: a set refuses both, a union of them conflicts, neither covers
    /// the other, and they are not disjoint. Annotations are published as
    /// specification extensions on the Operation Object.
    AsyncApiCodec,
    AsyncApiOperation,
    "urn:aauth:vocabulary:asyncapi",
    AnnotationEncoding::SPECIFICATION_EXTENSION
);

standard_codec!(
    /// `urn:aauth:vocabulary:wsdl`: `{"operation", "service"?}`.
    ///
    /// `service` disambiguates. An entry covers only an entry with the same
    /// operation and the same service or the same absence of one. An entry
    /// without `service` overlaps every entry for its operation, so a set or a
    /// union refuses it beside a service-qualified entry of the same name. The
    /// draft defines no annotation encoding.
    WsdlCodec,
    WsdlOperation,
    "urn:aauth:vocabulary:wsdl",
    AnnotationEncoding::UNAVAILABLE
);

standard_codec!(
    /// `urn:aauth:vocabulary:odata`: `{"operation", "methods"?}`.
    ///
    /// `operation` names an entity set or a bound operation. `methods` is a
    /// non-empty list of distinct HTTP method tokens and compares as a set: a
    /// union merges them, and two entries for one operation are disjoint when
    /// they share no method. An entry without `methods` covers only an entry
    /// without `methods`, overlaps every entry for its operation, and conflicts
    /// with one that has `methods`. Annotations are published in `$metadata`.
    ODataCodec,
    ODataOperation,
    "urn:aauth:vocabulary:odata",
    AnnotationEncoding::ODATA_METADATA
);

/// MCP operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpTool {
    tool: String,
}

impl Entry for McpTool {
    const MEMBERS: &'static [&'static str] = &["tool"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        Ok(Self {
            tool: required_string(members, "tool")?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_key(out, "tool");
        push_string(out, &self.tool);
    }

    fn label(&self) -> String {
        format!("tool \"{}\"", self.tool)
    }
}

/// OpenAPI operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenApiOperation {
    operation_id: String,
}

impl Entry for OpenApiOperation {
    const MEMBERS: &'static [&'static str] = &["operationId"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        Ok(Self {
            operation_id: required_string(members, "operationId")?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_key(out, "operationId");
        push_string(out, &self.operation_id);
    }

    fn label(&self) -> String {
        format!("operationId \"{}\"", self.operation_id)
    }
}

/// gRPC operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrpcMethod {
    method: String,
}

impl Entry for GrpcMethod {
    const MEMBERS: &'static [&'static str] = &["method"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        let method = required_string(members, "method")?;
        validate_grpc_method(&method)?;
        Ok(Self { method })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_key(out, "method");
        push_string(out, &self.method);
    }

    fn label(&self) -> String {
        format!("method \"{}\"", self.method)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GraphQlType {
    Query,
    Mutation,
    Subscription,
}

impl GraphQlType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
            Self::Subscription => "subscription",
        }
    }
}

/// GraphQL operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphQlOperation {
    operation: String,
    kind: GraphQlType,
}

impl Entry for GraphQlOperation {
    const MEMBERS: &'static [&'static str] = &["operation", "type"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        let operation = required_string(members, "operation")?;
        if !is_ascii_identifier(&operation) {
            return Err(Error::new(format!(
                "operation \"{operation}\" is not a GraphQL name"
            )));
        }
        let kind = match required_string(members, "type")?.as_str() {
            "query" => GraphQlType::Query,
            "mutation" => GraphQlType::Mutation,
            "subscription" => GraphQlType::Subscription,
            other => {
                return Err(Error::new(format!(
                    "type \"{other}\" is not query, mutation, or subscription"
                )));
            }
        };
        Ok(Self { operation, kind })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_key(out, "operation");
        push_string(out, &self.operation);
        out.push(b',');
        push_key(out, "type");
        push_string(out, self.kind.as_str());
    }

    fn label(&self) -> String {
        format!("{} \"{}\"", self.kind.as_str(), self.operation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsyncApiAction {
    Send,
    Receive,
}

impl AsyncApiAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }
}

/// AsyncAPI operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncApiOperation {
    operation_id: String,
    action: Option<AsyncApiAction>,
}

impl Entry for AsyncApiOperation {
    const MEMBERS: &'static [&'static str] = &["operationId", "action"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        let operation_id = required_string(members, "operationId")?;
        let action = match optional_string(members, "action")?.as_deref() {
            None => None,
            Some("send") => Some(AsyncApiAction::Send),
            Some("receive") => Some(AsyncApiAction::Receive),
            Some(other) => {
                return Err(Error::new(format!(
                    "action \"{other}\" is not send or receive"
                )));
            }
        };
        Ok(Self {
            operation_id,
            action,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_key(out, "operationId");
        push_string(out, &self.operation_id);
        if let Some(action) = self.action {
            out.push(b',');
            push_key(out, "action");
            push_string(out, action.as_str());
        }
    }

    fn label(&self) -> String {
        format!("operationId \"{}\"", self.operation_id)
    }

    fn same_slot(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id
    }
}

/// WSDL operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsdlOperation {
    operation: String,
    service: Option<String>,
}

impl Entry for WsdlOperation {
    const MEMBERS: &'static [&'static str] = &["operation", "service"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        Ok(Self {
            operation: required_string(members, "operation")?,
            service: optional_string(members, "service")?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_key(out, "operation");
        push_string(out, &self.operation);
        if let Some(service) = &self.service {
            out.push(b',');
            push_key(out, "service");
            push_string(out, service);
        }
    }

    fn label(&self) -> String {
        match &self.service {
            Some(service) => format!("operation \"{}\" of service \"{service}\"", self.operation),
            None => format!("operation \"{}\" with no service", self.operation),
        }
    }

    fn same_slot(&self, other: &Self) -> bool {
        self.operation == other.operation
            && match (&self.service, &other.service) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
    }
}

/// OData operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ODataOperation {
    operation: String,
    methods: Option<Vec<String>>,
}

impl Entry for ODataOperation {
    const MEMBERS: &'static [&'static str] = &["operation", "methods"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        let operation = required_string(members, "operation")?;
        let methods = match member(members, "methods") {
            None => None,
            Some(Json::Array(items)) => Some(parse_methods(items)?),
            Some(_) => return Err(Error::new("member \"methods\" must be an array")),
        };
        Ok(Self { operation, methods })
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_key(out, "operation");
        push_string(out, &self.operation);
        if let Some(methods) = &self.methods {
            out.push(b',');
            push_key(out, "methods");
            out.push(b'[');
            for (index, method) in methods.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                push_string(out, method);
            }
            out.push(b']');
        }
    }

    fn label(&self) -> String {
        format!("operation \"{}\"", self.operation)
    }

    fn same_slot(&self, other: &Self) -> bool {
        self.operation == other.operation
    }

    fn covered_by(&self, other: &Self) -> bool {
        self.operation == other.operation
            && match (&self.methods, &other.methods) {
                (None, None) => true,
                (Some(mine), Some(theirs)) => mine.iter().all(|method| theirs.contains(method)),
                _ => false,
            }
    }

    fn may_overlap(&self, other: &Self) -> bool {
        self.operation == other.operation
            && match (&self.methods, &other.methods) {
                (Some(mine), Some(theirs)) => mine.iter().any(|method| theirs.contains(method)),
                _ => true,
            }
    }

    fn merge(&self, other: &Self) -> Result<Self, Error> {
        let methods = match (&self.methods, &other.methods) {
            (None, None) => None,
            (Some(mine), Some(theirs)) => {
                let mut merged = mine.clone();
                for method in theirs {
                    if !merged.contains(method) {
                        merged.push(method.clone());
                    }
                }
                Some(merged)
            }
            _ => {
                return Err(Error::new(format!(
                    "r3: conflicting entries for {}: methods present in one and absent in the other",
                    self.label()
                )));
            }
        };
        Ok(Self {
            operation: self.operation.clone(),
            methods,
        })
    }
}

fn parse_methods(items: &[Json]) -> Result<Vec<String>, Error> {
    if items.is_empty() {
        return Err(Error::new("member \"methods\" must not be empty"));
    }
    let mut methods: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let Json::String(method) = item else {
            return Err(Error::new("member \"methods\" must contain only strings"));
        };
        if !is_http_token(method) {
            return Err(Error::new(format!(
                "method \"{method}\" is not an HTTP method token"
            )));
        }
        if methods.contains(method) {
            return Err(Error::new(format!("method \"{method}\" is repeated")));
        }
        methods.push(method.clone());
    }
    Ok(methods)
}

fn parse_entries<E: Entry>(raw: &[Vec<u8>]) -> Result<StandardSet<E>, Error> {
    let mut entries: Vec<E> = Vec::with_capacity(raw.len());
    for (index, value) in raw.iter().enumerate() {
        let entry = parse_entry::<E>(value)
            .map_err(|err| Error::wrap(format!("r3: operation {index}"), err))?;
        if let Some(existing) = entries.iter().find(|existing| existing.same_slot(&entry)) {
            let relation = if *existing == entry {
                "repeats"
            } else {
                "overlaps"
            };
            return Err(Error::new(format!(
                "r3: operation {index} {relation} {}",
                existing.label()
            )));
        }
        entries.push(entry);
    }
    Ok(StandardSet(entries))
}

fn parse_entry<E: Entry>(raw: &[u8]) -> Result<E, Error> {
    let Json::Object(members) = parse_json(raw)? else {
        return Err(Error::new("operation must be a JSON object"));
    };
    if let Some((name, _)) = members
        .iter()
        .find(|(name, _)| !E::MEMBERS.contains(&name.as_str()))
    {
        return Err(Error::new(format!("unknown member \"{name}\"")));
    }
    E::parse(&members)
}

fn marshal_entry<E: Entry>(entry: &E) -> Vec<u8> {
    let mut out = vec![b'{'];
    entry.write(&mut out);
    out.push(b'}');
    out
}

fn union_entries<'a, E: Entry + 'a>(
    sets: impl IntoIterator<Item = &'a StandardSet<E>>,
) -> Result<StandardSet<E>, Error> {
    let mut union: Vec<E> = Vec::new();
    for set in sets {
        for entry in &set.0 {
            match union.iter().position(|existing| existing.same_slot(entry)) {
                Some(index) => union[index] = union[index].merge(entry)?,
                None => union.push(entry.clone()),
            }
        }
    }
    Ok(StandardSet(union))
}

fn entries_subset<E: Entry>(subset: &StandardSet<E>, superset: &StandardSet<E>) -> bool {
    subset
        .0
        .iter()
        .all(|entry| superset.0.iter().any(|other| entry.covered_by(other)))
}

fn entries_disjoint<E: Entry>(left: &StandardSet<E>, right: &StandardSet<E>) -> bool {
    !left
        .0
        .iter()
        .any(|entry| right.0.iter().any(|other| entry.may_overlap(other)))
}

fn member<'a>(members: &'a [(String, Json)], name: &str) -> Option<&'a Json> {
    members
        .iter()
        .find(|(member, _)| member.as_str() == name)
        .map(|(_, value)| value)
}

fn required_string(members: &[(String, Json)], name: &str) -> Result<String, Error> {
    let value =
        member(members, name).ok_or_else(|| Error::new(format!("missing member \"{name}\"")))?;
    string_value(name, value)
}

/// `None` only when the member is absent. A present `null` is refused.
fn optional_string(members: &[(String, Json)], name: &str) -> Result<Option<String>, Error> {
    member(members, name)
        .map(|value| string_value(name, value))
        .transpose()
}

fn string_value(name: &str, value: &Json) -> Result<String, Error> {
    match value {
        Json::String(text) if text.is_empty() => {
            Err(Error::new(format!("member \"{name}\" must not be empty")))
        }
        Json::String(text) if text.trim() != text => Err(Error::new(format!(
            "member \"{name}\" must not have surrounding whitespace"
        ))),
        Json::String(text) => Ok(text.clone()),
        _ => Err(Error::new(format!("member \"{name}\" must be a string"))),
    }
}

fn validate_grpc_method(method: &str) -> Result<(), Error> {
    let valid = method.split_once('/').is_some_and(|(service, name)| {
        service
            .rsplit_once('.')
            .is_some_and(|(package, service_name)| {
                package.split('.').all(is_ascii_identifier) && is_ascii_identifier(service_name)
            })
            && is_ascii_identifier(name)
    });
    if valid {
        Ok(())
    } else {
        Err(Error::new(format!(
            "method \"{method}\" is not package.ServiceName/MethodName"
        )))
    }
}

/// `[A-Za-z_][A-Za-z0-9_]*`: a protobuf identifier and a GraphQL name.
fn is_ascii_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|first| first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// RFC 9110 `token`: one or more `tchar`.
fn is_http_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Absolute HTTPS URI, plus the refusals Go `net/url` makes that the shared
/// check does not: surrounding Unicode whitespace, DEL, a host byte that must be
/// escaped, and an invalid percent escape in the path.
fn validate_standard_endpoint(endpoint: &str) -> Result<(), Error> {
    if endpoint.trim() != endpoint || endpoint.contains('\u{7f}') {
        return Err(Error::new(
            "r3: discovery endpoint must be trimmed and free of control characters",
        ));
    }
    validate_https_uri(endpoint, "discovery endpoint")?;
    let rest = endpoint.split_once("//").map_or("", |(_, rest)| rest);
    let before_query = rest.split_once('?').map_or(rest, |(head, _)| head);
    let (authority, path) = before_query.split_once('/').unwrap_or((before_query, ""));
    if !is_url_host(authority) {
        return Err(Error::new(
            "r3: discovery endpoint host contains a byte that must be escaped",
        ));
    }
    if !has_valid_escapes(path) {
        return Err(Error::new(
            "r3: discovery endpoint path contains an invalid percent escape",
        ));
    }
    Ok(())
}

/// Bytes Go `net/url` accepts in a host and port: unreserved, sub-delims,
/// `:[]<>"`, non-ASCII, and a percent escape of a non-ASCII byte or `%25`.
fn is_url_host(authority: &str) -> bool {
    let bytes = authority.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(&[high, low]) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return false;
            }
            if matches!(high, b'0'..=b'7') && (high, low) != (b'2', b'5') {
                return false;
            }
            index += 3;
            continue;
        }
        if byte.is_ascii()
            && !byte.is_ascii_alphanumeric()
            && !b"-._~!$&'()*+,;=:[]<>\"".contains(&byte)
        {
            return false;
        }
        index += 1;
    }
    true
}

fn has_valid_escapes(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().all(|(index, byte)| {
        *byte != b'%'
            || bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    })
}
