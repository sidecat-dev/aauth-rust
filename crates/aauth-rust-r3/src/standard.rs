//! The seven standard vocabularies, `urn:aauth:vocabulary:*`.
//!
//! Each codec parses the operation grammar the draft gives it and nothing more.
//! It does not fetch or read a definition and does not read annotations. An
//! operation object carries only the members its vocabulary defines. An optional
//! member is either absent or a valid value: `null` and `""` are refused, and
//! absence never equals a present value.

use crate::annotation::AnnotationEncoding;
use crate::error::Error;
use crate::jsonvalue::{Json, parse_json, push_key, push_string};
use crate::reference::validate_https_uri;
use crate::uri::VocabularyUri;
use crate::vocabulary::{Codec, Vocabulary};

/// One fresh registration for each standard vocabulary, in draft order.
///
/// Registrations from two calls are not interchangeable.
///
/// # Errors
/// Returns [`Error`] when a built-in URI or annotation encoding is refused.
pub fn standard_vocabularies() -> Result<Vec<Vocabulary>, Error> {
    Ok(vec![
        Vocabulary::new(McpCodec)?,
        Vocabulary::new(OpenApiCodec)?,
        Vocabulary::new(GrpcCodec)?,
        Vocabulary::new(GraphQlCodec)?,
        Vocabulary::new(AsyncApiCodec)?,
        Vocabulary::new(WsdlCodec)?,
        Vocabulary::new(ODataCodec)?,
    ])
}

/// Operations parsed by one standard codec, in first-seen order.
///
/// Opaque. Compare sets through the codec or a [`crate::Registry`].
#[derive(Clone, Debug)]
pub struct StandardSet<E>(Vec<E>);

/// One operation object of a standard vocabulary.
///
/// `same_slot` is the identity a set holds at most once. `covered_by` and
/// `may_overlap` default to that identity. An entry with a qualifier or a method
/// list overrides them, and `may_overlap` errs toward overlap.
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
                validate_https_uri(endpoint, "discovery endpoint")
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
    /// A GraphQL name and one of `query`, `mutation`, or `subscription`. The name
    /// is the identifier: one name with two types is a conflict, never two
    /// operations. The draft defines no annotation encoding.
    GraphQlCodec,
    GraphQlOperation,
    "urn:aauth:vocabulary:graphql",
    AnnotationEncoding::UNAVAILABLE
);

standard_codec!(
    /// `urn:aauth:vocabulary:asyncapi`: `{"operationId", "action"?}`.
    ///
    /// `operationId` is the identifier. `action`, when present, is `send` or
    /// `receive`. An entry without `action` and one with it name the same
    /// operation, so a set refuses both, a union of them conflicts, and neither
    /// covers the other. Annotations are published as specification extensions
    /// on the Operation Object.
    AsyncApiCodec,
    AsyncApiOperation,
    "urn:aauth:vocabulary:asyncapi",
    AnnotationEncoding::SPECIFICATION_EXTENSION
);

standard_codec!(
    /// `urn:aauth:vocabulary:wsdl`: `{"operation", "service"?}`.
    ///
    /// XML NCNames. `service` disambiguates, so it is part of the identity: an
    /// entry without `service` covers only an entry without `service`. Because
    /// either may name the same call, they are never disjoint. The draft defines
    /// no annotation encoding.
    WsdlCodec,
    WsdlOperation,
    "urn:aauth:vocabulary:wsdl",
    AnnotationEncoding::UNAVAILABLE
);

standard_codec!(
    /// `urn:aauth:vocabulary:odata`: `{"operation", "methods"?}`.
    ///
    /// `EntitySet`, or `EntitySet/Operation` for a bound function or action.
    /// `methods` is a non-empty list of distinct `GET`, `POST`, `PUT`, `PATCH`,
    /// and `DELETE`, allowed only on an entity set. Methods compare as a set: a
    /// union merges them, and two entries for one entity set are disjoint when
    /// they share no method. An entry without `methods` covers only an entry
    /// without `methods` and overlaps every entry for its entity set.
    /// Annotations are published in `$metadata`.
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
        format!("operation \"{}\"", self.operation)
    }

    fn same_slot(&self, other: &Self) -> bool {
        self.operation == other.operation
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
        let operation = required_string(members, "operation")?;
        if !is_ncname(&operation) {
            return Err(Error::new(format!(
                "operation \"{operation}\" is not an XML NCName"
            )));
        }
        let service = optional_string(members, "service")?;
        if let Some(invalid) = service.as_deref().filter(|service| !is_ncname(service)) {
            return Err(Error::new(format!(
                "service \"{invalid}\" is not an XML NCName"
            )));
        }
        Ok(Self { operation, service })
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
            Some(service) => format!(
                "operation \"{}\" of service \"{service}\"",
                self.operation
            ),
            None => format!("operation \"{}\" with no service", self.operation),
        }
    }

    fn may_overlap(&self, other: &Self) -> bool {
        self.operation == other.operation
            && match (&self.service, &other.service) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ODataMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl ODataMethod {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// OData operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ODataOperation {
    operation: String,
    methods: Option<Vec<ODataMethod>>,
}

impl Entry for ODataOperation {
    const MEMBERS: &'static [&'static str] = &["operation", "methods"];

    fn parse(members: &[(String, Json)]) -> Result<Self, Error> {
        let operation = required_string(members, "operation")?;
        let bound = match operation.split_once('/') {
            None if is_odata_identifier(&operation) => false,
            Some((entity_set, name))
                if is_odata_identifier(entity_set) && is_odata_identifier(name) =>
            {
                true
            }
            _ => {
                return Err(Error::new(format!(
                    "operation \"{operation}\" is not EntitySet or EntitySet/Operation"
                )));
            }
        };
        let methods = match member(members, "methods") {
            None => None,
            Some(_) if bound => {
                return Err(Error::new(
                    "member \"methods\" is not allowed on a bound function or action",
                ));
            }
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
                push_string(out, method.as_str());
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
                        merged.push(*method);
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

fn parse_methods(items: &[Json]) -> Result<Vec<ODataMethod>, Error> {
    if items.is_empty() {
        return Err(Error::new("member \"methods\" must not be empty"));
    }
    let mut methods = Vec::with_capacity(items.len());
    for item in items {
        let Json::String(text) = item else {
            return Err(Error::new("member \"methods\" must contain only strings"));
        };
        let Some(method) = ODataMethod::parse(text) else {
            return Err(Error::new(format!(
                "method \"{text}\" is not GET, POST, PUT, PATCH, or DELETE"
            )));
        };
        if methods.contains(&method) {
            return Err(Error::new(format!("method \"{text}\" is repeated")));
        }
        methods.push(method);
    }
    Ok(methods)
}

fn parse_entries<E: Entry>(raw: &[Vec<u8>]) -> Result<StandardSet<E>, Error> {
    let mut entries: Vec<E> = Vec::with_capacity(raw.len());
    for (index, value) in raw.iter().enumerate() {
        let entry = parse_entry::<E>(value)
            .map_err(|err| Error::wrap(format!("r3: operation {index}"), err))?;
        if entries.iter().any(|existing| existing.same_slot(&entry)) {
            return Err(Error::new(format!(
                "r3: operation {index} repeats {}",
                entry.label()
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
        Json::String(text) if text.is_empty() => Err(Error::new(format!(
            "member \"{name}\" must not be empty"
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

/// OData `SimpleIdentifier`, limited to its ASCII subset.
fn is_odata_identifier(text: &str) -> bool {
    text.len() <= 128 && is_ascii_identifier(text)
}

/// XML Namespaces `NCName`: an XML 1.0 `Name` without `:`.
fn is_ncname(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(is_name_start_char) && chars.all(is_name_char)
}

fn is_name_start_char(c: char) -> bool {
    matches!(c,
        'A'..='Z'
        | '_'
        | 'a'..='z'
        | '\u{C0}'..='\u{D6}'
        | '\u{D8}'..='\u{F6}'
        | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}'
        | '\u{37F}'..='\u{1FFF}'
        | '\u{200C}'..='\u{200D}'
        | '\u{2070}'..='\u{218F}'
        | '\u{2C00}'..='\u{2FEF}'
        | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}'
        | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start_char(c)
        || matches!(c,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}
