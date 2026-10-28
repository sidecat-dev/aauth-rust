//! WSDL 1.1 definitions for the standard WSDL vocabulary.
//!
//! A self-contained document yields the operations its services expose.
//! Imports and includes are unresolved dependencies. Nothing here fetches.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinedOperation, DefinitionCodec, DefinitionError, DefinitionErrorKind,
    DefinitionMaterial, DefinitionParser, DefinitionRegistration, SourceEncoding,
};
use crate::definition_support::{cached_parser, parse_standard};
use crate::error::Error;
use crate::jsonvalue::{push_key, push_string};
use crate::standard::WsdlCodec;

const WSDL_NAMESPACE: &str = "http://schemas.xmlsoap.org/wsdl/";

/// Exact self-contained WSDL 1.1 document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsdlDocumentSource {
    exact: Vec<u8>,
}

impl WsdlDocumentSource {
    /// Receipt encoding shared with the Go reference.
    pub const SOURCE_ENCODING: &'static str = "application/wsdl+xml";
    /// Copy `exact`.
    pub fn new(exact: &[u8]) -> Self {
        Self {
            exact: exact.to_vec(),
        }
    }
    /// Exact document bytes.
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}

struct WsdlDefinitionCodec;

impl DefinitionCodec<WsdlDocumentSource> for WsdlDefinitionCodec {
    fn vocabulary(&self) -> Result<crate::Vocabulary, Error> {
        WsdlCodec::vocabulary()
    }
    fn parse_definition(
        &self,
        source: &WsdlDocumentSource,
    ) -> Result<DefinitionMaterial, DefinitionError> {
        parse_wsdl_definition(source)
    }
}

impl WsdlCodec {
    /// Process-wide WSDL definition parser.
    ///
    /// # Errors
    /// Returns [`Error`] when the WSDL vocabulary is unavailable.
    pub fn definition_parser() -> Result<DefinitionParser<WsdlDocumentSource>, Error> {
        static PARSER: OnceLock<Option<DefinitionParser<WsdlDocumentSource>>> = OnceLock::new();
        cached_parser(
            &PARSER,
            || DefinitionParser::new(WsdlDefinitionCodec),
            Self::URI,
        )
    }

    /// Derive operations from one WSDL 1.1 document. Performs no I/O.
    ///
    /// # Errors
    /// Returns a typed [`DefinitionError`].
    pub fn parse_definition(
        endpoint: &str,
        source: &WsdlDocumentSource,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        parse_standard(Self::definition_parser(), Self::URI, endpoint, source)
    }

    /// Registration of [`Self::definition_parser`].
    ///
    /// # Errors
    /// Returns [`Error`] when the WSDL vocabulary is unavailable.
    pub fn definition_registration() -> Result<DefinitionRegistration, Error> {
        Self::definition_parser().map(|parser| parser.registration())
    }
}

struct Operation {
    name: String,
    service: Option<String>,
}

fn new_operation(name: &str) -> Result<Operation, Error> {
    new_operation_parts(name, None)
}

fn new_service_operation(name: &str, service: &str) -> Result<Operation, Error> {
    new_operation_parts(name, Some(service))
}

fn new_operation_parts(name: &str, service: Option<&str>) -> Result<Operation, Error> {
    validate_name("operation", name)?;
    let service = match service {
        Some(service) => {
            validate_name("service", service)?;
            Some(service.to_owned())
        }
        None => None,
    };
    Ok(Operation {
        name: name.to_owned(),
        service,
    })
}

fn marshal_operation(operation: &Operation) -> Result<Vec<u8>, Error> {
    let validated = new_operation_parts(&operation.name, operation.service.as_deref())?;
    let mut out = Vec::new();
    out.push(b'{');
    push_key(&mut out, "operation");
    push_string(&mut out, &validated.name);
    if let Some(service) = &validated.service {
        out.push(b',');
        push_key(&mut out, "service");
        push_string(&mut out, service);
    }
    out.push(b'}');
    Ok(out)
}

fn validate_name(kind: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value != value.trim() {
        return Err(Error::new(format!(
            "wsdl: {kind} must be non-empty, trimmed UTF-8"
        )));
    }
    Ok(())
}

fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{code:04x}", code = c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_wsdl_definition(
    source: &WsdlDocumentSource,
) -> Result<DefinitionMaterial, DefinitionError> {
    if blank_document(&source.exact) {
        return Err(incomplete("WSDL document is empty"));
    }
    let (port_types, bindings, services) = parse_wsdl_document(&source.exact)?;
    let typed = derive_bound_operations(&port_types, &bindings, &services)?;
    let encoding =
        SourceEncoding::new(WsdlDocumentSource::SOURCE_ENCODING).map_err(material_error)?;
    let mut operations = Vec::with_capacity(typed.len());
    for operation in &typed {
        let encoded = marshal_operation(operation).map_err(material_error)?;
        operations.push(DefinedOperation::new(&encoded, None).map_err(material_error)?);
    }
    DefinitionMaterial::new(encoding, source.exact.clone(), operations).map_err(material_error)
}

fn material_error(err: Error) -> DefinitionError {
    DefinitionError::new(
        DefinitionErrorKind::InvalidSource,
        "parse authoritative definition",
    )
    .with_cause(err)
}

fn blank_document(source: &[u8]) -> bool {
    match std::str::from_utf8(source) {
        Ok(text) => text.trim().is_empty(),
        Err(_) => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QName {
    namespace: String,
    local: String,
}

impl QName {
    fn blank() -> Self {
        Self {
            namespace: String::new(),
            local: String::new(),
        }
    }
}

impl fmt::Display for QName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{{{}}}{}", self.namespace, self.local)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RawName {
    prefix: String,
    local: String,
}

struct RawAttr {
    name: RawName,
    value: String,
}

struct Attr {
    space: String,
    local: String,
    value: String,
}

struct PortTypeDefinition {
    name: QName,
    by_name: BTreeSet<String>,
}

struct BindingDefinition {
    name: QName,
    port_type: QName,
    operations: Vec<String>,
    by_name: BTreeSet<String>,
}

struct ServiceDefinition {
    name: String,
    bindings: Vec<QName>,
}

struct Frame {
    name: QName,
    raw: RawName,
    namespaces: BTreeMap<String, String>,
}

struct ParseState {
    port_types: BTreeMap<QName, PortTypeDefinition>,
    bindings: BTreeMap<QName, BindingDefinition>,
    messages: BTreeSet<QName>,
    message_references: Vec<QName>,
    services: Vec<ServiceDefinition>,
    frames: Vec<Frame>,
    target_namespace: String,
    current_port_type: Option<QName>,
    current_port_type_operation: String,
    current_port_type_operation_has_message: bool,
    current_binding: Option<QName>,
    current_service: Option<usize>,
    root_seen: bool,
}

#[derive(Debug)]
struct XmlError(String);

impl std::error::Error for XmlError {}

impl fmt::Display for XmlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl XmlError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

fn invalid_xml(err: XmlError) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::InvalidSource, "invalid WSDL XML").with_cause(err)
}

fn invalid_source(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::InvalidSource, reason)
}

fn incomplete(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::IncompleteSource, reason)
}

fn unresolved(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::UnresolvedDependency, reason)
}

fn ambiguous(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::IdentityAmbiguous, reason)
}

fn unsupported(reason: impl Into<String>) -> DefinitionError {
    DefinitionError::new(DefinitionErrorKind::SourceKindUnsupported, reason)
}

type WsdlDocument = (
    BTreeMap<QName, PortTypeDefinition>,
    BTreeMap<QName, BindingDefinition>,
    Vec<ServiceDefinition>,
);

fn parse_wsdl_document(source: &[u8]) -> Result<WsdlDocument, DefinitionError> {
    let mut parser = XmlCursor {
        data: source,
        index: 0,
    };
    let mut state = ParseState {
        port_types: BTreeMap::new(),
        bindings: BTreeMap::new(),
        messages: BTreeSet::new(),
        message_references: Vec::new(),
        services: Vec::new(),
        frames: Vec::new(),
        target_namespace: String::new(),
        current_port_type: None,
        current_port_type_operation: String::new(),
        current_port_type_operation_has_message: false,
        current_binding: None,
        current_service: None,
        root_seen: false,
    };
    loop {
        match parser.next_token().map_err(invalid_xml)? {
            None => break,
            Some(Token::Directive) => {
                return Err(invalid_source("WSDL directives are not supported"));
            }
            Some(Token::Text(text)) => {
                if state.frames.is_empty() && !text.trim().is_empty() {
                    return Err(invalid_source(
                        "WSDL document contains text outside its root element",
                    ));
                }
            }
            Some(Token::Start {
                raw_name,
                attrs,
                empty,
            }) => state.on_start(raw_name, attrs, empty)?,
            Some(Token::End { raw_name }) => {
                let (name, open_raw) = match state.frames.last() {
                    Some(frame) => (frame.name.clone(), frame.raw.clone()),
                    None => return Err(invalid_source("unbalanced WSDL XML")),
                };
                if open_raw != raw_name {
                    return Err(invalid_xml(XmlError::new(
                        "end tag does not match the open element",
                    )));
                }
                state.on_end(&name)?;
            }
        }
    }
    if !state.root_seen {
        return Err(incomplete("WSDL document is empty"));
    }
    for reference in &state.message_references {
        if !state.messages.contains(reference) {
            return Err(unresolved(format!(
                "portType operation references unknown message {reference}"
            )));
        }
    }
    Ok((state.port_types, state.bindings, state.services))
}

impl ParseState {
    fn on_start(
        &mut self,
        raw_name: RawName,
        raw_attrs: Vec<RawAttr>,
        empty: bool,
    ) -> Result<(), DefinitionError> {
        let namespaces = self.element_namespaces(&raw_attrs)?;
        let name = expand_element(&raw_name, &namespaces).map_err(invalid_xml)?;
        let attrs = translate_attributes(&raw_attrs, &namespaces).map_err(invalid_xml)?;
        if self.frames.is_empty() && self.root_seen {
            return Err(invalid_source(
                "WSDL document contains multiple top-level elements",
            ));
        }
        if let Err(cause) = distinct_attributes(&attrs) {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "WSDL element has duplicate attributes",
            )
            .with_cause(Error::new(cause)));
        }
        let parent = match self.frames.last() {
            Some(frame) => frame.name.clone(),
            None => QName::blank(),
        };
        self.frames.push(Frame {
            name: name.clone(),
            raw: raw_name,
            namespaces: namespaces.clone(),
        });
        self.after_start(&parent, &name, &attrs, &namespaces)?;
        if empty {
            self.on_end(&name)?;
        }
        Ok(())
    }

    fn element_namespaces(
        &self,
        raw_attrs: &[RawAttr],
    ) -> Result<BTreeMap<String, String>, DefinitionError> {
        let mut namespaces = match self.frames.last() {
            Some(frame) => frame.namespaces.clone(),
            None => {
                let mut namespaces = BTreeMap::new();
                namespaces.insert(
                    "xml".to_owned(),
                    "http://www.w3.org/XML/1998/namespace".to_owned(),
                );
                namespaces
            }
        };
        apply_namespace_declarations(&mut namespaces, raw_attrs);
        Ok(namespaces)
    }

    fn after_start(
        &mut self,
        parent: &QName,
        name: &QName,
        attrs: &[Attr],
        namespaces: &BTreeMap<String, String>,
    ) -> Result<(), DefinitionError> {
        if !self.root_seen {
            self.root_seen = true;
            if name.namespace != WSDL_NAMESPACE || name.local != "definitions" {
                return Err(unsupported("document root must be WSDL 1.1 definitions"));
            }
            let target_namespace = attribute(attrs, "targetNamespace");
            if target_namespace.is_empty() {
                return Err(incomplete("WSDL definitions requires targetNamespace"));
            }
            self.target_namespace = target_namespace.to_owned();
        }
        if name.local == "import" || name.local == "include" {
            return Err(unresolved(format!(
                "WSDL {} requires caller resolution",
                name.local
            )));
        }
        if name.namespace != WSDL_NAMESPACE {
            return Ok(());
        }
        if !valid_wsdl_placement(&name.local, parent) {
            return Err(invalid_source(format!(
                "WSDL {} is not valid below {}",
                name.local, parent.local
            )));
        }
        self.observe(parent, name, attrs, namespaces)
    }

    fn observe(
        &mut self,
        parent: &QName,
        name: &QName,
        attrs: &[Attr],
        namespaces: &BTreeMap<String, String>,
    ) -> Result<(), DefinitionError> {
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "definitions"
            && name.local == "message"
        {
            let declared = declared_name(attrs, &self.target_namespace, "message")?;
            if self.messages.contains(&declared) {
                return Err(ambiguous(format!("duplicate WSDL message {declared}")));
            }
            self.messages.insert(declared);
            return Ok(());
        }
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "definitions"
            && name.local == "portType"
        {
            let declared = declared_name(attrs, &self.target_namespace, "portType")?;
            if self.port_types.contains_key(&declared) {
                return Err(ambiguous(format!("duplicate WSDL portType {declared}")));
            }
            self.port_types.insert(
                declared.clone(),
                PortTypeDefinition {
                    name: declared.clone(),
                    by_name: BTreeSet::new(),
                },
            );
            self.current_port_type = Some(declared);
            return Ok(());
        }
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "portType"
            && name.local == "operation"
            && self.current_port_type.is_some()
        {
            let op_name = required_attribute(attrs, "name", "portType operation")?;
            let current_name = match &self.current_port_type {
                Some(current_name) => current_name.clone(),
                None => return Ok(()),
            };
            {
                let Some(port_type) = self.port_types.get_mut(&current_name) else {
                    return Ok(());
                };
                if port_type.by_name.contains(&op_name) {
                    return Err(ambiguous(format!(
                        "portType {} overloads operation {}",
                        port_type.name,
                        quoted(&op_name)
                    )));
                }
                port_type.by_name.insert(op_name.clone());
            }
            self.current_port_type_operation = op_name;
            self.current_port_type_operation_has_message = false;
            return Ok(());
        }
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "operation"
            && !self.current_port_type_operation.is_empty()
            && (name.local == "input" || name.local == "output")
        {
            let context = format!("portType operation {}", name.local);
            let reference = required_qname(attrs, "message", namespaces, &context)?;
            self.message_references.push(reference);
            self.current_port_type_operation_has_message = true;
            return Ok(());
        }
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "definitions"
            && name.local == "binding"
        {
            let declared = declared_name(attrs, &self.target_namespace, "binding")?;
            if self.bindings.contains_key(&declared) {
                return Err(ambiguous(format!("duplicate WSDL binding {declared}")));
            }
            let port_type = required_qname(attrs, "type", namespaces, "binding type")?;
            self.bindings.insert(
                declared.clone(),
                BindingDefinition {
                    name: declared.clone(),
                    port_type,
                    operations: Vec::new(),
                    by_name: BTreeSet::new(),
                },
            );
            self.current_binding = Some(declared);
            return Ok(());
        }
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "binding"
            && name.local == "operation"
            && self.current_binding.is_some()
        {
            let op_name = required_attribute(attrs, "name", "binding operation")?;
            let current_name = match &self.current_binding {
                Some(current_name) => current_name.clone(),
                None => return Ok(()),
            };
            let Some(binding) = self.bindings.get_mut(&current_name) else {
                return Ok(());
            };
            if binding.by_name.contains(&op_name) {
                return Err(ambiguous(format!(
                    "binding {} repeats operation {}",
                    binding.name,
                    quoted(&op_name)
                )));
            }
            binding.by_name.insert(op_name.clone());
            binding.operations.push(op_name);
            return Ok(());
        }
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "definitions"
            && name.local == "service"
        {
            let service_name = required_attribute(attrs, "name", "service")?;
            if self
                .services
                .iter()
                .any(|existing| existing.name == service_name)
            {
                return Err(ambiguous(format!(
                    "duplicate WSDL service {}",
                    quoted(&service_name)
                )));
            }
            self.current_service = Some(self.services.len());
            self.services.push(ServiceDefinition {
                name: service_name,
                bindings: Vec::new(),
            });
            return Ok(());
        }
        if parent.namespace == WSDL_NAMESPACE
            && parent.local == "service"
            && name.local == "port"
            && self.current_service.is_some()
        {
            let reference = required_qname(attrs, "binding", namespaces, "service port binding")?;
            let Some(index) = self.current_service else {
                return Ok(());
            };
            if let Some(service) = self.services.get_mut(index) {
                service.bindings.push(reference);
            }
        }
        Ok(())
    }

    fn on_end(&mut self, name: &QName) -> Result<(), DefinitionError> {
        if name.namespace == WSDL_NAMESPACE {
            match name.local.as_str() {
                "operation" => {
                    if !self.current_port_type_operation.is_empty() {
                        if !self.current_port_type_operation_has_message {
                            return Err(incomplete(format!(
                                "WSDL portType operation {} requires input or output message",
                                quoted(&self.current_port_type_operation)
                            )));
                        }
                        self.current_port_type_operation.clear();
                        self.current_port_type_operation_has_message = false;
                    }
                }
                "portType" => self.current_port_type = None,
                "binding" => self.current_binding = None,
                "service" => self.current_service = None,
                _ => {}
            }
        }
        if self.frames.pop().is_none() {
            return Err(invalid_source("unbalanced WSDL XML"));
        }
        Ok(())
    }
}

fn valid_wsdl_placement(local: &str, parent: &QName) -> bool {
    if local == "documentation" {
        return true;
    }
    if local == "definitions" {
        return parent.namespace.is_empty() && parent.local.is_empty();
    }
    if parent.namespace != WSDL_NAMESPACE {
        return false;
    }
    match parent.local.as_str() {
        "definitions" => matches!(
            local,
            "types" | "import" | "include" | "message" | "portType" | "binding" | "service"
        ),
        "message" => local == "part",
        "portType" | "binding" => local == "operation",
        "operation" => matches!(local, "input" | "output" | "fault"),
        "service" => local == "port",
        _ => false,
    }
}

fn distinct_attributes(attrs: &[Attr]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for attr in attrs {
        if !seen.insert((attr.space.clone(), attr.local.clone())) {
            return Err(format!("duplicate attribute {}", attr.local));
        }
    }
    Ok(())
}

struct BoundObservation {
    service: String,
    name: String,
    meaning: String,
}

fn derive_bound_operations(
    port_types: &BTreeMap<QName, PortTypeDefinition>,
    bindings: &BTreeMap<QName, BindingDefinition>,
    services: &[ServiceDefinition],
) -> Result<Vec<Operation>, DefinitionError> {
    // Map keys are namespace then local, so a missing binding refuses in one stable order.
    for (name, binding) in bindings {
        let Some(port_type) = port_types.get(&binding.port_type) else {
            return Err(unresolved(format!(
                "binding {name} references unknown portType {}",
                binding.port_type
            )));
        };
        for operation in &binding.operations {
            if !port_type.by_name.contains(operation) {
                return Err(unresolved(format!(
                    "binding {name} operation {} is absent from portType {}",
                    quoted(operation),
                    port_type.name
                )));
            }
        }
    }

    let mut observations = Vec::new();
    for service in services {
        let mut by_operation: BTreeMap<String, String> = BTreeMap::new();
        for binding_name in &service.bindings {
            let Some(binding) = bindings.get(binding_name) else {
                return Err(unresolved(format!(
                    "service {} references unknown binding {binding_name}",
                    quoted(&service.name)
                )));
            };
            for operation in &binding.operations {
                let meaning = format!("{}/{}", binding.name, operation);
                if let Some(previous) = by_operation.get(operation) {
                    if previous != &meaning {
                        return Err(ambiguous(format!(
                            "service {} maps operation {} to multiple bindings",
                            quoted(&service.name),
                            quoted(operation)
                        )));
                    }
                    continue;
                }
                by_operation.insert(operation.clone(), meaning.clone());
                observations.push(BoundObservation {
                    service: service.name.clone(),
                    name: operation.clone(),
                    meaning,
                });
            }
        }
    }

    let mut by_name: BTreeMap<String, Vec<BoundObservation>> = BTreeMap::new();
    let mut names = Vec::new();
    for observation in observations {
        if !by_name.contains_key(&observation.name) {
            names.push(observation.name.clone());
        }
        by_name
            .entry(observation.name.clone())
            .or_default()
            .push(observation);
    }
    let mut result = Vec::new();
    for name in names {
        let Some(group) = by_name.remove(&name) else {
            continue;
        };
        let mut meanings = BTreeSet::new();
        for observation in &group {
            meanings.insert(observation.meaning.clone());
        }
        if meanings.len() == 1 {
            let operation = new_operation(&name).map_err(|err| {
                DefinitionError::new(
                    DefinitionErrorKind::IdentityUnavailable,
                    "invalid WSDL operation name",
                )
                .with_cause(err)
            })?;
            result.push(operation);
            continue;
        }
        for observation in group {
            let operation = new_service_operation(&name, &observation.service).map_err(|err| {
                DefinitionError::new(
                    DefinitionErrorKind::IdentityUnavailable,
                    "invalid WSDL service-qualified operation",
                )
                .with_cause(err)
            })?;
            result.push(operation);
        }
    }
    Ok(result)
}

fn apply_namespace_declarations(namespaces: &mut BTreeMap<String, String>, attrs: &[RawAttr]) {
    for attr in attrs {
        if attr.name.prefix.is_empty() && attr.name.local == "xmlns" {
            namespaces.insert(String::new(), attr.value.clone());
        } else if attr.name.prefix == "xmlns" {
            namespaces.insert(attr.name.local.clone(), attr.value.clone());
        }
    }
}

fn expand_element(
    name: &RawName,
    namespaces: &BTreeMap<String, String>,
) -> Result<QName, XmlError> {
    if name.prefix.is_empty() {
        let namespace = match namespaces.get("") {
            Some(namespace) => namespace.clone(),
            None => String::new(),
        };
        return Ok(QName {
            namespace,
            local: name.local.clone(),
        });
    }
    match namespaces.get(&name.prefix) {
        Some(namespace) if !namespace.is_empty() => Ok(QName {
            namespace: namespace.clone(),
            local: name.local.clone(),
        }),
        _ => Err(XmlError::new(format!(
            "undeclared namespace prefix {}",
            quoted(&name.prefix)
        ))),
    }
}

fn translate_attributes(
    raw_attrs: &[RawAttr],
    namespaces: &BTreeMap<String, String>,
) -> Result<Vec<Attr>, XmlError> {
    let mut attrs = Vec::with_capacity(raw_attrs.len());
    for attr in raw_attrs {
        let translated = if attr.name.prefix.is_empty() && attr.name.local == "xmlns" {
            Attr {
                space: String::new(),
                local: "xmlns".to_owned(),
                value: attr.value.clone(),
            }
        } else if attr.name.prefix == "xmlns" {
            Attr {
                space: "xmlns".to_owned(),
                local: attr.name.local.clone(),
                value: attr.value.clone(),
            }
        } else if attr.name.prefix.is_empty() {
            Attr {
                space: String::new(),
                local: attr.name.local.clone(),
                value: attr.value.clone(),
            }
        } else {
            match namespaces.get(&attr.name.prefix) {
                Some(namespace) if !namespace.is_empty() => Attr {
                    space: namespace.clone(),
                    local: attr.name.local.clone(),
                    value: attr.value.clone(),
                },
                _ => {
                    return Err(XmlError::new(format!(
                        "undeclared namespace prefix {}",
                        quoted(&attr.name.prefix)
                    )));
                }
            }
        };
        attrs.push(translated);
    }
    Ok(attrs)
}

fn declared_name(attrs: &[Attr], namespace: &str, kind: &str) -> Result<QName, DefinitionError> {
    let name = required_attribute(attrs, "name", kind)?;
    Ok(QName {
        namespace: namespace.to_owned(),
        local: name,
    })
}

fn required_qname(
    attrs: &[Attr],
    name: &str,
    namespaces: &BTreeMap<String, String>,
    context: &str,
) -> Result<QName, DefinitionError> {
    let value = required_attribute(attrs, name, context)?;
    let mut parts = value.split(':');
    let Some(first) = parts.next() else {
        return Err(unresolved(format!(
            "{context} has invalid QName {}",
            quoted(&value)
        )));
    };
    let second = parts.next();
    let third = parts.next();
    if third.is_some() || first.is_empty() || matches!(second, Some("")) {
        return Err(unresolved(format!(
            "{context} has invalid QName {}",
            quoted(&value)
        )));
    }
    let (prefix, local) = match second {
        Some(local) => (first, local),
        None => ("", first),
    };
    match namespaces.get(prefix) {
        Some(namespace) if !namespace.is_empty() => Ok(QName {
            namespace: namespace.clone(),
            local: local.to_owned(),
        }),
        _ => Err(unresolved(format!(
            "{context} QName {} has no namespace mapping",
            quoted(&value)
        ))),
    }
}

fn required_attribute(
    attrs: &[Attr],
    name: &str,
    context: &str,
) -> Result<String, DefinitionError> {
    let value = attribute(attrs, name);
    if value.is_empty() || value != value.trim() {
        return Err(incomplete(format!(
            "WSDL {context} requires a nonempty {name}"
        )));
    }
    Ok(value.to_owned())
}

fn attribute<'a>(attrs: &'a [Attr], name: &str) -> &'a str {
    for attr in attrs {
        if attr.space.is_empty() && attr.local == name {
            return &attr.value;
        }
    }
    ""
}

enum Token {
    Start {
        raw_name: RawName,
        attrs: Vec<RawAttr>,
        empty: bool,
    },
    End {
        raw_name: RawName,
    },
    Text(String),
    Directive,
}

struct XmlCursor<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> XmlCursor<'a> {
    fn next_token(&mut self) -> Result<Option<Token>, XmlError> {
        if self.index == 0 && self.data.starts_with(&[0xEF, 0xBB, 0xBF]) {
            self.index = 3;
        }
        loop {
            if self.index >= self.data.len() {
                return Ok(None);
            }
            if self.data[self.index] != b'<' {
                let start = self.index;
                while self.index < self.data.len() && self.data[self.index] != b'<' {
                    self.index += 1;
                }
                return Ok(Some(Token::Text(decode_xml_text(
                    &self.data[start..self.index],
                )?)));
            }
            if self.starts_with(b"<?") {
                self.skip_until(b"?>")?;
                continue;
            }
            if self.starts_with(b"<!--") {
                self.index += 4;
                self.skip_until(b"-->")?;
                continue;
            }
            break;
        }
        if self.starts_with(b"<![CDATA[") {
            self.index += 9;
            let start = self.index;
            self.skip_until(b"]]>")?;
            let end = self.index - 3;
            let text = std::str::from_utf8(&self.data[start..end])
                .map_err(|_| XmlError::new("invalid UTF-8 in CDATA"))?;
            return Ok(Some(Token::Text(text.to_owned())));
        }
        if self.starts_with(b"<! ") || self.starts_with(b"<!") {
            return Ok(Some(Token::Directive));
        }
        if self.starts_with(b"</") {
            self.index += 2;
            let raw_name = self.read_name()?;
            self.skip_ascii_space();
            if self.peek() != Some(b'>') {
                return Err(self.error("expected '>' after end tag"));
            }
            self.bump();
            return Ok(Some(Token::End { raw_name }));
        }
        self.index += 1;
        let raw_name = self.read_name()?;
        let mut attrs = Vec::new();
        let empty = loop {
            self.skip_ascii_space();
            match self.peek() {
                Some(b'>') => {
                    self.bump();
                    break false;
                }
                Some(b'/') => {
                    self.bump();
                    if self.peek() != Some(b'>') {
                        return Err(self.error("expected '>' after '/'"));
                    }
                    self.bump();
                    break true;
                }
                Some(_) => {
                    let name = self.read_name()?;
                    self.skip_ascii_space();
                    if self.peek() != Some(b'=') {
                        return Err(self.error("expected '=' after attribute name"));
                    }
                    self.bump();
                    self.skip_ascii_space();
                    let value = self.read_quoted()?;
                    attrs.push(RawAttr { name, value });
                }
                None => return Err(self.error("unterminated start tag")),
            }
        };
        Ok(Some(Token::Start {
            raw_name,
            attrs,
            empty,
        }))
    }

    fn read_name(&mut self) -> Result<RawName, XmlError> {
        let start = self.index;
        let Some((first, width)) = self.peek_char()? else {
            return Err(self.error("expected an XML name"));
        };
        if !is_name_start(first) {
            return Err(self.error("expected an XML name"));
        }
        self.index += width;
        loop {
            let saved = self.index;
            match self.peek_char()? {
                Some((ch, width)) if is_name_char(ch) => self.index += width,
                _ => {
                    self.index = saved;
                    break;
                }
            }
        }
        let text = std::str::from_utf8(&self.data[start..self.index])
            .map_err(|_| XmlError::new("invalid UTF-8 in XML name"))?;
        split_qname(text)
    }

    fn read_quoted(&mut self) -> Result<String, XmlError> {
        let Some(quote) = self.bump() else {
            return Err(self.error("expected a quoted attribute"));
        };
        if quote != b'"' && quote != b'\'' {
            return Err(self.error("expected a quoted attribute"));
        }
        let start = self.index;
        while let Some(byte) = self.peek() {
            if byte == quote {
                break;
            }
            if byte == b'<' {
                return Err(self.error("unescaped '<' in attribute value"));
            }
            self.bump();
        }
        if self.peek() != Some(quote) {
            return Err(self.error("unterminated attribute value"));
        }
        let raw = &self.data[start..self.index];
        self.bump();
        decode_xml_text(raw)
    }

    fn skip_until(&mut self, marker: &[u8]) -> Result<(), XmlError> {
        if marker.is_empty() {
            return Err(self.error("invalid XML marker"));
        }
        while let Some(end) = self.index.checked_add(marker.len()) {
            if end > self.data.len() {
                break;
            }
            if &self.data[self.index..end] == marker {
                self.index = end;
                return Ok(());
            }
            self.index += 1;
        }
        Err(self.error("unterminated XML construct"))
    }

    fn skip_ascii_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.data[self.index..].starts_with(prefix)
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.index).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index += 1;
        Some(byte)
    }

    fn peek_char(&self) -> Result<Option<(char, usize)>, XmlError> {
        if self.index >= self.data.len() {
            return Ok(None);
        }
        let width = utf8_char_width(self.data[self.index]);
        if width == 0 || self.index + width > self.data.len() {
            return Err(XmlError::new("invalid UTF-8"));
        }
        let text = std::str::from_utf8(&self.data[self.index..self.index + width])
            .map_err(|_| XmlError::new("invalid UTF-8"))?;
        let Some(ch) = text.chars().next() else {
            return Err(XmlError::new("invalid UTF-8"));
        };
        Ok(Some((ch, width)))
    }

    fn error(&self, message: &str) -> XmlError {
        XmlError::new(format!("{message} at byte {}", self.index))
    }
}

fn split_qname(raw: &str) -> Result<RawName, XmlError> {
    match raw.split_once(':') {
        Some((prefix, local)) => {
            if prefix.is_empty() || local.is_empty() || local.contains(':') {
                return Err(XmlError::new("invalid XML name"));
            }
            Ok(RawName {
                prefix: prefix.to_owned(),
                local: local.to_owned(),
            })
        }
        None => Ok(RawName {
            prefix: String::new(),
            local: raw.to_owned(),
        }),
    }
}

fn decode_xml_text(raw: &[u8]) -> Result<String, XmlError> {
    let mut out = String::new();
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'&' {
            let rest = &raw[index + 1..];
            let Some(semi) = rest.iter().position(|byte| *byte == b';') else {
                return Err(XmlError::new("unterminated XML entity"));
            };
            out.push(decode_entity(&rest[..semi])?);
            index += semi + 2;
            continue;
        }
        let width = utf8_char_width(raw[index]);
        if width == 0 || index + width > raw.len() {
            return Err(XmlError::new("invalid UTF-8"));
        }
        let text = std::str::from_utf8(&raw[index..index + width])
            .map_err(|_| XmlError::new("invalid UTF-8"))?;
        let Some(ch) = text.chars().next() else {
            return Err(XmlError::new("invalid UTF-8"));
        };
        if !matches!(ch as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
        {
            return Err(XmlError::new("illegal XML character"));
        }
        out.push(ch);
        index += width;
    }
    Ok(out)
}

fn decode_entity(body: &[u8]) -> Result<char, XmlError> {
    match body {
        b"lt" => Ok('<'),
        b"gt" => Ok('>'),
        b"amp" => Ok('&'),
        b"quot" => Ok('"'),
        b"apos" => Ok('\''),
        _ if body.starts_with(b"#x") || body.starts_with(b"#X") => xml_char(
            u32::from_str_radix(entity_digits(&body[2..])?, 16)
                .map_err(|_| XmlError::new("invalid XML character reference"))?,
        ),
        _ if body.starts_with(b"#") => xml_char(
            entity_digits(&body[1..])?
                .parse::<u32>()
                .map_err(|_| XmlError::new("invalid XML character reference"))?,
        ),
        _ => Err(XmlError::new("unknown XML entity")),
    }
}

fn entity_digits(digits: &[u8]) -> Result<&str, XmlError> {
    if digits.is_empty() {
        return Err(XmlError::new("invalid XML character reference"));
    }
    std::str::from_utf8(digits).map_err(|_| XmlError::new("invalid XML character reference"))
}

fn xml_char(code: u32) -> Result<char, XmlError> {
    let Some(ch) = char::from_u32(code) else {
        return Err(XmlError::new("invalid XML character reference"));
    };
    if matches!(code, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF) {
        Ok(ch)
    } else {
        Err(XmlError::new("invalid XML character reference"))
    }
}

fn utf8_char_width(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte & 0xE0 == 0xC0 {
        2
    } else if byte & 0xF0 == 0xE0 {
        3
    } else if byte & 0xF8 == 0xF0 {
        4
    } else {
        0
    }
}

fn is_name_start(ch: char) -> bool {
    ch == ':' || ch == '_' || ch.is_alphabetic()
}

fn is_name_char(ch: char) -> bool {
    is_name_start(ch) || ch.is_ascii_digit() || ch == '-' || ch == '.' || ch == '\u{00B7}'
}

#[cfg(test)]
mod tests {
    use super::{WsdlCodec, WsdlDocumentSource};
    use crate::definition::DefinitionErrorKind;

    const ENDPOINT: &str = "https://resource.example/wsdl";

    fn refusal(
        result: Result<crate::AuthoritativeSnapshot, crate::DefinitionError>,
    ) -> crate::DefinitionError {
        match result {
            Err(err) => err,
            Ok(_) => panic!("expected a definition refusal"),
        }
    }

    /// One service, so bound operations stay name-only. No import or include.
    const HEALTH: &[u8] = br#"<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:tns="urn:example:health" targetNamespace="urn:example:health">
  <message name="HealthRequest"/>
  <message name="StatusRequest"/>
  <portType name="HealthPortType">
    <operation name="Health"><input message="tns:HealthRequest"/></operation>
    <operation name="Status"><input message="tns:StatusRequest"/></operation>
  </portType>
  <binding name="HealthBinding" type="tns:HealthPortType">
    <operation name="Health"/>
    <operation name="Status"/>
  </binding>
  <service name="HealthService">
    <port name="HealthPort" binding="tns:HealthBinding"/>
  </service>
</definitions>"#;

    #[test]
    fn self_contained_wsdl_derives_name_only_bound_operations() {
        let snapshot =
            WsdlCodec::parse_definition(ENDPOINT, &WsdlDocumentSource::new(HEALTH)).expect("wsdl");
        let names: Vec<String> = snapshot
            .operations()
            .operations()
            .expect("operations")
            .iter()
            .map(|operation| String::from_utf8(operation.json().expect("json")).expect("utf8"))
            .collect();
        assert_eq!(
            names,
            vec![
                r#"{"operation":"Health"}"#.to_owned(),
                r#"{"operation":"Status"}"#.to_owned(),
            ]
        );
    }

    #[test]
    fn imports_and_empty_documents_are_outside_the_self_contained_profile() {
        let imported = br#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:test"><import location="other.wsdl"/></definitions>"#;
        assert_eq!(
            refusal(WsdlCodec::parse_definition(
                ENDPOINT,
                &WsdlDocumentSource::new(imported)
            ))
            .kind(),
            DefinitionErrorKind::UnresolvedDependency
        );
        let included = br#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:test"><include location="other.wsdl"/></definitions>"#;
        assert_eq!(
            refusal(WsdlCodec::parse_definition(
                ENDPOINT,
                &WsdlDocumentSource::new(included)
            ))
            .kind(),
            DefinitionErrorKind::UnresolvedDependency
        );
        assert_eq!(
            refusal(WsdlCodec::parse_definition(
                ENDPOINT,
                &WsdlDocumentSource::new(b"   ")
            ))
            .kind(),
            DefinitionErrorKind::IncompleteSource
        );
        assert_eq!(
            refusal(WsdlCodec::parse_definition(
                ENDPOINT,
                &WsdlDocumentSource::new(b"<")
            ))
            .kind(),
            DefinitionErrorKind::InvalidSource
        );
    }
}
