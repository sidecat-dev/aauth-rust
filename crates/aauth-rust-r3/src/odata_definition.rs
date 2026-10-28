//! OData 4.0 CSDL definitions for the standard OData vocabulary.
//!
//! Derived operations name entity sets and bound actions or functions.
//! The metadata does not prove HTTP methods. An `AAuth.*` annotation term
//! is refused. `edmx:Reference` is an unresolved dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinedOperation, DefinitionCodec, DefinitionError, DefinitionErrorKind,
    DefinitionMaterial, DefinitionParser, DefinitionRegistration, SourceEncoding,
};
use crate::definition_support::{cached_parser, invalid, parse_standard, single_member_operation};
use crate::error::Error;
use crate::standard::ODataCodec;

const EDMX: &str = "http://docs.oasis-open.org/odata/ns/edmx";
const EDM: &str = "http://docs.oasis-open.org/odata/ns/edm";

/// Maximum element nesting accepted from a metadata document.
///
/// Edmx 4.0 documents used here are only a handful of elements deep.
/// `element` checks this before it parses a child, so a deeper document
/// returns [`DefinitionErrorKind::InvalidSource`] instead of growing the
/// call stack without a bound.
const MAX_XML_NESTING: usize = 64;

/// Exact OData CSDL XML document. Acquisition stays with the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ODataMetadataSource {
    exact: Vec<u8>,
}

impl ODataMetadataSource {
    /// Receipt encoding shared with the Go reference.
    pub const SOURCE_ENCODING: &'static str = "application/xml;profile=odata-csdl-edmx-4.0";

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

struct ODataDefinitionCodec;

impl DefinitionCodec<ODataMetadataSource> for ODataDefinitionCodec {
    fn vocabulary(&self) -> Result<crate::Vocabulary, Error> {
        ODataCodec::vocabulary()
    }

    fn parse_definition(
        &self,
        source: &ODataMetadataSource,
    ) -> Result<DefinitionMaterial, DefinitionError> {
        parse_metadata(source)
    }
}

impl ODataCodec {
    /// Process-wide OData definition parser. Every call returns the same registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the OData vocabulary is unavailable.
    pub fn definition_parser() -> Result<DefinitionParser<ODataMetadataSource>, Error> {
        static PARSER: OnceLock<Option<DefinitionParser<ODataMetadataSource>>> = OnceLock::new();
        cached_parser(
            &PARSER,
            || DefinitionParser::new(ODataDefinitionCodec),
            Self::URI,
        )
    }

    /// Derive a snapshot from one Edmx 4.0 document. Performs no I/O.
    ///
    /// # Errors
    /// Returns a typed [`DefinitionError`]. CSDL does not publish HTTP methods.
    pub fn parse_definition(
        endpoint: &str,
        source: &ODataMetadataSource,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        parse_standard(Self::definition_parser(), Self::URI, endpoint, source)
    }

    /// Registration of [`Self::definition_parser`].
    ///
    /// # Errors
    /// Returns [`Error`] when the OData vocabulary is unavailable.
    pub fn definition_registration() -> Result<DefinitionRegistration, Error> {
        Self::definition_parser().map(|parser| parser.registration())
    }
}

fn parse_metadata(source: &ODataMetadataSource) -> Result<DefinitionMaterial, DefinitionError> {
    let root = parse_metadata_xml(&source.exact)?;
    if root.space != EDMX || root.local != "Edmx" {
        return Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "OData metadata root must be edmx:Edmx",
        ));
    }
    let version = attr(&root, "Version").unwrap_or("");
    if version != "4.0" {
        return Err(DefinitionError::new(
            DefinitionErrorKind::SourceKindUnsupported,
            "only OData CSDL Edmx version 4.0 is supported",
        ));
    }
    let mut entity_types: BTreeMap<String, String> = BTreeMap::new();
    let mut containers = Vec::new();
    let mut bound = Vec::new();
    for schema in
        children(&root, EDMX, "DataServices").flat_map(|services| children(services, EDM, "Schema"))
    {
        let namespace = attr(schema, "Namespace").unwrap_or("");
        if namespace.is_empty() {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "OData Schema requires Namespace",
            ));
        }
        let alias = attr(schema, "Alias").unwrap_or("");
        for entity in children(schema, EDM, "EntityType") {
            let name = attr(entity, "Name").unwrap_or("");
            if name.is_empty() {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::InvalidSource,
                    "OData EntityType requires Name",
                ));
            }
            let canonical = format!("{namespace}.{name}");
            register_type(&mut entity_types, &canonical, &canonical)?;
            if !alias.is_empty() && alias != namespace {
                register_type(&mut entity_types, &format!("{alias}.{name}"), &canonical)?;
            }
        }
        containers.extend(children(schema, EDM, "EntityContainer"));
        for operation in children(schema, EDM, "Action").chain(children(schema, EDM, "Function")) {
            let is_bound = attr(operation, "IsBound").unwrap_or("");
            if is_bound != "true" && is_bound != "1" {
                continue;
            }
            let name = attr(operation, "Name").unwrap_or("");
            let parameter = children(operation, EDM, "Parameter").next();
            let (parameter_name, parameter_type) = parameter
                .map(|parameter| {
                    (
                        attr(parameter, "Name").unwrap_or("").to_owned(),
                        attr(parameter, "Type").unwrap_or("").to_owned(),
                    )
                })
                .unwrap_or_default();
            if name.is_empty() || parameter_name.is_empty() || parameter_type.is_empty() {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::InvalidSource,
                    "bound OData operation requires Name and binding parameter",
                ));
            }
            let binding = parse_binding_type(&parameter_type)?;
            bound.push((name.to_owned(), binding));
        }
    }
    if containers.is_empty() {
        return Err(DefinitionError::new(
            DefinitionErrorKind::IncompleteSource,
            "OData metadata has no EntityContainer",
        ));
    }
    if containers.len() != 1 {
        return Err(DefinitionError::new(
            DefinitionErrorKind::IdentityAmbiguous,
            "OData metadata has multiple EntityContainers",
        ));
    }
    let container_name = attr(containers[0], "Name").unwrap_or("");
    if container_name.is_empty() || container_name != container_name.trim() {
        return Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "OData EntityContainer requires Name",
        ));
    }
    let mut entity_sets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen_sets = BTreeSet::new();
    let mut identifiers = Vec::new();
    for entity_set in children(containers[0], EDM, "EntitySet") {
        let name = attr(entity_set, "Name").unwrap_or("");
        let entity_type = attr(entity_set, "EntityType").unwrap_or("");
        if name.is_empty() || entity_type.is_empty() {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "OData EntitySet requires Name and EntityType",
            ));
        }
        if !seen_sets.insert(name.to_owned()) {
            return Err(DefinitionError::new(
                DefinitionErrorKind::IdentityAmbiguous,
                format!("duplicate OData EntitySet \"{name}\""),
            ));
        }
        let Some(canonical) = entity_types.get(entity_type) else {
            return Err(DefinitionError::new(
                DefinitionErrorKind::UnresolvedDependency,
                format!(
                    "OData EntitySet \"{name}\" references unknown EntityType \"{entity_type}\""
                ),
            ));
        };
        entity_sets
            .entry(canonical.clone())
            .or_default()
            .push(name.to_owned());
        identifiers.push(name.to_owned());
    }
    if identifiers.is_empty() {
        return Err(DefinitionError::new(
            DefinitionErrorKind::IncompleteSource,
            "OData EntityContainer has no EntitySets",
        ));
    }
    let mut seen_bound = BTreeSet::new();
    for (name, binding) in bound {
        let Some(canonical) = entity_types.get(&binding) else {
            return Err(DefinitionError::new(
                DefinitionErrorKind::UnresolvedDependency,
                format!(
                    "bound OData operation \"{name}\" references unknown EntityType \"{binding}\""
                ),
            ));
        };
        for entity_set in entity_sets.get(canonical).into_iter().flatten() {
            let identifier = format!("{entity_set}/{name}");
            if !seen_bound.insert(identifier.clone()) {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::IdentityAmbiguous,
                    format!("OData operation \"{identifier}\" has multiple overloads"),
                ));
            }
            identifiers.push(identifier);
        }
    }
    identifiers.sort();
    let mut operations = Vec::with_capacity(identifiers.len());
    for identifier in identifiers {
        operations.push(
            DefinedOperation::new(
                single_member_operation("operation", &identifier).as_slice(),
                None,
            )
            .map_err(|err| invalid("encode derived OData operation").with_cause(err))?,
        );
    }
    let encoding = SourceEncoding::new(ODataMetadataSource::SOURCE_ENCODING).map_err(|err| {
        DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "invalid definition material",
        )
        .with_cause(err)
    })?;
    DefinitionMaterial::new(encoding, source.exact.clone(), operations).map_err(|err| {
        DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "invalid definition material",
        )
        .with_cause(err)
    })
}

fn register_type(
    types: &mut BTreeMap<String, String>,
    name: &str,
    canonical: &str,
) -> Result<(), DefinitionError> {
    if let Some(existing) = types.get(name) {
        if existing != canonical {
            return Err(DefinitionError::new(
                DefinitionErrorKind::IdentityAmbiguous,
                format!("OData EntityType name \"{name}\" resolves to multiple types"),
            ));
        }
        return Err(DefinitionError::new(
            DefinitionErrorKind::IdentityAmbiguous,
            format!("duplicate OData EntityType \"{canonical}\""),
        ));
    }
    types.insert(name.to_owned(), canonical.to_owned());
    Ok(())
}

fn parse_binding_type(value: &str) -> Result<String, DefinitionError> {
    if value.is_empty() || value != value.trim() {
        return Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "bound OData operation has invalid binding parameter type",
        ));
    }
    const PREFIX: &str = "Collection(";
    if let Some(inner) = value.strip_prefix(PREFIX) {
        let Some(inner) = inner.strip_suffix(')') else {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "bound OData operation has invalid binding parameter type",
            ));
        };
        if inner.is_empty() || inner.contains(['(', ')']) {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "bound OData operation has invalid binding parameter type",
            ));
        }
        return Ok(inner.to_owned());
    }
    if value.contains(['(', ')']) {
        return Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "bound OData operation has invalid binding parameter type",
        ));
    }
    Ok(value.to_owned())
}

fn children<'a>(
    parent: &'a XmlElem,
    space: &str,
    local: &str,
) -> impl Iterator<Item = &'a XmlElem> {
    parent
        .children
        .iter()
        .filter(move |child| child.space == space && child.local == local)
}

fn attr<'a>(element: &'a XmlElem, local: &str) -> Option<&'a str> {
    element
        .attrs
        .iter()
        .find(|(space, name, _)| space.is_empty() && name == local)
        .map(|(_, _, value)| value.as_str())
}

struct XmlElem {
    space: String,
    local: String,
    attrs: Vec<(String, String, String)>,
    children: Vec<XmlElem>,
}

fn parse_metadata_xml(source: &[u8]) -> Result<XmlElem, DefinitionError> {
    let text = std::str::from_utf8(source).map_err(|err| {
        DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "invalid OData metadata XML",
        )
        .with_cause(err)
    })?;
    let mut parser = XmlParser {
        text,
        index: 0,
        scopes: vec![BTreeMap::new()],
    };
    parser.skip_misc()?;
    if parser.done() {
        return Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "invalid OData metadata XML",
        ));
    }
    let root = parser.element(0)?;
    parser.skip_misc()?;
    if !parser.done() {
        return Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "OData metadata contains text outside its root element",
        ));
    }
    Ok(root)
}

struct XmlParser<'a> {
    text: &'a str,
    index: usize,
    scopes: Vec<BTreeMap<String, String>>,
}

impl<'a> XmlParser<'a> {
    fn done(&self) -> bool {
        self.index >= self.text.len()
    }

    fn skip_misc(&mut self) -> Result<(), DefinitionError> {
        loop {
            self.skip_ws();
            if self.text[self.index..].starts_with("<!--") {
                let Some(end) = self.text[self.index..].find("-->") else {
                    return Err(DefinitionError::new(
                        DefinitionErrorKind::InvalidSource,
                        "invalid OData metadata XML",
                    ));
                };
                self.index += end + 3;
                continue;
            }
            if self.text[self.index..].starts_with("<?") {
                let Some(end) = self.text[self.index..].find("?>") else {
                    return Err(DefinitionError::new(
                        DefinitionErrorKind::InvalidSource,
                        "invalid OData metadata XML",
                    ));
                };
                self.index += end + 2;
                continue;
            }
            break;
        }
        Ok(())
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.text[self.index..].chars().next() {
            if ch.is_whitespace() {
                self.index += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn element(&mut self, depth: usize) -> Result<XmlElem, DefinitionError> {
        if depth >= MAX_XML_NESTING {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "OData metadata XML exceeds the nesting limit",
            ));
        }
        self.skip_misc()?;
        if !self.text[self.index..].starts_with('<') || self.text[self.index..].starts_with("</") {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "invalid OData metadata XML",
            ));
        }
        self.index += 1;
        let raw_name = self.read_name()?;
        let mut raw_attrs = Vec::new();
        loop {
            self.skip_ws();
            if self.text[self.index..].starts_with("/>") || self.text[self.index..].starts_with('>')
            {
                break;
            }
            let attr_name = self.read_name()?;
            self.skip_ws();
            if !self.text[self.index..].starts_with('=') {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::InvalidSource,
                    "invalid OData metadata XML",
                ));
            }
            self.index += 1;
            self.skip_ws();
            let value = self.read_attr_value()?;
            raw_attrs.push((attr_name, value));
        }
        // This element's declarations live only on the scope pushed here.
        // A later sibling clones the parent scope, so it cannot see them.
        let mut scope = self.scopes.last().expect("scope").clone();
        for (attr_name, value) in &raw_attrs {
            let (prefix, local) = split_name(attr_name);
            if prefix == "xmlns" {
                scope.insert(local.clone(), value.clone());
            } else if attr_name == "xmlns" {
                scope.insert(String::new(), value.clone());
            }
        }
        self.scopes.push(scope);
        let parsed = self.element_in_scope(depth, &raw_name, raw_attrs);
        self.scopes.pop();
        parsed
    }

    fn element_in_scope(
        &mut self,
        depth: usize,
        raw_name: &str,
        raw_attrs: Vec<(String, String)>,
    ) -> Result<XmlElem, DefinitionError> {
        let mut attrs = Vec::new();
        let mut seen = BTreeSet::new();
        for (attr_name, value) in raw_attrs {
            let (prefix, local) = split_name(&attr_name);
            let space = if prefix.is_empty() || prefix == "xmlns" || attr_name == "xmlns" {
                String::new()
            } else {
                self.lookup(&prefix)?
            };
            if !seen.insert((space.clone(), local.clone())) {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::InvalidSource,
                    "OData metadata element has duplicate attributes",
                ));
            }
            attrs.push((space, local, value));
        }
        let (prefix, local) = split_name(raw_name);
        let space = if prefix.is_empty() {
            self.lookup("").unwrap_or_default()
        } else {
            self.lookup(&prefix)?
        };
        if space == EDMX && local == "Reference" {
            return Err(DefinitionError::new(
                DefinitionErrorKind::UnresolvedDependency,
                "OData metadata contains edmx:Reference",
            ));
        }
        if space == EDM
            && local == "Annotation"
            && attrs
                .iter()
                .any(|(_, name, value)| name == "Term" && value.starts_with("AAuth."))
        {
            return Err(DefinitionError::new(
                DefinitionErrorKind::SourceKindUnsupported,
                "the R3 draft does not define the OData AAuth term namespace and overload targeting",
            ));
        }
        let empty = self.text[self.index..].starts_with("/>");
        self.index += if empty { 2 } else { 1 };
        let mut children = Vec::new();
        if !empty {
            loop {
                self.skip_misc()?;
                if self.text[self.index..].starts_with("</") {
                    break;
                }
                if self.done() || !self.text[self.index..].starts_with('<') {
                    return Err(DefinitionError::new(
                        DefinitionErrorKind::InvalidSource,
                        "invalid OData metadata XML",
                    ));
                }
                children.push(self.element(depth + 1)?);
            }
            self.index += 2;
            let end_name = self.read_name()?;
            self.skip_ws();
            if !self.text[self.index..].starts_with('>') || end_name != raw_name {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::InvalidSource,
                    "invalid OData metadata XML",
                ));
            }
            self.index += 1;
        }
        Ok(XmlElem {
            space,
            local,
            attrs,
            children,
        })
    }

    fn lookup(&self, prefix: &str) -> Result<String, DefinitionError> {
        for scope in self.scopes.iter().rev() {
            if let Some(value) = scope.get(prefix) {
                return Ok(value.clone());
            }
        }
        if prefix.is_empty() {
            return Ok(String::new());
        }
        Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "invalid OData metadata XML",
        ))
    }

    fn read_name(&mut self) -> Result<String, DefinitionError> {
        let start = self.index;
        while let Some(ch) = self.text[self.index..].chars().next() {
            if ch.is_whitespace() || matches!(ch, '=' | '>' | '/' | '<') {
                break;
            }
            self.index += ch.len_utf8();
        }
        if start == self.index {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "invalid OData metadata XML",
            ));
        }
        Ok(self.text[start..self.index].to_owned())
    }

    fn read_attr_value(&mut self) -> Result<String, DefinitionError> {
        let quote = self.text[self.index..].chars().next().unwrap_or('\0');
        if quote != '"' && quote != '\'' {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "invalid OData metadata XML",
            ));
        }
        self.index += quote.len_utf8();
        let start = self.index;
        while let Some(ch) = self.text[self.index..].chars().next() {
            if ch == quote {
                let value = self.text[start..self.index].to_owned();
                self.index += ch.len_utf8();
                return Ok(value);
            }
            self.index += ch.len_utf8();
        }
        Err(DefinitionError::new(
            DefinitionErrorKind::InvalidSource,
            "invalid OData metadata XML",
        ))
    }
}

fn split_name(name: &str) -> (String, String) {
    match name.split_once(':') {
        Some((prefix, local)) => (prefix.to_owned(), local.to_owned()),
        None => (String::new(), name.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_XML_NESTING, ODataCodec, ODataMetadataSource};
    use crate::definition::DefinitionErrorKind;

    const ENDPOINT: &str = "https://resource.example/odata";

    fn refusal(
        result: Result<crate::AuthoritativeSnapshot, crate::DefinitionError>,
    ) -> crate::DefinitionError {
        match result {
            Err(err) => err,
            Ok(_) => panic!("expected a definition refusal"),
        }
    }

    #[test]
    fn metadata_derives_entity_sets_without_claiming_methods() {
        let source = ODataMetadataSource::new(
            br#"
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:DataServices>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar" Alias="Cal">
      <EntityType Name="Event"/>
      <EntityContainer Name="Service">
        <EntitySet Name="Events" EntityType="Calendar.Event"/>
      </EntityContainer>
      <Action Name="Cancel" IsBound="true">
        <Parameter Name="bindingParameter" Type="Cal.Event"/>
      </Action>
      <Function Name="Upcoming" IsBound="true">
        <Parameter Name="bindingParameter" Type="Collection(Calendar.Event)"/>
      </Function>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#,
        );
        let snapshot = ODataCodec::parse_definition(ENDPOINT, &source).expect("metadata");
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
                r#"{"operation":"Events"}"#.to_owned(),
                r#"{"operation":"Events/Cancel"}"#.to_owned(),
                r#"{"operation":"Events/Upcoming"}"#.to_owned(),
            ]
        );
        let with_method = crate::Operation::new(
            &ODataCodec::vocabulary().expect("vocabulary"),
            br#"{"operation":"Events","methods":["GET"]}"#,
        )
        .expect("method operation");
        let declared = crate::OperationSet::new(&[with_method]).expect("set");
        assert_eq!(
            snapshot
                .validate_defined(&declared)
                .expect_err("methods")
                .definition_kind(),
            Some(DefinitionErrorKind::OperationNotDefined)
        );
    }

    #[test]
    fn metadata_refuses_reference_annotation_and_bad_xml() {
        let reference = br#"<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:Reference Uri="types.xml"/><edmx:DataServices/></edmx:Edmx>"#;
        assert_eq!(
            refusal(ODataCodec::parse_definition(
                ENDPOINT,
                &ODataMetadataSource::new(reference)
            ))
            .kind(),
            DefinitionErrorKind::UnresolvedDependency
        );
        let annotation = br#"<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityType Name="Event"/><EntityContainer Name="Service"><EntitySet Name="Events" EntityType="Calendar.Event"><Annotation Term="AAuth.AccessMode" String="person-token"/></EntitySet></EntityContainer></Schema></edmx:DataServices></edmx:Edmx>"#;
        assert_eq!(
            refusal(ODataCodec::parse_definition(
                ENDPOINT,
                &ODataMetadataSource::new(annotation)
            ))
            .kind(),
            DefinitionErrorKind::SourceKindUnsupported
        );
        assert_eq!(
            refusal(ODataCodec::parse_definition(
                ENDPOINT,
                &ODataMetadataSource::new(b"<")
            ))
            .kind(),
            DefinitionErrorKind::InvalidSource
        );
    }

    #[test]
    fn sibling_xmlns_rebinding_does_not_leak() {
        // The wrapper rebinds `edm` for its own Annotation descendant.
        // The next EntitySet rebinds `edm` for itself only. `Places` is a
        // later sibling and must keep the Schema binding. If either rebind
        // leaked, `Places` would leave the EDM namespace and disappear, or
        // the descendant Annotation would still be an EDM AAuth term.
        let source = ODataMetadataSource::new(
            br#"
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:DataServices>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" xmlns:edm="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar">
      <EntityType Name="Event"/>
      <EntityContainer Name="Service">
        <EntitySet Name="Events" EntityType="Calendar.Event">
          <wrapper xmlns:edm="http://example.invalid/leaked">
            <edm:Annotation Term="AAuth.AccessMode" String="person-token"/>
          </wrapper>
        </EntitySet>
        <edm:EntitySet xmlns:edm="http://example.invalid/sibling" Name="Hidden" EntityType="Calendar.Event"/>
        <edm:EntitySet Name="Places" EntityType="Calendar.Event"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#,
        );
        let snapshot = ODataCodec::parse_definition(ENDPOINT, &source).expect("sibling scopes");
        let mut names: Vec<String> = snapshot
            .operations()
            .operations()
            .expect("operations")
            .iter()
            .map(|operation| String::from_utf8(operation.json().expect("json")).expect("utf8"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                r#"{"operation":"Events"}"#.to_owned(),
                r#"{"operation":"Places"}"#.to_owned(),
            ]
        );
    }

    #[test]
    fn deeply_nested_xml_fails_closed() {
        let depth = MAX_XML_NESTING + 8;
        let mut xml = String::new();
        for index in 0..depth {
            xml.push('<');
            xml.push_str(&format!("e{index}"));
            xml.push('>');
        }
        for index in (0..depth).rev() {
            xml.push_str(&format!("</e{index}>"));
        }
        let err = refusal(ODataCodec::parse_definition(
            ENDPOINT,
            &ODataMetadataSource::new(xml.as_bytes()),
        ));
        assert_eq!(err.kind(), DefinitionErrorKind::InvalidSource);
        assert_eq!(err.reason(), "OData metadata XML exceeds the nesting limit");
    }
}
