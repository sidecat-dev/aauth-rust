//! GraphQL authoritative definitions: one GraphQL introspection response.
//!
//! Ported from Go `r3/vocab/graphql/definition.go`. The R3 GraphQL operation
//! identity is a client-authored executable operation name and type. Schema
//! introspection publishes types and fields, not those names, so a well-formed
//! response is refused with `operation_identity_unavailable` instead of
//! inventing identities. A GraphQL operation therefore cannot yet be checked
//! against an authoritative definition.

use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinitionCodec, DefinitionError, DefinitionMaterial, DefinitionParser,
    DefinitionRegistration,
};
use crate::definition_support::{
    cached_parser, incomplete, invalid, member, parse_standard, refuse_field_variants, unavailable,
};
use crate::error::Error;
use crate::jsonvalue::{Json, parse_json};
use crate::standard::GraphQlCodec;
use crate::vocabulary::Vocabulary;

/// Exact bytes of one GraphQL introspection response.
///
/// Fetching and request policy stay with the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphQlIntrospectionSource {
    exact: Vec<u8>,
}

impl GraphQlIntrospectionSource {
    /// Receipt encoding: the exact response bytes. Shared with the Go reference.
    pub const SOURCE_ENCODING: &'static str =
        "urn:aauth:source-encoding:graphql-introspection-response-exact-v1";

    /// Copy the exact response bytes.
    pub fn new(exact: &[u8]) -> Self {
        Self {
            exact: exact.to_vec(),
        }
    }

    /// The exact response bytes.
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}

struct GraphQlDefinitionCodec;

impl DefinitionCodec<GraphQlIntrospectionSource> for GraphQlDefinitionCodec {
    fn vocabulary(&self) -> Result<Vocabulary, Error> {
        GraphQlCodec::vocabulary()
    }

    fn parse_definition(
        &self,
        source: &GraphQlIntrospectionSource,
    ) -> Result<DefinitionMaterial, DefinitionError> {
        refuse_introspection(source)
    }
}

impl GraphQlCodec {
    /// The process-wide GraphQL definition parser. Every call returns the
    /// same parser registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the GraphQL vocabulary is unavailable.
    pub fn definition_parser() -> Result<DefinitionParser<GraphQlIntrospectionSource>, Error> {
        static PARSER: OnceLock<Option<DefinitionParser<GraphQlIntrospectionSource>>> =
            OnceLock::new();
        cached_parser(
            &PARSER,
            || DefinitionParser::new(GraphQlDefinitionCodec),
            Self::URI,
        )
    }

    /// Check that `source` is an introspection response with an object
    /// `data.__schema`, then refuse it: the draft's GraphQL identity is not
    /// published by introspection. Performs no I/O.
    ///
    /// # Errors
    /// Always returns a typed [`DefinitionError`]:
    /// `operation_identity_unavailable` for a well-formed response,
    /// `incomplete_source` when `data` or `data.__schema` is absent or `null`,
    /// and `invalid_source` otherwise.
    pub fn parse_definition(
        endpoint: &str,
        source: &GraphQlIntrospectionSource,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        parse_standard(Self::definition_parser(), Self::URI, endpoint, source)
    }

    /// Registration of [`Self::definition_parser`], for a [`crate::DefinitionRegistry`].
    ///
    /// # Errors
    /// Returns [`Error`] when the GraphQL vocabulary is unavailable.
    pub fn definition_registration() -> Result<DefinitionRegistration, Error> {
        Self::definition_parser().map(|parser| parser.registration())
    }
}

/// Go decodes the response into a struct, so a `null` root or `data` reads as
/// absent, and a case variant of `data` or `__schema` would be read as the
/// member; such variants are refused here.
fn refuse_introspection(
    source: &GraphQlIntrospectionSource,
) -> Result<DefinitionMaterial, DefinitionError> {
    let document = match parse_json(&source.exact) {
        Ok(document) => document,
        Err(err) => return Err(invalid("invalid GraphQL introspection response").with_cause(err)),
    };
    let missing = || incomplete("GraphQL introspection response is missing data.__schema");
    let members: &[(String, Json)] = match &document {
        Json::Object(members) => members,
        Json::Null => &[],
        _ => {
            return Err(invalid(
                "GraphQL introspection response must be a JSON object",
            ));
        }
    };
    refuse_field_variants(members, &["data"], "GraphQL response")?;
    let data = match member(members, "data") {
        None | Some(Json::Null) => return Err(missing()),
        Some(Json::Object(data)) => data,
        Some(_) => return Err(invalid("GraphQL data must be an object")),
    };
    refuse_field_variants(data, &["__schema"], "GraphQL data")?;
    match member(data, "__schema") {
        None | Some(Json::Null) => Err(missing()),
        Some(Json::Object(_)) => Err(unavailable(
            "GraphQL schema introspection does not publish client-authored executable operation names",
        )),
        Some(_) => Err(invalid("GraphQL data.__schema is not an object")),
    }
}
