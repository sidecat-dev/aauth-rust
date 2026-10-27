//! AAuth Rich Resource Requests (`draft-hardt-aauth-r3`).
//!
//! Vocabulary grammar, whole-set algebra, R3 documents, direct grants,
//! per-call proposals, operation access hints, authoritative definitions, and
//! the R3 claims of Resource and Auth tokens. A host registers one codec per
//! vocabulary; codecs for the seven standard vocabularies are included.
//! Definition parsers derive MCP, OpenAPI and AsyncAPI operations. GraphQL
//! introspection is refused because a schema alone supplies no operation
//! identity; WSDL, OData and gRPC definitions are not parsed yet. A signed
//! artifact fetcher uses a trusted host HTTPS adapter. This crate does not
//! fetch a definition, decide policy, execute a call, or bind a token to a request.
#![deny(missing_docs)]

mod annotation;
mod artifact;
mod asyncapi_definition;
mod budget_token;
mod definition;
mod definition_support;
mod digest;
mod document;
mod envelope;
mod error;
mod fetch;
mod grant;
mod graphql_definition;
mod hints;
mod issuance;
mod json_schema;
mod jsonvalue;
mod mcp_definition;
mod openapi_definition;
mod proposal;
mod reference;
mod standard;
mod token;
mod uri;
mod vocabulary;

pub use annotation::AnnotationEncoding;
pub use artifact::{ArtifactKind, ReferencedArtifact};
pub use asyncapi_definition::AsyncApiDocumentSource;
pub use budget_token::{
    mint_budget_auth_token, mint_budget_resource_token, verify_budget_auth_token,
    verify_budget_resource_token,
};
pub use definition::{
    AuthoritativeSnapshot, DefinedOperation, DefinitionCheckError, DefinitionCodec,
    DefinitionError, DefinitionErrorKind, DefinitionMaterial, DefinitionParser,
    DefinitionRegistration, DefinitionRegistry, SourceEncoding, SourceReceipt,
};
pub use digest::digest;
pub use document::{Display, Document, DocumentOptions, validate_document_account};
pub use error::Error;
pub use fetch::{
    DEFAULT_ARTIFACT_FETCH_TIMEOUT, DEFAULT_MAXIMUM_DOCUMENT_BYTES, FetchBody, FetchClient,
    FetchConfig, FetchEgress, FetchError, FetchIdentity, FetchLimits, FetchResponse,
    FetchTransport,
};
pub use grant::{Authorization, Grant};
pub use graphql_definition::GraphQlIntrospectionSource;
pub use hints::{AccessMode, ExpectedAccess, OperationHints};
pub use issuance::{IssuanceError, IssuanceRecord, IssuanceStore};
pub use mcp_definition::{ToolsListPage, ToolsListSnapshot};
pub use openapi_definition::OpenApiDocumentSource;
pub use proposal::{
    Parameter, ParameterDigest, Parameters, PresentedParameter, Proposal, ProposalDisplay,
    ProposalOptions, ProposalResult, validate_proposal_account,
};
pub use reference::Reference;
pub use standard::{
    AsyncApiCodec, GraphQlCodec, GrpcCodec, McpCodec, ODataCodec, OpenApiCodec, WsdlCodec,
    standard_registry, standard_vocabularies,
};
pub use token::{
    AuthTokenOperations, OperationAccess, R3TokenError, VerifiedR3AuthToken,
    VerifiedR3ResourceToken, mint_auth_token, mint_direct_auth_token, mint_per_call_auth_token,
    mint_proposal_resource_token, mint_resource_token, verify_auth_token_claims,
    verify_direct_auth_token, verify_per_call_auth_token, verify_resource_token,
};
pub use uri::VocabularyUri;
pub use vocabulary::{Codec, GrantedOperations, Operation, OperationSet, Registry, Vocabulary};

#[cfg(test)]
mod artifact_tests;
#[cfg(test)]
mod definition_adapter_tests;
#[cfg(test)]
mod definition_tests;
#[cfg(test)]
mod fetch_tests;
#[cfg(test)]
mod hints_tests;
#[cfg(test)]
mod standard_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod token_tests;
