//! AAuth Rich Resource Requests (`draft-hardt-aauth-r3`).
//!
//! Vocabulary grammar, whole-set algebra, R3 documents, direct grants, and
//! per-call proposals. A host registers one codec per vocabulary; codecs for
//! the seven standard vocabularies are included. This crate does not fetch a
//! definition, decide policy, execute a call, or issue a token.
#![deny(missing_docs)]

mod annotation;
mod digest;
mod document;
mod envelope;
mod error;
mod grant;
mod jsonvalue;
mod proposal;
mod reference;
mod standard;
mod uri;
mod vocabulary;

pub use annotation::AnnotationEncoding;
pub use digest::digest;
pub use document::{Display, Document, DocumentOptions, validate_document_account};
pub use error::Error;
pub use grant::{Authorization, Grant};
pub use proposal::{
    Parameter, ParameterDigest, Parameters, PresentedParameter, Proposal, ProposalDisplay,
    ProposalOptions, validate_proposal_account,
};
pub use reference::Reference;
pub use standard::{
    AsyncApiCodec, GraphQlCodec, GrpcCodec, McpCodec, ODataCodec, OpenApiCodec, WsdlCodec,
    standard_vocabularies,
};
pub use uri::VocabularyUri;
pub use vocabulary::{Codec, GrantedOperations, Operation, OperationSet, Registry, Vocabulary};

#[cfg(test)]
mod artifact_tests;
#[cfg(test)]
mod standard_tests;
#[cfg(test)]
mod tests;
