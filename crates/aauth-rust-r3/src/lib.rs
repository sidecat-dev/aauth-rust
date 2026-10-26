//! AAuth Rich Resource Requests (`draft-hardt-aauth-r3`).
//!
//! Vocabulary grammar and whole-set algebra. A host registers one codec per
//! vocabulary. This crate does not fetch a definition, decide policy, execute
//! a call, or issue a token.
#![deny(missing_docs)]

mod annotation;
mod envelope;
mod error;
mod uri;
mod vocabulary;

pub use annotation::AnnotationEncoding;
pub use error::Error;
pub use uri::VocabularyUri;
pub use vocabulary::{Codec, GrantedOperations, Operation, OperationSet, Registry, Vocabulary};

#[cfg(test)]
mod tests;
