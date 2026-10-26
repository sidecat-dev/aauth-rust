//! Exact-byte artifact classification, independent of the reference URI's path.
use crate::{Document, Error, Proposal, Reference, Registry, digest};
use crate::jsonvalue::parse_raw_object;

/// Closed R3 artifact shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// Class authorization document.
    Document,
    /// Concrete per-call proposal.
    Proposal,
}

#[derive(Clone)]
enum Content { Document(Document), Proposal(Proposal) }

/// A validated artifact and the exact bytes bound by its reference.
#[derive(Clone)]
pub struct ReferencedArtifact {
    reference: Reference,
    exact: Vec<u8>,
    content: Content,
}
impl ReferencedArtifact {
    /// Classification obtained from the bytes, never from the URI.
    pub fn kind(&self) -> ArtifactKind {
        match &self.content {Content::Document(_)=>ArtifactKind::Document,Content::Proposal(_)=>ArtifactKind::Proposal}
    }
    /// Reference whose digest was verified.
    pub fn reference(&self)->&Reference {&self.reference}
    /// Exact bytes used for hashing and parsing; forward or retain without reserialization.
    pub fn exact_bytes(&self)->&[u8] {&self.exact}
    /// Class document, when the artifact has that shape.
    pub fn document(&self)->Option<&Document> {match &self.content {Content::Document(value)=>Some(value),Content::Proposal(_)=>None}}
    /// Per-call proposal, when the artifact has that shape.
    pub fn proposal(&self)->Option<&Proposal> {match &self.content {Content::Proposal(value)=>Some(value),Content::Document(_)=>None}}
}
impl Registry {
    /// Verify the exact digest before selecting a parser or vocabulary.
    /// Presence of `parameters` selects the strict proposal parser; absence
    /// selects the strict class parser. Malformed proposals never fall back.
    ///
    /// # Errors
    /// Rejects an invalid reference, changed bytes, ambiguous JSON, or an invalid artifact.
    pub fn parse_referenced_artifact(&self,reference:&Reference,exact:&[u8])->Result<ReferencedArtifact,Error>{
        reference.validate()?;
        if digest(exact)!=reference.digest(){return Err(Error::new("r3: referenced artifact digest mismatch"))}
        let members=parse_raw_object(exact)?;
        let content=if members.iter().any(|member|member.name=="parameters"){
            Content::Proposal(self.parse_proposal(exact)?)
        }else{Content::Document(self.parse_document(exact)?)};
        Ok(ReferencedArtifact{reference:reference.clone(),exact:exact.to_vec(),content})
    }
}
