//! Authoritative vocabulary definitions.
//!
//! Ported from Go `r3/definition.go`. A definition codec reduces one
//! vocabulary-native source, already acquired by the caller, to the R3
//! operations that source defines and the hints published beside them. The
//! parser binds that result to the exact bytes it came from and to one parser
//! registration. Nothing here fetches, resolves an external dependency,
//! caches, or decides policy. The draft's requirement that a Resource validate
//! declared operations against its authoritative definition before it issues
//! a resource token is [`AuthoritativeSnapshot::validate_defined`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::digest::digest;
use crate::error::Error;
use crate::hints::OperationHints;
use crate::jsonvalue::{Json, parse_json};
use crate::uri::VocabularyUri;
use crate::vocabulary::{
    Operation, OperationSet, SetUse, Vocabulary, compatible_set_and_operation, new_parsed,
};

/// Why an authoritative source could not be reduced to R3 operations.
///
/// The wire spellings are shared with the Go reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DefinitionErrorKind {
    /// `invalid_source`: the source is malformed for its format or profile.
    InvalidSource,
    /// `incomplete_source`: a required part of the source is missing.
    IncompleteSource,
    /// `unresolved_dependency`: the source needs material the caller did not supply.
    UnresolvedDependency,
    /// `source_kind_unsupported`: this parser does not read this kind or version of source.
    SourceKindUnsupported,
    /// `operation_identity_unavailable`: the source publishes no R3 operation identity.
    IdentityUnavailable,
    /// `operation_identity_ambiguous`: one identity names more than one operation.
    IdentityAmbiguous,
    /// `invalid_annotation`: a published access-mode or budget annotation is invalid.
    InvalidAnnotation,
    /// `operation_not_defined`: an operation is outside the authoritative source.
    OperationNotDefined,
}

impl DefinitionErrorKind {
    /// Wire spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSource => "invalid_source",
            Self::IncompleteSource => "incomplete_source",
            Self::UnresolvedDependency => "unresolved_dependency",
            Self::SourceKindUnsupported => "source_kind_unsupported",
            Self::IdentityUnavailable => "operation_identity_unavailable",
            Self::IdentityAmbiguous => "operation_identity_ambiguous",
            Self::InvalidAnnotation => "invalid_annotation",
            Self::OperationNotDefined => "operation_not_defined",
        }
    }
}

impl fmt::Display for DefinitionErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A stable, typed refusal from definition parsing or a definition check.
#[derive(Debug)]
pub struct DefinitionError {
    kind: DefinitionErrorKind,
    vocabulary: Option<VocabularyUri>,
    reason: String,
    cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl DefinitionError {
    /// A refusal for a definition codec to return. The parser adds the exact
    /// registered vocabulary URI.
    pub fn new(kind: DefinitionErrorKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            vocabulary: None,
            reason: reason.into(),
            cause: None,
        }
    }

    /// Keep the format-specific cause. It is returned by `source()`.
    #[must_use]
    pub fn with_cause(mut self, cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    /// Refusal kind.
    pub fn kind(&self) -> DefinitionErrorKind {
        self.kind
    }

    /// Exact registered vocabulary URI, once a parser or snapshot attached it.
    pub fn vocabulary(&self) -> Option<&VocabularyUri> {
        self.vocabulary.as_ref()
    }

    /// Human-readable reason. It is not a stable interface.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub(crate) fn for_vocabulary(mut self, uri: VocabularyUri) -> Self {
        self.vocabulary = Some(uri);
        self
    }
}

impl fmt::Display for DefinitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("r3: definition")?;
        if let Some(uri) = &self.vocabulary {
            write!(formatter, " \"{uri}\"")?;
        }
        write!(formatter, " refused with {}", self.kind)?;
        if !self.reason.is_empty() {
            write!(formatter, ": {}", self.reason)?;
        }
        if let Some(cause) = &self.cause {
            write!(formatter, ": {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DefinitionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// An untyped codec failure becomes `invalid_source`, keeping the error as its cause.
impl From<Error> for DefinitionError {
    fn from(err: Error) -> Self {
        Self::new(
            DefinitionErrorKind::InvalidSource,
            "parse authoritative definition",
        )
        .with_cause(err)
    }
}

/// A snapshot check failed.
#[derive(Debug)]
pub enum DefinitionCheckError {
    /// The authoritative source refuses the operation. The kind is
    /// [`DefinitionErrorKind::OperationNotDefined`].
    Refused(DefinitionError),
    /// The operands cannot be compared, for example because they use another
    /// vocabulary registration.
    Invalid(Error),
}

impl DefinitionCheckError {
    /// The typed refusal kind, when there is one.
    pub fn definition_kind(&self) -> Option<DefinitionErrorKind> {
        match self {
            Self::Refused(err) => Some(err.kind()),
            Self::Invalid(_) => None,
        }
    }
}

impl fmt::Display for DefinitionCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(err) => write!(formatter, "{err}"),
            Self::Invalid(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for DefinitionCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(err) => Some(err),
            Self::Invalid(err) => Some(err),
        }
    }
}

/// The exact byte encoding covered by a [`SourceReceipt`].
///
/// A document adapter normally names a media type or a namespaced URN; a
/// multi-part source names its framing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SourceEncoding(String);

impl SourceEncoding {
    /// Accept non-empty text with no surrounding whitespace.
    ///
    /// # Errors
    /// Returns [`Error`] for empty or padded text.
    pub fn new(text: impl Into<String>) -> Result<Self, Error> {
        let text = text.into();
        if text.is_empty() || text.trim() != text {
            return Err(Error::new(
                "r3: definition source encoding must be non-empty, trimmed UTF-8",
            ));
        }
        Ok(Self(text))
    }

    /// Encoding text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One operation a codec derived from its source, with the hints the source
/// published for it.
#[derive(Clone, Debug)]
pub struct DefinedOperation {
    raw: Vec<u8>,
    hints: Option<OperationHints>,
}

impl DefinedOperation {
    /// Copy one operation object. `None` means the source published no AAuth
    /// annotation for it.
    ///
    /// # Errors
    /// Returns [`Error`] when `raw` is not one strict JSON object.
    pub fn new(raw: &[u8], hints: Option<&OperationHints>) -> Result<Self, Error> {
        match parse_json(raw) {
            Ok(Json::Object(_)) => Ok(Self {
                raw: raw.to_vec(),
                hints: hints.cloned(),
            }),
            Ok(_) => Err(Error::new("r3: defined operation must be a JSON object")),
            Err(err) => Err(Error::wrap(
                "r3: defined operation must be valid JSON",
                err,
            )),
        }
    }

    /// Operation object bytes, as derived.
    pub fn json(&self) -> &[u8] {
        &self.raw
    }

    /// Published hints, when any.
    pub fn hints(&self) -> Option<&OperationHints> {
        self.hints.as_ref()
    }
}

/// The bounded result of one atomic native parse.
///
/// It holds the exact receipt input and copied derived values, never a parser
/// tree, resolver, transport, cache, policy, or lifecycle object.
#[derive(Clone, Debug)]
pub struct DefinitionMaterial {
    encoding: SourceEncoding,
    digest_input: Vec<u8>,
    operations: Vec<DefinedOperation>,
}

impl DefinitionMaterial {
    /// Own the exact receipt input and every derived operation.
    ///
    /// # Errors
    /// Returns [`Error`] when the receipt input is empty or no operation was derived.
    pub fn new(
        encoding: SourceEncoding,
        digest_input: Vec<u8>,
        operations: Vec<DefinedOperation>,
    ) -> Result<Self, Error> {
        if digest_input.is_empty() {
            return Err(Error::new(
                "r3: definition receipt input must not be empty",
            ));
        }
        if operations.is_empty() {
            return Err(Error::new(
                "r3: definition must derive at least one operation",
            ));
        }
        Ok(Self {
            encoding,
            digest_input,
            operations,
        })
    }
}

/// Atomically reads one vocabulary-native source.
///
/// Implementations are deterministic, safe to call concurrently, and perform
/// no I/O. Digest input, operations, and hints come from one observation of
/// the source. Acquiring the source and resolving dependencies outside it are
/// the caller's duties; a codec may resolve dependencies contained in it.
pub trait DefinitionCodec<S: ?Sized>: Send + Sync {
    /// The operation vocabulary registration the derived operations belong to.
    ///
    /// # Errors
    /// Returns [`Error`] when the registration is unavailable.
    fn vocabulary(&self) -> Result<Vocabulary, Error>;

    /// Parse one complete source.
    ///
    /// # Errors
    /// Returns a typed [`DefinitionError`]. The parser attaches the vocabulary URI.
    fn parse_definition(&self, source: &S) -> Result<DefinitionMaterial, DefinitionError>;
}

struct DefinitionIdentity;

/// One immutable parser over a vocabulary-native source type.
pub struct DefinitionParser<S: ?Sized + 'static> {
    vocabulary: Vocabulary,
    identity: Arc<DefinitionIdentity>,
    codec: Arc<dyn DefinitionCodec<S>>,
}

impl<S: ?Sized + 'static> Clone for DefinitionParser<S> {
    fn clone(&self) -> Self {
        Self {
            vocabulary: self.vocabulary.clone(),
            identity: Arc::clone(&self.identity),
            codec: Arc::clone(&self.codec),
        }
    }
}

impl<S: ?Sized + 'static> DefinitionParser<S> {
    /// Bind `codec` to its exact operation vocabulary registration. Each call
    /// creates a new parser registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the codec's vocabulary is unavailable or uninitialized.
    pub fn new<C>(codec: C) -> Result<Self, Error>
    where
        C: DefinitionCodec<S> + 'static,
    {
        let vocabulary = codec
            .vocabulary()
            .map_err(|err| Error::wrap("r3: definition vocabulary", err))?;
        vocabulary
            .validate_registration()
            .map_err(|err| Error::wrap("r3: definition vocabulary", err))?;
        Ok(Self {
            vocabulary,
            identity: Arc::new(DefinitionIdentity),
            codec: Arc::new(codec),
        })
    }

    /// Exact vocabulary URI.
    pub fn vocabulary(&self) -> &VocabularyUri {
        self.vocabulary.uri()
    }

    /// Type-erased identity of this parser, for an explicit [`DefinitionRegistry`].
    pub fn registration(&self) -> DefinitionRegistration {
        DefinitionRegistration {
            uri: self.vocabulary.uri().clone(),
            identity: Arc::clone(&self.identity),
        }
    }

    /// Reduce one source to a copied, source-bound snapshot. Performs no I/O.
    ///
    /// # Errors
    /// Returns a [`DefinitionError`] carrying this vocabulary's URI: the
    /// codec's own refusal, or `invalid_source` for an invalid discovery
    /// endpoint, a refusal from another vocabulary, or derived operations the
    /// vocabulary does not accept.
    pub fn parse(
        &self,
        endpoint: &str,
        source: &S,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        let uri = self.vocabulary.uri().clone();
        if let Err(err) = self.vocabulary.validate_discovery_endpoint(endpoint) {
            return Err(invalid_source(&uri, "invalid discovery endpoint", err));
        }
        let material = match self.codec.parse_definition(source) {
            Ok(material) => material,
            Err(err) => return Err(attach_vocabulary(&uri, err)),
        };
        let mut raw = Vec::with_capacity(material.operations.len());
        let mut hinted = Vec::new();
        for operation in &material.operations {
            raw.push(operation.raw.clone());
            if let Some(hints) = &operation.hints {
                let canonical = match Operation::new(&self.vocabulary, &operation.raw)
                    .and_then(|parsed| parsed.json())
                {
                    Ok(canonical) => canonical,
                    Err(err) => {
                        return Err(invalid_source(&uri, "derived operation is invalid", err));
                    }
                };
                hinted.push((canonical, hints.clone()));
            }
        }
        let operations = match new_parsed(self.vocabulary.clone(), raw, SetUse::Document) {
            Ok(operations) => operations,
            Err(err) => return Err(invalid_source(&uri, "derived operations are invalid", err)),
        };
        // Go keys hints by canonical operation and lets a later entry win. A
        // vocabulary that admits two operations with one canonical form makes
        // the publication ambiguous, so it is refused instead.
        let mut hints = BTreeMap::new();
        for (canonical, published) in hinted {
            if hints.insert(canonical, published).is_some() {
                return Err(failure(
                    &uri,
                    DefinitionErrorKind::IdentityAmbiguous,
                    "two hinted operations share one canonical operation",
                ));
            }
        }
        Ok(AuthoritativeSnapshot {
            parser_identity: Arc::clone(&self.identity),
            operations,
            receipt: SourceReceipt {
                encoding: material.encoding,
                endpoint: endpoint.to_owned(),
                digest: digest(&material.digest_input),
                byte_length: material.digest_input.len() as u64,
            },
            hints,
        })
    }
}

/// Type-erased identity of one definition parser.
#[derive(Clone)]
pub struct DefinitionRegistration {
    uri: VocabularyUri,
    identity: Arc<DefinitionIdentity>,
}

impl DefinitionRegistration {
    /// Exact vocabulary URI of the registered parser.
    pub fn vocabulary(&self) -> &VocabularyUri {
        &self.uri
    }
}

/// Explicit allowlist of definition parser registrations.
///
/// It prevents mixing snapshots from different parser registrations. It does
/// not attest that a host chose a trustworthy parser or source.
#[derive(Clone)]
pub struct DefinitionRegistry {
    registrations: BTreeMap<VocabularyUri, DefinitionRegistration>,
}

impl DefinitionRegistry {
    /// Build the allowlist. A vocabulary URI cannot be registered twice.
    ///
    /// # Errors
    /// Returns [`Error`] when a vocabulary URI repeats.
    pub fn new(registrations: &[DefinitionRegistration]) -> Result<Self, Error> {
        let mut registered = BTreeMap::new();
        for registration in registrations {
            if registered.contains_key(&registration.uri) {
                return Err(Error::new(format!(
                    "r3: duplicate definition parser for vocabulary \"{}\"",
                    registration.uri
                )));
            }
            registered.insert(registration.uri.clone(), registration.clone());
        }
        Ok(Self {
            registrations: registered,
        })
    }

    /// Number of registered parsers.
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    /// Whether no parser is registered.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    /// Whether `uri` has a registered parser.
    pub fn contains(&self, uri: &VocabularyUri) -> bool {
        self.registrations.contains_key(uri)
    }

    /// Require that `snapshot` came from the parser registered for its vocabulary.
    ///
    /// # Errors
    /// Returns [`Error`] when the vocabulary has no registered parser, another
    /// parser produced the snapshot, or its operations are no longer valid.
    pub fn validate(&self, snapshot: &AuthoritativeSnapshot) -> Result<(), Error> {
        snapshot.operations.json_operations()?;
        let uri = snapshot.vocabulary();
        let Some(registration) = self.registrations.get(uri) else {
            return Err(Error::new(format!(
                "r3: definition parser for vocabulary \"{uri}\" is not registered"
            )));
        };
        if !Arc::ptr_eq(&registration.identity, &snapshot.parser_identity) {
            return Err(Error::new(format!(
                "r3: definition snapshot for vocabulary \"{uri}\" uses another parser registration"
            )));
        }
        Ok(())
    }
}

/// The exact digest input one parser covered.
///
/// `byte_length` measures that input, which may be a document, a descriptor
/// set, or a framed multi-part source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceReceipt {
    encoding: SourceEncoding,
    endpoint: String,
    digest: String,
    byte_length: u64,
}

impl SourceReceipt {
    /// How the digest input was formed.
    pub fn encoding(&self) -> &SourceEncoding {
        &self.encoding
    }

    /// The advertised discovery endpoint the source was parsed for.
    pub fn discovery_endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Unpadded base64url SHA-256 of the digest input.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Length of the digest input in bytes.
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

/// A copied view of the operations one source defines and their hints.
///
/// It owns no source bytes, parse tree, transport, resolver, cache, policy,
/// token, or lifecycle state. Hints are advisory and are never evidence of a
/// grant.
#[derive(Clone)]
pub struct AuthoritativeSnapshot {
    parser_identity: Arc<DefinitionIdentity>,
    operations: OperationSet,
    receipt: SourceReceipt,
    hints: BTreeMap<Vec<u8>, OperationHints>,
}

impl AuthoritativeSnapshot {
    /// Exact operation vocabulary URI.
    pub fn vocabulary(&self) -> &VocabularyUri {
        self.operations.vocabulary()
    }

    /// The receipt for the exact parser digest input.
    pub fn receipt(&self) -> &SourceReceipt {
        &self.receipt
    }

    /// The derived operations, in the vocabulary's canonical order.
    pub fn operations(&self) -> OperationSet {
        self.operations.clone()
    }

    /// Require every declared operation to be defined by this source.
    ///
    /// Containment uses the vocabulary's own subset relation. The codec is not
    /// invoked again.
    ///
    /// # Errors
    /// Returns [`DefinitionCheckError::Refused`] with `operation_not_defined`
    /// when an operation is outside the source, and
    /// [`DefinitionCheckError::Invalid`] when `declared` uses another registration.
    pub fn validate_defined(&self, declared: &OperationSet) -> Result<(), DefinitionCheckError> {
        let known = declared
            .is_subset_of(&self.operations)
            .map_err(DefinitionCheckError::Invalid)?;
        if !known {
            return Err(DefinitionCheckError::Refused(failure(
                self.vocabulary(),
                DefinitionErrorKind::OperationNotDefined,
                "declared operation is outside the authoritative source",
            )));
        }
        Ok(())
    }

    /// Published hints for one defined operation. `None` means the source
    /// published no annotation for it.
    ///
    /// # Errors
    /// Returns [`DefinitionCheckError::Refused`] with `operation_not_defined`
    /// when the operation is outside the source, and
    /// [`DefinitionCheckError::Invalid`] when it uses another registration.
    pub fn hints_for(
        &self,
        operation: &Operation,
    ) -> Result<Option<OperationHints>, DefinitionCheckError> {
        compatible_set_and_operation(&self.operations, operation)
            .map_err(DefinitionCheckError::Invalid)?;
        let candidates = self
            .operations
            .operations()
            .map_err(DefinitionCheckError::Invalid)?;
        for candidate in candidates {
            if candidate
                .equal(operation)
                .map_err(DefinitionCheckError::Invalid)?
            {
                let canonical = candidate.json().map_err(DefinitionCheckError::Invalid)?;
                return Ok(self.hints.get(&canonical).cloned());
            }
        }
        Err(DefinitionCheckError::Refused(failure(
            self.vocabulary(),
            DefinitionErrorKind::OperationNotDefined,
            "operation is outside the authoritative source",
        )))
    }
}

fn failure(uri: &VocabularyUri, kind: DefinitionErrorKind, reason: &str) -> DefinitionError {
    DefinitionError::new(kind, reason).for_vocabulary(uri.clone())
}

fn invalid_source(uri: &VocabularyUri, reason: &str, cause: Error) -> DefinitionError {
    failure(uri, DefinitionErrorKind::InvalidSource, reason).with_cause(cause)
}

/// Attach the registered vocabulary to a codec refusal. A refusal already
/// attached to another vocabulary is not passed off as this one's.
fn attach_vocabulary(uri: &VocabularyUri, err: DefinitionError) -> DefinitionError {
    let foreign = err.vocabulary.as_ref().is_some_and(|other| other != uri);
    if foreign {
        let reason = "parser returned a refusal for another vocabulary";
        return failure(uri, DefinitionErrorKind::InvalidSource, reason).with_cause(err);
    }
    err.for_vocabulary(uri.clone())
}
