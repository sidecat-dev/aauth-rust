//! Checks ported from Go `r3/definition_test.go` at 0225f3f4, plus the
//! refusals this port adds. The vocabulary is a private `{name}` codec.

use std::error::Error as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::annotation::AnnotationEncoding;
use crate::definition_support::single_member_operation;
use crate::error::Error;
use crate::jsonvalue::{Json, parse_json};
use crate::uri::VocabularyUri;
use crate::vocabulary::Codec;
use crate::{
    AccessMode, AuthoritativeSnapshot, DefinedOperation, DefinitionCheckError, DefinitionCodec,
    DefinitionError, DefinitionErrorKind, DefinitionMaterial, DefinitionParser,
    DefinitionRegistry, Operation, OperationHints, OperationSet, SourceEncoding, Vocabulary,
    digest,
};

const WIDGETS: &str = "https://example.test/r3/widgets";
const OTHER: &str = "https://example.test/r3/other";
const ENDPOINT: &str = "https://resource.example/definitions/widgets";
const FIXTURE: &[u8] = br#"{"operations":["read","write"]}"#;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Naming {
    /// Exact names; a repeated name is refused.
    Exact,
    /// Exact names; canonical marshal sorts them, as Go `sortingNamedCodec`.
    Sorted,
    /// ASCII case-insensitive equality, as Go `caseFoldNamedCodec`.
    CaseFolded,
    /// Accepts a repeated name, so one canonical operation can occur twice.
    Repeating,
}

struct NamedCodec {
    uri: &'static str,
    naming: Naming,
}

impl NamedCodec {
    fn same(&self, left: &str, right: &str) -> bool {
        match self.naming {
            Naming::CaseFolded => left.eq_ignore_ascii_case(right),
            _ => left == right,
        }
    }
}

impl Codec for NamedCodec {
    type Set = Vec<String>;

    fn uri(&self) -> VocabularyUri {
        VocabularyUri::parse(self.uri).expect("vocabulary URI")
    }

    fn annotation_encoding(&self) -> AnnotationEncoding {
        AnnotationEncoding::UNAVAILABLE
    }

    fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), Error> {
        if endpoint.starts_with("https://") {
            Ok(())
        } else {
            Err(Error::new("named discovery endpoint must be HTTPS"))
        }
    }

    fn parse_set(&self, raw: &[Vec<u8>]) -> Result<Self::Set, Error> {
        let mut names: Vec<String> = Vec::with_capacity(raw.len());
        for value in raw {
            let name = parse_name(value)?;
            let repeated = names.iter().any(|existing| self.same(existing, &name));
            if repeated && self.naming != Naming::Repeating {
                return Err(Error::new(format!("repeated name \"{name}\"")));
            }
            names.push(name);
        }
        Ok(names)
    }

    fn marshal_set(&self, set: &Self::Set) -> Result<Vec<Vec<u8>>, Error> {
        let mut names = set.clone();
        if self.naming == Naming::Sorted {
            names.sort();
        }
        Ok(names.iter().map(|name| name_json(name)).collect())
    }

    fn union_sets<'a>(
        &self,
        sets: impl IntoIterator<Item = &'a Self::Set>,
    ) -> Result<Self::Set, Error>
    where
        Self::Set: 'a,
    {
        let mut union: Vec<String> = Vec::new();
        for set in sets {
            for name in set {
                if !union.iter().any(|existing| self.same(existing, name)) {
                    union.push(name.clone());
                }
            }
        }
        Ok(union)
    }

    fn sets_equal(&self, left: &Self::Set, right: &Self::Set) -> bool {
        self.is_subset(left, right) && self.is_subset(right, left)
    }

    fn is_subset(&self, subset: &Self::Set, superset: &Self::Set) -> bool {
        subset
            .iter()
            .all(|name| superset.iter().any(|other| self.same(name, other)))
    }

    fn is_disjoint(&self, left: &Self::Set, right: &Self::Set) -> bool {
        !left
            .iter()
            .any(|name| right.iter().any(|other| self.same(name, other)))
    }
}

fn parse_name(raw: &[u8]) -> Result<String, Error> {
    match parse_json(raw)? {
        Json::Object(members) if members.len() == 1 => match &members[0] {
            (key, Json::String(name)) if key.as_str() == "name" && !name.is_empty() => {
                Ok(name.clone())
            }
            _ => Err(Error::new("invalid named operation")),
        },
        _ => Err(Error::new("invalid named operation")),
    }
}

fn name_json(name: &str) -> Vec<u8> {
    single_member_operation("name", name)
}

fn vocabulary(uri: &'static str, naming: Naming) -> Vocabulary {
    Vocabulary::new(NamedCodec { uri, naming }).expect("vocabulary")
}

fn operation(vocabulary: &Vocabulary, name: &str) -> Operation {
    Operation::new(vocabulary, &name_json(name)).expect("operation")
}

fn encoding() -> SourceEncoding {
    SourceEncoding::new("application/vnd.example.widgets+json").expect("source encoding")
}

fn person_token() -> OperationHints {
    OperationHints::new(Some(AccessMode::PersonToken), None).expect("hints")
}

fn defined(name: &str, hints: Option<&OperationHints>) -> Result<DefinedOperation, DefinitionError> {
    DefinedOperation::new(&name_json(name), hints).map_err(DefinitionError::from)
}

fn material(
    source: &[u8],
    operations: Vec<DefinedOperation>,
) -> Result<DefinitionMaterial, DefinitionError> {
    DefinitionMaterial::new(encoding(), source.to_vec(), operations).map_err(DefinitionError::from)
}

type ParseFn = dyn Fn(&[u8]) -> Result<DefinitionMaterial, DefinitionError> + Send + Sync;

/// Go `atomicDefinitionCodec`: a byte-source codec that counts its calls.
struct AtomicCodec {
    vocabulary: Vocabulary,
    calls: Arc<AtomicUsize>,
    parse: Box<ParseFn>,
}

impl DefinitionCodec<[u8]> for AtomicCodec {
    fn vocabulary(&self) -> Result<Vocabulary, Error> {
        Ok(self.vocabulary.clone())
    }

    fn parse_definition(&self, source: &[u8]) -> Result<DefinitionMaterial, DefinitionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.parse)(source)
    }
}

fn atomic_parser(
    vocabulary: &Vocabulary,
    parse: impl Fn(&[u8]) -> Result<DefinitionMaterial, DefinitionError> + Send + Sync + 'static,
) -> (DefinitionParser<[u8]>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let codec = AtomicCodec {
        vocabulary: vocabulary.clone(),
        calls: Arc::clone(&calls),
        parse: Box::new(parse),
    };
    let parser = DefinitionParser::<[u8]>::new(codec).expect("definition parser");
    (parser, calls)
}

/// Go `mustAtomicDefinitionParser`: one unhinted operation per source.
fn single_parser(vocabulary: &Vocabulary, name: &'static str) -> DefinitionParser<[u8]> {
    atomic_parser(vocabulary, move |source| {
        material(source, vec![defined(name, None)?])
    })
    .0
}

fn refusal(result: Result<AuthoritativeSnapshot, DefinitionError>) -> DefinitionError {
    match result {
        Ok(_) => panic!("expected a definition refusal"),
        Err(err) => err,
    }
}

fn check_kind(result: Result<(), DefinitionCheckError>) -> Option<DefinitionErrorKind> {
    result.err().and_then(|err| err.definition_kind())
}

#[test]
fn definition_parser_atomically_owns_source_operations_and_hints() {
    let vocabulary = vocabulary(WIDGETS, Naming::Exact);
    let (parser, calls) = atomic_parser(&vocabulary, |source| {
        if source != FIXTURE {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "unexpected fixture",
            ));
        }
        let read = defined("read", Some(&person_token()))?;
        let write = defined("write", None)?;
        material(source, vec![read, write])
    });
    let registry = DefinitionRegistry::new(&[parser.registration()]).expect("registry");

    let mut exact = FIXTURE.to_vec();
    let snapshot = parser.parse(ENDPOINT, &exact).expect("parse");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one atomic codec call");
    exact[0] = b'[';

    let receipt = snapshot.receipt();
    assert_eq!(receipt.encoding(), &encoding());
    assert_eq!(receipt.discovery_endpoint(), ENDPOINT);
    assert_eq!(receipt.digest(), digest(FIXTURE));
    assert_eq!(receipt.byte_length(), FIXTURE.len() as u64);
    assert_eq!(snapshot.vocabulary().as_str(), WIDGETS);

    let operations = snapshot.operations().operations().expect("operations");
    assert_eq!(operations.len(), 2);
    assert_eq!(
        snapshot.hints_for(&operations[0]).expect("read hints"),
        Some(person_token())
    );
    assert_eq!(snapshot.hints_for(&operations[1]).expect("write hints"), None);
    snapshot
        .validate_defined(&snapshot.operations())
        .expect("derived operations are defined");
    registry.validate(&snapshot).expect("registered parser");
    assert!(registry.contains(snapshot.vocabulary()));
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());
}

#[test]
fn definition_snapshot_refuses_unknown_and_foreign_operations() {
    let local = vocabulary(WIDGETS, Naming::Exact);
    let foreign = vocabulary(WIDGETS, Naming::Exact);
    let parser = single_parser(&local, "read");
    let snapshot = parser.parse(ENDPOINT, b"source").expect("parse");

    let unknown = operation(&local, "unknown");
    let unknown_set = OperationSet::new(std::slice::from_ref(&unknown)).expect("unknown set");
    let err = snapshot.validate_defined(&unknown_set);
    assert_eq!(check_kind(err), Some(DefinitionErrorKind::OperationNotDefined));
    match snapshot.hints_for(&unknown) {
        Err(DefinitionCheckError::Refused(err)) => {
            assert_eq!(err.kind(), DefinitionErrorKind::OperationNotDefined);
            assert_eq!(err.vocabulary().map(VocabularyUri::as_str), Some(WIDGETS));
        }
        _ => panic!("snapshot served hints for an unknown operation"),
    }

    let foreign_read = operation(&foreign, "read");
    assert!(matches!(
        snapshot.hints_for(&foreign_read),
        Err(DefinitionCheckError::Invalid(_))
    ));
    let foreign_set = OperationSet::new(&[foreign_read]).expect("foreign set");
    assert!(matches!(
        snapshot.validate_defined(&foreign_set),
        Err(DefinitionCheckError::Invalid(_))
    ));

    let foreign_parser = single_parser(&foreign, "read");
    let foreign_registry =
        DefinitionRegistry::new(&[foreign_parser.registration()]).expect("registry");
    assert!(foreign_registry.validate(&snapshot).is_err());

    // The same vocabulary registration under another parser registration.
    let sibling = single_parser(&local, "read");
    let sibling_registry = DefinitionRegistry::new(&[sibling.registration()]).expect("registry");
    assert!(sibling_registry.validate(&snapshot).is_err());
    assert!(
        DefinitionRegistry::new(&[])
            .expect("empty registry")
            .validate(&snapshot)
            .is_err()
    );
    assert!(
        DefinitionRegistry::new(&[parser.registration(), sibling.registration()]).is_err(),
        "one vocabulary URI cannot be registered twice"
    );
}

#[test]
fn definition_hints_follow_operations_across_canonical_reordering() {
    let vocabulary = vocabulary("https://example.test/r3/sorted", Naming::Sorted);
    let (parser, _) = atomic_parser(&vocabulary, |source| {
        let z = defined("z", Some(&person_token()))?;
        let a = defined("a", None)?;
        material(source, vec![z, a])
    });
    let snapshot = parser.parse(ENDPOINT, b"source").expect("parse");
    let operations = snapshot.operations().operations().expect("operations");
    assert_eq!(operations[0].json().expect("a"), br#"{"name":"a"}"#);
    assert_eq!(operations[1].json().expect("z"), br#"{"name":"z"}"#);
    assert_eq!(
        snapshot.hints_for(&operations[1]).expect("z hints"),
        Some(person_token())
    );
    assert_eq!(snapshot.hints_for(&operations[0]).expect("a hints"), None);
}

#[test]
fn definition_hints_follow_semantically_equal_operation_encoding() {
    let vocabulary = vocabulary("https://example.test/r3/case-folded", Naming::CaseFolded);
    let (parser, _) = atomic_parser(&vocabulary, |source| {
        material(source, vec![defined("read", Some(&person_token()))?])
    });
    let snapshot = parser.parse(ENDPOINT, b"source").expect("parse");
    let alias = operation(&vocabulary, "READ");
    assert_eq!(
        snapshot.hints_for(&alias).expect("alias hints"),
        Some(person_token())
    );
    let unknown = operation(&vocabulary, "write");
    let refused = snapshot.hints_for(&unknown).err().and_then(|err| err.definition_kind());
    assert_eq!(refused, Some(DefinitionErrorKind::OperationNotDefined));
}

#[test]
fn definition_parser_returns_stable_typed_refusal_with_cause() {
    let vocabulary = vocabulary(WIDGETS, Naming::Exact);
    let (parser, _) = atomic_parser(&vocabulary, |_| {
        Err(DefinitionError::new(
            DefinitionErrorKind::IdentityUnavailable,
            "the source does not publish operation identities",
        )
        .with_cause(Error::new("missing registry")))
    });
    let err = refusal(parser.parse(ENDPOINT, b"source"));
    assert_eq!(err.kind(), DefinitionErrorKind::IdentityUnavailable);
    assert_eq!(err.vocabulary(), Some(vocabulary.uri()));
    assert_eq!(
        err.source().map(ToString::to_string).as_deref(),
        Some("missing registry")
    );
    assert!(err.to_string().contains("operation_identity_unavailable"));
}

#[test]
fn definition_parser_refuses_a_refusal_from_another_vocabulary() {
    let vocabulary = vocabulary(WIDGETS, Naming::Exact);
    let other = self::vocabulary(OTHER, Naming::Exact);
    let (inner, _) = atomic_parser(&other, |_| {
        Err(DefinitionError::new(
            DefinitionErrorKind::IncompleteSource,
            "inner",
        ))
    });
    let (outer, _) = atomic_parser(&vocabulary, move |source| {
        match inner.parse(ENDPOINT, source) {
            Ok(_) => Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                "inner parse unexpectedly succeeded",
            )),
            Err(err) => Err(err),
        }
    });
    let err = refusal(outer.parse(ENDPOINT, b"source"));
    assert_eq!(err.kind(), DefinitionErrorKind::InvalidSource);
    assert_eq!(err.vocabulary().map(VocabularyUri::as_str), Some(WIDGETS));
}

#[test]
fn definition_parser_checks_the_endpoint_before_the_codec() {
    let vocabulary = vocabulary(WIDGETS, Naming::Exact);
    let (parser, calls) = atomic_parser(&vocabulary, |source| {
        material(source, vec![defined("read", None)?])
    });
    let err = refusal(parser.parse("http://resource.example/widgets", b"source"));
    assert_eq!(err.kind(), DefinitionErrorKind::InvalidSource);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn definition_parser_refuses_derived_operations_the_vocabulary_refuses() {
    let vocabulary = vocabulary(WIDGETS, Naming::Exact);
    let not_named: &'static [u8] = br#"{"other":"read"}"#;
    let (unhinted, _) = atomic_parser(&vocabulary, move |source| {
        let operation = DefinedOperation::new(not_named, None)?;
        material(source, vec![operation])
    });
    let err = refusal(unhinted.parse(ENDPOINT, b"source"));
    assert_eq!(err.kind(), DefinitionErrorKind::InvalidSource);
    let (hinted, _) = atomic_parser(&vocabulary, move |source| {
        let operation = DefinedOperation::new(not_named, Some(&person_token()))?;
        material(source, vec![operation])
    });
    let err = refusal(hinted.parse(ENDPOINT, b"source"));
    assert_eq!(err.kind(), DefinitionErrorKind::InvalidSource);
    let (repeated, _) = atomic_parser(&vocabulary, |source| {
        material(source, vec![defined("read", None)?, defined("read", None)?])
    });
    let err = refusal(repeated.parse(ENDPOINT, b"source"));
    assert_eq!(err.kind(), DefinitionErrorKind::InvalidSource);
}

/// Go keeps the last of two hinted operations with one canonical form. This
/// port refuses the publication as ambiguous.
#[test]
fn definition_parser_refuses_two_hinted_operations_with_one_canonical_form() {
    let vocabulary = vocabulary(WIDGETS, Naming::Repeating);
    let auth = OperationHints::new(Some(AccessMode::AuthToken), Some(true)).expect("hints");
    let (parser, _) = atomic_parser(&vocabulary, move |source| {
        let first = defined("read", Some(&person_token()))?;
        let second = defined("read", Some(&auth))?;
        material(source, vec![first, second])
    });
    let err = refusal(parser.parse(ENDPOINT, b"source"));
    assert_eq!(err.kind(), DefinitionErrorKind::IdentityAmbiguous);
}

#[test]
fn definition_material_refuses_empty_or_unowned_evidence() {
    assert!(SourceEncoding::new("").is_err(), "missing encoding");
    assert!(SourceEncoding::new(" application/json").is_err());
    assert!(SourceEncoding::new("application/json\n").is_err());
    let read = DefinedOperation::new(&name_json("read"), None).expect("operation");
    assert!(
        DefinitionMaterial::new(encoding(), Vec::new(), vec![read.clone()]).is_err(),
        "empty receipt input"
    );
    assert!(
        DefinitionMaterial::new(encoding(), b"source".to_vec(), Vec::new()).is_err(),
        "no operations"
    );
    assert!(DefinitionMaterial::new(encoding(), b"source".to_vec(), vec![read]).is_ok());
    for raw in [
        b"".as_slice(),
        b"{".as_slice(),
        b"[]".as_slice(),
        b"\"read\"".as_slice(),
        br#"{"name":"read","name":"write"}"#.as_slice(),
    ] {
        assert!(DefinedOperation::new(raw, None).is_err(), "{raw:?}");
    }
    let hinted = DefinedOperation::new(&name_json("read"), Some(&person_token())).expect("hinted");
    assert_eq!(hinted.json(), br#"{"name":"read"}"#);
    assert_eq!(hinted.hints(), Some(&person_token()));
}

/// The wire spellings are a cross-language interface.
#[test]
fn definition_error_kinds_use_the_go_wire_spellings() {
    let kinds = [
        (DefinitionErrorKind::InvalidSource, "invalid_source"),
        (DefinitionErrorKind::IncompleteSource, "incomplete_source"),
        (DefinitionErrorKind::UnresolvedDependency, "unresolved_dependency"),
        (DefinitionErrorKind::SourceKindUnsupported, "source_kind_unsupported"),
        (DefinitionErrorKind::IdentityUnavailable, "operation_identity_unavailable"),
        (DefinitionErrorKind::IdentityAmbiguous, "operation_identity_ambiguous"),
        (DefinitionErrorKind::InvalidAnnotation, "invalid_annotation"),
        (DefinitionErrorKind::OperationNotDefined, "operation_not_defined"),
    ];
    for (kind, wire) in kinds {
        assert_eq!(kind.as_str(), wire);
        assert_eq!(kind.to_string(), wire);
    }
    let converted = DefinitionError::from(Error::new("plain"));
    assert_eq!(converted.kind(), DefinitionErrorKind::InvalidSource);
    assert!(converted.vocabulary().is_none());
    assert!(converted.source().is_some());
}
