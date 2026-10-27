use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::annotation::AnnotationEncoding;
use crate::error::Error;
use crate::uri::VocabularyUri;
use crate::vocabulary::{
    Codec, GrantedOperations, Operation, OperationSet, Registry, SetUse, Vocabulary,
    new_operation_value,
};

const NAMED: &str = "https://example.test/vocabulary/named";

#[derive(Clone, Copy)]
enum Discovery {
    Any,
    CustomUnix,
}

struct TestCodec {
    uri: VocabularyUri,
    encoding: AnnotationEncoding,
    parse_calls: Arc<AtomicUsize>,
    drop_on_parse: bool,
    expand_marshal: bool,
    rewrite_marshal: bool,
    discovery: Discovery,
    seen: Arc<Mutex<String>>,
}

fn test_codec(uri: &str) -> TestCodec {
    TestCodec {
        uri: VocabularyUri::parse(uri).expect("vocabulary URI"),
        encoding: AnnotationEncoding::UNAVAILABLE,
        parse_calls: Arc::new(AtomicUsize::new(0)),
        drop_on_parse: false,
        expand_marshal: false,
        rewrite_marshal: false,
        discovery: Discovery::Any,
        seen: Arc::new(Mutex::new(String::new())),
    }
}

fn parse_named(raw: &[Vec<u8>]) -> Result<Vec<String>, Error> {
    let mut set = Vec::with_capacity(raw.len());
    let mut seen = std::collections::BTreeSet::new();
    for value in raw {
        let operation: NameBody =
            serde_json::from_slice(value).map_err(|_| Error::new("invalid named operation"))?;
        if operation.name.is_empty() {
            return Err(Error::new("invalid named operation"));
        }
        if !seen.insert(operation.name.clone()) {
            return Err(Error::new(format!(
                "duplicate named operation \"{}\"",
                operation.name
            )));
        }
        set.push(operation.name);
    }
    Ok(set)
}

fn marshal_named(set: &[String]) -> Result<Vec<Vec<u8>>, Error> {
    set.iter()
        .map(|name| {
            serde_json::to_vec(&NameBody { name: name.clone() })
                .map_err(|err| Error::new(format!("r3: marshal named operation: {err}")))
        })
        .collect()
}

#[derive(serde::Deserialize, serde::Serialize)]
struct NameBody {
    name: String,
}

impl Codec for TestCodec {
    type Set = Vec<String>;

    fn uri(&self) -> VocabularyUri {
        self.uri.clone()
    }

    fn annotation_encoding(&self) -> AnnotationEncoding {
        self.encoding.clone()
    }

    fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), Error> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| Error::new("r3: discovery observer lock poisoned"))?;
        *seen = endpoint.to_owned();
        match self.discovery {
            Discovery::Any => Ok(()),
            Discovery::CustomUnix if endpoint.starts_with("custom+unix:///") => Ok(()),
            Discovery::CustomUnix => {
                Err(Error::new("custom discovery endpoint must use custom+unix"))
            }
        }
    }

    fn parse_set(&self, raw: &[Vec<u8>]) -> Result<Self::Set, Error> {
        self.parse_calls.fetch_add(1, Ordering::SeqCst);
        let mut set = parse_named(raw)?;
        if self.drop_on_parse && !set.is_empty() {
            set.pop();
        }
        Ok(set)
    }

    fn marshal_set(&self, set: &Self::Set) -> Result<Vec<Vec<u8>>, Error> {
        let mut set = set.clone();
        if self.rewrite_marshal && !set.is_empty() {
            set[0] = "substituted".to_owned();
        }
        if self.expand_marshal {
            set.push("injected".to_owned());
        }
        marshal_named(&set)
    }

    fn union_sets<'a>(
        &self,
        sets: impl IntoIterator<Item = &'a Self::Set>,
    ) -> Result<Self::Set, Error>
    where
        Self::Set: 'a,
    {
        let mut union = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for set in sets {
            for name in set {
                if seen.insert(name.clone()) {
                    union.push(name.clone());
                }
            }
        }
        Ok(union)
    }

    fn sets_equal(&self, left: &Self::Set, right: &Self::Set) -> bool {
        left.len() == right.len() && self.is_subset(left, right)
    }

    fn is_subset(&self, subset: &Self::Set, superset: &Self::Set) -> bool {
        subset
            .iter()
            .all(|name| superset.iter().any(|other| other == name))
    }

    fn is_disjoint(&self, left: &Self::Set, right: &Self::Set) -> bool {
        !left
            .iter()
            .any(|name| right.iter().any(|other| other == name))
    }
}

fn name_json(name: &str) -> Vec<u8> {
    format!(r#"{{"name":"{name}"}}"#).into_bytes()
}

fn json_bytes(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("JSON")
}

#[test]
fn vocabulary_enforces_cardinality_before_codec_dispatch() -> Result<(), Error> {
    let mut codec = test_codec("https://example.test/vocabulary/cardinality-before");
    let parse_calls = Arc::clone(&codec.parse_calls);
    codec.encoding = AnnotationEncoding::UNAVAILABLE;
    let vocabulary = Vocabulary::new(codec)?;
    let two = vec![name_json("one"), name_json("two")];
    for (name, use_, raw) in [
        ("empty request", SetUse::Request, Vec::new()),
        ("empty document", SetUse::Document, Vec::new()),
        ("empty proposal", SetUse::Proposal, Vec::new()),
        ("multi-operation proposal", SetUse::Proposal, two),
    ] {
        parse_calls.store(0, Ordering::SeqCst);
        assert!(
            new_operation_value(&vocabulary, &raw, use_).is_err(),
            "{name} reached the codec and was accepted"
        );
        assert_eq!(
            parse_calls.load(Ordering::SeqCst),
            0,
            "{name} dispatched to the codec"
        );
    }
    parse_calls.store(0, Ordering::SeqCst);
    new_operation_value(&vocabulary, &[], SetUse::Grant)?;
    assert_eq!(
        parse_calls.load(Ordering::SeqCst),
        2,
        "valid empty grant parse calls"
    );
    Ok(())
}

#[test]
fn vocabulary_enforces_cardinality_after_canonical_marshal() -> Result<(), Error> {
    let mut codec = test_codec("https://example.test/vocabulary/cardinality-after");
    let parse_calls = Arc::clone(&codec.parse_calls);
    codec.expand_marshal = true;
    let vocabulary = Vocabulary::new(codec)?;
    assert!(
        Operation::new(&vocabulary, &name_json("one")).is_err(),
        "codec expanded a proposal during canonical marshal"
    );
    assert_eq!(parse_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn vocabulary_rejects_codec_that_drops_operations_during_normalization() -> Result<(), Error> {
    let mut codec = test_codec("https://example.test/vocabulary/lossy");
    codec.drop_on_parse = true;
    let vocabulary = Vocabulary::new(codec)?;
    let raw = vec![name_json("one"), name_json("two")];
    for use_ in [SetUse::Request, SetUse::Grant] {
        assert!(
            new_operation_value(&vocabulary, &raw, use_).is_err(),
            "lossy codec dropped a {use_:?} operation"
        );
    }
    Ok(())
}

#[test]
fn vocabulary_rejects_codec_that_changes_operations_during_normalization() -> Result<(), Error> {
    let mut codec = test_codec("https://example.test/vocabulary/substituting");
    codec.rewrite_marshal = true;
    let vocabulary = Vocabulary::new(codec)?;
    assert!(Operation::new(&vocabulary, &name_json("one")).is_err());
    Ok(())
}

#[test]
fn vocabulary_accepts_a_namespaced_third_party_annotation_encoding() -> Result<(), Error> {
    let encoding = AnnotationEncoding::from_wire("https://example.test/r3/annotation-encoding");
    let mut codec = test_codec("https://example.test/vocabulary/custom-annotation");
    codec.encoding = encoding.clone();
    let vocabulary = Vocabulary::new(codec)?;
    assert_eq!(vocabulary.annotation_encoding(), encoding);

    let mut rejected = test_codec("https://example.test/vocabulary/invalid-annotation");
    rejected.encoding = AnnotationEncoding::from_wire("private words");
    assert!(Vocabulary::new(rejected).is_err());
    Ok(())
}

#[test]
fn vocabulary_delegates_discovery_endpoint_validation_to_codec() -> Result<(), Error> {
    let mut codec = test_codec("https://example.test/vocabulary/custom-discovery");
    let seen = Arc::clone(&codec.seen);
    codec.discovery = Discovery::CustomUnix;
    let vocabulary = Vocabulary::new(codec)?;
    let endpoint = "custom+unix:///run/example.sock?definition=current";
    vocabulary.validate_discovery_endpoint(endpoint)?;
    assert_eq!(seen.lock().expect("seen").as_str(), endpoint);
    assert!(
        vocabulary
            .validate_discovery_endpoint("https://resource.example/openapi.json")
            .is_err()
    );
    Ok(())
}

#[test]
fn vocabulary_registry_drives_whole_set_algebra() -> Result<(), Error> {
    let vocabulary = Vocabulary::new(test_codec(NAMED))?;
    let registry = Registry::new(std::slice::from_ref(&vocabulary))?;
    let all = registry.parse_operation_set(
        br#"{
        "vocabulary":"https://example.test/vocabulary/named",
        "operations":[{"name":"read"},{"name":"write"}]
    }"#,
    )?;
    let read = Operation::new(&vocabulary, &name_json("read"))?;
    let read_set = OperationSet::new(&[read])?;
    assert!(read_set.is_subset_of(&all)?);
    assert!(!read_set.is_disjoint(&all)?);
    let union = read_set.union_with(std::slice::from_ref(&all))?;
    assert!(union.equal(&all)?);
    let encoded = json_bytes(&all);
    assert_eq!(
        std::str::from_utf8(&encoded).expect("utf-8"),
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"read"},{"name":"write"}]}"#
    );
    Ok(())
}

#[test]
fn vocabulary_registry_fails_closed() -> Result<(), Error> {
    let first = Vocabulary::new(test_codec(NAMED))?;
    assert!(Registry::new(&[first.clone(), first.clone()]).is_err());
    let registry = Registry::new(std::slice::from_ref(&first))?;
    assert!(
        registry
            .parse_operation_set(
                br#"{"vocabulary":"https://example.test/vocabulary/unknown","operations":[{"name":"read"}]}"#,
            )
            .is_err()
    );
    let second = Vocabulary::new(test_codec(NAMED))?;
    let left = Operation::new(&first, &name_json("read"))?;
    let right = Operation::new(&second, &name_json("read"))?;
    let left_set = OperationSet::new(&[left])?;
    let right_set = OperationSet::new(&[right])?;
    assert!(left_set.equal(&right_set).is_err());
    registry.validate_operation_set(&left_set)?;
    assert!(registry.validate_operation_set(&right_set).is_err());
    Ok(())
}

#[test]
fn vocabulary_zero_value_operation_set_union_returns_an_error() {
    assert!(OperationSet::default().union_with(&[]).is_err());
}

#[test]
fn vocabulary_context_bound_operation_envelopes_refuse_context_free_unmarshal() -> Result<(), Error>
{
    let vocabulary = Vocabulary::new(test_codec("https://example.test/vocabulary/unmarshal"))?;
    let operation = Operation::new(&vocabulary, &name_json("read"))?;
    let mut operation_set = OperationSet::new(std::slice::from_ref(&operation))?;
    let mut granted = GrantedOperations::new(&vocabulary, std::slice::from_ref(&operation))?;
    let encoded = br#"{"vocabulary":"https://example.test/vocabulary/unmarshal","operations":[{"name":"write"}]}"#;

    assert!(serde_json::to_vec(&operation).is_err());
    let set_before = json_bytes(&operation_set);
    let refused = OperationSet::deserialize_in_place(
        &mut serde_json::Deserializer::from_slice(encoded),
        &mut operation_set,
    );
    assert!(refused.is_err());
    assert_eq!(json_bytes(&operation_set), set_before);

    let grant_before = json_bytes(&granted);
    let refused = GrantedOperations::deserialize_in_place(
        &mut serde_json::Deserializer::from_slice(encoded),
        &mut granted,
    );
    assert!(refused.is_err());
    assert_eq!(json_bytes(&granted), grant_before);
    Ok(())
}

#[test]
fn vocabulary_uri_rejects_a_fragment_and_a_non_absolute_form() {
    assert!(VocabularyUri::parse("https://example.test/vocabulary/named").is_ok());
    assert!(VocabularyUri::parse("urn:aauth:vocabulary:mcp").is_ok());
    assert!(VocabularyUri::parse("").is_err());
    assert!(VocabularyUri::parse(" https://example.test/v").is_err());
    assert!(VocabularyUri::parse("https://example.test/v ").is_err());
    assert!(VocabularyUri::parse("private words").is_err());
    assert!(VocabularyUri::parse("/relative").is_err());
    assert!(VocabularyUri::parse("https://example.test/v#frag").is_err());
    assert!(VocabularyUri::parse("https://example.test/v#").is_err());
}

#[test]
fn vocabulary_envelope_rejects_duplicate_and_unknown_members() -> Result<(), Error> {
    let vocabulary = Vocabulary::new(test_codec(NAMED))?;
    let registry = Registry::new(&[vocabulary])?;
    let rejected = [
        br#"{"vocabulary":"https://example.test/vocabulary/named","vocabulary":"https://example.test/vocabulary/named","operations":[]}"#.as_slice(),
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[],"extra":true}"#.as_slice(),
        br#"{"operations":[]}"#.as_slice(),
        br#"{"vocabulary":"https://example.test/vocabulary/named"}"#.as_slice(),
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":null}"#.as_slice(),
        br#"{"Vocabulary":"https://example.test/vocabulary/named","operations":[]}"#.as_slice(),
        br#"[]"#.as_slice(),
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]} {}"#.as_slice(),
        b"\xff".as_slice(),
    ];
    for source in rejected {
        assert!(
            registry.parse_operation_set(source).is_err(),
            "accepted {}",
            String::from_utf8_lossy(source)
        );
        assert!(
            registry.parse_granted_operations(source).is_err(),
            "grant accepted {}",
            String::from_utf8_lossy(source)
        );
    }
    assert!(
        registry
            .parse_operation_set(
                br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#,
            )
            .is_err()
    );
    let empty = registry.parse_granted_operations(
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#,
    )?;
    assert_eq!(empty.vocabulary().as_str(), NAMED);
    assert!(empty.operations()?.is_empty());
    assert_eq!(
        json_bytes(&empty),
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#
    );
    Ok(())
}

#[test]
fn vocabulary_granted_operations_keep_owned_copies_and_set_relations() -> Result<(), Error> {
    let vocabulary = Vocabulary::new(test_codec(NAMED))?;
    let read = Operation::new(&vocabulary, &name_json("read"))?;
    let write = Operation::new(&vocabulary, &name_json("write"))?;
    let both = GrantedOperations::new(&vocabulary, &[read.clone(), write.clone()])?;
    let reversed = GrantedOperations::new(&vocabulary, &[write, read.clone()])?;
    assert!(both.equal(&reversed)?);
    let document = OperationSet::new(&[
        Operation::new(&vocabulary, &name_json("read"))?,
        Operation::new(&vocabulary, &name_json("write"))?,
    ])?;
    let only_read = GrantedOperations::new(&vocabulary, &[read])?;
    let empty = GrantedOperations::new(&vocabulary, &[])?;
    assert!(only_read.is_subset_of(&document)?);
    assert!(empty.is_subset_of(&document)?);
    assert!(empty.equal(&GrantedOperations::new(&vocabulary, &[])?)?);
    assert!(!both.is_subset_of(&OperationSet::new(&[Operation::new(
        &vocabulary,
        &name_json("read")
    )?,])?)?);
    assert!(only_read.is_disjoint(&GrantedOperations::new(
        &vocabulary,
        &[Operation::new(&vocabulary, &name_json("write"))?],
    )?)?);
    assert!(only_read.contains(&Operation::new(&vocabulary, &name_json("read"))?)?);

    let mut inputs = vec![Operation::new(&vocabulary, &name_json("retained"))?];
    let granted = GrantedOperations::new(&vocabulary, &inputs)?;
    inputs[0] = Operation::new(&vocabulary, &name_json("changed-input"))?;
    let mut returned = granted.operations()?;
    returned[0] = Operation::new(&vocabulary, &name_json("changed-output"))?;
    assert_eq!(granted.operations()?[0].json()?, name_json("retained"));
    let duplicate = Operation::new(&vocabulary, &name_json("same"))?;
    assert!(GrantedOperations::new(&vocabulary, &[duplicate.clone(), duplicate]).is_err());
    assert!(GrantedOperations::new(&vocabulary, &[Operation::default()]).is_err());
    Ok(())
}
