use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize, Serializer};

use crate::annotation::AnnotationEncoding;
use crate::envelope::{parse_operation_envelope, serialize_envelope};
use crate::error::Error;
use crate::uri::{self, VocabularyUri};

/// Which R3 boundary owns this operation set's cardinality.
///
/// Vocabularies parse their own grammar. They do not decide the common set shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetUse {
    Request,
    Document,
    Grant,
    Proposal,
}

fn validate_set_cardinality(use_: SetUse, length: usize) -> Result<(), Error> {
    match use_ {
        SetUse::Request | SetUse::Document if length == 0 => {
            Err(Error::new("r3: operation set must not be empty"))
        }
        SetUse::Request | SetUse::Document => Ok(()),
        // An empty grant is valid and keeps the vocabulary it names.
        SetUse::Grant => Ok(()),
        SetUse::Proposal if length != 1 => Err(Error::new(
            "r3: proposal must contain exactly one operation",
        )),
        SetUse::Proposal => Ok(()),
    }
}

/// One operation grammar and a coherent whole-set algebra.
///
/// `parse_set` and `marshal_set` are semantic inverses. Returned values are
/// owned. Canonical marshal must not drop or change an operation. `sets_equal`,
/// `is_subset`, `is_disjoint`, and `union_sets` agree with one another.
/// Discovery validation is syntax only: it does not fetch a definition.
pub trait Codec: Send + Sync {
    /// Codec-owned operation set. The vocabulary root stores canonical JSON, not this type.
    type Set: Clone + Send + Sync;

    /// Vocabulary URI this codec parses.
    fn uri(&self) -> VocabularyUri;

    /// Annotation mechanism, or [`AnnotationEncoding::UNAVAILABLE`].
    fn annotation_encoding(&self) -> AnnotationEncoding;

    /// Check discovery-endpoint syntax for this vocabulary.
    ///
    /// # Errors
    /// Returns [`Error`] when `endpoint` is outside this vocabulary's grammar.
    fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), Error>;

    /// Parse owned operation objects into a set.
    ///
    /// # Errors
    /// Returns [`Error`] when an object is outside this grammar.
    fn parse_set(&self, raw: &[Vec<u8>]) -> Result<Self::Set, Error>;

    /// Emit one owned JSON object per operation, in retained order.
    ///
    /// # Errors
    /// Returns [`Error`] when the set cannot be encoded.
    fn marshal_set(&self, set: &Self::Set) -> Result<Vec<Vec<u8>>, Error>;

    /// Union in first-seen vocabulary order.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands cannot be combined.
    fn union_sets<'a>(
        &self,
        sets: impl IntoIterator<Item = &'a Self::Set>,
    ) -> Result<Self::Set, Error>
    where
        Self::Set: 'a;

    /// Semantic equality, including order-insensitive grammars.
    fn sets_equal(&self, left: &Self::Set, right: &Self::Set) -> bool;

    /// Whether every operation in `subset` is authorized by `superset`.
    fn is_subset(&self, subset: &Self::Set, superset: &Self::Set) -> bool;

    /// Whether the sets share no operation.
    fn is_disjoint(&self, left: &Self::Set, right: &Self::Set) -> bool;
}

trait VocabOps: Send + Sync {
    fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), Error>;
    fn normalize(&self, raw: &[Vec<u8>], use_: SetUse) -> Result<Vec<Vec<u8>>, Error>;
    fn combine(&self, values: &[OperationValue]) -> Result<Vec<Vec<u8>>, Error>;
    fn equal(&self, left: &OperationValue, right: &OperationValue) -> Result<bool, Error>;
    fn subset(&self, left: &OperationValue, right: &OperationValue) -> Result<bool, Error>;
    fn disjoint(&self, left: &OperationValue, right: &OperationValue) -> Result<bool, Error>;
}

struct VocabularyIdentity;

struct Registered<C: Codec> {
    codec: C,
    uri: VocabularyUri,
    identity: Arc<VocabularyIdentity>,
}

impl<C: Codec> Registered<C> {
    fn parse(&self, raw: &[Vec<u8>], use_: SetUse) -> Result<C::Set, Error> {
        validate_set_cardinality(use_, raw.len())?;
        let owned = clone_raw(raw);
        self.codec.parse_set(&owned)
    }

    fn marshal(&self, set: &C::Set, use_: SetUse) -> Result<Vec<Vec<u8>>, Error> {
        let raw = self.codec.marshal_set(set)?;
        validate_set_cardinality(use_, raw.len()).map_err(|err| {
            Error::wrap(
                format!(
                    "r3: vocabulary \"{}\" emitted invalid operation cardinality",
                    self.uri
                ),
                err,
            )
        })?;
        for (index, operation) in raw.iter().enumerate() {
            require_json_object(&self.uri, index, operation)?;
        }
        Ok(clone_raw(&raw))
    }

    fn decode(&self, value: &OperationValue) -> Result<C::Set, Error> {
        let same = value
            .vocabulary
            .registration
            .as_ref()
            .is_some_and(|registration| Arc::ptr_eq(&registration.identity, &self.identity))
            && value.vocabulary.uri == self.uri;
        if !same {
            return Err(Error::new(
                "r3: operation sets use different vocabulary registrations",
            ));
        }
        self.parse(&value.raw, value.use_)
    }
}

impl<C: Codec> VocabOps for Registered<C> {
    fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), Error> {
        self.codec.validate_discovery_endpoint(endpoint)
    }

    fn normalize(&self, raw: &[Vec<u8>], use_: SetUse) -> Result<Vec<Vec<u8>>, Error> {
        let set = self.parse(raw, use_)?;
        let canonical = self.marshal(&set, use_)?;
        if canonical.len() != raw.len() {
            return Err(Error::new(format!(
                "r3: vocabulary \"{}\" changed operation count during normalization from {} to {}",
                self.uri,
                raw.len(),
                canonical.len()
            )));
        }
        let canonical_set = self.parse(&canonical, use_).map_err(|err| {
            Error::wrap(
                format!(
                    "r3: vocabulary \"{}\" emitted an invalid canonical set",
                    self.uri
                ),
                err,
            )
        })?;
        if !self.codec.sets_equal(&set, &canonical_set) {
            return Err(Error::new(format!(
                "r3: vocabulary \"{}\" changed operation semantics during normalization",
                self.uri
            )));
        }
        Ok(canonical)
    }

    fn combine(&self, values: &[OperationValue]) -> Result<Vec<Vec<u8>>, Error> {
        let mut sets = Vec::with_capacity(values.len());
        for value in values {
            sets.push(self.decode(value)?);
        }
        let union = self.codec.union_sets(sets.iter())?;
        self.marshal(&union, SetUse::Document)
    }

    fn equal(&self, left: &OperationValue, right: &OperationValue) -> Result<bool, Error> {
        Ok(self
            .codec
            .sets_equal(&self.decode(left)?, &self.decode(right)?))
    }

    fn subset(&self, left: &OperationValue, right: &OperationValue) -> Result<bool, Error> {
        Ok(self
            .codec
            .is_subset(&self.decode(left)?, &self.decode(right)?))
    }

    fn disjoint(&self, left: &OperationValue, right: &OperationValue) -> Result<bool, Error> {
        Ok(self
            .codec
            .is_disjoint(&self.decode(left)?, &self.decode(right)?))
    }
}

#[derive(Clone)]
struct Registration {
    identity: Arc<VocabularyIdentity>,
    ops: Arc<dyn VocabOps>,
}

/// One immutable codec registration.
///
/// Two values with the same URI and different registrations are not interchangeable.
/// Constructing a vocabulary does not install process-global state.
#[derive(Clone)]
pub struct Vocabulary {
    uri: VocabularyUri,
    annotation: AnnotationEncoding,
    registration: Option<Registration>,
}

impl Vocabulary {
    /// Erase one codec. The codec value is retained only behind the registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the URI or annotation encoding is not allowed.
    pub fn new<C>(codec: C) -> Result<Self, Error>
    where
        C: Codec + 'static,
    {
        let uri = codec.uri();
        uri::validate(uri.as_str())?;
        let annotation = codec.annotation_encoding();
        annotation
            .validate()
            .map_err(|err| Error::wrap(format!("r3: vocabulary \"{uri}\""), err))?;
        let identity = Arc::new(VocabularyIdentity);
        let ops: Arc<dyn VocabOps> = Arc::new(Registered {
            uri: uri.clone(),
            identity: Arc::clone(&identity),
            codec,
        });
        Ok(Self {
            uri,
            annotation,
            registration: Some(Registration { identity, ops }),
        })
    }

    /// Exact registered URI.
    pub fn uri(&self) -> &VocabularyUri {
        &self.uri
    }

    /// Registered annotation mechanism.
    pub fn annotation_encoding(&self) -> AnnotationEncoding {
        self.annotation.clone()
    }

    /// Apply the codec's discovery-endpoint grammar. This does not fetch.
    ///
    /// # Errors
    /// Returns [`Error`] when the vocabulary is uninitialized or the codec refuses `endpoint`.
    pub fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), Error> {
        let ops = self.ops()?;
        ops.validate_discovery_endpoint(endpoint).map_err(|err| {
            Error::wrap(
                format!("r3: vocabulary \"{}\" discovery endpoint", self.uri),
                err,
            )
        })
    }

    fn registration(&self) -> Result<&Registration, Error> {
        uri::validate(self.uri.as_str())?;
        self.annotation.validate()?;
        self.registration
            .as_ref()
            .ok_or_else(|| Error::new(format!("r3: vocabulary \"{}\" is uninitialized", self.uri)))
    }

    fn ops(&self) -> Result<Arc<dyn VocabOps>, Error> {
        Ok(Arc::clone(&self.registration()?.ops))
    }
}

impl Default for Vocabulary {
    fn default() -> Self {
        Self {
            uri: VocabularyUri::uninitialized(),
            annotation: AnnotationEncoding::UNAVAILABLE,
            registration: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct OperationValue {
    vocabulary: Vocabulary,
    use_: SetUse,
    raw: Vec<Vec<u8>>,
}

impl OperationValue {
    fn validate(&self) -> Result<(), Error> {
        let ops = self.vocabulary.ops()?;
        let _canonical = ops.normalize(&self.raw, self.use_)?;
        Ok(())
    }
}

pub(crate) fn new_operation_value(
    vocabulary: &Vocabulary,
    raw: &[Vec<u8>],
    use_: SetUse,
) -> Result<OperationValue, Error> {
    let uri = vocabulary.uri().as_str().to_owned();
    let ops = vocabulary.ops()?;
    let canonical = ops
        .normalize(raw, use_)
        .map_err(|err| Error::wrap(format!("r3: invalid \"{uri}\" operations"), err))?;
    Ok(OperationValue {
        vocabulary: vocabulary.clone(),
        use_,
        raw: canonical,
    })
}

fn compatible_operations(left: &OperationValue, right: &OperationValue) -> Result<(), Error> {
    left.validate()?;
    right.validate()?;
    if left.vocabulary.uri != right.vocabulary.uri {
        return Err(Error::new(format!(
            "r3: operation vocabularies differ: \"{}\" and \"{}\"",
            left.vocabulary.uri, right.vocabulary.uri
        )));
    }
    let same = match (
        &left.vocabulary.registration,
        &right.vocabulary.registration,
    ) {
        (Some(left), Some(right)) => Arc::ptr_eq(&left.identity, &right.identity),
        _ => false,
    };
    if !same {
        return Err(Error::new(format!(
            "r3: vocabulary \"{}\" uses different registrations",
            left.vocabulary.uri
        )));
    }
    Ok(())
}

/// One vocabulary-tagged R3 operation.
#[derive(Clone)]
pub struct Operation {
    value: OperationValue,
}

impl Operation {
    /// Parse one operation through an allowlisted vocabulary.
    ///
    /// # Errors
    /// Returns [`Error`] when the object is not one canonical operation.
    pub fn new(vocabulary: &Vocabulary, raw: &[u8]) -> Result<Self, Error> {
        let value = new_operation_value(vocabulary, &[raw.to_vec()], SetUse::Proposal)?;
        if value.raw.len() != 1 {
            return Err(Error::new(
                "r3: vocabulary did not preserve one proposal operation",
            ));
        }
        Ok(Self { value })
    }

    /// Vocabulary URI of this operation.
    pub fn vocabulary(&self) -> &VocabularyUri {
        self.value.vocabulary.uri()
    }

    /// Owned canonical operation object.
    ///
    /// # Errors
    /// Returns [`Error`] when the operation is uninitialized or no longer one object.
    pub fn json(&self) -> Result<Vec<u8>, Error> {
        self.value.validate()?;
        let Some(operation) = self.value.raw.first() else {
            return Err(Error::new(
                "r3: vocabulary did not preserve one proposal operation",
            ));
        };
        if self.value.raw.len() != 1 {
            return Err(Error::new(
                "r3: vocabulary did not preserve one proposal operation",
            ));
        }
        Ok(operation.clone())
    }

    /// Semantic equality inside one registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn equal(&self, other: &Self) -> Result<bool, Error> {
        compatible_operations(&self.value, &other.value)?;
        self.value
            .vocabulary
            .ops()?
            .equal(&self.value, &other.value)
    }
}

impl Default for Operation {
    fn default() -> Self {
        Self {
            value: OperationValue {
                vocabulary: Vocabulary::default(),
                use_: SetUse::Proposal,
                raw: Vec::new(),
            },
        }
    }
}

impl Serialize for Operation {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "r3: Operation has no context-free JSON form; use Operation::json inside a registered vocabulary envelope",
        ))
    }
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: serde::Deserializer<'de>>(_deserializer: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "r3: Operation requires a vocabulary; use Operation::new or a typed vocabulary adapter",
        ))
    }
}

/// A non-empty homogeneous operation set.
#[derive(Clone)]
pub struct OperationSet {
    value: OperationValue,
}

impl OperationSet {
    /// Build a set from operations that already share one registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the list is empty or mixes registrations.
    pub fn new(operations: &[Operation]) -> Result<Self, Error> {
        if operations.is_empty() {
            return Err(Error::new("r3: operation set must not be empty"));
        }
        let vocabulary = &operations[0].value.vocabulary;
        let mut raw = Vec::with_capacity(operations.len());
        for (index, operation) in operations.iter().enumerate() {
            compatible_operations(&operations[0].value, &operation.value)
                .map_err(|err| Error::wrap(format!("r3: operation {index}"), err))?;
            if operation.value.raw.len() != 1 {
                return Err(Error::new(format!("r3: operation {index} is not singular")));
            }
            raw.push(operation.value.raw[0].clone());
        }
        let value = new_operation_value(vocabulary, &raw, SetUse::Request)?;
        Ok(Self { value })
    }

    /// Vocabulary URI shared by the set.
    pub fn vocabulary(&self) -> &VocabularyUri {
        self.value.vocabulary.uri()
    }

    /// Operations in retained wire order.
    ///
    /// # Errors
    /// Returns [`Error`] when the set is uninitialized or an element is no longer one operation.
    pub fn operations(&self) -> Result<Vec<Operation>, Error> {
        self.value.validate()?;
        let mut operations = Vec::with_capacity(self.value.raw.len());
        for raw in &self.value.raw {
            operations.push(Operation::new(&self.value.vocabulary, raw)?);
        }
        Ok(operations)
    }

    /// Semantic equality inside one registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn equal(&self, other: &Self) -> Result<bool, Error> {
        compatible_operations(&self.value, &other.value)?;
        self.value
            .vocabulary
            .ops()?
            .equal(&self.value, &other.value)
    }

    /// Whether every operation in `self` is authorized by `other`.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn is_subset_of(&self, other: &Self) -> Result<bool, Error> {
        compatible_operations(&self.value, &other.value)?;
        self.value
            .vocabulary
            .ops()?
            .subset(&self.value, &other.value)
    }

    /// Whether the sets share no operation.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn is_disjoint(&self, other: &Self) -> Result<bool, Error> {
        compatible_operations(&self.value, &other.value)?;
        self.value
            .vocabulary
            .ops()?
            .disjoint(&self.value, &other.value)
    }

    /// Compose sets with the vocabulary's union.
    ///
    /// # Errors
    /// Returns [`Error`] when `self` is uninitialized or an operand uses another registration.
    pub fn union_with(&self, others: &[Self]) -> Result<Self, Error> {
        self.value.validate()?;
        let mut values = Vec::with_capacity(others.len() + 1);
        values.push(self.value.clone());
        for (index, other) in others.iter().enumerate() {
            compatible_operations(&self.value, &other.value)
                .map_err(|err| Error::wrap(format!("r3: union operand {}", index + 1), err))?;
            values.push(other.value.clone());
        }
        let ops = self.value.vocabulary.ops()?;
        let raw = ops.combine(&values)?;
        new_parsed(self.value.vocabulary.clone(), raw, SetUse::Document)
    }
}

fn new_parsed(
    vocabulary: Vocabulary,
    raw: Vec<Vec<u8>>,
    use_: SetUse,
) -> Result<OperationSet, Error> {
    let value = new_operation_value(&vocabulary, &raw, use_)?;
    Ok(OperationSet { value })
}

impl Default for OperationSet {
    fn default() -> Self {
        Self {
            value: OperationValue {
                vocabulary: Vocabulary::default(),
                use_: SetUse::Request,
                raw: Vec::new(),
            },
        }
    }
}

impl Serialize for OperationSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_value(&self.value, serializer)
    }
}

impl<'de> Deserialize<'de> for OperationSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let _ignored = serde_json::Value::deserialize(deserializer)?;
        Err(serde::de::Error::custom(
            "r3: OperationSet requires a registry; use Registry::parse_operation_set",
        ))
    }
}

/// Vocabulary-tagged operations carried by a grant, including a valid empty grant.
#[derive(Clone)]
pub struct GrantedOperations {
    value: OperationValue,
}

impl GrantedOperations {
    /// Build a grant set. The vocabulary is kept even when `operations` is empty.
    ///
    /// # Errors
    /// Returns [`Error`] when the vocabulary is uninitialized or an operation uses another registration.
    pub fn new(vocabulary: &Vocabulary, operations: &[Operation]) -> Result<Self, Error> {
        vocabulary.ops()?;
        let mut raw = Vec::with_capacity(operations.len());
        for (index, operation) in operations.iter().enumerate() {
            let same = operation
                .value
                .vocabulary
                .registration
                .as_ref()
                .zip(vocabulary.registration.as_ref())
                .is_some_and(|(left, right)| Arc::ptr_eq(&left.identity, &right.identity))
                && operation.value.vocabulary.uri == vocabulary.uri;
            if !same {
                return Err(Error::new(format!(
                    "r3: granted operation {index} uses a different vocabulary registration"
                )));
            }
            let Some(operation_json) = operation.value.raw.first() else {
                return Err(Error::new(format!(
                    "r3: granted operation {index} is not singular"
                )));
            };
            if operation.value.raw.len() != 1 {
                return Err(Error::new(format!(
                    "r3: granted operation {index} is not singular"
                )));
            }
            raw.push(operation_json.clone());
        }
        let value = new_operation_value(vocabulary, &raw, SetUse::Grant)?;
        Ok(Self { value })
    }

    /// Vocabulary URI, including the URI of an empty grant.
    pub fn vocabulary(&self) -> &VocabularyUri {
        self.value.vocabulary.uri()
    }

    /// Operations in retained wire order. An empty grant returns an empty vector.
    ///
    /// # Errors
    /// Returns [`Error`] when the grant is uninitialized.
    pub fn operations(&self) -> Result<Vec<Operation>, Error> {
        self.value.validate()?;
        let mut operations = Vec::with_capacity(self.value.raw.len());
        for raw in &self.value.raw {
            operations.push(Operation::new(&self.value.vocabulary, raw)?);
        }
        Ok(operations)
    }

    /// Semantic equality inside one registration.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn equal(&self, other: &Self) -> Result<bool, Error> {
        compatible_operations(&self.value, &other.value)?;
        self.value
            .vocabulary
            .ops()?
            .equal(&self.value, &other.value)
    }

    /// Whether this grant is contained by `other`.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn is_subset_of(&self, other: &OperationSet) -> Result<bool, Error> {
        compatible_operations(&self.value, &other.value)?;
        self.value
            .vocabulary
            .ops()?
            .subset(&self.value, &other.value)
    }

    /// Whether two grants share no operation.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn is_disjoint(&self, other: &Self) -> Result<bool, Error> {
        compatible_operations(&self.value, &other.value)?;
        self.value
            .vocabulary
            .ops()?
            .disjoint(&self.value, &other.value)
    }

    /// Whether the grant covers one operation.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands are uninitialized or use different registrations.
    pub fn contains(&self, operation: &Operation) -> Result<bool, Error> {
        compatible_operations(&self.value, &operation.value)?;
        self.value
            .vocabulary
            .ops()?
            .subset(&operation.value, &self.value)
    }
}

impl Default for GrantedOperations {
    fn default() -> Self {
        Self {
            value: OperationValue {
                vocabulary: Vocabulary::default(),
                use_: SetUse::Grant,
                raw: Vec::new(),
            },
        }
    }
}

impl Serialize for GrantedOperations {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_value(&self.value, serializer)
    }
}

impl<'de> Deserialize<'de> for GrantedOperations {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let _ignored = serde_json::Value::deserialize(deserializer)?;
        Err(serde::de::Error::custom(
            "r3: GrantedOperations requires a registry; use Registry::parse_granted_operations",
        ))
    }
}

fn serialize_value<S: Serializer>(
    value: &OperationValue,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.validate().map_err(serde::ser::Error::custom)?;
    serialize_envelope(value.vocabulary.uri().as_str(), &value.raw, serializer)
}

/// Immutable allowlist of vocabulary registrations.
#[derive(Clone)]
pub struct Registry {
    vocabularies: BTreeMap<VocabularyUri, Vocabulary>,
}

impl Registry {
    /// Build an allowlist. The same URI cannot be registered twice.
    ///
    /// # Errors
    /// Returns [`Error`] when a vocabulary is uninitialized or its URI is repeated.
    pub fn new(vocabularies: &[Vocabulary]) -> Result<Self, Error> {
        let mut registered = BTreeMap::new();
        for (index, vocabulary) in vocabularies.iter().enumerate() {
            vocabulary
                .ops()
                .map_err(|err| Error::wrap(format!("r3: vocabulary {index}"), err))?;
            if registered.contains_key(vocabulary.uri()) {
                return Err(Error::new(format!(
                    "r3: duplicate vocabulary URI \"{}\"",
                    vocabulary.uri()
                )));
            }
            registered.insert(vocabulary.uri().clone(), vocabulary.clone());
        }
        Ok(Self {
            vocabularies: registered,
        })
    }

    /// The registration stored for `uri`.
    pub fn vocabulary(&self, uri: &VocabularyUri) -> Option<Vocabulary> {
        self.vocabularies.get(uri).cloned()
    }

    /// Number of allowlisted vocabularies.
    pub fn len(&self) -> usize {
        self.vocabularies.len()
    }

    /// Whether the allowlist is empty.
    pub fn is_empty(&self) -> bool {
        self.vocabularies.is_empty()
    }

    /// Prove `set` was built by this allowlist's registration, not another codec with the same URI.
    ///
    /// # Errors
    /// Returns [`Error`] when the set is uninitialized, unknown, or from another registration.
    pub fn validate_operation_set(&self, set: &OperationSet) -> Result<(), Error> {
        set.value.validate()?;
        let Some(registered) = self.vocabularies.get(set.vocabulary()) else {
            return Err(Error::new(format!(
                "r3: vocabulary \"{}\" is not registered",
                set.vocabulary()
            )));
        };
        let same = set
            .value
            .vocabulary
            .registration
            .as_ref()
            .zip(registered.registration.as_ref())
            .is_some_and(|(left, right)| Arc::ptr_eq(&left.identity, &right.identity));
        if !same {
            return Err(Error::new(format!(
                "r3: vocabulary \"{}\" uses a different registration",
                set.vocabulary()
            )));
        }
        Ok(())
    }

    /// Parse one non-empty operations envelope and dispatch on its vocabulary URI.
    ///
    /// # Errors
    /// Returns [`Error`] when the JSON is not a strict envelope or the vocabulary is not allowlisted.
    pub fn parse_operation_set(&self, source: &[u8]) -> Result<OperationSet, Error> {
        let (uri, raw) = parse_operation_envelope(source)?;
        let Some(vocabulary) = self.vocabularies.get(&uri) else {
            return Err(Error::new(format!(
                "r3: vocabulary \"{uri}\" is not registered"
            )));
        };
        new_parsed(vocabulary.clone(), raw, SetUse::Request)
    }

    /// Parse a grant envelope, including an empty operations array.
    ///
    /// # Errors
    /// Returns [`Error`] when the JSON is not a strict envelope or the vocabulary is not allowlisted.
    pub fn parse_granted_operations(&self, source: &[u8]) -> Result<GrantedOperations, Error> {
        let (uri, raw) = parse_operation_envelope(source)?;
        let Some(vocabulary) = self.vocabularies.get(&uri) else {
            return Err(Error::new(format!(
                "r3: vocabulary \"{uri}\" is not registered"
            )));
        };
        let value = new_operation_value(vocabulary, &raw, SetUse::Grant)?;
        Ok(GrantedOperations { value })
    }
}

fn clone_raw(values: &[Vec<u8>]) -> Vec<Vec<u8>> {
    values.to_vec()
}

fn require_json_object(uri: &VocabularyUri, index: usize, operation: &[u8]) -> Result<(), Error> {
    if operation.is_empty() {
        return Err(Error::new(format!(
            "r3: vocabulary \"{uri}\" emitted invalid operation {index}"
        )));
    }
    match serde_json::from_slice::<serde_json::Value>(operation) {
        Ok(serde_json::Value::Object(_)) => Ok(()),
        Ok(_) => Err(Error::new(format!(
            "r3: vocabulary \"{uri}\" emitted non-object operation {index}"
        ))),
        Err(_) => Err(Error::new(format!(
            "r3: vocabulary \"{uri}\" emitted invalid operation {index}"
        ))),
    }
}
