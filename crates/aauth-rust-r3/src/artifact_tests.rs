use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::annotation::AnnotationEncoding;
use crate::error::Error;
use crate::jsonvalue::{Json, parse_json, take_name_comparisons};
use crate::vocabulary::{Codec, GrantedOperations, Operation, OperationSet, Registry, Vocabulary};
use crate::{
    Authorization, Display, Document, DocumentOptions, Grant, Parameter, Parameters,
    PresentedParameter, Proposal, ProposalDisplay, ProposalOptions, ProposalResult, Reference,
    digest, validate_document_account, validate_proposal_account,
};

const NAMED: &str = "https://example.test/vocabulary/named";

struct NamedCodec;

#[derive(serde::Serialize)]
struct NameBody {
    name: String,
}

impl Codec for NamedCodec {
    type Set = Vec<String>;

    fn uri(&self) -> crate::VocabularyUri {
        crate::VocabularyUri::parse(NAMED).expect("vocabulary URI")
    }

    fn annotation_encoding(&self) -> AnnotationEncoding {
        AnnotationEncoding::UNAVAILABLE
    }

    fn validate_discovery_endpoint(&self, _endpoint: &str) -> Result<(), Error> {
        Ok(())
    }

    fn parse_set(&self, raw: &[Vec<u8>]) -> Result<Self::Set, Error> {
        let mut set = Vec::with_capacity(raw.len());
        let mut seen = BTreeSet::new();
        for value in raw {
            let parsed = parse_json(value).map_err(|_| Error::new("invalid named operation"))?;
            let Json::Object(members) = parsed else {
                return Err(Error::new("invalid named operation"));
            };
            if members.len() != 1 || members[0].0 != "name" {
                return Err(Error::new("invalid named operation"));
            }
            let Json::String(name) = &members[0].1 else {
                return Err(Error::new("invalid named operation"));
            };
            if name.is_empty() || !seen.insert(name.clone()) {
                return Err(Error::new("invalid named operation"));
            }
            set.push(name.clone());
        }
        Ok(set)
    }

    fn marshal_set(&self, set: &Self::Set) -> Result<Vec<Vec<u8>>, Error> {
        set.iter()
            .map(|name| {
                serde_json::to_vec(&NameBody { name: name.clone() })
                    .map_err(|err| Error::new(format!("r3: marshal named operation: {err}")))
            })
            .collect()
    }

    fn union_sets<'a>(
        &self,
        sets: impl IntoIterator<Item = &'a Self::Set>,
    ) -> Result<Self::Set, Error>
    where
        Self::Set: 'a,
    {
        let mut union = Vec::new();
        let mut seen = BTreeSet::new();
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

fn vocabulary() -> Vocabulary {
    Vocabulary::new(NamedCodec).expect("vocabulary")
}

fn registry(vocabulary: &Vocabulary) -> Registry {
    Registry::new(std::slice::from_ref(vocabulary)).expect("registry")
}

fn name_json(name: &str) -> Vec<u8> {
    format!(r#"{{"name":"{name}"}}"#).into_bytes()
}

fn operation(vocabulary: &Vocabulary, name: &str) -> Operation {
    Operation::new(vocabulary, &name_json(name)).expect(name)
}

fn operation_set(vocabulary: &Vocabulary, names: &[&str]) -> OperationSet {
    let operations: Vec<_> = names
        .iter()
        .map(|name| operation(vocabulary, name))
        .collect();
    OperationSet::new(&operations).expect("operation set")
}

fn granted(vocabulary: &Vocabulary, names: &[&str]) -> GrantedOperations {
    let operations: Vec<_> = names
        .iter()
        .map(|name| operation(vocabulary, name))
        .collect();
    GrantedOperations::new(vocabulary, &operations).expect("granted operations")
}

fn json_text(value: &impl serde::Serialize) -> String {
    String::from_utf8(serde_json::to_vec(value).expect("json")).expect("utf-8")
}

fn must_err<T>(result: Result<T, Error>) -> Error {
    match result {
        Err(err) => err,
        Ok(_) => panic!("expected an error"),
    }
}

#[test]
fn document_validation_and_strict_json() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let display = Display::new(
        "Create events",
        Some("May send invitations"),
        Some("Calendar data"),
        Some("Invitations cannot be unsent"),
    )?;
    let account = "work-account";
    let document = Document::new(
        &operation_set(&vocabulary, &["create_event"]),
        DocumentOptions {
            account: Some(account),
            display: Some(&display),
        },
    )?;
    let encoded = json_text(&document);
    let want = r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"create_event"}],"account":"work-account","display":{"summary":"Create events","implications":"May send invitations","data_accessed":"Calendar data","irreversible":"Invitations cannot be unsent"}}"#;
    assert_eq!(encoded, want);
    let parsed = registry.parse_document(encoded.as_bytes())?;
    assert!(parsed.operation_set().equal(&document.operation_set())?);
    assert_eq!(parsed.account(), Some(account));
    let parsed_display = parsed.display().expect("display");
    assert_eq!(parsed_display.summary(), "Create events");
    assert_eq!(parsed_display.implications(), Some("May send invitations"));
    assert_eq!(parsed_display.data_accessed(), Some("Calendar data"));
    assert_eq!(
        parsed_display.irreversible(),
        Some("Invitations cannot be unsent")
    );

    let invalid = [
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{}}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{"summary":""}}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{"summary":"   "}}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{"summary":"x","extra":"no"}}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{"summary":"x","summary":"y"}}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{"Summary":"x"}}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{"summary":"x","implications":null}}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"extra":true}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"account":"a","account":"b"}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"Account":"a"}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"account":null}"#,
        r#"{"operations":[{"name":"x"}]}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#,
        r#"{"vocabulary":"https://example.test/vocabulary/named"}"#,
    ];
    for source in invalid {
        let err = registry.parse_document(source.as_bytes());
        assert!(err.is_err(), "accepted invalid document: {source}");
    }
    let missing_summary = registry
        .parse_document(br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}],"display":{}}"#)
        .map_or_else(|err| err, |_| panic!("expected an error"));
    assert!(missing_summary.to_string().contains("summary"));
    assert!(Display::new("   ", None, None, None).is_err());

    let empty_account = Document::new(
        &operation_set(&vocabulary, &["create_event"]),
        DocumentOptions {
            account: Some(""),
            display: None,
        },
    )?;
    assert!(json_text(&empty_account).contains(r#""account":"""#));
    let omitted = Document::new(
        &operation_set(&vocabulary, &["create_event"]),
        DocumentOptions::default(),
    )?;
    assert!(!json_text(&omitted).contains("account"));
    assert!(serde_json::from_slice::<Document>(encoded.as_bytes()).is_err());
    Ok(())
}

#[test]
fn document_digest_uses_exact_caller_owned_bytes() -> Result<(), Error> {
    let registry = registry(&vocabulary());
    let compact =
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"x"}]}"#;
    let mut owned = compact.to_vec();
    let spaced =
        br#"{ "vocabulary":"https://example.test/vocabulary/named", "operations":[{"name":"x"}] }"#;
    registry.parse_document(compact)?;
    registry.parse_document(spaced)?;
    assert_ne!(digest(compact), digest(spaced));
    let parsed = registry.parse_document(&owned)?;
    owned[0] = b'[';
    assert_eq!(
        parsed.operation_set().operations()?[0].json()?,
        name_json("x")
    );
    Ok(())
}

#[test]
fn reference_validation() -> Result<(), Error> {
    let digest = digest(b"exact document bytes");
    let reference = Reference::new("https://resource.example/r3/document", &digest)?;
    assert_eq!(reference.uri(), "https://resource.example/r3/document");
    assert_eq!(reference.digest(), digest);
    let query = "https://resource.example/r3/document?version=1&tenant=work";
    let query_reference = Reference::new(query, &digest)?;
    assert_eq!(query_reference.uri(), query);
    assert!(Reference::new("HTTPS://resource.example/r3/document", &digest).is_ok());

    let invalid = [
        ("", digest.as_str()),
        ("/relative", digest.as_str()),
        ("http://resource.example/r3/document", digest.as_str()),
        ("https:///document", digest.as_str()),
        ("https://user@resource.example/document", digest.as_str()),
        ("https://resource.example/document#part", digest.as_str()),
        ("https://resource.example/document", ""),
        ("https://resource.example/document", "abcd"),
        ("https://resource.example/document", &format!("{digest}=")),
        (
            "https://resource.example/document",
            &"+".repeat(digest.len()),
        ),
    ];
    for (uri, digest) in invalid {
        assert!(
            Reference::new(uri, digest).is_err(),
            "accepted invalid reference uri={uri} digest={digest}"
        );
    }
    Ok(())
}

#[test]
fn reference_rejects_context_free_json() -> Result<(), Error> {
    let digest = digest(b"document");
    let mut populated = Reference::new("https://resource.example/r3/document", &digest)?;
    assert!(serde_json::to_vec(&Reference::default()).is_err());
    assert!(serde_json::to_vec(&populated).is_err());
    assert!(serde_json::from_slice::<Reference>(b"{}").is_err());
    let before_uri = populated.uri().to_owned();
    let before_digest = populated.digest().to_owned();
    let refused = Reference::deserialize_in_place(
        &mut serde_json::Deserializer::from_slice(b"{}"),
        &mut populated,
    );
    assert!(refused.is_err());
    assert_eq!(populated.uri(), before_uri);
    assert_eq!(populated.digest(), before_digest);
    Ok(())
}

#[test]
fn grant_must_be_document_subset() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let document = Document::new(
        &operation_set(&vocabulary, &["read", "write"]),
        DocumentOptions::default(),
    )?;
    let grant = Grant::new(&granted(&vocabulary, &["write"]), &document)?;
    assert!(
        grant
            .granted_operations()
            .equal(&granted(&vocabulary, &["write"]))?
    );
    assert!(Grant::new(&granted(&vocabulary, &["delete"]), &document).is_err());
    Grant::new(&granted(&vocabulary, &[]), &document)?;
    Ok(())
}

#[test]
fn grant_parse_accepts_empty_and_subset_and_rejects_adversarial_input() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let document = Document::new(
        &operation_set(&vocabulary, &["read", "write"]),
        DocumentOptions::default(),
    )?;
    let cases = [
        (
            br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#.as_slice(),
            0,
        ),
        (
            br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"write"}]}"#
                .as_slice(),
            1,
        ),
    ];
    for (source, length) in cases {
        let grant = registry.parse_grant(source, &document)?;
        assert_eq!(grant.granted_operations().operations()?.len(), length);
        assert_eq!(serde_json::to_vec(&grant).expect("grant json"), source);
    }
    let invalid: &[&[u8]] = &[
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"delete"}]}"#,
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"read"},{"name":"read"}]}"#,
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[],"extra":true}"#,
        br#"{"operations":[]}"#,
        br#"{"vocabulary":"https://example.test/vocabulary/named"}"#,
        b"\xff",
    ];
    for source in invalid {
        assert!(registry.parse_grant(source, &document).is_err());
    }
    assert!(
        registry
            .parse_grant(
                br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#,
                &Document::default(),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn grant_unmarshal_requires_document_context() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let source = br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#;
    assert!(serde_json::from_slice::<Grant>(source).is_err());
    assert!(serde_json::to_vec(&Grant::default()).is_err());
    let document = Document::new(
        &operation_set(&vocabulary, &["read"]),
        DocumentOptions::default(),
    )?;
    let mut valid = Grant::new(&granted(&vocabulary, &["read"]), &document)?;
    let before = serde_json::to_vec(&valid).expect("grant");
    let refused = Grant::deserialize_in_place(
        &mut serde_json::Deserializer::from_slice(source),
        &mut valid,
    );
    let message = refused.expect_err("grant unmarshal").to_string();
    assert!(message.contains("parse_grant"), "{message}");
    assert_eq!(serde_json::to_vec(&valid).expect("grant"), before);
    Ok(())
}

#[test]
fn document_returned_operation_copies() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let set = operation_set(&vocabulary, &["a", "b"]);
    let mut operations = set.operations()?;
    operations[0] = operation(&vocabulary, "changed");
    assert_eq!(set.operations()?[0].json()?, name_json("a"));
    let document = Document::new(&set, DocumentOptions::default())?;
    let mut document_operations = document.operation_set().operations()?;
    document_operations[0] = operation(&vocabulary, "changed-again");
    assert_eq!(
        document.operation_set().operations()?[0].json()?,
        name_json("a")
    );
    let grant = Grant::new(&granted(&vocabulary, &["a"]), &document)?;
    let mut grant_operations = grant.granted_operations().operations()?;
    grant_operations[0] = operation(&vocabulary, "changed-grant");
    assert_eq!(
        grant.granted_operations().operations()?[0].json()?,
        name_json("a")
    );
    Ok(())
}

#[test]
fn document_parse_referenced_binds_exact_bytes() -> Result<(), Error> {
    let registry = registry(&vocabulary());
    let exact =
        br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"read"}]}"#;
    let reference = Reference::new(
        "https://resource.example/r3/document?version=1",
        digest(exact),
    )?;
    let document = registry.parse_referenced_document(&reference, exact)?;
    assert_eq!(
        document.operation_set().operations()?[0].json()?,
        name_json("read")
    );
    let mut mismatched = exact.to_vec();
    mismatched.push(b' ');
    assert!(
        registry
            .parse_referenced_document(&reference, &mismatched)
            .is_err()
    );
    let invalid = registry.parse_referenced_document(&Reference::default(), exact);
    let message = must_err(invalid).to_string();
    assert!(message.contains("reference"), "{message}");
    let empty = br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[]}"#;
    let empty_reference = Reference::new("https://resource.example/r3/invalid", digest(empty))?;
    assert!(
        registry
            .parse_referenced_document(&empty_reference, empty)
            .is_err()
    );
    Ok(())
}

#[test]
fn document_rejects_raw_invalid_utf8() {
    let registry = registry(&vocabulary());
    let mut account = br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"read"}],"account":""#.to_vec();
    account.push(0xff);
    account.extend_from_slice(br#""}"#);
    assert!(registry.parse_document(&account).is_err());
    let mut summary = br#"{"vocabulary":"https://example.test/vocabulary/named","operations":[{"name":"read"}],"display":{"summary":""#.to_vec();
    summary.push(0xff);
    summary.extend_from_slice(br#""}}"#);
    assert!(registry.parse_document(&summary).is_err());
}

#[test]
fn document_account_parity() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let with_account = Document::new(
        &operation_set(&vocabulary, &["read"]),
        DocumentOptions {
            account: Some("work"),
            display: None,
        },
    )?;
    let without = Document::new(
        &operation_set(&vocabulary, &["read"]),
        DocumentOptions::default(),
    )?;
    validate_document_account(&without, None)?;
    validate_document_account(&with_account, Some("work"))?;
    let missing_token = validate_document_account(&with_account, None).unwrap_err();
    assert_eq!(
        missing_token.to_string(),
        "document contains account but token does not"
    );
    let missing_document = validate_document_account(&without, Some("work")).unwrap_err();
    assert_eq!(
        missing_document.to_string(),
        "token contains account but document does not"
    );
    let differs = validate_document_account(&with_account, Some("other")).unwrap_err();
    assert_eq!(
        differs.to_string(),
        "token and document account values differ"
    );
    Ok(())
}

#[test]
fn authorization_requires_disjoint_subsets() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let document = Document::new(
        &operation_set(&vocabulary, &["read", "write"]),
        DocumentOptions::default(),
    )?;
    let authorization = Authorization::new(
        &granted(&vocabulary, &["read"]),
        &granted(&vocabulary, &["write"]),
        &document,
    )?;
    assert!(authorization.is_proven());
    let mut direct = authorization.granted_operations().operations()?;
    direct[0] = operation(&vocabulary, "changed");
    assert_eq!(
        authorization.granted_operations().operations()?[0].json()?,
        name_json("read")
    );
    assert!(
        Authorization::new(
            &granted(&vocabulary, &["read"]),
            &granted(&vocabulary, &["read"]),
            &document,
        )
        .is_err()
    );
    assert!(
        Authorization::new(
            &granted(&vocabulary, &["delete"]),
            &granted(&vocabulary, &[]),
            &document,
        )
        .is_err()
    );
    Authorization::new(
        &granted(&vocabulary, &[]),
        &granted(&vocabulary, &[]),
        &document,
    )?;
    Ok(())
}

#[test]
fn proposal_json_round_trip_and_copy_safety() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let operation = operation(&vocabulary, "send_email");
    let to = Parameter::inline(br#""mom@example.com""#)?;
    let body_bytes = b"Hi Mom, are you free for dinner?";
    let body = Parameter::from_exact_bytes(
        body_bytes,
        Some("Hi Mom, are you free\u{2026}"),
        Some("text/plain"),
    )?;
    let parameters = Parameters::new([("to".to_owned(), to), ("body".to_owned(), body)])?;
    let display = Display::new("Send an email as you", None, None, None)?;
    let proposal_display = ProposalDisplay::new(&display, Some("## Action\nSend an email"))?;
    let proposal = Proposal::new(
        &operation,
        &parameters,
        ProposalOptions {
            account: Some("personal"),
            result: None,
            display: Some(&proposal_display),
        },
    )?;
    let encoded = json_text(&proposal);
    let want = format!(
        r###"{{"vocabulary":"https://example.test/vocabulary/named","operations":[{{"name":"send_email"}}],"parameters":{{"body":{{"s256":"{}","excerpt":"Hi Mom, are you free{}","media_type":"text/plain"}},"to":"mom@example.com"}},"account":"personal","display":{{"summary":"Send an email as you","detail":"## Action\nSend an email"}}}}"###,
        digest(body_bytes),
        "\u{2026}"
    );
    assert_eq!(encoded, want);
    let parsed = registry.parse_proposal(encoded.as_bytes())?;
    assert_eq!(parsed.operation().json()?, name_json("send_email"));
    assert_eq!(parsed.account(), Some("personal"));
    let parsed_display = parsed.display().expect("display");
    assert_eq!(parsed_display.detail(), Some("## Action\nSend an email"));
    assert_eq!(parsed_display.summary(), "Send an email as you");
    let mut inline = parsed
        .parameters()
        .get("to")
        .expect("to")
        .inline_json()
        .expect("inline");
    assert_eq!(inline, br#""mom@example.com""#);
    inline[0] = b'x';
    let again = parsed
        .parameters()
        .get("to")
        .expect("to")
        .inline_json()
        .expect("inline");
    assert_eq!(again, br#""mom@example.com""#);
    let digest_parameter = parsed
        .parameters()
        .get("body")
        .expect("body")
        .parameter_digest()
        .expect("digest");
    assert_eq!(digest_parameter.s256(), digest(body_bytes));
    assert_eq!(
        digest_parameter.excerpt(),
        Some("Hi Mom, are you free\u{2026}")
    );
    assert_eq!(digest_parameter.media_type(), Some("text/plain"));
    assert!(serde_json::from_slice::<Proposal>(encoded.as_bytes()).is_err());
    Ok(())
}

#[test]
fn proposal_parameter_matching_uses_structural_json_and_exact_digest_bytes() -> Result<(), Error> {
    let inline = Parameter::inline(br#"{"count":1,"nested":{"a":true,"b":[1,2]}}"#)?;
    for equivalent in [
        br#" { "nested" : { "b" : [1.0, 2e0], "a" : true }, "count" : 1.00 } "#.as_slice(),
        br#"{"nested":{"a":true,"b":[1,2]},"count":1}"#.as_slice(),
    ] {
        let presented = PresentedParameter::inline(equivalent)?;
        let one = Parameters::new([("value".to_owned(), inline.clone())])?;
        assert!(
            one.matches(&BTreeMap::from([("value".to_owned(), presented)]))?,
            "{}",
            String::from_utf8_lossy(equivalent)
        );
    }
    for different in [
        br#"{"count":2,"nested":{"a":true,"b":[1,2]}}"#.as_slice(),
        br#"{"count":1,"nested":{"a":true,"b":[2,1]}}"#.as_slice(),
    ] {
        let presented = PresentedParameter::inline(different)?;
        let one = Parameters::new([("value".to_owned(), inline.clone())])?;
        assert!(
            !one.matches(&BTreeMap::from([("value".to_owned(), presented)]))?,
            "{}",
            String::from_utf8_lossy(different)
        );
    }
    assert!(PresentedParameter::inline(br#"{"count":1,"count":1}"#).is_err());

    let exact = [0u8, 1, 2, 3, 255];
    let digested = Parameter::from_exact_bytes(&exact, None, Some("application/octet-stream"))?;
    let digest_set = Parameters::new([("value".to_owned(), digested.clone())])?;
    assert!(digest_set.matches(&BTreeMap::from([(
        "value".to_owned(),
        PresentedParameter::exact_bytes(&exact)
    )]))?);
    assert!(!digest_set.matches(&BTreeMap::from([(
        "value".to_owned(),
        PresentedParameter::exact_bytes(&[0, 1, 2, 3])
    )]))?);

    let parameters = Parameters::new([
        ("inline".to_owned(), inline),
        ("binary".to_owned(), digested),
    ])?;
    let presented_inline =
        PresentedParameter::inline(br#"{"nested":{"b":[1,2],"a":true},"count":1}"#)?;
    let mut presented = BTreeMap::from([
        ("inline".to_owned(), presented_inline),
        ("binary".to_owned(), PresentedParameter::exact_bytes(&exact)),
    ]);
    assert!(parameters.matches(&presented)?);
    let changed_inline =
        PresentedParameter::inline(br#"{"count":2,"nested":{"a":true,"b":[1,2]}}"#)?;
    let extra_inline = PresentedParameter::inline(b"true")?;
    let inline_value = presented.get("inline").expect("inline").clone();
    let binary_value = presented.get("binary").expect("binary").clone();
    let mismatches = [
        BTreeMap::from([("inline".to_owned(), inline_value.clone())]),
        BTreeMap::from([
            ("inline".to_owned(), inline_value.clone()),
            ("binary".to_owned(), binary_value.clone()),
            ("other".to_owned(), extra_inline.clone()),
        ]),
        BTreeMap::from([
            ("Inline".to_owned(), inline_value.clone()),
            ("binary".to_owned(), binary_value.clone()),
        ]),
        BTreeMap::from([
            ("inline".to_owned(), changed_inline),
            ("binary".to_owned(), binary_value.clone()),
        ]),
        BTreeMap::from([
            (
                "inline".to_owned(),
                PresentedParameter::exact_bytes(br#"{"nested":{"b":[1,2],"a":true},"count":1}"#),
            ),
            ("binary".to_owned(), binary_value),
        ]),
    ];
    for changed in mismatches {
        assert!(!parameters.matches(&changed)?);
    }
    presented.clear();
    let empty = Parameters::new([])?;
    assert!(empty.matches(&BTreeMap::new())?);
    assert!(!empty.matches(&BTreeMap::from([("extra".to_owned(), extra_inline)]))?);
    Ok(())
}

#[test]
fn proposal_rejects_ambiguous_or_invalid_shapes() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let valid_digest = digest(b"value");
    let tests = [
        format!(r#"{{"vocabulary":"{NAMED}","parameters":{{}}}}"#),
        format!(r#"{{"vocabulary":"{NAMED}","operations":[],"parameters":{{}}}}"#),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}},{{"name":"b"}}],"parameters":{{}}}}"#
        ),
        format!(r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}]}}"#),
        format!(r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":[]}}"#),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":1,"x":1}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":{{"a":1,"a":2}}}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":1,"\u0078":2}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a","name":"b"}}],"parameters":{{}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":{{"s256":"{valid_digest}","s256":"{valid_digest}"}}}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"display":{{"summary":"a","detail":"one","detail":"two"}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":{{"s256":"{valid_digest}","other":true}}}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":{{"s256":"short"}}}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":{{"s256":"{valid_digest}","excerpt":1}}}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"extra":true}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"parameters":{{}}}}"#
        ),
    ];
    for (index, source) in tests.iter().enumerate() {
        assert!(
            registry.parse_proposal(source.as_bytes()).is_err(),
            "accepted invalid proposal {index}: {source}"
        );
    }
    let proposal_json =
        format!(r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}}}}"#);
    assert!(registry.parse_document(proposal_json.as_bytes()).is_err());

    let operation = operation(&vocabulary, "a");
    assert!(
        Proposal::new(
            &operation,
            &Parameters::default(),
            ProposalOptions::default()
        )
        .is_err()
    );
    assert!(Parameter::inline(br#"{"x":1,"x":2}"#).is_err());
    let bounded = Parameter::inline(b"1e1000000")?;
    let presented_bounded = PresentedParameter::inline(b"10e999999")?;
    let bounded_set = Parameters::new([("value".to_owned(), bounded)])?;
    assert!(bounded_set.matches(&BTreeMap::from([("value".to_owned(), presented_bounded)]))?);
    let numeric = [
        ("9007199254740992", "9007199254740993", false),
        ("1.0000000000000000000000000001", "1", false),
        ("1e1000000", "1e999999", false),
        ("-0", "0e999999999999999999", true),
    ];
    for (approved_text, presented_text, matches) in numeric {
        let approved = Parameter::inline(approved_text.as_bytes())?;
        let actual = PresentedParameter::inline(presented_text.as_bytes())?;
        let set = Parameters::new([("value".to_owned(), approved)])?;
        assert_eq!(
            set.matches(&BTreeMap::from([("value".to_owned(), actual)]))?,
            matches,
            "{approved_text} vs {presented_text}"
        );
    }
    let approved = Parameter::inline(br#""a""#)?;
    let actual = PresentedParameter::inline(br#""\u0061""#)?;
    let set = Parameters::new([("value".to_owned(), approved)])?;
    assert!(set.matches(&BTreeMap::from([("value".to_owned(), actual)]))?);

    assert!(
        Parameter::from_digest(
            valid_digest,
            Some("x".repeat(4097).as_str()),
            Some("text/plain")
        )
        .is_ok()
    );
    let excerpt_only = registry.parse_proposal(
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"x":{{"excerpt":"ordinary application value"}}}}}}"#
        )
        .as_bytes(),
    )?;
    assert!(
        excerpt_only
            .parameters()
            .get("x")
            .expect("x")
            .inline_json()
            .is_some()
    );
    for ordinary in [
        br#"{"media_type":"ordinary"}"#.as_slice(),
        br#"{"S256":"ordinary"}"#.as_slice(),
        br#"{"nested":{"s256":"ordinary"}}"#.as_slice(),
    ] {
        let inline = Parameter::inline(ordinary)?;
        assert!(
            inline.inline_json().is_some(),
            "{}",
            String::from_utf8_lossy(ordinary)
        );
    }
    assert!(Parameter::inline(br#"{"s256":"ordinary","mode":"application"}"#).is_err());
    for name in ["", " x "] {
        let encoded_name = serde_json::to_string(name).expect("name");
        let source = format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{{encoded_name}:1}}}}"#
        );
        let proposal = registry.parse_proposal(source.as_bytes())?;
        assert!(proposal.parameters().get(name).is_some(), "{name}");
    }
    Ok(())
}

#[test]
fn proposal_account_parity_and_referenced_digest() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let operation = operation(&vocabulary, "read");
    let parameters = Parameters::new([])?;
    let with_account = Proposal::new(
        &operation,
        &parameters,
        ProposalOptions {
            account: Some("personal"),
            result: None,
            display: None,
        },
    )?;
    let without = Proposal::new(&operation, &parameters, ProposalOptions::default())?;
    validate_proposal_account(&without, None)?;
    validate_proposal_account(&with_account, Some("personal"))?;
    assert_eq!(
        validate_proposal_account(&with_account, None)
            .unwrap_err()
            .to_string(),
        "proposal contains account but token does not"
    );
    assert_eq!(
        validate_proposal_account(&without, Some("personal"))
            .unwrap_err()
            .to_string(),
        "token contains account but proposal does not"
    );
    assert_eq!(
        validate_proposal_account(&with_account, Some("other"))
            .unwrap_err()
            .to_string(),
        "token and proposal account values differ"
    );

    let exact = serde_json::to_vec(&without).expect("proposal");
    let reference = Reference::new("https://resource.example/r3/proposal", digest(&exact))?;
    registry.parse_referenced_proposal(&reference, &exact)?;
    let mut mismatched = exact.clone();
    mismatched.push(b' ');
    assert!(
        registry
            .parse_referenced_proposal(&reference, &mismatched)
            .is_err()
    );
    let invalid = registry.parse_referenced_proposal(&Reference::default(), &exact);
    assert!(must_err(invalid).to_string().contains("reference"));
    Ok(())
}

/// `levels` objects and arrays, alternating from the outside in, around `leaf`.
fn nested_json(levels: usize, leaf: &str) -> String {
    let mut text = String::new();
    for level in 0..levels {
        text.push_str(if level % 2 == 0 { r#"{"a":"# } else { "[" });
    }
    text.push_str(leaf);
    for level in (0..levels).rev() {
        text.push(if level % 2 == 0 { '}' } else { ']' });
    }
    text
}

fn document_with_operation(operation: &str) -> String {
    format!(r#"{{"vocabulary":"{NAMED}","operations":[{operation}]}}"#)
}

fn proposal_with_parameter(value: &str) -> String {
    format!(
        r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"p":{value}}}}}"#
    )
}

fn refused_for_depth<T>(result: Result<T, Error>) -> bool {
    result.is_err_and(|err| {
        err.to_string()
            .contains("JSON nesting exceeds the depth limit")
    })
}

#[test]
fn json_nesting_limit_matches_serde_json_default() -> Result<(), Error> {
    for levels in [127, 128] {
        let arrays = format!("{}{}", "[".repeat(levels), "]".repeat(levels));
        for text in [nested_json(levels, "1"), arrays] {
            let baseline = serde_json::from_str::<serde_json::Value>(&text).is_ok();
            assert_eq!(baseline, levels == 127, "serde_json at {levels} levels");
            if baseline {
                parse_json(text.as_bytes())?;
            } else {
                assert!(refused_for_depth(parse_json(text.as_bytes())), "{levels}");
            }
        }
    }
    Ok(())
}

#[test]
fn inline_parameters_compare_at_the_depth_limit_and_refuse_past_it() -> Result<(), Error> {
    let limit = nested_json(127, "1");
    let inline = Parameter::inline(limit.as_bytes())?;
    assert_eq!(inline.inline_json(), Some(limit.into_bytes()));
    let one = Parameters::new([("value".to_owned(), inline)])?;
    let same = PresentedParameter::inline(nested_json(127, "1.0").as_bytes())?;
    assert!(one.matches(&BTreeMap::from([("value".to_owned(), same)]))?);
    let changed = PresentedParameter::inline(nested_json(127, "2").as_bytes())?;
    assert!(!one.matches(&BTreeMap::from([("value".to_owned(), changed)]))?);

    let past = nested_json(128, "1");
    assert!(refused_for_depth(Parameter::inline(past.as_bytes())));
    assert!(refused_for_depth(PresentedParameter::inline(
        past.as_bytes()
    )));
    Ok(())
}

#[test]
fn documents_and_proposals_count_depth_from_the_outermost_object() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let below = nested_json(125, "1");
    let at = nested_json(126, "1");

    let document = registry.parse_document(document_with_operation(&below).as_bytes());
    assert!(document.is_err() && !refused_for_depth(document));
    let document = registry.parse_document(document_with_operation(&at).as_bytes());
    assert!(refused_for_depth(document));

    let proposal = registry.parse_proposal(proposal_with_parameter(&below).as_bytes())?;
    let parameter = proposal.parameters().get("p").expect("parameter");
    assert_eq!(parameter.inline_json(), Some(below.into_bytes()));
    let proposal = registry.parse_proposal(proposal_with_parameter(&at).as_bytes());
    assert!(refused_for_depth(proposal));
    Ok(())
}

#[test]
fn very_deep_json_is_refused_through_public_entry_points() {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let deep = nested_json(1_000_000, "1");
    let document = document_with_operation(&deep);
    let proposal = proposal_with_parameter(&deep);
    assert!(refused_for_depth(
        registry.parse_document(document.as_bytes())
    ));
    assert!(refused_for_depth(
        registry.parse_proposal(proposal.as_bytes())
    ));
    assert!(refused_for_depth(Parameter::inline(deep.as_bytes())));
    assert!(refused_for_depth(PresentedParameter::inline(
        deep.as_bytes()
    )));
}

/// `{"k00000":0,...}` with members in `order`.
fn wide_members(order: impl IntoIterator<Item = usize>) -> String {
    let members: Vec<String> = order
        .into_iter()
        .map(|index| format!(r#""k{index:05}":{index}"#))
        .collect();
    format!("{{{}}}", members.join(","))
}

fn proposal_with_parameters(parameters: &str) -> String {
    format!(r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{parameters}}}"#)
}

fn presented_value(value: &str) -> Result<BTreeMap<String, PresentedParameter>, Error> {
    Ok(BTreeMap::from([(
        "value".to_owned(),
        PresentedParameter::inline(value.as_bytes())?,
    )]))
}

#[test]
fn wide_parameter_objects_match_and_refuse_duplicates_in_n_log_n() -> Result<(), Error> {
    const WIDTH_LOG2: u32 = 14;
    const WIDTH: usize = 1 << WIDTH_LOG2;
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let approved = wide_members(0..WIDTH);
    let reversed = wide_members((0..WIDTH).rev());
    let one = Parameters::new([("value".to_owned(), Parameter::inline(approved.as_bytes())?)])?;
    let reordered = presented_value(&reversed)?;

    take_name_comparisons();
    assert!(one.matches(&reordered)?);
    let comparisons = take_name_comparisons();
    // `matches` parses each side again and compares once. A pairwise scan
    // needs WIDTH * (WIDTH - 1) / 2 (over 2^27) comparisons for one parse.
    assert!(
        comparisons <= 64 * WIDTH as u64 * u64::from(WIDTH_LOG2),
        "{comparisons} name comparisons for {WIDTH} members"
    );

    let changed = reversed.replacen(r#""k00000":0"#, r#""k00000":1"#, 1);
    assert!(!one.matches(&presented_value(&changed)?)?);
    let respelled = reversed.replacen(r#""k00000":0"#, r#""k00000":-0.0e9"#, 1);
    assert!(one.matches(&presented_value(&respelled)?)?);
    let renamed = reversed.replacen(r#""k00000":0"#, r#""k0000":0"#, 1);
    assert!(!one.matches(&presented_value(&renamed)?)?);

    // A repeat of the last-read name, placed at the end, is refused at every entry.
    let repeated = format!(r#"{},"k00000":0}}"#, &reversed[..reversed.len() - 1]);
    for result in [
        Parameter::inline(repeated.as_bytes()).map(|_| ()),
        PresentedParameter::inline(repeated.as_bytes()).map(|_| ()),
        registry
            .parse_proposal(proposal_with_parameter(&repeated).as_bytes())
            .map(|_| ()),
        registry
            .parse_proposal(proposal_with_parameters(&repeated).as_bytes())
            .map(|_| ()),
    ] {
        let err = must_err(result);
        assert!(
            err.to_string().contains(r#"duplicate member "k00000""#),
            "{err}"
        );
    }

    // A wide parameters object keeps every name.
    let proposal = registry.parse_proposal(proposal_with_parameters(&reversed).as_bytes())?;
    let names = proposal.parameters().names();
    assert_eq!(names.len(), WIDTH);
    assert_eq!(names[0], "k00000");
    assert_eq!(names[WIDTH - 1], format!("k{:05}", WIDTH - 1));
    Ok(())
}

#[test]
fn proposal_result_marks_release_gating_and_round_trips() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    // The draft's release-gating example, in this test's named vocabulary.
    let source = format!(
        r###"{{"vocabulary":"{NAMED}","operations":[{{"name":"runQuery"}}],"parameters":{{"query":"SELECT * FROM employees WHERE department = 'Engineering'"}},"result":{{"records":214,"contains":["national_id","compensation","home_address"]}},"display":{{"summary":"Release the result of a query over employee records","data_accessed":"214 employee records, including national identifiers, compensation, and home addresses","detail":"## Action\nThis query has already run. What you are approving is release of its result to the agent."}}}}"###
    );
    let proposal = registry.parse_proposal(source.as_bytes())?;
    let held = proposal.result().expect("result");
    assert_eq!(
        held.json(),
        br#"{"contains":["national_id","compensation","home_address"],"records":214}"#
    );
    let encoded = json_text(&proposal);
    let want = source.replacen(
        r#""result":{"records":214,"contains":["national_id","compensation","home_address"]}"#,
        r#""result":{"contains":["national_id","compensation","home_address"],"records":214}"#,
        1,
    );
    assert_eq!(encoded, want);
    let again = registry.parse_proposal(encoded.as_bytes())?;
    assert_eq!(json_text(&again), encoded);
    let reference = Reference::new(
        "https://resource.example/r3/release",
        digest(encoded.as_bytes()),
    )?;
    assert!(
        registry
            .parse_referenced_proposal(&reference, encoded.as_bytes())?
            .result()
            .is_some()
    );

    // Absent means approval for execution; present and empty is still present.
    let without = registry.parse_proposal(proposal_with_parameters("{}").as_bytes())?;
    assert!(without.result().is_none());
    assert!(!json_text(&without).contains("result"));
    let empty_source =
        format!(r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"result":{{}}}}"#);
    let empty = registry.parse_proposal(empty_source.as_bytes())?;
    assert_eq!(empty.result().expect("empty result").json(), b"{}");
    assert_eq!(json_text(&empty), empty_source);

    // Construction sorts names, keeps number spelling, and serializes `result` after `parameters`.
    let built_result =
        ProposalResult::new(br#" { "rows" : 2.140e2 , "nested" : { "b" : 1 , "a" : 0 } } "#)?;
    assert_eq!(
        built_result.json(),
        br#"{"nested":{"a":0,"b":1},"rows":2.140e2}"#
    );
    let built = Proposal::new(
        &operation(&vocabulary, "runQuery"),
        &Parameters::new([])?,
        ProposalOptions {
            account: Some(""),
            result: Some(&built_result),
            display: None,
        },
    )?;
    let built_json = json_text(&built);
    assert_eq!(
        built_json,
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"runQuery"}}],"parameters":{{}},"result":{{"nested":{{"a":0,"b":1}},"rows":2.140e2}},"account":""}}"#
        )
    );
    let reparsed = registry.parse_proposal(built_json.as_bytes())?;
    assert_eq!(
        reparsed.result().expect("result").json(),
        built_result.json()
    );

    for value in ["null", "[]", r#""ran""#, "214", "true", r#"{"a":1,"a":2}"#] {
        assert!(ProposalResult::new(value.as_bytes()).is_err(), "{value}");
        let source = format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"result":{value}}}"#
        );
        assert!(registry.parse_proposal(source.as_bytes()).is_err(), "{source}");
    }
    for value in ["", "{", "{} {}", r#"{"a":1}x"#] {
        assert!(ProposalResult::new(value.as_bytes()).is_err(), "{value}");
    }
    let refused = [
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"result":{{}},"result":{{}}}}"#
        ),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"Result":{{}}}}"#
        ),
        format!(r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"result":{{}}}}"#),
        format!(r#"{{"vocabulary":"{NAMED}","operations":[],"parameters":{{}},"result":{{}}}}"#),
    ];
    for source in refused {
        assert!(registry.parse_proposal(source.as_bytes()).is_err(), "{source}");
    }
    // `result` belongs to proposals, not documents.
    let document = format!(r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"result":{{}}}}"#);
    assert!(registry.parse_document(document.as_bytes()).is_err());
    Ok(())
}

#[test]
fn optional_strings_keep_absent_and_present_empty_apart() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let full = format!(
        r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"x"}}],"display":{{"summary":"Read","implications":"","data_accessed":"","irreversible":""}}}}"#
    );
    let document = registry.parse_document(full.as_bytes())?;
    let display = document.display().expect("display");
    assert_eq!(
        (
            display.implications(),
            display.data_accessed(),
            display.irreversible()
        ),
        (Some(""), Some(""), Some(""))
    );
    // A host that re-serializes a parsed document gets the signed bytes back.
    let encoded = json_text(&document);
    assert_eq!(encoded, full);
    assert_eq!(digest(encoded.as_bytes()), digest(full.as_bytes()));

    let sparse = format!(
        r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"x"}}],"display":{{"summary":"Read","data_accessed":""}}}}"#
    );
    let document = registry.parse_document(sparse.as_bytes())?;
    let display = document.display().expect("display");
    assert_eq!(
        (
            display.implications(),
            display.data_accessed(),
            display.irreversible()
        ),
        (None, Some(""), None)
    );
    assert_eq!(json_text(&document), sparse);

    let built = Display::new("Read", Some(""), None, Some(""))?;
    let document = Document::new(
        &operation_set(&vocabulary, &["x"]),
        DocumentOptions {
            account: None,
            display: Some(&built),
        },
    )?;
    assert_eq!(
        json_text(&document),
        format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"x"}}],"display":{{"summary":"Read","implications":"","irreversible":""}}}}"#
        )
    );
    let absent = Display::new("Read", None, None, None)?;
    assert_eq!(json_text(&absent), r#"{"summary":"Read"}"#);

    let s256 = digest(b"body");
    let proposal_source = format!(
        r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{"body":{{"s256":"{s256}","excerpt":"","media_type":""}},"note":{{"s256":"{s256}"}}}},"display":{{"summary":"Send","implications":"","detail":""}}}}"#
    );
    let proposal = registry.parse_proposal(proposal_source.as_bytes())?;
    let parameters = proposal.parameters();
    let body = parameters
        .get("body")
        .and_then(|parameter| parameter.parameter_digest())
        .expect("body digest");
    assert_eq!((body.excerpt(), body.media_type()), (Some(""), Some("")));
    let note = parameters
        .get("note")
        .and_then(|parameter| parameter.parameter_digest())
        .expect("note digest");
    assert_eq!((note.excerpt(), note.media_type()), (None, None));
    let display = proposal.display().expect("display");
    assert_eq!(
        (
            display.implications(),
            display.data_accessed(),
            display.detail()
        ),
        (Some(""), None, Some(""))
    );
    assert_eq!(json_text(&proposal), proposal_source);
    let reference = Reference::new(
        "https://resource.example/r3/proposal",
        digest(proposal_source.as_bytes()),
    )?;
    let referenced = registry.parse_referenced_proposal(&reference, proposal_source.as_bytes())?;
    assert_eq!(json_text(&referenced), proposal_source);

    let built = Parameter::from_digest(s256.clone(), Some(""), None)?;
    let built_digest = built.parameter_digest().expect("digest");
    assert_eq!(
        (built_digest.excerpt(), built_digest.media_type()),
        (Some(""), None)
    );
    let built_set = Parameters::new([("body".to_owned(), built)])?;
    assert_eq!(
        json_text(&built_set),
        format!(r#"{{"body":{{"s256":"{s256}","excerpt":""}}}}"#)
    );
    let typed = Parameter::from_exact_bytes(b"body", None, Some(""))?;
    assert_eq!(
        typed.parameter_digest().expect("digest").media_type(),
        Some("")
    );
    let with_detail = ProposalDisplay::new(&absent, Some(""))?;
    assert_eq!(with_detail.detail(), Some(""));
    assert_eq!(ProposalDisplay::new(&absent, None)?.detail(), None);

    // Required members and string types are still enforced.
    for display in [
        r#"{"summary":"","implications":""}"#,
        r#"{"implications":""}"#,
        r#"{"summary":"Read","implications":null}"#,
        r#"{"summary":"Read","detail":""}"#,
    ] {
        let source = format!(
            r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"x"}}],"display":{display}}}"#
        );
        assert!(registry.parse_document(source.as_bytes()).is_err(), "{source}");
    }
    for value in [
        format!(r#"{{"s256":"{s256}","media_type":" text/plain"}}"#),
        format!(r#"{{"s256":"{s256}","excerpt":null}}"#),
        format!(r#"{{"s256":"{s256}","media_type":null}}"#),
        r#"{"s256":"short","excerpt":""}"#.to_owned(),
    ] {
        let source = proposal_with_parameter(&value);
        assert!(registry.parse_proposal(source.as_bytes()).is_err(), "{source}");
    }
    let detail_null = format!(
        r#"{{"vocabulary":"{NAMED}","operations":[{{"name":"a"}}],"parameters":{{}},"display":{{"summary":"Send","detail":null}}}}"#
    );
    assert!(registry.parse_proposal(detail_null.as_bytes()).is_err());
    assert!(Display::new(" ", Some("x"), None, None).is_err());
    Ok(())
}

#[test]
fn digest_media_types_follow_rfc_9110() -> Result<(), Error> {
    let vocabulary = vocabulary();
    let registry = registry(&vocabulary);
    let s256 = digest(b"body");
    let valid = [
        "text/plain",
        "Text/Plain",
        "application/vnd.example+json",
        "text/plain;charset=utf-8",
        "text/plain; charset=\"utf-8\"",
        "text/plain ;\tcharset=utf-8 ; format=flowed",
        "text/plain;x=\"\"",
        "text/plain;x=\"\";y=z",
        "text/plain;x=\"a;b\";y=c",
        "text/plain;x=\"a\\\"b\"",
        "text/plain;x=\"a\\\\\"",
        "text/plain;x=\"caf\u{e9} \t!#\"",
        "text/plain;",
        "text/plain;;x=y",
    ];
    for media_type in valid {
        let built = Parameter::from_digest(s256.clone(), None, Some(media_type))?;
        assert_eq!(
            built.parameter_digest().expect("digest").media_type(),
            Some(media_type)
        );
        let encoded = serde_json::to_string(media_type).expect("media type");
        let source =
            proposal_with_parameter(&format!(r#"{{"s256":"{s256}","media_type":{encoded}}}"#));
        let proposal = registry.parse_proposal(source.as_bytes())?;
        let again = registry.parse_proposal(json_text(&proposal).as_bytes())?;
        for parsed in [proposal, again] {
            let digest_value = parsed
                .parameters()
                .get("p")
                .and_then(|parameter| parameter.parameter_digest())
                .expect("digest");
            assert_eq!(digest_value.media_type(), Some(media_type), "{source}");
        }
    }
    let invalid = [
        "text",
        "text/",
        "/plain",
        "text/plain/x",
        "text /plain",
        "text/ plain",
        "text/{plain}",
        "text/pl\u{e9}in",
        "text/plain x",
        "text/plain;x",
        "text/plain;x=",
        "text/plain;=y",
        "text/plain;x =y",
        "text/plain;x= y",
        "text/plain;x=a b",
        "text/plain;x=a\"b\"",
        "text/plain;x=\"a\"b\"",
        "text/plain;x=\"a\"\"b\"",
        "text/plain;x=\"a",
        "text/plain;x=\"a\\\"",
        "text/plain;x=\"a\\",
        "text/plain;x=\"\u{7f}\"",
        "text/plain;x=\"\u{1}\"",
        "text/plain;x=\"a\\\u{1}\"",
        "text/plain;x=a;X=b",
        "text/plain;x=a;x=\"a\"",
        " text/plain",
        "text/plain ",
    ];
    for media_type in invalid {
        let err = must_err(Parameter::from_digest(
            s256.clone(),
            None,
            Some(media_type),
        ));
        assert!(err.to_string().contains("media_type"), "{media_type}: {err}");
        let encoded = serde_json::to_string(media_type).expect("media type");
        let source =
            proposal_with_parameter(&format!(r#"{{"s256":"{s256}","media_type":{encoded}}}"#));
        assert!(
            registry.parse_proposal(source.as_bytes()).is_err(),
            "{source}"
        );
    }
    Ok(())
}
