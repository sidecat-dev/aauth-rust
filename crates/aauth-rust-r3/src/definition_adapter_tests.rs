//! Checks for the four JSON definition adapters, through the public API.
//!
//! Fixtures are ported from Go `r3/vocab/{mcp,openapi,asyncapi,graphql}/
//! definition_test.go` and `r3/vocabtest/definition_contract_test.go` at
//! 0225f3f4. Checks marked "Rust" cover refusals this port adds or a Go
//! fixture this port reads differently.

use crate::{
    AccessMode, AsyncApiCodec, AsyncApiDocumentSource, AuthoritativeSnapshot, DefinitionCheckError,
    DefinitionCodec, DefinitionError, DefinitionErrorKind, DefinitionMaterial, DefinitionParser,
    DefinitionRegistration, DefinitionRegistry, Error, GraphQlCodec, GraphQlIntrospectionSource,
    McpCodec, OpenApiCodec, OpenApiDocumentSource, Operation, OperationSet, ToolsListPage,
    ToolsListSnapshot, Vocabulary, VocabularyUri, digest,
};

const MCP_ENDPOINT: &str = "https://resource.example/mcp";
const OPENAPI_ENDPOINT: &str = "https://resource.example/openapi.yaml";
const ASYNCAPI_ENDPOINT: &str = "https://resource.example/asyncapi.json";
const GRAPHQL_ENDPOINT: &str = "https://resource.example/graphql";

// Independent public-API counterexamples reproduced against Go 0225f3f4 and
// the pre-repair Rust baseline on build3. These are code controls; the retained
// consumer observations are separate evidence.
#[test]
fn mcp_definition_closes_referenced_annotation_targets() {
    for (schema, kind) in [
        (
            r##"{"type":"object","$ref":"#/hidden","hidden":{"$ref":"https://outside.example/schema"}}"##,
            UnresolvedDependency,
        ),
        (
            r##"{"type":"object","$ref":"#/hidden","hidden":{"$ref":"#/second"},"second":{"$ref":"https://outside.example/schema"}}"##,
            UnresolvedDependency,
        ),
        (
            r##"{"type":"object","$ref":"#/hidden","hidden":{"type":17}}"##,
            InvalidSource,
        ),
        (
            r##"{"type":"object","$ref":"#/hidden","hidden":{"$ref":"#/missing"}}"##,
            InvalidSource,
        ),
    ] {
        let body = format!(r#"{{"tools":[{{"name":"read","inputSchema":{schema}}}]}}"#);
        assert_refusal(
            McpCodec::parse_definition(MCP_ENDPOINT, &mcp_snapshot(&[(None, &body)])),
            kind,
            McpCodec::URI,
        );
    }
}

#[test]
fn mcp_definition_refuses_ambiguous_schema_bindings() {
    for schema in [
        r##"{"type":"object","properties":{"x":{"$ref":"#same"}},"$defs":{"a":{"$anchor":"same","type":"string"},"b":{"$anchor":"same","type":"number"}}}"##,
        r##"{"type":"object","properties":{"x":{"$ref":"urn:shared"}},"$defs":{"a":{"$id":"urn:shared","type":"string"},"b":{"$id":"urn:shared","type":"number"}}}"##,
        r##"{"type":"object","properties":{"x":{"$ref":"#same"}},"$defs":{"a":{"$anchor":"same","type":"string"},"b":{"$dynamicAnchor":"same","type":"number"}}}"##,
        r##"{"type":"object","$defs":{"a":{"$id":"urn:aauth:mcp:tool-input-schema","type":"string"}}}"##,
    ] {
        let body = format!(r#"{{"tools":[{{"name":"read","inputSchema":{schema}}}]}}"#);
        assert_refusal(
            McpCodec::parse_definition(MCP_ENDPOINT, &mcp_snapshot(&[(None, &body)])),
            InvalidSource,
            McpCodec::URI,
        );
    }
}

#[test]
fn mcp_definition_preserves_recursive_and_unreferenced_sources() {
    for schema in [
        r##"{"type":"object","properties":{"child":{"$ref":"#"}}}"##,
        r##"{"type":"object","x-vendor":{"$ref":"https://outside.example/annotation"}}"##,
        r##"{"type":"object","$ref":"#/hidden","hidden":{"$ref":"#/hidden"}}"##,
        r##"{"type":"object","$anchor":"same","$dynamicAnchor":"same","properties":{"child":{"$ref":"#same"}}}"##,
        r##"{"type":"object","$defs":{"nested":{"$id":"https://schemas.example/nested","$defs":{"leaf":{"$id":"leaf","type":"string"}},"hidden":{"$ref":"leaf"}}},"properties":{"child":{"$ref":"#/$defs/nested/hidden"}}}"##,
    ] {
        let body = format!(r#"{{"tools":[{{"name":"read","inputSchema":{schema}}}]}}"#);
        let snapshot = McpCodec::parse_definition(MCP_ENDPOINT, &mcp_snapshot(&[(None, &body)]))
            .expect("self-contained schema");
        snapshot
            .validate_defined(&set_of(&mcp_tool("read")))
            .expect("defined read operation");
    }
}

#[test]
fn openapi_definition_refuses_conflicting_route_templates() {
    let source = br#"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/pets/{id}":{"get":{"operationId":"readPet","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},"/pets/{name}":{"get":{"operationId":"archivePet","parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}"#;
    assert_refusal(
        OpenApiCodec::parse_definition(OPENAPI_ENDPOINT, &OpenApiDocumentSource::new(source)),
        InvalidSource,
        OpenApiCodec::URI,
    );
    let distinct = br#"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/pets/me":{"get":{"operationId":"self","responses":{"200":{"description":"ok"}}}},"/pets/{id}":{"get":{"operationId":"readPet","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}"#;
    OpenApiCodec::parse_definition(OPENAPI_ENDPOINT, &OpenApiDocumentSource::new(distinct))
        .expect("concrete and templated routes remain distinct");
}

use DefinitionErrorKind::{
    IdentityAmbiguous, IdentityUnavailable, IncompleteSource, InvalidAnnotation, InvalidSource,
    OperationNotDefined, SourceKindUnsupported, UnresolvedDependency,
};

fn refused(result: Result<AuthoritativeSnapshot, DefinitionError>) -> DefinitionError {
    match result {
        Ok(_) => panic!("expected a definition refusal"),
        Err(err) => err,
    }
}

/// Go `assertDefinitionError`: the kind and the exact registered vocabulary.
fn assert_refusal(
    result: Result<AuthoritativeSnapshot, DefinitionError>,
    kind: DefinitionErrorKind,
    uri: &str,
) {
    let err = refused(result);
    assert_eq!(err.kind(), kind, "{err}");
    assert_eq!(
        err.vocabulary().map(VocabularyUri::as_str),
        Some(uri),
        "{err}"
    );
}

fn check_kind(result: Result<(), DefinitionCheckError>) -> Option<DefinitionErrorKind> {
    result.err().and_then(|err| err.definition_kind())
}

fn standard_operation(vocabulary: fn() -> Result<Vocabulary, Error>, raw: &str) -> Operation {
    let vocabulary = vocabulary().expect("standard vocabulary");
    Operation::new(&vocabulary, raw.as_bytes()).unwrap_or_else(|err| panic!("{raw}: {err}"))
}

fn mcp_tool(tool: &str) -> Operation {
    standard_operation(McpCodec::vocabulary, &format!(r#"{{"tool":"{tool}"}}"#))
}

fn openapi_operation(operation_id: &str) -> Operation {
    let raw = format!(r#"{{"operationId":"{operation_id}"}}"#);
    standard_operation(OpenApiCodec::vocabulary, &raw)
}

fn asyncapi_operation(operation_id: &str, action: Option<&str>) -> Operation {
    let raw = match action {
        Some(action) => format!(r#"{{"operationId":"{operation_id}","action":"{action}"}}"#),
        None => format!(r#"{{"operationId":"{operation_id}"}}"#),
    };
    standard_operation(AsyncApiCodec::vocabulary, &raw)
}

fn set_of(operation: &Operation) -> OperationSet {
    OperationSet::new(std::slice::from_ref(operation)).expect("operation set")
}

fn hints_of(snapshot: &AuthoritativeSnapshot, operation: &Operation) -> crate::OperationHints {
    snapshot
        .hints_for(operation)
        .expect("hints lookup")
        .expect("hints are present")
}

fn operation_json(snapshot: &AuthoritativeSnapshot) -> Vec<String> {
    snapshot
        .operations()
        .operations()
        .expect("operations")
        .iter()
        .map(|operation| String::from_utf8(operation.json().expect("json")).expect("utf-8"))
        .collect()
}

// ---- The shared definition contract (Go `vocabtest.RunDefinition`) ----

struct HintsExpectation {
    operation: Operation,
    access_mode: Option<AccessMode>,
    budget: Option<bool>,
}

struct Refusal<S> {
    name: &'static str,
    source: S,
    kind: DefinitionErrorKind,
}

type ParseFn<S> = fn(&str, &S) -> Result<AuthoritativeSnapshot, DefinitionError>;

struct Contract<S> {
    registration: DefinitionRegistration,
    parse: ParseFn<S>,
    endpoint: &'static str,
    source: S,
    changed: S,
    known: Operation,
    unknown: Operation,
    changed_only: Operation,
    hints: Option<HintsExpectation>,
    refusals: Vec<Refusal<S>>,
}

fn check_hints(snapshot: &AuthoritativeSnapshot, expected: &HintsExpectation) {
    let hints = hints_of(snapshot, &expected.operation);
    assert_eq!(hints.access_mode(), expected.access_mode);
    assert_eq!(hints.budget(), expected.budget);
}

fn run_contract<S: Sync>(contract: &Contract<S>) {
    let registry =
        DefinitionRegistry::new(std::slice::from_ref(&contract.registration)).expect("registry");
    let snapshot = (contract.parse)(contract.endpoint, &contract.source).expect("valid source");
    registry
        .validate(&snapshot)
        .expect("definition registration");
    let receipt = snapshot.receipt();
    assert!(!receipt.encoding().as_str().is_empty());
    assert_eq!(receipt.discovery_endpoint(), contract.endpoint);
    assert!(!receipt.digest().is_empty());
    assert!(receipt.byte_length() > 0);
    assert!(
        !snapshot
            .operations()
            .operations()
            .expect("operations")
            .is_empty()
    );

    let known = set_of(&contract.known);
    snapshot
        .validate_defined(&known)
        .expect("known operation is defined");
    let unknown = set_of(&contract.unknown);
    assert_eq!(
        check_kind(snapshot.validate_defined(&unknown)),
        Some(OperationNotDefined)
    );
    assert!(snapshot.hints_for(&contract.unknown).is_err());
    if let Some(expected) = &contract.hints {
        check_hints(&snapshot, expected);
    }

    let replayed = (contract.parse)(contract.endpoint, &contract.source).expect("replay");
    assert!(
        snapshot
            .operations()
            .equal(&replayed.operations())
            .expect("compare")
    );
    assert_eq!(snapshot.receipt(), replayed.receipt());
    if let Some(expected) = &contract.hints {
        check_hints(&replayed, expected);
    }
    std::thread::scope(|scope| {
        let mut readers = Vec::new();
        for _ in 0..8 {
            readers.push(scope.spawn(|| (contract.parse)(contract.endpoint, &contract.source)));
        }
        for reader in readers {
            let concurrent = reader
                .join()
                .expect("reader thread")
                .expect("concurrent replay");
            assert!(
                snapshot
                    .operations()
                    .equal(&concurrent.operations())
                    .expect("compare")
            );
            assert_eq!(snapshot.receipt(), concurrent.receipt());
            if let Some(expected) = &contract.hints {
                check_hints(&concurrent, expected);
            }
        }
    });

    let changed = (contract.parse)(contract.endpoint, &contract.changed).expect("changed source");
    assert_ne!(changed.receipt().digest(), snapshot.receipt().digest());
    assert!(
        !snapshot
            .operations()
            .equal(&changed.operations())
            .expect("compare")
    );
    changed
        .validate_defined(&known)
        .expect("changed source keeps the known operation");
    let changed_only = set_of(&contract.changed_only);
    assert_eq!(
        check_kind(snapshot.validate_defined(&changed_only)),
        Some(OperationNotDefined)
    );
    changed
        .validate_defined(&changed_only)
        .expect("changed source derives the changed-only operation");

    assert!(!contract.refusals.is_empty());
    for refusal in &contract.refusals {
        let err = refused((contract.parse)(contract.endpoint, &refusal.source));
        assert_eq!(err.kind(), refusal.kind, "{}: {err}", refusal.name);
    }
}

fn mcp_snapshot(pages: &[(Option<&str>, &str)]) -> ToolsListSnapshot {
    ToolsListSnapshot::new(
        pages
            .iter()
            .map(|(cursor, body)| match cursor {
                None => ToolsListPage::initial(body.as_bytes()),
                Some(cursor) => ToolsListPage::continued(*cursor, body.as_bytes()),
            })
            .collect(),
    )
}

fn asyncapi_contract_source(operations: &str) -> AsyncApiDocumentSource {
    let document = format!(
        r#"{{"asyncapi":"3.0.0","info":{{"title":"events","version":"1"}},"channels":{{"events":{{"address":"events","messages":{{}}}}}},"operations":{{{operations}}}}}"#
    );
    AsyncApiDocumentSource::new(document.as_bytes())
}

#[test]
fn definition_contract_exercises_native_mcp_source() {
    let read = r#"{"name":"read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token","aauth.dev/budget":false}}"#;
    let write = r#"{"name":"write","inputSchema":{"type":"object"}}"#;
    let source = format!(r#"{{"tools":[{read}]}}"#);
    let changed = format!(r#"{{"tools":[{read},{write}]}}"#);
    run_contract(&Contract {
        registration: McpCodec::definition_registration().expect("registration"),
        parse: McpCodec::parse_definition,
        endpoint: MCP_ENDPOINT,
        source: mcp_snapshot(&[(None, source.as_str())]),
        changed: mcp_snapshot(&[(None, changed.as_str())]),
        known: mcp_tool("read"),
        unknown: mcp_tool("unknown"),
        changed_only: mcp_tool("write"),
        hints: Some(HintsExpectation {
            operation: mcp_tool("read"),
            access_mode: Some(AccessMode::PersonToken),
            budget: Some(false),
        }),
        refusals: vec![Refusal {
            name: "invalid annotation",
            source: mcp_snapshot(&[(
                None,
                r#"{"tools":[{"name":"read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":"yes"}}]}"#,
            )]),
            kind: InvalidAnnotation,
        }],
    });
}

#[test]
fn definition_contract_exercises_openapi_document() {
    let read = r#""/read":{"get":{"operationId":"read","responses":{"204":{"description":"ok"}}}}"#;
    let write =
        r#""/write":{"post":{"operationId":"write","responses":{"204":{"description":"ok"}}}}"#;
    let document = |paths: &str| {
        OpenApiDocumentSource::new(
            format!(
                r#"{{"openapi":"3.1.0","info":{{"title":"test","version":"1"}},"paths":{{{paths}}}}}"#
            )
            .as_bytes(),
        )
    };
    run_contract(&Contract {
        registration: OpenApiCodec::definition_registration().expect("registration"),
        parse: OpenApiCodec::parse_definition,
        endpoint: "https://resource.example/openapi.json",
        source: document(read),
        changed: document(&format!("{read},{write}")),
        known: openapi_operation("read"),
        unknown: openapi_operation("unknown"),
        changed_only: openapi_operation("write"),
        hints: None,
        refusals: vec![Refusal {
            name: "unsupported version",
            source: OpenApiDocumentSource::new(br#"{"swagger":"2.0"}"#),
            kind: SourceKindUnsupported,
        }],
    });
}

#[test]
fn definition_contract_exercises_asyncapi_document() {
    let read = r##""read":{"action":"receive","channel":{"$ref":"#/channels/events"}}"##;
    let write = r##""write":{"action":"send","channel":{"$ref":"#/channels/events"}}"##;
    run_contract(&Contract {
        registration: AsyncApiCodec::definition_registration().expect("registration"),
        parse: AsyncApiCodec::parse_definition,
        endpoint: ASYNCAPI_ENDPOINT,
        source: asyncapi_contract_source(read),
        changed: asyncapi_contract_source(&format!("{read},{write}")),
        known: asyncapi_operation("read", Some("receive")),
        unknown: asyncapi_operation("unknown", Some("receive")),
        changed_only: asyncapi_operation("write", Some("send")),
        hints: None,
        refusals: vec![Refusal {
            name: "missing action",
            source: asyncapi_contract_source(
                r##""read":{"channel":{"$ref":"#/channels/events"}}"##,
            ),
            kind: InvalidSource,
        }],
    });
}

#[test]
fn definition_refusal_contract_exercises_graphql_identity_gap() {
    let source =
        GraphQlIntrospectionSource::new(br#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#);
    assert_refusal(
        GraphQlCodec::parse_definition(GRAPHQL_ENDPOINT, &source),
        IdentityUnavailable,
        GraphQlCodec::URI,
    );
}

/// The four JSON registrations are distinct, stable, and refuse each
/// other's snapshots. A parser built over the same vocabulary is a different
/// registration.
#[test]
fn definition_registrations_are_explicit_and_stable() {
    let registry = DefinitionRegistry::new(&[
        McpCodec::definition_registration().expect("mcp"),
        OpenApiCodec::definition_registration().expect("openapi"),
        GraphQlCodec::definition_registration().expect("graphql"),
        AsyncApiCodec::definition_registration().expect("asyncapi"),
    ])
    .expect("registry");
    assert_eq!(registry.len(), 4);
    for uri in [
        McpCodec::URI,
        OpenApiCodec::URI,
        GraphQlCodec::URI,
        AsyncApiCodec::URI,
    ] {
        assert!(
            registry.contains(&VocabularyUri::parse(uri).expect("uri")),
            "{uri}"
        );
    }
    assert!(
        DefinitionRegistry::new(&[
            GraphQlCodec::definition_registration().expect("graphql"),
            GraphQlCodec::definition_registration().expect("graphql again"),
        ])
        .is_err()
    );

    let source = mcp_snapshot(&[(
        None,
        r#"{"tools":[{"name":"read","inputSchema":{"type":"object"}}]}"#,
    )]);
    let snapshot = McpCodec::parse_definition(MCP_ENDPOINT, &source).expect("mcp snapshot");
    registry
        .validate(&snapshot)
        .expect("standard MCP registration");
    let graphql_only =
        DefinitionRegistry::new(&[GraphQlCodec::definition_registration().expect("graphql")])
            .expect("registry");
    assert!(graphql_only.validate(&snapshot).is_err());

    /// A host parser that claims the MCP vocabulary.
    struct HostMcp;
    impl DefinitionCodec<[u8]> for HostMcp {
        fn vocabulary(&self) -> Result<Vocabulary, Error> {
            McpCodec::vocabulary()
        }
        fn parse_definition(&self, _: &[u8]) -> Result<DefinitionMaterial, DefinitionError> {
            Err(DefinitionError::new(InvalidSource, "unused"))
        }
    }
    let host = DefinitionParser::<[u8]>::new(HostMcp).expect("host parser");
    let host_registry = DefinitionRegistry::new(&[host.registration()]).expect("registry");
    assert!(
        host_registry.validate(&snapshot).is_err(),
        "a snapshot from the standard parser is not the host parser's"
    );
}

// ---- MCP (Go `r3/vocab/mcp/definition_test.go`) ----

#[test]
fn mcp_definition_owns_complete_paginated_tools_list_snapshot() {
    let mut first = br#"{"tools":[{"name":"calendar.read","description":"Read calendars","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token"}}],"nextCursor":"page-2"}"#.to_vec();
    let mut second = br#"{"tools":[{"name":"calendar.write","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"auth-token","aauth.dev/budget":true}}]}"#.to_vec();
    let source = ToolsListSnapshot::new(vec![
        ToolsListPage::initial(&first),
        ToolsListPage::continued("page-2", &second),
    ]);
    first[0] = b'[';
    second[0] = b'[';

    let snapshot = McpCodec::parse_definition(MCP_ENDPOINT, &source).expect("snapshot");
    assert_eq!(snapshot.vocabulary().as_str(), McpCodec::URI);
    assert_eq!(
        operation_json(&snapshot),
        [
            r#"{"tool":"calendar.read"}"#,
            r#"{"tool":"calendar.write"}"#
        ]
    );
    let read = hints_of(&snapshot, &mcp_tool("calendar.read"));
    assert_eq!(read.access_mode(), Some(AccessMode::PersonToken));
    assert_eq!(read.budget(), None);
    let write = hints_of(&snapshot, &mcp_tool("calendar.write"));
    assert_eq!(write.access_mode(), Some(AccessMode::AuthToken));
    assert_eq!(write.budget(), Some(true));
}

#[test]
fn mcp_exact_source_receipt_frames_page_boundaries() {
    let first = br#"{"tools":[],"nextCursor":"page-2"} "#;
    let second = br#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}"#;
    let left = ToolsListSnapshot::new(vec![
        ToolsListPage::initial(first),
        ToolsListPage::continued("page-2", second),
    ]);
    let snapshot = McpCodec::parse_definition(MCP_ENDPOINT, &left).expect("left");
    assert_eq!(
        snapshot.receipt().encoding().as_str(),
        ToolsListSnapshot::SOURCE_ENCODING
    );
    assert_eq!(snapshot.receipt().digest(), digest(&left.receipt_input()));
    assert_eq!(
        snapshot.receipt().byte_length(),
        left.receipt_input().len() as u64
    );

    // Cross-language fixture: the framing Go `ToolsListSnapshot.ReceiptInput` writes.
    let mut framed = b"aauth-r3-mcp-tools-list-cursor-result-json-frames\0".to_vec();
    framed.extend_from_slice(&2u64.to_be_bytes());
    framed.push(0);
    framed.extend_from_slice(&(first.len() as u64).to_be_bytes());
    framed.extend_from_slice(first);
    framed.push(1);
    framed.extend_from_slice(&6u64.to_be_bytes());
    framed.extend_from_slice(b"page-2");
    framed.extend_from_slice(&(second.len() as u64).to_be_bytes());
    framed.extend_from_slice(second);
    assert_eq!(left.receipt_input(), framed);

    let right = ToolsListSnapshot::new(vec![
        ToolsListPage::initial(br#"{"tools":[],"nextCursor":"page-2"}"#),
        ToolsListPage::continued(
            "page-2",
            br#" {"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}"#,
        ),
    ]);
    let other = McpCodec::parse_definition(MCP_ENDPOINT, &right).expect("right");
    assert_ne!(
        snapshot.receipt().digest(),
        other.receipt().digest(),
        "the same concatenated bytes at other page boundaries"
    );
}

#[test]
fn mcp_definition_rejects_duplicate_tools_across_pages() {
    let source = mcp_snapshot(&[
        (
            None,
            r#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}"#,
        ),
        (
            Some("page-2"),
            r#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}"#,
        ),
    ]);
    assert_refusal(
        McpCodec::parse_definition(MCP_ENDPOINT, &source),
        IdentityAmbiguous,
        McpCodec::URI,
    );
}

#[test]
fn mcp_definition_rejects_incomplete_pagination() {
    let read = r#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}"#;
    let read_more = r#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}"#;
    let write = r#"{"tools":[{"name":"calendar.write","inputSchema":{"type":"object"}}]}"#;
    let empty_more = r#"{"tools":[],"nextCursor":"page-2"}"#;
    type PaginationCase<'a> = (&'a str, Vec<(Option<&'a str>, &'a str)>);
    let cases: [PaginationCase<'_>; 9] = [
        ("no pages", vec![]),
        (
            "nonfinal page has no next cursor",
            vec![(None, read), (Some("page-2"), write)],
        ),
        ("final page has next cursor", vec![(None, read_more)]),
        (
            "first page has a requested cursor",
            vec![(Some("page-1"), read)],
        ),
        (
            "continuation omits requested cursor",
            vec![(None, empty_more), (None, read)],
        ),
        (
            "continuation requests empty cursor",
            vec![(None, empty_more), (Some(""), read)],
        ),
        (
            "continuation requests another cursor",
            vec![(None, empty_more), (Some("page-3"), read)],
        ),
        // Go decodes a null cursor as an empty one.
        (
            "final page has a null cursor",
            vec![(
                None,
                r#"{"tools":[{"name":"a","inputSchema":{"type":"object"}}],"nextCursor":null}"#,
            )],
        ),
        (
            "nextCursor repeats",
            vec![
                (None, empty_more),
                (Some("page-2"), r#"{"tools":[],"nextCursor":"page-2"}"#),
                (Some("page-2"), read),
            ],
        ),
    ];
    for (name, pages) in cases {
        let err = refused(McpCodec::parse_definition(
            MCP_ENDPOINT,
            &mcp_snapshot(&pages),
        ));
        assert_eq!(err.kind(), IncompleteSource, "{name}: {err}");
    }
    let no_tools = mcp_snapshot(&[(None, r#"{"tools":[]}"#)]);
    assert_refusal(
        McpCodec::parse_definition(MCP_ENDPOINT, &no_tools),
        IncompleteSource,
        McpCodec::URI,
    );
}

#[test]
fn mcp_definition_rejects_invalid_annotations() {
    for meta in [
        r#"{"aauth.dev/access-mode":"session-token"}"#,
        r#"{"aauth.dev/access-mode":true}"#,
        r#"{"aauth.dev/budget":"yes"}"#,
        r#"{"aauth.dev/budget":null}"#,
        // Rust: an unknown mode, a null mode, and a _meta that is not an object.
        r#"{"aauth.dev/access-mode":"bogus"}"#,
        r#"{"aauth.dev/access-mode":null}"#,
        "null",
        "[]",
    ] {
        let body = format!(
            r#"{{"tools":[{{"name":"calendar.read","inputSchema":{{"type":"object"}},"_meta":{meta}}}]}}"#
        );
        let err = refused(McpCodec::parse_definition(
            MCP_ENDPOINT,
            &mcp_snapshot(&[(None, body.as_str())]),
        ));
        assert_eq!(err.kind(), InvalidAnnotation, "{meta}: {err}");
    }
}

#[test]
fn mcp_definition_rejects_invalid_tool_input_schema() {
    for (name, tool) in [
        ("missing", r#"{"name":"calendar.read"}"#),
        (
            "not an object",
            r#"{"name":"calendar.read","inputSchema":true}"#,
        ),
        (
            "not object rooted",
            r#"{"name":"calendar.read","inputSchema":{"type":"string"}}"#,
        ),
        (
            "invalid properties shape",
            r#"{"name":"calendar.read","inputSchema":{"type":"object","properties":[]}}"#,
        ),
        (
            "invalid required shape",
            r#"{"name":"calendar.read","inputSchema":{"type":"object","required":"account"}}"#,
        ),
        // Rust: further meta-schema shapes, one per draft family.
        (
            "type array at the root",
            r#"{"name":"a","inputSchema":{"type":["object"]}}"#,
        ),
        (
            "negative minLength",
            r#"{"name":"a","inputSchema":{"type":"object","properties":{"x":{"minLength":-1}}}}"#,
        ),
        (
            "fractional maxItems",
            r#"{"name":"a","inputSchema":{"type":"object","properties":{"x":{"maxItems":1.5}}}}"#,
        ),
        (
            "repeated type",
            r#"{"name":"a","inputSchema":{"type":"object","properties":{"x":{"type":["string","string"]}}}}"#,
        ),
        (
            "unknown simple type",
            r#"{"name":"a","inputSchema":{"type":"object","properties":{"x":{"type":"text"}}}}"#,
        ),
        (
            "2020-12 items array",
            r#"{"name":"a","inputSchema":{"type":"object","properties":{"x":{"items":[{}]}}}}"#,
        ),
        (
            "draft-04 boolean subschema",
            r#"{"name":"a","inputSchema":{"$schema":"http://json-schema.org/draft-04/schema#","type":"object","properties":{"x":true}}}"#,
        ),
        (
            "draft-04 exclusiveMaximum without maximum",
            r#"{"name":"a","inputSchema":{"$schema":"http://json-schema.org/draft-04/schema#","type":"object","exclusiveMaximum":true}}"#,
        ),
        (
            "2020-12 $id with a fragment",
            r##"{"name":"a","inputSchema":{"$id":"https://schemas.example/tool#x","type":"object"}}"##,
        ),
        (
            "invalid anchor",
            r#"{"name":"a","inputSchema":{"type":"object","$anchor":"1x"}}"#,
        ),
        (
            "missing internal reference",
            r##"{"name":"a","inputSchema":{"type":"object","properties":{"x":{"$ref":"#/$defs/missing"}}}}"##,
        ),
        (
            "unknown anchor reference",
            r##"{"name":"a","inputSchema":{"type":"object","properties":{"x":{"$ref":"#nowhere"}}}}"##,
        ),
        (
            "empty tool name",
            r#"{"name":"","inputSchema":{"type":"object"}}"#,
        ),
        (
            "padded tool name",
            r#"{"name":" a","inputSchema":{"type":"object"}}"#,
        ),
        ("null tool", "null"),
    ] {
        let body = format!(r#"{{"tools":[{tool}]}}"#);
        let err = refused(McpCodec::parse_definition(
            MCP_ENDPOINT,
            &mcp_snapshot(&[(None, body.as_str())]),
        ));
        assert_eq!(err.kind(), InvalidSource, "{name}: {err}");
    }
}

#[test]
fn mcp_definition_accepts_self_contained_schemas_of_each_draft() {
    for (name, schema) in [
        ("empty object", r#"{"type":"object"}"#),
        (
            "local $defs reference",
            r##"{"type":"object","properties":{"record":{"$ref":"#/$defs/record"}},"$defs":{"record":{"type":"object","required":["id"],"properties":{"id":{"type":"string","minLength":1.0}}}}}"##,
        ),
        (
            "anchor reference",
            r##"{"type":"object","properties":{"a":{"$ref":"#node"}},"$defs":{"n":{"$anchor":"node","type":"string"}}}"##,
        ),
        (
            "embedded resource",
            r#"{"$id":"https://schemas.example/tool.json","type":"object","properties":{"a":{"$ref":"item.json"}},"$defs":{"item":{"$id":"item.json","type":"string"}}}"#,
        ),
        (
            "draft-07 items array",
            r##"{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"pair":{"type":"array","items":[{"type":"string"},{"type":"number"}],"additionalItems":false}},"definitions":{"x":{"type":"string"}}}"##,
        ),
        (
            "draft-04 exclusive bounds",
            r#"{"$schema":"http://json-schema.org/draft-04/schema#","type":"object","properties":{"n":{"type":"number","maximum":5,"exclusiveMaximum":true}},"additionalProperties":false}"#,
        ),
        (
            "unknown keywords are annotations",
            r#"{"type":"object","x-vendor":{"$ref":"https://schemas.example/not-a-schema"}}"#,
        ),
    ] {
        let body = format!(r#"{{"tools":[{{"name":"a","inputSchema":{schema}}}]}}"#);
        if let Err(err) =
            McpCodec::parse_definition(MCP_ENDPOINT, &mcp_snapshot(&[(None, body.as_str())]))
        {
            panic!("{name}: {err}");
        }
    }
}

#[test]
fn mcp_definition_classifies_external_input_schema_references() {
    for schema in [
        r#"{"type":"object","properties":{"record":{"$ref":"https://schemas.example/record.json"}}}"#,
        // Rust: a relative reference, and a meta-schema that is not bundled.
        r#"{"type":"object","properties":{"record":{"$ref":"record.json"}}}"#,
        r#"{"$schema":"https://schemas.example/meta","type":"object"}"#,
    ] {
        let body = format!(r#"{{"tools":[{{"name":"calendar.read","inputSchema":{schema}}}]}}"#);
        assert_refusal(
            McpCodec::parse_definition(MCP_ENDPOINT, &mcp_snapshot(&[(None, body.as_str())])),
            UnresolvedDependency,
            McpCodec::URI,
        );
    }
}

#[test]
fn mcp_definition_validates_known_operations_without_adding_authority() {
    let source = mcp_snapshot(&[(
        None,
        r#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}},{"name":"calendar.write","inputSchema":{"type":"object"}}]}"#,
    )]);
    let snapshot = McpCodec::parse_definition(MCP_ENDPOINT, &source).expect("snapshot");
    snapshot
        .validate_defined(&set_of(&mcp_tool("calendar.read")))
        .expect("known");
    assert_eq!(
        check_kind(snapshot.validate_defined(&set_of(&mcp_tool("calendar.delete")))),
        Some(OperationNotDefined)
    );
    let registry = DefinitionRegistry::new(&[McpCodec::definition_registration().expect("mcp")])
        .expect("registry");
    registry.validate(&snapshot).expect("registration");
}

#[test]
fn mcp_definition_retains_no_hints_when_meta_has_no_r3_annotations() {
    let source = mcp_snapshot(&[(
        None,
        r#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"},"_meta":{"vendor.example/color":"blue","aauth.dev/Access-Mode":"per-call"}},{"name":"calendar.write","inputSchema":{"type":"object"}}]}"#,
    )]);
    let snapshot = McpCodec::parse_definition(MCP_ENDPOINT, &source).expect("snapshot");
    for tool in ["calendar.read", "calendar.write"] {
        assert_eq!(
            snapshot.hints_for(&mcp_tool(tool)).expect(tool),
            None,
            "{tool}"
        );
    }
}

/// Rust: Go decodes pages and tools into structs and reads a case variant of
/// a member as the member. This port refuses the variant instead.
#[test]
fn mcp_definition_refuses_member_case_variants() {
    for body in [
        r#"{"Tools":[{"name":"a","inputSchema":{"type":"object"}}]}"#,
        r#"{"tools":[{"name":"a","inputSchema":{"type":"object"}}],"NEXTCURSOR":"x"}"#,
        r#"{"tools":[{"name":"a","Name":"b","inputSchema":{"type":"object"}}]}"#,
        r#"{"tools":[{"name":"a","inputſchema":{"type":"object"}}]}"#,
        r#"{"tools":[{"name":"a","inputSchema":{"type":"object"},"_META":{"aauth.dev/budget":true}}]}"#,
        r#"{"tools":[{"naMe":"a","name":"b","inputSchema":{"type":"object"}}]}"#,
    ] {
        let err = refused(McpCodec::parse_definition(
            MCP_ENDPOINT,
            &mcp_snapshot(&[(None, body)]),
        ));
        assert_eq!(err.kind(), InvalidSource, "{body}: {err}");
    }
}

// ---- OpenAPI (Go `r3/vocab/openapi/definition_test.go`) ----

const PET_API_YAML: &str = "openapi: 3.1.0
info:
  title: Pet API
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      x-aauth-access-mode: person-token
      x-aauth-budget: false
      responses:
        \"200\":
          description: ok
    post:
      operationId: createPet
      responses:
        \"204\":
          description: created
";

/// The same document as `PET_API_YAML`, in its JSON form.
const PET_API_JSON: &str = r#"{
  "openapi": "3.1.0",
  "info": {"title": "Pet API", "version": "1.0.0"},
  "paths": {
    "/pets": {
      "get": {
        "operationId": "listPets",
        "x-aauth-access-mode": "person-token",
        "x-aauth-budget": false,
        "responses": {"200": {"description": "ok"}}
      },
      "post": {
        "operationId": "createPet",
        "responses": {"204": {"description": "created"}}
      }
    }
  }
}"#;

fn openapi_ids(snapshot: &AuthoritativeSnapshot) -> Vec<String> {
    operation_json(snapshot)
        .iter()
        .map(|json| {
            json.trim_start_matches(r#"{"operationId":""#)
                .trim_end_matches(r#""}"#)
                .to_owned()
        })
        .collect()
}

fn openapi(document: &str) -> Result<AuthoritativeSnapshot, DefinitionError> {
    OpenApiCodec::parse_definition(
        OPENAPI_ENDPOINT,
        &OpenApiDocumentSource::new(document.as_bytes()),
    )
}

fn openapi_kind(document: &str) -> DefinitionErrorKind {
    refused(openapi(document)).kind()
}

fn openapi_paths(paths: &str) -> String {
    format!(r#"{{"openapi":"3.1.0","info":{{"title":"test","version":"1"}},"paths":{paths}}}"#)
}

/// Rust: the YAML form of Go's first fixture is refused until a YAML parser
/// joins; its JSON form derives the same operations and hints.
#[test]
fn openapi_definition_owns_exact_source_and_derives_caller_operations() {
    assert_refusal(
        openapi(PET_API_YAML),
        SourceKindUnsupported,
        OpenApiCodec::URI,
    );

    let mut original = PET_API_JSON.as_bytes().to_vec();
    let source = OpenApiDocumentSource::new(&original);
    original[0] = b'X';
    let snapshot = OpenApiCodec::parse_definition(OPENAPI_ENDPOINT, &source).expect("snapshot");
    assert_eq!(source.exact_bytes(), PET_API_JSON.as_bytes());
    let receipt = snapshot.receipt();
    assert_eq!(receipt.digest(), digest(PET_API_JSON.as_bytes()));
    assert_eq!(receipt.byte_length(), PET_API_JSON.len() as u64);
    assert_eq!(receipt.discovery_endpoint(), OPENAPI_ENDPOINT);
    assert_eq!(
        receipt.encoding().as_str(),
        OpenApiDocumentSource::SOURCE_ENCODING
    );
    assert_eq!(openapi_ids(&snapshot), ["listPets", "createPet"]);
    snapshot
        .validate_defined(&set_of(&openapi_operation("listPets")))
        .expect("known");
    assert_eq!(
        check_kind(snapshot.validate_defined(&set_of(&openapi_operation("missing")))),
        Some(OperationNotDefined)
    );
    let hints = hints_of(&snapshot, &openapi_operation("listPets"));
    assert_eq!(hints.access_mode(), Some(AccessMode::PersonToken));
    assert_eq!(hints.budget(), Some(false));
    let registry =
        DefinitionRegistry::new(&[OpenApiCodec::definition_registration().expect("openapi")])
            .expect("registry");
    registry.validate(&snapshot).expect("registration");
}

#[test]
fn openapi_definition_accepts_self_contained_30_and_internal_references() {
    let snapshot = openapi(
        r##"{
  "openapi":"3.0.3",
  "info":{"title":"Pet API","version":"1"},
  "paths":{"/pets":{"get":{"operationId":"listPets","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Pet"}}}}}}}},
  "components":{"schemas":{"Pet":{"type":"object","properties":{"name":{"type":"string"}}}}}
}"##,
    )
    .expect("snapshot");
    assert_eq!(openapi_ids(&snapshot), ["listPets"]);
}

#[test]
fn openapi_definition_does_not_treat_example_payload_fields_as_references() {
    let snapshot = openapi(
        r#"{
  "openapi":"3.1.0",
  "info":{"title":"Example API","version":"1"},
  "paths":{"/example":{"get":{"operationId":"example","responses":{"200":{"description":"ok","content":{"application/json":{"example":{"$ref":"https://payload.example/not-an-openapi-reference"}}}}}}}}
}"#,
    )
    .expect("snapshot");
    assert_eq!(openapi_ids(&snapshot), ["example"]);
}

#[test]
fn openapi_definition_keeps_named_subset_when_other_operations_are_unnamed() {
    let snapshot = openapi(&openapi_paths(
        r#"{"/named":{"get":{"operationId":"named","responses":{"204":{"description":"ok"}}}},"/unnamed":{"post":{"responses":{"204":{"description":"ok"}}}}}"#,
    ))
    .expect("snapshot");
    assert_eq!(openapi_ids(&snapshot), ["named"]);
}

#[test]
fn openapi_definition_refuses_no_identifiable_or_duplicate_operations() {
    assert_eq!(
        openapi_kind(&openapi_paths(
            r#"{"/a":{"get":{"responses":{"204":{"description":"ok"}}}}}"#
        )),
        IdentityUnavailable
    );
    assert_eq!(
        openapi_kind(&openapi_paths(
            r#"{"/a":{"get":{"operationId":"same","responses":{"204":{"description":"ok"}}}},"/b":{"post":{"operationId":"same","responses":{"204":{"description":"ok"}}}}}"#
        )),
        IdentityAmbiguous
    );
}

#[test]
fn openapi_definition_refuses_invalid_versions_documents_and_external_references() {
    for (name, document, kind) in [
        ("invalid document", "{", InvalidSource),
        (
            "swagger 2",
            r#"{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{}}"#,
            SourceKindUnsupported,
        ),
        (
            "unsupported OpenAPI version",
            r#"{"openapi":"3.2.0","info":{"title":"x","version":"1"},"paths":{}}"#,
            SourceKindUnsupported,
        ),
        (
            "external HTTPS reference",
            r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x","responses":{"200":{"$ref":"https://schemas.example/responses.yaml#/OK"}}}}}}"##,
            UnresolvedDependency,
        ),
        (
            "external file reference",
            r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x","responses":{"200":{"$ref":"./responses.yaml#/OK"}}}}}}"##,
            UnresolvedDependency,
        ),
        // Rust: further version, framing, and reference cases.
        ("empty document", " \n", IncompleteSource),
        (
            "numeric version",
            r#"{"openapi":3.1,"paths":{}}"#,
            SourceKindUnsupported,
        ),
        ("array root", "[]", InvalidSource),
        (
            "duplicate member",
            r#"{"openapi":"3.1.0","openapi":"3.0.0"}"#,
            InvalidSource,
        ),
        (
            "missing internal reference",
            r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x","responses":{"200":{"$ref":"#/components/responses/Missing"}}}}}}"##,
            InvalidSource,
        ),
        (
            "reference cycle",
            r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x","responses":{"200":{"$ref":"#/components/responses/A"}}}}},"components":{"responses":{"A":{"$ref":"#/components/responses/B"},"B":{"$ref":"#/components/responses/A"}}}}"##,
            InvalidSource,
        ),
        (
            "external reference in a component schema",
            r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{"operationId":"x","responses":{"200":{"description":"ok"}}}}},"components":{"schemas":{"A":{"properties":{"b":{"$ref":"https://schemas.example/b.json"}}}}}}"##,
            UnresolvedDependency,
        ),
        (
            "external Path Item reference",
            r#"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"$ref":"paths.json"}}}"#,
            UnresolvedDependency,
        ),
        (
            "paths is an array",
            r#"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":[]}"#,
            InvalidSource,
        ),
    ] {
        assert_eq!(openapi_kind(document), kind, "{name}");
    }
}

#[test]
fn openapi_definition_preserves_sparse_hints_and_reports_invalid_ones() {
    let snapshot = openapi(
        r#"{
  "openapi":"3.1.0",
  "info":{"title":"hints","version":"1"},
  "paths":{
    "/mode":{"get":{"operationId":"modeOnly","x-aauth-access-mode":"per-call","responses":{"204":{"description":"ok"}}}},
    "/budget":{"get":{"operationId":"budgetOnly","x-aauth-budget":true,"responses":{"204":{"description":"ok"}}}},
    "/conflict":{"get":{"operationId":"conflict","x-aauth-access-mode":"agent-token","x-aauth-budget":true,"responses":{"204":{"description":"ok"}}}},
    "/none":{"get":{"operationId":"none","responses":{"204":{"description":"ok"}}}}
  }
}"#,
    )
    .expect("snapshot");
    let mode = hints_of(&snapshot, &openapi_operation("modeOnly"));
    assert_eq!(mode.access_mode(), Some(AccessMode::PerCall));
    assert_eq!(mode.budget(), None);
    let budget = hints_of(&snapshot, &openapi_operation("budgetOnly"));
    assert_eq!(budget.budget(), Some(true));
    assert_eq!(budget.access_mode(), None);
    let planned = hints_of(&snapshot, &openapi_operation("conflict")).plan(AccessMode::PersonToken);
    assert!(planned.publisher_conflict());
    assert_eq!(planned.access_mode(), AccessMode::AuthToken);
    assert_eq!(
        snapshot
            .hints_for(&openapi_operation("none"))
            .expect("none"),
        None
    );

    for extension in [
        r#""x-aauth-access-mode":true"#,
        r#""x-aauth-access-mode":"session-token""#,
        r#""x-aauth-budget":"true""#,
        r#""x-aauth-budget":null"#,
    ] {
        let document = openapi_paths(&format!(
            r#"{{"/x":{{"get":{{"operationId":"x",{extension},"responses":{{"204":{{"description":"ok"}}}}}}}}}}"#
        ));
        assert_eq!(openapi_kind(&document), InvalidAnnotation, "{extension}");
    }
}

#[test]
fn openapi_definition_ignores_callback_and_webhook_operations() {
    let snapshot = openapi(
        r#"{
  "openapi":"3.1.0",
  "info":{"title":"profile","version":"1"},
  "paths":{"/start":{"post":{"operationId":"start","responses":{"202":{"description":"ok"}},"callbacks":{"finished":{"{$request.body#/callback}":{"post":{"operationId":"callbackFinished","responses":{"204":{"description":"ok"}}}}}}}}},
  "webhooks":{"updated":{"post":{"operationId":"webhookUpdated","responses":{"204":{"description":"ok"}}}}}
}"#,
    )
    .expect("snapshot");
    assert_eq!(openapi_ids(&snapshot), ["start"]);
}

/// Rust: an `operationId` must be unique among every operation the document
/// describes, so a callback or webhook with a derived identity is ambiguous.
/// Go checks Paths operations only.
#[test]
fn openapi_definition_refuses_identities_shared_with_callbacks_or_webhooks() {
    let callback = r#"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/start":{"post":{"operationId":"start","responses":{"202":{"description":"ok"}},"callbacks":{"done":{"{$request.body#/callback}":{"post":{"operationId":"start","responses":{"204":{"description":"ok"}}}}}}}}}}"#;
    assert_eq!(openapi_kind(callback), IdentityAmbiguous);
    let webhook = r#"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/start":{"post":{"operationId":"start","responses":{"202":{"description":"ok"}}}}},"webhooks":{"start":{"post":{"operationId":"start","responses":{"204":{"description":"ok"}}}}}}"#;
    assert_eq!(openapi_kind(webhook), IdentityAmbiguous);
}

/// Rust: Path Item references resolve inside the document, and an operation
/// named both beside and behind a `$ref` is ambiguous.
#[test]
fn openapi_definition_resolves_path_item_references() {
    let snapshot = openapi(
        r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/a":{"$ref":"#/components/pathItems/A","summary":"shared"}},"components":{"pathItems":{"A":{"get":{"operationId":"fromComponent","responses":{"204":{"description":"ok"}}}}}}}"##,
    )
    .expect("snapshot");
    assert_eq!(openapi_ids(&snapshot), ["fromComponent"]);
    assert_eq!(
        openapi_kind(
            r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/a":{"$ref":"#/components/pathItems/A","post":{"operationId":"beside","responses":{"204":{"description":"ok"}}}}},"components":{"pathItems":{"A":{"get":{"operationId":"behind","responses":{"204":{"description":"ok"}}}}}}}"##
        ),
        IdentityAmbiguous
    );
}

/// Rust: the kin-openapi validations this port carries, and Go's order of
/// refusal: identity refusals precede validation refusals.
#[test]
fn openapi_definition_validates_the_operation_graph_after_identity() {
    for (name, paths) in [
        ("missing responses", r#"{"/a":{"get":{"operationId":"a"}}}"#),
        (
            "empty responses",
            r#"{"/a":{"get":{"operationId":"a","responses":{}}}}"#,
        ),
        (
            "response without description",
            r#"{"/a":{"get":{"operationId":"a","responses":{"200":{}}}}}"#,
        ),
        (
            "invalid response code",
            r#"{"/a":{"get":{"operationId":"a","responses":{"600":{"description":"ok"}}}}}"#,
        ),
        (
            "path without a leading slash",
            r#"{"a":{"get":{"operationId":"a","responses":{"204":{"description":"ok"}}}}}"#,
        ),
        (
            "undeclared path parameter",
            r#"{"/a/{id}":{"get":{"operationId":"a","responses":{"204":{"description":"ok"}}}}}"#,
        ),
        (
            "optional path parameter",
            r#"{"/a/{id}":{"get":{"operationId":"a","parameters":[{"name":"id","in":"path","schema":{"type":"string"}}],"responses":{"204":{"description":"ok"}}}}}"#,
        ),
        (
            "unknown Operation member",
            r#"{"/a":{"get":{"operationId":"a","OperationId":"b","responses":{"204":{"description":"ok"}}}}}"#,
        ),
        (
            "upper-case method",
            r#"{"/a":{"GET":{"operationId":"a","responses":{"204":{"description":"ok"}}}}}"#,
        ),
        (
            "repeated parameter",
            r#"{"/a":{"get":{"operationId":"a","parameters":[{"name":"q","in":"query"},{"name":"q","in":"query"}],"responses":{"204":{"description":"ok"}}}}}"#,
        ),
    ] {
        assert_eq!(openapi_kind(&openapi_paths(paths)), InvalidSource, "{name}");
    }
    let declared = openapi(&openapi_paths(
        r##"{"/a/{id}":{"parameters":[{"$ref":"#/components/parameters/Id"}],"get":{"operationId":"a","responses":{"204":{"description":"ok"}}}}}"##,
    ));
    assert_eq!(
        refused(declared).kind(),
        InvalidSource,
        "the referenced parameter is missing"
    );
    let snapshot = openapi(
        r##"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/a/{id}":{"parameters":[{"$ref":"#/components/parameters/Id"}],"get":{"operationId":"a","responses":{"204":{"description":"ok"}}}}},"components":{"parameters":{"Id":{"name":"id","in":"path","required":true,"schema":{"type":"string"}}}}}"##,
    )
    .expect("declared path parameter");
    assert_eq!(openapi_ids(&snapshot), ["a"]);
    assert_eq!(
        openapi_kind(
            r#"{"openapi":"3.1.0","paths":{"/a":{"get":{"operationId":"a","responses":{"204":{"description":"ok"}}}}}}"#
        ),
        InvalidSource,
        "missing info"
    );
    assert_eq!(
        openapi_kind(&openapi_paths(
            r#"{"/a":{"get":{"operationId":"same"}},"/b":{"get":{"operationId":"same"}}}"#
        )),
        IdentityAmbiguous,
        "Go derives before it validates"
    );
    assert_eq!(
        openapi_kind(&openapi_paths(
            r#"{"/a":{"get":{"operationId":" padded","responses":{"204":{"description":"ok"}}}}}"#
        )),
        IdentityUnavailable
    );
}

// ---- AsyncAPI (Go `r3/vocab/asyncapi/definition_test.go`) ----

fn asyncapi(document: &str) -> Result<AuthoritativeSnapshot, DefinitionError> {
    AsyncApiCodec::parse_definition(
        ASYNCAPI_ENDPOINT,
        &AsyncApiDocumentSource::new(document.as_bytes()),
    )
}

fn asyncapi_document(operation: &str) -> String {
    format!(
        r#"{{"asyncapi":"3.0.0","info":{{"title":"events","version":"1"}},"channels":{{"events":{{"address":"events","messages":{{}}}}}},"operations":{{"event":{operation}}}}}"#
    )
}

#[test]
fn asyncapi_definition_derives_operations_and_sparse_hints() {
    let mut exact = br##"{
		"asyncapi":"3.0.0",
		"info":{"title":"events","version":"1.0.0"},
		"operations":{
			"receiveEvent":{"action":"receive","channel":{"$ref":"#/channels/events"}},
			"publishEvent":{"action":"send","channel":{"$ref":"#/channels/events"},"x-aauth-access-mode":"person-token","x-aauth-budget":false}
		},
		"channels":{"events":{"address":"events","messages":{}}}
	}"##
    .to_vec();
    let source = AsyncApiDocumentSource::new(&exact);
    let snapshot = AsyncApiCodec::parse_definition(ASYNCAPI_ENDPOINT, &source).expect("snapshot");
    exact[0] = b'[';
    assert_eq!(snapshot.receipt().digest(), digest(source.exact_bytes()));
    assert_eq!(
        snapshot.receipt().encoding().as_str(),
        AsyncApiDocumentSource::SOURCE_ENCODING
    );
    let operations = snapshot.operations().operations().expect("operations");
    assert_eq!(operations.len(), 2);
    assert_eq!(
        operations[0].json().expect("first"),
        br#"{"operationId":"publishEvent","action":"send"}"#
    );
    let hints = hints_of(&snapshot, &operations[0]);
    assert_eq!(hints.access_mode(), Some(AccessMode::PersonToken));
    assert_eq!(hints.budget(), Some(false));
    assert_eq!(snapshot.hints_for(&operations[1]).expect("second"), None);
    snapshot
        .validate_defined(&snapshot.operations())
        .expect("own operations");
}

#[test]
fn asyncapi_definition_preserves_operation_map_keys_without_private_grammar() {
    let document =
        asyncapi_document(r##"{"action":"send","channel":{"$ref":"#/channels/events"}}"##)
            .replacen(r#""event":"#, r#""calendar.events/read":"#, 1);
    let snapshot = asyncapi(&document).expect("snapshot");
    assert_eq!(
        operation_json(&snapshot),
        [r#"{"operationId":"calendar.events/read","action":"send"}"#]
    );
}

#[test]
fn asyncapi_definition_resolves_one_escaped_or_encoded_channel_token() {
    for document in [
        r##"{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events/archive":{"address":"events"}},"operations":{"read":{"action":"receive","channel":{"$ref":"#/channels/events~1archive"}}}}"##,
        r##"{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events archive":{"address":"events"}},"operations":{"read":{"action":"receive","channel":{"$ref":"#/channels/events%20archive"}}}}"##,
    ] {
        let snapshot = asyncapi(document).expect("snapshot");
        assert_eq!(
            snapshot
                .operations()
                .operations()
                .expect("operations")
                .len(),
            1
        );
    }
}

#[test]
fn asyncapi_definition_refuses_omitted_action_as_not_defined() {
    let snapshot = asyncapi(&asyncapi_document(
        r##"{"action":"send","channel":{"$ref":"#/channels/events"}}"##,
    ))
    .expect("snapshot");
    for declared in [
        asyncapi_operation("publishEvent", None),
        // Rust: the defined name without its action is still not defined.
        asyncapi_operation("event", None),
        asyncapi_operation("event", Some("receive")),
    ] {
        assert_eq!(
            check_kind(snapshot.validate_defined(&set_of(&declared))),
            Some(OperationNotDefined)
        );
    }
    snapshot
        .validate_defined(&set_of(&asyncapi_operation("event", Some("send"))))
        .expect("defined");
}

#[test]
fn asyncapi_definition_refuses_invalid_sources() {
    let channel = r##""channel":{"$ref":"#/channels/events"}"##;
    let header = r#"{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"#;
    let cases: Vec<(&str, String, DefinitionErrorKind)> = vec![
        ("invalid JSON", "{".to_owned(), InvalidSource),
        (
            "duplicate member",
            r#"{"asyncapi":"3.0.0","asyncapi":"3.1.0","operations":{}}"#.to_owned(),
            InvalidSource,
        ),
        (
            "old version",
            r#"{"asyncapi":"2.6.0","operations":{"event":{"action":"send"}}}"#.to_owned(),
            SourceKindUnsupported,
        ),
        (
            "missing info",
            format!(
                r#"{{"asyncapi":"3.0.0","channels":{{"events":{{}}}},"operations":{{"event":{{"action":"send",{channel}}}}}}}"#
            ),
            IncompleteSource,
        ),
        (
            "missing operations",
            format!(r#"{header}"channels":{{"events":{{}}}}}}"#),
            IncompleteSource,
        ),
        (
            "empty operations",
            format!(r#"{header}"channels":{{"events":{{}}}},"operations":{{}}}}"#),
            IncompleteSource,
        ),
        (
            "reference",
            asyncapi_document(r##"{"$ref":"other.json#/event"}"##),
            UnresolvedDependency,
        ),
        (
            "missing action",
            asyncapi_document(&format!("{{{channel}}}")),
            InvalidSource,
        ),
        (
            "missing channel",
            asyncapi_document(r#"{"action":"send"}"#),
            IncompleteSource,
        ),
        (
            "external channel",
            asyncapi_document(
                r#"{"action":"send","channel":{"$ref":"https://example.test/channel"}}"#,
            ),
            UnresolvedDependency,
        ),
        (
            "nested channel pointer",
            format!(
                r##"{header}"channels":{{"events/child":{{"address":"events"}}}},"operations":{{"event":{{"action":"send","channel":{{"$ref":"#/channels/events/child"}}}}}}}}"##
            ),
            UnresolvedDependency,
        ),
        (
            "invalid channel pointer escape",
            format!(
                r##"{header}"channels":{{"events~2":{{"address":"events"}}}},"operations":{{"event":{{"action":"send","channel":{{"$ref":"#/channels/events~2"}}}}}}}}"##
            ),
            UnresolvedDependency,
        ),
        (
            "nested external reference",
            format!(
                r#"{header}"channels":{{"events":{{"address":"events","messages":{{"event":{{"$ref":"https://example.test/message"}}}}}}}},"operations":{{"event":{{"action":"send",{channel}}}}}}}"#
            ),
            UnresolvedDependency,
        ),
        (
            "operation traits",
            asyncapi_document(&format!(r#"{{"action":"send",{channel},"traits":[]}}"#)),
            SourceKindUnsupported,
        ),
        (
            "invalid access hint",
            asyncapi_document(&format!(
                r#"{{"action":"send",{channel},"x-aauth-access-mode":"session-token"}}"#
            )),
            InvalidAnnotation,
        ),
        (
            "invalid budget hint",
            asyncapi_document(&format!(
                r#"{{"action":"send",{channel},"x-aauth-budget":"yes"}}"#
            )),
            InvalidAnnotation,
        ),
        (
            "null budget hint",
            asyncapi_document(&format!(
                r#"{{"action":"send",{channel},"x-aauth-budget":null}}"#
            )),
            InvalidAnnotation,
        ),
        // Rust: Go decodes the root before it reads the version, and decodes
        // `info` leniently; it reads struct members case-insensitively.
        (
            "typed member mismatch before version",
            r#"{"asyncapi":"2.6.0","channels":[]}"#.to_owned(),
            InvalidSource,
        ),
        (
            "info without a title",
            format!(
                r#"{{"asyncapi":"3.0.0","info":{{"version":"1"}},"channels":{{"events":{{}}}},"operations":{{"event":{{"action":"send",{channel}}}}}}}"#
            ),
            IncompleteSource,
        ),
        (
            "case variant of operations",
            format!(
                r#"{header}"channels":{{"events":{{}}}},"Operations":{{}},"operations":{{"event":{{"action":"send",{channel}}}}}}}"#
            ),
            InvalidSource,
        ),
        (
            "case variant of the channel reference",
            asyncapi_document(
                r##"{"action":"send","channel":{"$ref":"#/channels/events","$REF":"#/channels/other"}}"##,
            ),
            InvalidSource,
        ),
        (
            "non-string reference",
            asyncapi_document(r#"{"action":"send","channel":{"$ref":1}}"#),
            InvalidSource,
        ),
        (
            "local operation reference is not resolved",
            asyncapi_document(r##"{"$ref":"#/components/operations/event"}"##),
            UnresolvedDependency,
        ),
    ];
    for (name, document, kind) in cases {
        let err = refused(asyncapi(&document));
        assert_eq!(err.kind(), kind, "{name}: {err}");
        assert_eq!(
            err.vocabulary().map(VocabularyUri::as_str),
            Some(AsyncApiCodec::URI)
        );
    }
}

#[test]
fn asyncapi_document_source_owns_exact_bytes() {
    let mut exact = br#"{"asyncapi":"3.0.0","operations":{"event":{"action":"send"}}}"#.to_vec();
    let source = AsyncApiDocumentSource::new(&exact);
    exact[0] = b'[';
    assert_eq!(source.exact_bytes()[0], b'{');
}

// ---- GraphQL (Go `r3/vocab/graphql/definition_test.go`) ----

fn graphql(response: &str) -> Result<AuthoritativeSnapshot, DefinitionError> {
    GraphQlCodec::parse_definition(
        GRAPHQL_ENDPOINT,
        &GraphQlIntrospectionSource::new(response.as_bytes()),
    )
}

#[test]
fn graphql_introspection_separates_invalid_and_incomplete_sources() {
    for (name, response, kind) in [
        ("invalid JSON", "{", InvalidSource),
        ("missing data", r#"{"errors":[]}"#, IncompleteSource),
        ("missing schema", r#"{"data":{}}"#, IncompleteSource),
        // Rust: Go's struct decode reads these the same way.
        ("null root", "null", IncompleteSource),
        ("null data", r#"{"data":null}"#, IncompleteSource),
        (
            "null schema",
            r#"{"data":{"__schema":null}}"#,
            IncompleteSource,
        ),
        ("data is not an object", r#"{"data":5}"#, InvalidSource),
        (
            "schema is not an object",
            r#"{"data":{"__schema":[]}}"#,
            InvalidSource,
        ),
        ("array root", "[]", InvalidSource),
        (
            "case variant of data",
            r#"{"Data":{"__schema":{}}}"#,
            InvalidSource,
        ),
        (
            "well-formed",
            r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#,
            IdentityUnavailable,
        ),
    ] {
        let err = refused(graphql(response));
        assert_eq!(err.kind(), kind, "{name}: {err}");
        assert_eq!(
            err.vocabulary().map(VocabularyUri::as_str),
            Some(GraphQlCodec::URI)
        );
    }
}

#[test]
fn graphql_introspection_source_owns_exact_bytes() {
    let mut exact = br#"{"data":{"__schema":{}}}"#.to_vec();
    let source = GraphQlIntrospectionSource::new(&exact);
    exact[0] = b'[';
    assert_eq!(source.exact_bytes(), br#"{"data":{"__schema":{}}}"#);
}
