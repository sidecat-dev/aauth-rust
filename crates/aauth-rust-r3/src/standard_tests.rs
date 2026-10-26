use crate::error::Error;
use crate::uri::VocabularyUri;
use crate::vocabulary::{Codec, GrantedOperations, Operation, OperationSet, Registry, Vocabulary};
use crate::{
    AnnotationEncoding, AsyncApiCodec, Authorization, Document, DocumentOptions, GraphQlCodec,
    GrpcCodec, McpCodec, ODataCodec, OpenApiCodec, Reference, WsdlCodec, digest,
    standard_registry, standard_vocabularies,
};

const MCP: &str = "urn:aauth:vocabulary:mcp";
const OPENAPI: &str = "urn:aauth:vocabulary:openapi";
const GRPC: &str = "urn:aauth:vocabulary:grpc";
const GRAPHQL: &str = "urn:aauth:vocabulary:graphql";
const ASYNCAPI: &str = "urn:aauth:vocabulary:asyncapi";
const WSDL: &str = "urn:aauth:vocabulary:wsdl";
const ODATA: &str = "urn:aauth:vocabulary:odata";

fn registry() -> Registry {
    standard_registry().expect("standard registry")
}

fn vocabulary(registry: &Registry, uri: &str) -> Vocabulary {
    registry
        .vocabulary(&VocabularyUri::parse(uri).expect("vocabulary URI"))
        .expect("registered vocabulary")
}

fn envelope(uri: &str, operations: &[&str]) -> String {
    format!(
        r#"{{"vocabulary":"{uri}","operations":[{}]}}"#,
        operations.join(",")
    )
}

fn set(registry: &Registry, uri: &str, operations: &[&str]) -> OperationSet {
    registry
        .parse_operation_set(envelope(uri, operations).as_bytes())
        .unwrap_or_else(|err| panic!("{uri} {operations:?}: {err}"))
}

fn granted(registry: &Registry, uri: &str, operations: &[&str]) -> GrantedOperations {
    registry
        .parse_granted_operations(envelope(uri, operations).as_bytes())
        .unwrap_or_else(|err| panic!("{uri} {operations:?}: {err}"))
}

fn json_text(value: &impl serde::Serialize) -> String {
    String::from_utf8(serde_json::to_vec(value).expect("json")).expect("utf-8")
}

fn refused<T>(result: Result<T, Error>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => err.to_string(),
    }
}

/// The samples of Go `vocabtest/standard_contract_test.go` at 0225f3f.
struct GoSample {
    uri: &'static str,
    a: &'static str,
    b: &'static str,
    unknown_member: &'static str,
    duplicate_member: &'static str,
    private: fn() -> Result<Vocabulary, Error>,
}

fn go_samples() -> [GoSample; 7] {
    [
        GoSample {
            uri: MCP,
            a: r#"{"tool":"records.read"}"#,
            b: r#"{"tool":"records.write"}"#,
            unknown_member: r#"{"tool":"records.read","unknown":true}"#,
            duplicate_member: r#"{"tool":"records.read","tool":"records.write"}"#,
            private: || Vocabulary::new(McpCodec),
        },
        GoSample {
            uri: OPENAPI,
            a: r#"{"operationId":"readRecord"}"#,
            b: r#"{"operationId":"writeRecord"}"#,
            unknown_member: r#"{"operationId":"readRecord","unknown":true}"#,
            duplicate_member: r#"{"operationId":"readRecord","operationId":"writeRecord"}"#,
            private: || Vocabulary::new(OpenApiCodec),
        },
        GoSample {
            uri: GRPC,
            a: r#"{"method":"records.RecordService/Read"}"#,
            b: r#"{"method":"records.RecordService/Write"}"#,
            unknown_member: r#"{"method":"records.RecordService/Read","unknown":true}"#,
            duplicate_member: r#"{"method":"records.RecordService/Read","method":"records.RecordService/Write"}"#,
            private: || Vocabulary::new(GrpcCodec),
        },
        GoSample {
            uri: GRAPHQL,
            a: r#"{"operation":"ReadRecord","type":"query"}"#,
            b: r#"{"operation":"WriteRecord","type":"mutation"}"#,
            unknown_member: r#"{"operation":"ReadRecord","type":"query","unknown":true}"#,
            duplicate_member: r#"{"operation":"ReadRecord","operation":"Other","type":"query"}"#,
            private: || Vocabulary::new(GraphQlCodec),
        },
        GoSample {
            uri: ASYNCAPI,
            a: r#"{"operationId":"recordRead","action":"receive"}"#,
            b: r#"{"operationId":"recordWrite","action":"send"}"#,
            unknown_member: r#"{"operationId":"recordRead","action":"receive","unknown":true}"#,
            duplicate_member: r#"{"operationId":"recordRead","operationId":"other","action":"receive"}"#,
            private: || Vocabulary::new(AsyncApiCodec),
        },
        GoSample {
            uri: WSDL,
            a: r#"{"operation":"ReadRecord","service":"RecordService"}"#,
            b: r#"{"operation":"WriteRecord","service":"RecordService"}"#,
            unknown_member: r#"{"operation":"ReadRecord","service":"RecordService","unknown":true}"#,
            duplicate_member: r#"{"operation":"ReadRecord","operation":"Other","service":"RecordService"}"#,
            private: || Vocabulary::new(WsdlCodec),
        },
        GoSample {
            uri: ODATA,
            a: r#"{"operation":"Records","methods":["GET"]}"#,
            b: r#"{"operation":"OtherRecords","methods":["POST"]}"#,
            unknown_member: r#"{"operation":"Records","methods":["GET"],"unknown":true}"#,
            duplicate_member: r#"{"operation":"Records","operation":"Other","methods":["GET"]}"#,
            private: || Vocabulary::new(ODataCodec),
        },
    ]
}

#[test]
fn standard_codecs_satisfy_the_go_vocabulary_contract() -> Result<(), Error> {
    let registry = registry();
    for sample in go_samples() {
        let uri = sample.uri;
        let a = set(&registry, uri, &[sample.a]);
        let b = set(&registry, uri, &[sample.b]);
        let both = set(&registry, uri, &[sample.a, sample.b]);

        assert_eq!(json_text(&a), envelope(uri, &[sample.a]), "{uri}");
        assert_eq!(a.operations()?[0].json()?, sample.a.as_bytes(), "{uri}");
        let reparsed = registry.parse_operation_set(json_text(&both).as_bytes())?;
        assert_eq!(json_text(&reparsed), json_text(&both), "{uri}");
        assert!(reparsed.equal(&both)?, "{uri}");

        assert!(a.equal(&a)?, "{uri}");
        assert!(!a.equal(&b)? && !b.equal(&a)?, "{uri}");
        assert!(a.is_subset_of(&a)?, "{uri}");
        assert!(a.is_subset_of(&both)? && b.is_subset_of(&both)?, "{uri}");
        assert!(!both.is_subset_of(&a)?, "{uri}");
        assert!(a.is_disjoint(&b)? && b.is_disjoint(&a)?, "{uri}");
        for (left, right) in [(&a, &a), (&b, &b), (&both, &both), (&a, &both)] {
            assert!(!left.is_disjoint(right)?, "{uri}");
        }

        let a_before = json_text(&a);
        let b_before = json_text(&b);
        let ab = a.union_with(std::slice::from_ref(&b))?;
        let ba = b.union_with(std::slice::from_ref(&a))?;
        assert!(ab.equal(&both)? && ab.equal(&ba)?, "{uri}");
        assert!(a.union_with(std::slice::from_ref(&a))?.equal(&a)?, "{uri}");
        let left_associated = ab.union_with(std::slice::from_ref(&a))?;
        let right_associated = a.union_with(std::slice::from_ref(&ba))?;
        assert!(left_associated.equal(&right_associated)?, "{uri}");
        assert!(a.is_subset_of(&ab)? && b.is_subset_of(&ab)?, "{uri}");
        assert_eq!(json_text(&a), a_before, "{uri}");
        assert_eq!(json_text(&b), b_before, "{uri}");

        for operations in [
            [sample.unknown_member].as_slice(),
            [sample.duplicate_member].as_slice(),
            [sample.a, sample.a].as_slice(),
        ] {
            assert!(
                registry
                    .parse_operation_set(envelope(uri, operations).as_bytes())
                    .is_err(),
                "{uri} accepted {operations:?}"
            );
        }
        let extra = format!(
            r#"{{"vocabulary":"{uri}","operations":[{}],"extra":true}}"#,
            sample.a
        );
        assert!(registry.parse_operation_set(extra.as_bytes()).is_err(), "{uri}");
        let doubled = format!(
            r#"{{"vocabulary":"{uri}","vocabulary":"{uri}","operations":[{}]}}"#,
            sample.a
        );
        assert!(registry.parse_operation_set(doubled.as_bytes()).is_err(), "{uri}");

        let private = (sample.private)()?;
        let private_set = Registry::new(std::slice::from_ref(&private))?
            .parse_operation_set(envelope(uri, &[sample.a]).as_bytes())?;
        assert!(private_set.equal(&a).is_err(), "{uri}");
        assert!(private_set.is_subset_of(&a).is_err(), "{uri}");
        assert!(private_set.is_disjoint(&a).is_err(), "{uri}");
        assert!(private_set.union_with(std::slice::from_ref(&a)).is_err(), "{uri}");
        assert!(registry.validate_operation_set(&private_set).is_err(), "{uri}");
        assert!(
            Registry::new(&[vocabulary(&registry, uri), private]).is_err(),
            "{uri}"
        );
    }
    Ok(())
}

#[test]
fn standard_vocabularies_are_stable_registrations_with_draft_annotations() -> Result<(), Error> {
    let vocabularies = standard_vocabularies()?;
    let want = [
        (MCP, AnnotationEncoding::MCP_META),
        (OPENAPI, AnnotationEncoding::SPECIFICATION_EXTENSION),
        (GRPC, AnnotationEncoding::UNAVAILABLE),
        (GRAPHQL, AnnotationEncoding::UNAVAILABLE),
        (ASYNCAPI, AnnotationEncoding::SPECIFICATION_EXTENSION),
        (WSDL, AnnotationEncoding::UNAVAILABLE),
        (ODATA, AnnotationEncoding::ODATA_METADATA),
    ];
    assert_eq!(vocabularies.len(), want.len());
    for (vocabulary, (uri, encoding)) in vocabularies.iter().zip(want) {
        assert_eq!(vocabulary.uri().as_str(), uri);
        assert_eq!(vocabulary.annotation_encoding(), encoding, "{uri}");
    }
    let constants = [
        McpCodec::URI,
        OpenApiCodec::URI,
        GrpcCodec::URI,
        GraphQlCodec::URI,
        AsyncApiCodec::URI,
        WsdlCodec::URI,
        ODataCodec::URI,
    ];
    assert_eq!(constants, [MCP, OPENAPI, GRPC, GRAPHQL, ASYNCAPI, WSDL, ODATA]);
    assert_eq!(ODataCodec.uri().as_str(), ODATA);

    let registry = standard_registry()?;
    assert_eq!(registry.len(), 7);
    let tool = br#"{"tool":"create_calendar_event"}"#;
    let first = Operation::new(&vocabularies[0], tool)?;
    let again = Operation::new(&standard_vocabularies()?[0], tool)?;
    let via_codec = Operation::new(&McpCodec::vocabulary()?, tool)?;
    assert!(first.equal(&again)?);
    assert!(first.equal(&via_codec)?);
    registry.validate_operation_set(&OperationSet::new(&[again])?)?;

    let private = Operation::new(&Vocabulary::new(McpCodec)?, tool)?;
    assert!(first.equal(&private).is_err());
    assert!(
        registry
            .validate_operation_set(&OperationSet::new(&[private])?)
            .is_err()
    );
    assert!(Registry::new(&[McpCodec::vocabulary()?, Vocabulary::new(McpCodec)?]).is_err());
    Ok(())
}

#[test]
fn standard_discovery_endpoints_follow_the_go_https_profile() -> Result<(), Error> {
    let accepted = [
        "https://resource.example/definition?version=current",
        "HTTPS://RESOURCE.EXAMPLE/definition",
        "https://grpc.example/reflection?service=records.v1.Records",
        "https://grpc.example/records.proto",
        "https://calendar.example.com:8443/odata/",
        "https://[2001:db8::1]/calendar.wsdl?version=2",
        "https://b\u{fc}cher.example/definition",
        "https://resource.example/%E2%82%AC/definition",
        "https://resource.example/definition?filter=%zz",
    ];
    let rejected = [
        "",
        " https://resource.example/definition",
        "https://resource.example/definition ",
        "https://resource.example/definition\u{a0}",
        "/relative/definition",
        "http://resource.example/definition",
        "https:opaque-definition",
        "https:///definition-without-host",
        "https://user@resource.example/definition",
        "https://resource.example/definition#section",
        "dns:///grpc.example",
        "grpc://grpc.example",
        "https://resource.example/defi\u{7f}nition",
        "https://resource.example/%zz",
        "https://resource.example/%4",
        "https://exa{mple.com/definition",
        "https://exa%41mple.com/definition",
        // Go net/url accepts a raw space in a path. The shared HTTPS check does not.
        "https://resource.example/open api.json",
    ];
    for vocabulary in standard_vocabularies()? {
        for endpoint in accepted {
            vocabulary.validate_discovery_endpoint(endpoint)?;
        }
        for endpoint in rejected {
            assert!(
                vocabulary.validate_discovery_endpoint(endpoint).is_err(),
                "{} accepted {endpoint:?}",
                vocabulary.uri()
            );
        }
    }
    Ok(())
}

#[test]
fn standard_draft_examples_round_trip_byte_for_byte() -> Result<(), Error> {
    let registry = registry();
    let examples: [(&str, &[&str]); 7] = [
        (
            MCP,
            &[
                r#"{"tool":"create_calendar_event"}"#,
                r#"{"tool":"modify_calendar_event"}"#,
            ],
        ),
        (
            OPENAPI,
            &[
                r#"{"operationId":"createEvent"}"#,
                r#"{"operationId":"updateEvent"}"#,
            ],
        ),
        (
            GRPC,
            &[
                r#"{"method":"calendar.CalendarService/CreateEvent"}"#,
                r#"{"method":"calendar.CalendarService/UpdateEvent"}"#,
            ],
        ),
        (
            GRAPHQL,
            &[
                r#"{"operation":"CreateCalendarEvent","type":"mutation"}"#,
                r#"{"operation":"GetCalendarEvents","type":"query"}"#,
            ],
        ),
        (
            ASYNCAPI,
            &[
                r#"{"operationId":"publishCalendarUpdate","action":"send"}"#,
                r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#,
            ],
        ),
        (
            WSDL,
            &[r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#],
        ),
        (
            ODATA,
            &[
                r#"{"operation":"Events","methods":["GET","POST","PATCH"]}"#,
                r#"{"operation":"Events/SendCancellation"}"#,
            ],
        ),
    ];
    for (uri, operations) in examples {
        let source = envelope(uri, operations);
        assert_eq!(
            json_text(&registry.parse_operation_set(source.as_bytes())?),
            source
        );
        assert_eq!(
            json_text(&registry.parse_granted_operations(source.as_bytes())?),
            source
        );
        let vocabulary = vocabulary(&registry, uri);
        for operation in operations {
            assert_eq!(
                Operation::new(&vocabulary, operation.as_bytes())?.json()?,
                operation.as_bytes()
            );
        }
    }
    Ok(())
}

#[test]
fn standard_codecs_emit_one_canonical_spelling() -> Result<(), Error> {
    let registry = registry();
    let cases = [
        (
            MCP,
            r#" { "tool" : "café_tool" } "#,
            "{\"tool\":\"caf\u{e9}_tool\"}",
        ),
        (
            OPENAPI,
            r#"{"operationId":"list\/events"}"#,
            r#"{"operationId":"list/events"}"#,
        ),
        (
            GRPC,
            r#"{ "method" : "calendar.v1.CalendarService/ListEvents" }"#,
            r#"{"method":"calendar.v1.CalendarService/ListEvents"}"#,
        ),
        (
            GRAPHQL,
            r#"{"type":"query","operation":"GetCalendarEvents"}"#,
            r#"{"operation":"GetCalendarEvents","type":"query"}"#,
        ),
        (
            ASYNCAPI,
            r#"{"action":"receive","operationId":"receiveCalendarEvent"}"#,
            r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#,
        ),
        (
            WSDL,
            r#"{"service":"CalendarService","operation":"CreateCalendarEvent"}"#,
            r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#,
        ),
        (
            ODATA,
            r#"{"methods":["POST","GET"],"operation":"Events"}"#,
            r#"{"operation":"Events","methods":["POST","GET"]}"#,
        ),
    ];
    for (uri, source, canonical) in cases {
        let vocabulary = vocabulary(&registry, uri);
        let operation = Operation::new(&vocabulary, source.as_bytes())?;
        assert_eq!(operation.json()?, canonical.as_bytes(), "{uri}");
        assert!(operation.equal(&Operation::new(&vocabulary, canonical.as_bytes())?)?);
    }

    let codec = OpenApiCodec;
    let parsed = codec.parse_set(&[
        br#"{ "operationId" : "createEvent" }"#.to_vec(),
        br#"{"operationId":"updateEvent"}"#.to_vec(),
    ])?;
    assert_eq!(
        codec.marshal_set(&parsed)?,
        [
            br#"{"operationId":"createEvent"}"#.to_vec(),
            br#"{"operationId":"updateEvent"}"#.to_vec(),
        ]
    );
    Ok(())
}

#[test]
fn standard_codecs_reject_malformed_unknown_and_duplicate_members() {
    let registry = registry();
    let not_object = "operation must be a JSON object";
    let untrimmed = "must not have surrounding whitespace";
    let not_string = "must be a string";
    let grpc_form = "package.ServiceName/MethodName";
    let graphql_name = "is not a GraphQL name";
    let graphql_type = "is not query, mutation, or subscription";
    let asyncapi_action = "is not send or receive";
    let odata_token = "is not an HTTP method token";
    let rejected = [
        (MCP, "{}", r#"missing member "tool""#),
        (MCP, r#"{"tool":""}"#, r#"member "tool" must not be empty"#),
        (MCP, r#"{"tool":" calendar.create"}"#, untrimmed),
        (MCP, r#"{"tool":"calendar.create "}"#, untrimmed),
        (MCP, r#"{"tool":null}"#, not_string),
        (MCP, r#"{"tool":7}"#, not_string),
        (MCP, r#"{"tool":["create_calendar_event"]}"#, not_string),
        (MCP, r#"{"tool":"a","tool":"b"}"#, r#"duplicate member "tool""#),
        (MCP, r#"{"tool":"a","tool":"a"}"#, r#"duplicate member "tool""#),
        (MCP, r#"{"Tool":"a"}"#, r#"unknown member "Tool""#),
        (MCP, r#"{"tool":"a","arguments":{}}"#, r#"unknown member "arguments""#),
        (
            MCP,
            r#"{"tool":"a","_meta":{"aauth.dev/access-mode":"per-call"}}"#,
            r#"unknown member "_meta""#,
        ),
        (MCP, r#"{"operationId":"a"}"#, r#"unknown member "operationId""#),
        (MCP, r#""create_calendar_event""#, not_object),
        (MCP, r#"["tool"]"#, not_object),
        (MCP, "null", not_object),
        (OPENAPI, "{}", r#"missing member "operationId""#),
        (OPENAPI, r#"{"operationId":""}"#, "must not be empty"),
        (OPENAPI, r#"{"operationId":" createEvent"}"#, untrimmed),
        (OPENAPI, r#"{"operationId":null}"#, not_string),
        (OPENAPI, r#"{"operationID":"createEvent"}"#, r#"unknown member "operationID""#),
        (OPENAPI, r#"{"OperationId":"createEvent"}"#, r#"unknown member "OperationId""#),
        (
            OPENAPI,
            r#"{"operationId":"createEvent","method":"post"}"#,
            r#"unknown member "method""#,
        ),
        (
            OPENAPI,
            r#"{"operationId":"purchaseDataset","x-aauth-access-mode":"per-call"}"#,
            r#"unknown member "x-aauth-access-mode""#,
        ),
        (OPENAPI, r#"{"operationId":{"name":"createEvent"}}"#, not_string),
        (GRPC, r#"{"method":null}"#, not_string),
        (GRPC, r#"{"method":" calendar.CalendarService/CreateEvent"}"#, untrimmed),
        (GRPC, r#"{"method":"CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"/calendar.CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":".calendar.CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarServiceCreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarService/"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar..CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.2CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarService/2CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarService/Create.Event"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarService/Create/Event"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.Calendar-Service/CreateEvent"}"#, grpc_form),
        (
            GRPC,
            r#"{"method":"calendar.CalendarService/CreateEvent","service":"CalendarService"}"#,
            r#"unknown member "service""#,
        ),
        (GRAPHQL, r#"{"operation":"CalendarEvent"}"#, r#"missing member "type""#),
        (GRAPHQL, r#"{"type":"query"}"#, r#"missing member "operation""#),
        (
            GRAPHQL,
            r#"{"operation":"","type":"query"}"#,
            r#"member "operation" must not be empty"#,
        ),
        (GRAPHQL, r#"{"operation":null,"type":"query"}"#, not_string),
        (GRAPHQL, r#"{"operation":" CreateCalendarEvent","type":"query"}"#, untrimmed),
        (GRAPHQL, r#"{"operation":"CalendarEvent","type":"mutation "}"#, untrimmed),
        (GRAPHQL, r#"{"operation":"CalendarEvent","type":"QUERY"}"#, graphql_type),
        (GRAPHQL, r#"{"operation":"CalendarEvent","type":"fragment"}"#, graphql_type),
        (
            GRAPHQL,
            r#"{"operation":"CalendarEvent","type":null}"#,
            r#"member "type" must be a string"#,
        ),
        (GRAPHQL, r#"{"operation":"2CreateCalendarEvent","type":"query"}"#, graphql_name),
        (GRAPHQL, r#"{"operation":"Create-Calendar-Event","type":"query"}"#, graphql_name),
        (GRAPHQL, r#"{"operation":"Create.Calendar.Event","type":"query"}"#, graphql_name),
        (
            GRAPHQL,
            r#"{"Operation":"CalendarEvent","type":"query"}"#,
            r#"unknown member "Operation""#,
        ),
        (
            GRAPHQL,
            r#"{"operation":"CalendarEvent","type":"query","type":"mutation"}"#,
            r#"duplicate member "type""#,
        ),
        (ASYNCAPI, r#"{"action":"send"}"#, r#"missing member "operationId""#),
        (ASYNCAPI, r#"{"operationId":""}"#, "must not be empty"),
        (ASYNCAPI, r#"{"operationId":" x "}"#, untrimmed),
        (ASYNCAPI, r#"{"operationId":"x","action":"publish"}"#, asyncapi_action),
        (ASYNCAPI, r#"{"operationId":"x","action":"subscribe"}"#, asyncapi_action),
        (ASYNCAPI, r#"{"operationId":"x","action":"Receive"}"#, asyncapi_action),
        (
            ASYNCAPI,
            r#"{"operationId":"x","action":null}"#,
            r#"member "action" must be a string"#,
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"x","action":""}"#,
            r#"member "action" must not be empty"#,
        ),
        (ASYNCAPI, r#"{"operationId":"x","action":["receive"]}"#, not_string),
        (ASYNCAPI, r#"{"operationId":"x","extra":true}"#, r#"unknown member "extra""#),
        (WSDL, r#"{"service":"CalendarService"}"#, r#"missing member "operation""#),
        (WSDL, r#"{"operation":""}"#, "must not be empty"),
        (WSDL, r#"{"operation":" x "}"#, untrimmed),
        (
            WSDL,
            r#"{"operation":"x","service":null}"#,
            r#"member "service" must be a string"#,
        ),
        (
            WSDL,
            r#"{"operation":"x","service":""}"#,
            r#"member "service" must not be empty"#,
        ),
        (WSDL, r#"{"operation":"x","service":"CalendarService "}"#, untrimmed),
        (WSDL, r#"{"operation":"x","port":"CalendarPort"}"#, r#"unknown member "port""#),
        (WSDL, r#"{"operation":"x","operation":"y"}"#, r#"duplicate member "operation""#),
        (ODATA, r#"{"methods":["GET"]}"#, r#"missing member "operation""#),
        (ODATA, r#"{"operation":""}"#, "must not be empty"),
        (ODATA, r#"{"operation":" x "}"#, untrimmed),
        (
            ODATA,
            r#"{"operation":"Events","methods":[]}"#,
            r#"member "methods" must not be empty"#,
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":null}"#,
            r#"member "methods" must be an array"#,
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":"GET"}"#,
            r#"member "methods" must be an array"#,
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":["GET","GET"]}"#,
            r#"method "GET" is repeated"#,
        ),
        (ODATA, r#"{"operation":"Events","methods":["BAD METHOD"]}"#, odata_token),
        (ODATA, r#"{"operation":"Events","methods":[""]}"#, odata_token),
        (ODATA, r#"{"operation":"Events","methods":["GÉT"]}"#, odata_token),
        (
            ODATA,
            r#"{"operation":"Events","methods":[1]}"#,
            "must contain only strings",
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":[null]}"#,
            "must contain only strings",
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":["GET"],"filter":"Start gt 2026"}"#,
            r#"unknown member "filter""#,
        ),
        (ODATA, r#"{"operation":"x","operation":"y"}"#, r#"duplicate member "operation""#),
    ];
    for &(uri, operation, reason) in &rejected {
        let vocabulary = vocabulary(&registry, uri);
        let message = refused(Operation::new(&vocabulary, operation.as_bytes()));
        assert!(message.contains(reason), "{uri} {operation}: {message}");
        let source = envelope(uri, &[operation]);
        assert!(
            registry.parse_operation_set(source.as_bytes()).is_err(),
            "{uri} set accepted {operation}"
        );
        assert!(
            registry.parse_granted_operations(source.as_bytes()).is_err(),
            "{uri} grant accepted {operation}"
        );
    }
}

#[test]
fn standard_codecs_accept_what_the_go_codecs_accept() -> Result<(), Error> {
    let registry = registry();
    let long_name = format!(r#"{{"operation":"{}"}}"#, "E".repeat(129));
    let accepted = [
        (MCP, r#"{"tool":"calendar create"}"#),
        (MCP, r#"{"tool":"日本"}"#),
        (OPENAPI, r#"{"operationId":"list events/v2"}"#),
        (GRPC, r#"{"method":"_package._Service/_Method"}"#),
        (
            GRPC,
            r#"{"method":"com.example.calendar.Calendar_Service/Create_Event2"}"#,
        ),
        (GRAPHQL, r#"{"operation":"_CalendarEvent2","type":"subscription"}"#),
        (ASYNCAPI, r#"{"operationId":"calendar.event-received"}"#),
        (WSDL, r#"{"operation":"tns:CreateCalendarEvent"}"#),
        (
            WSDL,
            r#"{"operation":"1CreateCalendarEvent","service":"Calendar Service"}"#,
        ),
        (ODATA, r#"{"operation":"Events/Calendar.SendCancellation"}"#),
        (ODATA, r#"{"operation":"Events(1)"}"#),
        (ODATA, r#"{"operation":"Événements","methods":["GET"]}"#),
        (
            ODATA,
            r#"{"operation":"Events/SendCancellation","methods":["POST"]}"#,
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":["get","MERGE","X-Custom"]}"#,
        ),
        (ODATA, long_name.as_str()),
    ];
    for (uri, operation) in accepted {
        Operation::new(&vocabulary(&registry, uri), operation.as_bytes())
            .map_err(|err| Error::wrap(format!("{uri} {operation}"), err))?;
        registry.parse_operation_set(envelope(uri, &[operation]).as_bytes())?;
    }
    Ok(())
}

#[test]
fn standard_codecs_reject_a_repeated_or_overlapping_operation_in_one_set() {
    let registry = registry();
    let repeated = [
        (
            MCP,
            [
                r#"{"tool":"create_calendar_event"}"#,
                r#"{"tool":"create_calendar_event"}"#,
            ],
            "repeats",
        ),
        (MCP, [r#"{"tool":"a"}"#, r#"{"tool":"a"}"#], "repeats"),
        (
            OPENAPI,
            [
                r#"{"operationId":"createEvent"}"#,
                r#"{"operationId":"createEvent"}"#,
            ],
            "repeats",
        ),
        (
            GRPC,
            [
                r#"{"method":"calendar.CalendarService/CreateEvent"}"#,
                r#"{"method":"calendar.CalendarService/CreateEvent"}"#,
            ],
            "repeats",
        ),
        (
            GRAPHQL,
            [
                r#"{"operation":"CalendarEvents","type":"query"}"#,
                r#"{"type":"query","operation":"CalendarEvents"}"#,
            ],
            "repeats",
        ),
        (
            ASYNCAPI,
            [
                r#"{"operationId":"receiveCalendarEvent"}"#,
                r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#,
            ],
            "overlaps",
        ),
        (
            ASYNCAPI,
            [
                r#"{"operationId":"receiveCalendarEvent","action":"send"}"#,
                r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#,
            ],
            "overlaps",
        ),
        (
            WSDL,
            [
                r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#,
                r#"{"service":"CalendarService","operation":"CreateCalendarEvent"}"#,
            ],
            "repeats",
        ),
        (
            WSDL,
            [
                r#"{"operation":"CreateCalendarEvent"}"#,
                r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#,
            ],
            "overlaps",
        ),
        (
            ODATA,
            [
                r#"{"operation":"Events","methods":["GET"]}"#,
                r#"{"operation":"Events","methods":["POST"]}"#,
            ],
            "overlaps",
        ),
        (
            ODATA,
            [
                r#"{"operation":"Events"}"#,
                r#"{"operation":"Events","methods":["GET"]}"#,
            ],
            "overlaps",
        ),
    ];
    for (uri, operations, reason) in repeated {
        let source = envelope(uri, &operations);
        let message = refused(registry.parse_operation_set(source.as_bytes()));
        assert!(message.contains(reason), "{uri}: {message}");
        assert!(registry.parse_granted_operations(source.as_bytes()).is_err());
        assert!(registry.parse_document(source.as_bytes()).is_err());
    }
}

#[test]
fn standard_registry_refuses_unregistered_and_mismatched_vocabularies() -> Result<(), Error> {
    let registry = registry();
    for uri in [
        "urn:aauth:vocabulary:soap",
        "urn:aauth:vocabulary:mcp:v2",
        "https://example.test/vocabulary/mcp",
    ] {
        let source = envelope(uri, &[r#"{"tool":"create_calendar_event"}"#]);
        assert!(registry.parse_operation_set(source.as_bytes()).is_err(), "{uri}");
        assert!(registry.parse_granted_operations(source.as_bytes()).is_err(), "{uri}");
    }
    let only_mcp = Registry::new(&[McpCodec::vocabulary()?])?;
    let openapi_source = envelope(OPENAPI, &[r#"{"operationId":"createEvent"}"#]);
    assert!(only_mcp.parse_operation_set(openapi_source.as_bytes()).is_err());
    let borrowed_shape = envelope(GRAPHQL, &[r#"{"operationId":"createEvent"}"#]);
    assert!(registry.parse_operation_set(borrowed_shape.as_bytes()).is_err());

    let mcp = set(&registry, MCP, &[r#"{"tool":"createEvent"}"#]);
    let openapi = registry.parse_operation_set(openapi_source.as_bytes())?;
    assert!(mcp.equal(&openapi).is_err());
    assert!(mcp.is_subset_of(&openapi).is_err());
    assert!(mcp.is_disjoint(&openapi).is_err());
    assert!(mcp.union_with(&[openapi]).is_err());
    Ok(())
}

#[test]
fn standard_registry_algebra_holds_for_each_vocabulary() -> Result<(), Error> {
    let registry = registry();
    let cases = [
        (
            MCP,
            r#"{"tool":"list_calendar_events"}"#,
            r#"{"tool":"modify_calendar_event"}"#,
            r#"{"tool":"create_calendar_event"}"#,
        ),
        (
            OPENAPI,
            r#"{"operationId":"listEvents"}"#,
            r#"{"operationId":"updateEvent"}"#,
            r#"{"operationId":"createEvent"}"#,
        ),
        (
            GRPC,
            r#"{"method":"calendar.CalendarService/ListEvents"}"#,
            r#"{"method":"calendar.CalendarService/UpdateEvent"}"#,
            r#"{"method":"calendar.CalendarService/CreateEvent"}"#,
        ),
        (
            GRAPHQL,
            r#"{"operation":"GetCalendarEvents","type":"query"}"#,
            r#"{"operation":"UpdateCalendarEvent","type":"mutation"}"#,
            r#"{"operation":"CalendarEventChanged","type":"subscription"}"#,
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#,
            r#"{"operationId":"publishCalendarUpdate","action":"send"}"#,
            r#"{"operationId":"auditCalendar"}"#,
        ),
        (
            WSDL,
            r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#,
            r#"{"operation":"CreateCalendarEvent","service":"ArchiveService"}"#,
            r#"{"operation":"CancelCalendarEvent"}"#,
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":["GET"]}"#,
            r#"{"operation":"Calendars"}"#,
            r#"{"operation":"Events/SendCancellation"}"#,
        ),
    ];
    for (uri, a, b, c) in cases {
        let ab = set(&registry, uri, &[a, b]);
        let ba = set(&registry, uri, &[b, a]);
        let only_a = set(&registry, uri, &[a]);
        let only_c = set(&registry, uri, &[c]);
        let all = set(&registry, uri, &[a, b, c]);
        assert!(ab.equal(&ba)?, "{uri}");
        assert!(!ab.equal(&all)?, "{uri}");
        assert!(only_a.is_subset_of(&ab)?, "{uri}");
        assert!(ab.is_subset_of(&all)?, "{uri}");
        assert!(!ab.is_subset_of(&only_a)?, "{uri}");
        assert!(!only_c.is_subset_of(&ab)?, "{uri}");
        assert!(only_c.is_disjoint(&ab)?, "{uri}");
        assert!(!only_a.is_disjoint(&ab)?, "{uri}");
        let union = only_c.union_with(&[ab.clone(), only_a.clone()])?;
        assert!(union.equal(&all)?, "{uri}");
        assert_eq!(json_text(&union), envelope(uri, &[c, a, b]), "{uri}");

        let document = Document::new(&all, DocumentOptions::default())?;
        let authorization = Authorization::new(
            &granted(&registry, uri, &[a, b]),
            &granted(&registry, uri, &[c]),
            &document,
        )?;
        let call = Operation::new(&vocabulary(&registry, uri), c.as_bytes())?;
        assert!(authorization.per_call_operations().contains(&call)?, "{uri}");
        assert!(!authorization.granted_operations().contains(&call)?, "{uri}");
        assert!(
            Authorization::new(
                &granted(&registry, uri, &[a]),
                &granted(&registry, uri, &[a, c]),
                &document,
            )
            .is_err(),
            "{uri}"
        );
        let narrow = Document::new(&ab, DocumentOptions::default())?;
        assert!(
            registry
                .parse_grant(envelope(uri, &[c]).as_bytes(), &narrow)
                .is_err(),
            "{uri}"
        );
    }
    Ok(())
}

#[test]
fn standard_graphql_identity_is_the_name_and_type_pair() -> Result<(), Error> {
    let registry = registry();
    let query = r#"{"operation":"CalendarEvents","type":"query"}"#;
    let subscription = r#"{"operation":"CalendarEvents","type":"subscription"}"#;
    let query_set = set(&registry, GRAPHQL, &[query]);
    let subscription_set = set(&registry, GRAPHQL, &[subscription]);
    let both = set(&registry, GRAPHQL, &[query, subscription]);
    assert!(!query_set.equal(&subscription_set)?);
    assert!(!query_set.is_subset_of(&subscription_set)?);
    assert!(query_set.is_disjoint(&subscription_set)?);
    let union = query_set.union_with(std::slice::from_ref(&subscription_set))?;
    assert!(union.equal(&both)?);
    let document = Document::new(&both, DocumentOptions::default())?;
    Authorization::new(
        &granted(&registry, GRAPHQL, &[query]),
        &granted(&registry, GRAPHQL, &[subscription]),
        &document,
    )?;
    Ok(())
}

/// Go reports `{op}`, `{op,send}`, and `{op,receive}` pairwise disjoint. They name
/// one operationId, so this port keeps them overlapping. A document holds only one
/// spelling, so `Authorization` refuses the pairing in both ports by containment.
#[test]
fn standard_asyncapi_one_operation_id_is_never_disjoint_from_itself() -> Result<(), Error> {
    let registry = registry();
    let bare = r#"{"operationId":"receiveCalendarEvent"}"#;
    let receive = r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#;
    let send = r#"{"operationId":"receiveCalendarEvent","action":"send"}"#;
    let bare_set = set(&registry, ASYNCAPI, &[bare]);
    let receive_set = set(&registry, ASYNCAPI, &[receive]);
    let send_set = set(&registry, ASYNCAPI, &[send]);
    assert_eq!(json_text(&bare_set), envelope(ASYNCAPI, &[bare]));
    assert!(!bare_set.equal(&send_set)?);
    assert!(!bare_set.is_subset_of(&receive_set)?);
    assert!(!receive_set.is_subset_of(&bare_set)?);
    assert!(!receive_set.is_subset_of(&send_set)?);
    assert!(!bare_set.is_disjoint(&receive_set)?);
    assert!(!receive_set.is_disjoint(&send_set)?);
    assert!(
        bare_set
            .union_with(std::slice::from_ref(&receive_set))
            .is_err()
    );
    assert!(
        receive_set
            .union_with(std::slice::from_ref(&send_set))
            .is_err()
    );
    assert!(
        send_set
            .union_with(std::slice::from_ref(&send_set))?
            .equal(&send_set)?
    );

    let document = Document::new(&receive_set, DocumentOptions::default())?;
    assert!(
        Authorization::new(
            &granted(&registry, ASYNCAPI, &[bare]),
            &granted(&registry, ASYNCAPI, &[receive]),
            &document,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn standard_wsdl_unqualified_operation_overlaps_every_service() -> Result<(), Error> {
    let registry = registry();
    let unqualified = r#"{"operation":"CreateCalendarEvent"}"#;
    let calendar = r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#;
    let archive = r#"{"operation":"CreateCalendarEvent","service":"ArchiveService"}"#;
    let unqualified_set = set(&registry, WSDL, &[unqualified]);
    let calendar_set = set(&registry, WSDL, &[calendar]);
    let archive_set = set(&registry, WSDL, &[archive]);
    assert_eq!(json_text(&unqualified_set), envelope(WSDL, &[unqualified]));

    let message = refused(
        registry.parse_operation_set(envelope(WSDL, &[unqualified, calendar]).as_bytes()),
    );
    assert!(message.contains("overlaps"), "{message}");
    let message = refused(unqualified_set.union_with(std::slice::from_ref(&calendar_set)));
    assert!(message.contains("conflicting entries"), "{message}");
    assert!(!unqualified_set.is_subset_of(&calendar_set)?);
    assert!(!calendar_set.is_subset_of(&unqualified_set)?);
    assert!(!unqualified_set.is_disjoint(&calendar_set)?);
    assert!(calendar_set.is_disjoint(&archive_set)?);

    let qualified = calendar_set.union_with(std::slice::from_ref(&archive_set))?;
    assert_eq!(json_text(&qualified), envelope(WSDL, &[calendar, archive]));
    let document = Document::new(&qualified, DocumentOptions::default())?;
    Authorization::new(
        &granted(&registry, WSDL, &[calendar]),
        &granted(&registry, WSDL, &[archive]),
        &document,
    )?;
    Ok(())
}

#[test]
fn standard_odata_methods_compare_as_a_set_and_absence_stays_distinct() -> Result<(), Error> {
    let registry = registry();
    let odata = vocabulary(&registry, ODATA);
    let events = r#"{"operation":"Events"}"#;
    let get = r#"{"operation":"Events","methods":["GET"]}"#;
    let post = r#"{"operation":"Events","methods":["POST"]}"#;
    let get_post = r#"{"operation":"Events","methods":["GET","POST"]}"#;
    let post_get = r#"{"operation":"Events","methods":["POST","GET"]}"#;
    let events_set = set(&registry, ODATA, &[events]);
    let get_set = set(&registry, ODATA, &[get]);
    let post_set = set(&registry, ODATA, &[post]);
    let get_post_set = set(&registry, ODATA, &[get_post]);
    assert!(get_set.is_subset_of(&get_post_set)?);
    assert!(!get_post_set.is_subset_of(&get_set)?);
    assert!(get_post_set.equal(&set(&registry, ODATA, &[post_get]))?);
    // Go's Equal is `len && subset`, so it reports GET equal to GET+POST.
    assert!(!get_set.equal(&get_post_set)?);
    assert!(!get_post_set.equal(&get_set)?);
    assert!(get_set.is_disjoint(&post_set)?);
    assert!(!get_set.is_disjoint(&get_post_set)?);
    let merged = get_set.union_with(std::slice::from_ref(&post_set))?;
    assert_eq!(json_text(&merged), envelope(ODATA, &[get_post]));

    assert_eq!(json_text(&events_set), envelope(ODATA, &[events]));
    assert!(!get_set.is_subset_of(&events_set)?);
    assert!(!events_set.is_subset_of(&get_set)?);
    assert!(!events_set.is_disjoint(&get_set)?);
    let message = refused(events_set.union_with(std::slice::from_ref(&get_set)));
    assert!(message.contains("conflicting entries"), "{message}");

    let document = Document::new(
        &set(
            &registry,
            ODATA,
            &[
                r#"{"operation":"Events","methods":["GET","POST","PATCH"]}"#,
                r#"{"operation":"Events/SendCancellation"}"#,
            ],
        ),
        DocumentOptions::default(),
    )?;
    let authorization = Authorization::new(
        &granted(&registry, ODATA, &[get]),
        &granted(
            &registry,
            ODATA,
            &[
                r#"{"operation":"Events","methods":["POST","PATCH"]}"#,
                r#"{"operation":"Events/SendCancellation"}"#,
            ],
        ),
        &document,
    )?;
    assert!(
        authorization
            .granted_operations()
            .contains(&Operation::new(&odata, get.as_bytes())?)?
    );
    assert!(
        authorization
            .per_call_operations()
            .contains(&Operation::new(&odata, post.as_bytes())?)?
    );
    assert!(
        !authorization
            .granted_operations()
            .contains(&Operation::new(&odata, post.as_bytes())?)?
    );
    assert!(
        Authorization::new(
            &granted(&registry, ODATA, &[get_post]),
            &granted(&registry, ODATA, &[post]),
            &document,
        )
        .is_err()
    );
    assert!(
        registry
            .parse_grant(
                envelope(ODATA, &[r#"{"operation":"Events","methods":["DELETE"]}"#]).as_bytes(),
                &document,
            )
            .is_err()
    );
    assert!(
        registry
            .parse_grant(envelope(ODATA, &[events]).as_bytes(), &document)
            .is_err()
    );
    Ok(())
}

#[test]
fn standard_mcp_document_subset_grant_and_one_tool_proposal() -> Result<(), Error> {
    let registry = registry();
    let document_source = r#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_calendar_events"},{"tool":"create_calendar_event"},{"tool":"modify_calendar_event"}],"account":"dick@example.com","display":{"summary":"Create and modify events on your work calendar (dick@example.com)","implications":"Meetings can be scheduled or rescheduled. Existing events can be modified.","data_accessed":"Event titles, times, attendees, and descriptions in the work calendar","irreversible":"Sent meeting invitations cannot be unsent"}}"#;
    let document_reference = Reference::new(
        "https://calendar.example.com/r3/a1b2c3d4",
        digest(document_source.as_bytes()),
    )?;
    let document =
        registry.parse_referenced_document(&document_reference, document_source.as_bytes())?;
    assert_eq!(json_text(&document), document_source);

    let grant = registry.parse_grant(
        br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"modify_calendar_event"},{"tool":"list_calendar_events"}]}"#,
        &document,
    )?;
    let per_call = registry.parse_granted_operations(
        br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"create_calendar_event"}]}"#,
    )?;
    let authorization = Authorization::new(&grant.granted_operations(), &per_call, &document)?;

    let notes = b"Agenda: Q3 planning, room 4B, bring the roadmap";
    let proposal_source = format!(
        r#"{{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{{"tool":"create_calendar_event"}}],"parameters":{{"attendees":["mom@example.com"],"notes":{{"s256":"{}","excerpt":"Agenda: Q3 planning","media_type":"text/plain"}},"title":"Planning"}},"display":{{"summary":"Create one event on your work calendar"}}}}"#,
        digest(notes)
    );
    let proposal_reference = Reference::new(
        "https://calendar.example.com/r3/proposal-7f3c",
        digest(proposal_source.as_bytes()),
    )?;
    let proposal =
        registry.parse_referenced_proposal(&proposal_reference, proposal_source.as_bytes())?;
    assert_eq!(json_text(&proposal), proposal_source);
    let tool = proposal.operation();
    assert_eq!(tool.json()?, br#"{"tool":"create_calendar_event"}"#);
    assert!(authorization.per_call_operations().contains(&tool)?);
    assert!(!authorization.granted_operations().contains(&tool)?);
    assert!(
        OperationSet::new(std::slice::from_ref(&tool))?
            .is_subset_of(&document.operation_set())?
    );

    assert!(
        registry
            .parse_grant(
                br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"delete_calendar"}]}"#,
                &document,
            )
            .is_err()
    );
    assert!(
        registry
            .parse_grant(
                br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"list_calendar_events"},{"tool":"list_calendar_events"}]}"#,
                &document,
            )
            .is_err()
    );
    assert!(
        Authorization::new(
            &grant.granted_operations(),
            &granted(&registry, MCP, &[r#"{"tool":"modify_calendar_event"}"#]),
            &document,
        )
        .is_err()
    );

    let one_tool = r#"[{"tool":"create_calendar_event"}]"#;
    for replacement in [
        r#"[{"tool":"create_calendar_event"},{"tool":"modify_calendar_event"}]"#,
        "[]",
        r#"[{"tool":"create_calendar_event","arguments":{"title":"Planning"}}]"#,
        r#"[{"tool":""}]"#,
        r#"[{"tool":"create_calendar_event "}]"#,
    ] {
        let source = proposal_source.replace(one_tool, replacement);
        assert_ne!(source, proposal_source);
        assert!(
            registry.parse_proposal(source.as_bytes()).is_err(),
            "accepted {replacement}"
        );
    }

    let outside = registry.parse_proposal(
        proposal_source
            .replace("create_calendar_event", "delete_calendar")
            .as_bytes(),
    )?;
    assert!(
        !authorization
            .per_call_operations()
            .contains(&outside.operation())?
    );
    assert!(
        !authorization
            .granted_operations()
            .contains(&outside.operation())?
    );
    let openapi = registry.parse_proposal(
        proposal_source
            .replace(
                r#""vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"create_calendar_event"}]"#,
                r#""vocabulary":"urn:aauth:vocabulary:openapi","operations":[{"operationId":"create_calendar_event"}]"#,
            )
            .as_bytes(),
    )?;
    assert!(
        authorization
            .per_call_operations()
            .contains(&openapi.operation())
            .is_err()
    );
    Ok(())
}
