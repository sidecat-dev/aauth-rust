use crate::error::Error;
use crate::uri::VocabularyUri;
use crate::vocabulary::{Codec, GrantedOperations, Operation, OperationSet, Registry, Vocabulary};
use crate::{
    AnnotationEncoding, AsyncApiCodec, Authorization, Document, DocumentOptions, GraphQlCodec,
    GrpcCodec, McpCodec, ODataCodec, OpenApiCodec, Reference, WsdlCodec, digest,
    standard_vocabularies,
};

const MCP: &str = "urn:aauth:vocabulary:mcp";
const OPENAPI: &str = "urn:aauth:vocabulary:openapi";
const GRPC: &str = "urn:aauth:vocabulary:grpc";
const GRAPHQL: &str = "urn:aauth:vocabulary:graphql";
const ASYNCAPI: &str = "urn:aauth:vocabulary:asyncapi";
const WSDL: &str = "urn:aauth:vocabulary:wsdl";
const ODATA: &str = "urn:aauth:vocabulary:odata";

fn registry() -> Registry {
    Registry::new(&standard_vocabularies().expect("standard vocabularies")).expect("registry")
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

fn document(registry: &Registry, uri: &str, operations: &[&str]) -> Document {
    Document::new(&set(registry, uri, operations), DocumentOptions::default()).expect("document")
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

#[test]
fn standard_vocabularies_register_draft_uris_and_annotation_encodings() -> Result<(), Error> {
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

    let registry = Registry::new(&vocabularies)?;
    assert_eq!(registry.len(), 7);
    assert!(Registry::new(&[Vocabulary::new(McpCodec)?, Vocabulary::new(McpCodec)?]).is_err());

    let again = standard_vocabularies()?;
    let first = Operation::new(&vocabularies[0], br#"{"tool":"create_calendar_event"}"#)?;
    let second = Operation::new(&again[0], br#"{"tool":"create_calendar_event"}"#)?;
    assert!(first.equal(&second).is_err());
    registry.validate_operation_set(&OperationSet::new(&[first])?)?;
    assert!(
        registry
            .validate_operation_set(&OperationSet::new(&[second])?)
            .is_err()
    );
    Ok(())
}

#[test]
fn standard_discovery_endpoints_are_absolute_https_uris() -> Result<(), Error> {
    let accepted = [
        "https://calendar.example.com/mcp",
        "https://calendar.example.com/openapi.json",
        "https://calendar.example.com:8443/odata/",
        "https://[2001:db8::1]/calendar.wsdl?version=2",
    ];
    let rejected = [
        "",
        " https://calendar.example.com/graphql",
        "http://calendar.example.com/mcp",
        "/openapi.json",
        "calendar.example.com:443",
        "dns:///calendar.example.com:443",
        "grpcs://calendar.example.com",
        "https:///graphql",
        "https://user@calendar.example.com/mcp",
        "https://calendar.example.com/asyncapi.json#/operations",
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
    let at_limit = format!(r#"{{"operation":"{}"}}"#, "E".repeat(128));
    Operation::new(&vocabulary(&registry, ODATA), at_limit.as_bytes())?;
    Ok(())
}

#[test]
fn standard_codecs_reject_malformed_unknown_and_duplicate_members() {
    let registry = registry();
    let past_limit = format!(r#"{{"operation":"{}"}}"#, "E".repeat(129));
    let not_object = "operation must be a JSON object";
    let grpc_form = "package.ServiceName/MethodName";
    let graphql_type = "is not query, mutation, or subscription";
    let asyncapi_action = "is not send or receive";
    let ncname = "is not an XML NCName";
    let odata_form = "is not EntitySet or EntitySet/Operation";
    let odata_method = "is not GET, POST, PUT, PATCH, or DELETE";
    let rejected = [
        (MCP, "{}", r#"missing member "tool""#),
        (MCP, r#"{"tool":""}"#, r#"member "tool" must not be empty"#),
        (MCP, r#"{"tool":null}"#, r#"member "tool" must be a string"#),
        (MCP, r#"{"tool":7}"#, r#"member "tool" must be a string"#),
        (MCP, r#"{"tool":["create_calendar_event"]}"#, "must be a string"),
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
        (OPENAPI, r#"{"operationid":"createEvent"}"#, r#"unknown member "operationid""#),
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
        (OPENAPI, r#"{"operationId":{"name":"createEvent"}}"#, "must be a string"),
        (GRPC, r#"{"method":"CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"/calendar.CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":".calendar.CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarService.CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarService/"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar..CalendarService/CreateEvent"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.CalendarService/Create/Event"}"#, grpc_form),
        (GRPC, r#"{"method":"calendar.Calendar-Service/CreateEvent"}"#, grpc_form),
        (
            GRPC,
            r#"{"method":"calendar.CalendarService/CreateEvent","service":"CalendarService"}"#,
            r#"unknown member "service""#,
        ),
        (GRAPHQL, r#"{"operation":"GetCalendarEvents"}"#, r#"missing member "type""#),
        (GRAPHQL, r#"{"type":"query"}"#, r#"missing member "operation""#),
        (GRAPHQL, r#"{"operation":"GetCalendarEvents","type":"Query"}"#, graphql_type),
        (GRAPHQL, r#"{"operation":"GetCalendarEvents","type":"fragment"}"#, graphql_type),
        (
            GRAPHQL,
            r#"{"operation":"GetCalendarEvents","type":null}"#,
            r#"member "type" must be a string"#,
        ),
        (
            GRAPHQL,
            r#"{"operation":"","type":"query"}"#,
            r#"member "operation" must not be empty"#,
        ),
        (GRAPHQL, r#"{"operation":"1Events","type":"query"}"#, "is not a GraphQL name"),
        (GRAPHQL, r#"{"operation":"Get-Events","type":"query"}"#, "is not a GraphQL name"),
        (
            GRAPHQL,
            r#"{"operation":"GetCalendarEvents","type":"query","variables":{}}"#,
            r#"unknown member "variables""#,
        ),
        (ASYNCAPI, r#"{"action":"send"}"#, r#"missing member "operationId""#),
        (
            ASYNCAPI,
            r#"{"operationId":"receiveCalendarEvent","action":"subscribe"}"#,
            asyncapi_action,
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"publishCalendarUpdate","action":"publish"}"#,
            asyncapi_action,
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"receiveCalendarEvent","action":"Receive"}"#,
            asyncapi_action,
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"receiveCalendarEvent","action":null}"#,
            r#"member "action" must be a string"#,
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"receiveCalendarEvent","action":""}"#,
            r#"member "action" must not be empty"#,
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"receiveCalendarEvent","action":["receive"]}"#,
            "must be a string",
        ),
        (
            ASYNCAPI,
            r#"{"operationId":"receiveCalendarEvent","channel":"calendar"}"#,
            r#"unknown member "channel""#,
        ),
        (WSDL, r#"{"service":"CalendarService"}"#, r#"missing member "operation""#),
        (
            WSDL,
            r#"{"operation":"CreateCalendarEvent","service":null}"#,
            r#"member "service" must be a string"#,
        ),
        (
            WSDL,
            r#"{"operation":"CreateCalendarEvent","service":""}"#,
            r#"member "service" must not be empty"#,
        ),
        (WSDL, r#"{"operation":"tns:CreateCalendarEvent"}"#, ncname),
        (WSDL, r#"{"operation":"Create CalendarEvent"}"#, ncname),
        (WSDL, r#"{"operation":"1CreateCalendarEvent"}"#, ncname),
        (
            WSDL,
            r#"{"operation":"CreateCalendarEvent","service":"tns:CalendarService"}"#,
            r#"service "tns:CalendarService" is not an XML NCName"#,
        ),
        (
            WSDL,
            r#"{"operation":"CreateCalendarEvent","port":"CalendarPort"}"#,
            r#"unknown member "port""#,
        ),
        (ODATA, r#"{"methods":["GET"]}"#, r#"missing member "operation""#),
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
        (ODATA, r#"{"operation":"Events","methods":["get"]}"#, odata_method),
        (ODATA, r#"{"operation":"Events","methods":["HEAD"]}"#, odata_method),
        (
            ODATA,
            r#"{"operation":"Events","methods":["GET","GET"]}"#,
            r#"method "GET" is repeated"#,
        ),
        (
            ODATA,
            r#"{"operation":"Events","methods":[1]}"#,
            "must contain only strings",
        ),
        (
            ODATA,
            r#"{"operation":"Events/SendCancellation","methods":["POST"]}"#,
            "not allowed on a bound function or action",
        ),
        (ODATA, r#"{"operation":"Events/"}"#, odata_form),
        (ODATA, r#"{"operation":"/SendCancellation"}"#, odata_form),
        (ODATA, r#"{"operation":"Events/Calendar.SendCancellation"}"#, odata_form),
        (ODATA, r#"{"operation":"Events/SendCancellation/Again"}"#, odata_form),
        (ODATA, r#"{"operation":"Events(1)"}"#, odata_form),
        (ODATA, past_limit.as_str(), odata_form),
        (
            ODATA,
            r#"{"operation":"Events","methods":["GET"],"filter":"Start gt 2026"}"#,
            r#"unknown member "filter""#,
        ),
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
fn standard_codecs_reject_a_repeated_operation_in_one_set() {
    let registry = registry();
    let repeated = [
        (
            MCP,
            [
                r#"{"tool":"create_calendar_event"}"#,
                r#"{"tool":"create_calendar_event"}"#,
            ],
        ),
        (MCP, [r#"{"tool":"a"}"#, r#"{"tool":"a"}"#]),
        (
            OPENAPI,
            [
                r#"{"operationId":"createEvent"}"#,
                r#"{"operationId":"createEvent"}"#,
            ],
        ),
        (
            GRPC,
            [
                r#"{"method":"calendar.CalendarService/CreateEvent"}"#,
                r#"{"method":"calendar.CalendarService/CreateEvent"}"#,
            ],
        ),
        (
            GRAPHQL,
            [
                r#"{"operation":"CalendarEvents","type":"query"}"#,
                r#"{"operation":"CalendarEvents","type":"subscription"}"#,
            ],
        ),
        (
            ASYNCAPI,
            [
                r#"{"operationId":"receiveCalendarEvent"}"#,
                r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#,
            ],
        ),
        (
            ASYNCAPI,
            [
                r#"{"operationId":"receiveCalendarEvent","action":"send"}"#,
                r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#,
            ],
        ),
        (
            WSDL,
            [
                r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#,
                r#"{"service":"CalendarService","operation":"CreateCalendarEvent"}"#,
            ],
        ),
        (
            ODATA,
            [
                r#"{"operation":"Events","methods":["GET"]}"#,
                r#"{"operation":"Events","methods":["POST"]}"#,
            ],
        ),
        (
            ODATA,
            [
                r#"{"operation":"Events"}"#,
                r#"{"operation":"Events","methods":["GET"]}"#,
            ],
        ),
    ];
    for (uri, operations) in repeated {
        let source = envelope(uri, &operations);
        let message = refused(registry.parse_operation_set(source.as_bytes()));
        assert!(message.contains("repeats"), "{uri}: {message}");
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
    let only_mcp = Registry::new(&[Vocabulary::new(McpCodec)?])?;
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
fn standard_graphql_name_identifies_and_type_must_agree() -> Result<(), Error> {
    let registry = registry();
    let query = set(
        &registry,
        GRAPHQL,
        &[r#"{"operation":"CalendarEvents","type":"query"}"#],
    );
    let subscription = set(
        &registry,
        GRAPHQL,
        &[r#"{"operation":"CalendarEvents","type":"subscription"}"#],
    );
    assert!(!query.equal(&subscription)?);
    assert!(!query.is_subset_of(&subscription)?);
    assert!(!query.is_disjoint(&subscription)?);
    let message = refused(query.union_with(std::slice::from_ref(&subscription)));
    assert!(message.contains("conflicting entries"), "{message}");
    Ok(())
}

#[test]
fn standard_asyncapi_absent_action_is_not_a_present_action() -> Result<(), Error> {
    let registry = registry();
    let bare = r#"{"operationId":"receiveCalendarEvent"}"#;
    let receive = r#"{"operationId":"receiveCalendarEvent","action":"receive"}"#;
    let send = r#"{"operationId":"receiveCalendarEvent","action":"send"}"#;
    let bare_set = set(&registry, ASYNCAPI, &[bare]);
    let receive_set = set(&registry, ASYNCAPI, &[receive]);
    let send_set = set(&registry, ASYNCAPI, &[send]);
    assert_eq!(json_text(&bare_set), envelope(ASYNCAPI, &[bare]));
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
        receive_set
            .union_with(std::slice::from_ref(&receive_set))?
            .equal(&receive_set)?
    );
    Ok(())
}

#[test]
fn standard_wsdl_service_qualifies_identity_and_absence_overlaps() -> Result<(), Error> {
    let registry = registry();
    let unqualified = r#"{"operation":"CreateCalendarEvent"}"#;
    let calendar = r#"{"operation":"CreateCalendarEvent","service":"CalendarService"}"#;
    let archive = r#"{"operation":"CreateCalendarEvent","service":"ArchiveService"}"#;
    let unqualified_set = set(&registry, WSDL, &[unqualified]);
    let calendar_set = set(&registry, WSDL, &[calendar]);
    let archive_set = set(&registry, WSDL, &[archive]);
    assert_eq!(json_text(&unqualified_set), envelope(WSDL, &[unqualified]));
    assert!(!unqualified_set.is_subset_of(&calendar_set)?);
    assert!(!calendar_set.is_subset_of(&unqualified_set)?);
    assert!(!unqualified_set.is_disjoint(&calendar_set)?);
    assert!(calendar_set.is_disjoint(&archive_set)?);
    let both = unqualified_set.union_with(std::slice::from_ref(&calendar_set))?;
    assert_eq!(json_text(&both), envelope(WSDL, &[unqualified, calendar]));

    let document = document(&registry, WSDL, &[unqualified, calendar, archive]);
    assert!(
        Authorization::new(
            &granted(&registry, WSDL, &[unqualified]),
            &granted(&registry, WSDL, &[calendar]),
            &document,
        )
        .is_err()
    );
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

    let document = document(
        &registry,
        ODATA,
        &[
            r#"{"operation":"Events","methods":["GET","POST","PATCH"]}"#,
            r#"{"operation":"Events/SendCancellation"}"#,
        ],
    );
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
