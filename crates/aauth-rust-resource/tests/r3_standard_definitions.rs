//! OData, gRPC, and WSDL snapshots on the existing Resource and Person Server paths.
//!
//! Each profile is the bounded subset that parser actually implements:
//!
//! * OData is Edmx 4.0 CSDL. Operations are entity-set and bound-operation names.
//!   Metadata does not prove HTTP methods.
//! * gRPC is a binary `FileDescriptorSet`. Operations are `package.Service/Method`.
//!   Message descriptors are not required. Hosted `.proto` text and live reflection
//!   are outside the profile. A dependency absent from the set is unresolved.
//! * WSDL is one self-contained WSDL 1.1 document. One service yields name-only
//!   operations. Imports and includes are unresolved.
//!
//! Authorization commits both derived operations. The Person Server fetches that
//! document and grants one. The Resource admits the granted operation and refuses
//! the other. This file does not replace the revocation or result-release
//! tests already on this base.
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, Confirmation, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedClock, BoxedTokenIds, Config, Grant, MemoryStore, Person,
    PersonRequest, PersonServer, Policy, PolicyError, R3AuthorizationRequest, R3Decision,
    R3IssuerConfig,
};
use aauth_rust_r3::{
    AuthoritativeSnapshot, DefinitionErrorKind, DefinitionRegistration, DefinitionRegistry,
    FetchBody, FetchLimits, FetchResponse, FetchTransport, GrantedOperations, GrpcCodec,
    GrpcDefinitionSource, ODataCodec, ODataMetadataSource, Operation, Vocabulary, WsdlCodec,
    WsdlDocumentSource, standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthAdmissionPolicy, BoxedR3OperationMapper, Deny, PsAuthorizationConfig,
    PsAuthorizationResource, R3Config, R3DocumentRecord, R3DocumentStore, R3StoreError,
    R3Vocabulary,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;

#[path = "../examples/support/tls.rs"]
mod parser_tls;

const NOW: i64 = 1_700_000_000;
const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const RESOURCE: &str = "https://resource.example";

struct Profile {
    name: &'static str,
    registration: DefinitionRegistration,
    snapshot: AuthoritativeSnapshot,
    vocabulary: Vocabulary,
    /// Canonical operation objects from the parser, permit then refuse.
    operations: [&'static str; 2],
}

fn assert_derived(name: &str, snapshot: &AuthoritativeSnapshot, operations: &[&str]) {
    let mut derived: Vec<String> = snapshot
        .operations()
        .operations()
        .expect("derived operations")
        .iter()
        .map(|operation| {
            String::from_utf8(operation.json().expect("operation json")).expect("utf8")
        })
        .collect();
    derived.sort();
    let mut expected: Vec<String> = operations.iter().map(|raw| (*raw).to_owned()).collect();
    expected.sort();
    assert_eq!(derived, expected, "{name} parser output");
}

fn profiles() -> Vec<Profile> {
    vec![odata_profile(), grpc_profile(), wsdl_profile()]
}

fn odata_profile() -> Profile {
    let source = ODataMetadataSource::new(
        br#"
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:DataServices>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar" Alias="Cal">
      <EntityType Name="Event"/>
      <EntityContainer Name="Service">
        <EntitySet Name="Events" EntityType="Calendar.Event"/>
      </EntityContainer>
      <Action Name="Cancel" IsBound="true">
        <Parameter Name="bindingParameter" Type="Cal.Event"/>
      </Action>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#,
    );
    let snapshot = ODataCodec::parse_definition(&format!("{RESOURCE}/odata"), &source)
        .expect("odata snapshot");
    let operations = [
        r#"{"operation":"Events"}"#,
        r#"{"operation":"Events/Cancel"}"#,
    ];
    assert_derived("odata", &snapshot, &operations);
    Profile {
        name: "odata",
        registration: ODataCodec::definition_registration().expect("odata registration"),
        vocabulary: ODataCodec::vocabulary().expect("odata vocabulary"),
        operations,
        snapshot,
    }
}

fn grpc_profile() -> Profile {
    let snapshot = GrpcCodec::parse_definition(
        &format!("{RESOURCE}/grpc"),
        &GrpcDefinitionSource::descriptor_set(&calendar_descriptor_set()),
    )
    .expect("grpc snapshot");
    let operations = [
        r#"{"method":"example.calendar.Calendar/Read"}"#,
        r#"{"method":"example.calendar.Calendar/Delete"}"#,
    ];
    assert_derived("grpc", &snapshot, &operations);
    Profile {
        name: "grpc",
        registration: GrpcCodec::definition_registration().expect("grpc registration"),
        vocabulary: GrpcCodec::vocabulary().expect("grpc vocabulary"),
        operations,
        snapshot,
    }
}

fn wsdl_profile() -> Profile {
    let source = WsdlDocumentSource::new(
        br#"<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:tns="urn:example:health" targetNamespace="urn:example:health">
  <message name="HealthRequest"/>
  <message name="StatusRequest"/>
  <portType name="HealthPortType">
    <operation name="Health"><input message="tns:HealthRequest"/></operation>
    <operation name="Status"><input message="tns:StatusRequest"/></operation>
  </portType>
  <binding name="HealthBinding" type="tns:HealthPortType">
    <operation name="Health"/>
    <operation name="Status"/>
  </binding>
  <service name="HealthService">
    <port name="HealthPort" binding="tns:HealthBinding"/>
  </service>
</definitions>"#,
    );
    let snapshot =
        WsdlCodec::parse_definition(&format!("{RESOURCE}/wsdl"), &source).expect("wsdl snapshot");
    let operations = [r#"{"operation":"Health"}"#, r#"{"operation":"Status"}"#];
    assert_derived("wsdl", &snapshot, &operations);
    Profile {
        name: "wsdl",
        registration: WsdlCodec::definition_registration().expect("wsdl registration"),
        vocabulary: WsdlCodec::vocabulary().expect("wsdl vocabulary"),
        operations,
        snapshot,
    }
}

/// FileDescriptorSet fixture with no message descriptors. The gRPC parser is the only reader.
fn calendar_descriptor_set() -> Vec<u8> {
    let mut read = Vec::new();
    proto_string(&mut read, 1, "Read");
    proto_string(&mut read, 2, ".example.calendar.Req");
    proto_string(&mut read, 3, ".example.calendar.Res");
    let mut delete = Vec::new();
    proto_string(&mut delete, 1, "Delete");
    proto_string(&mut delete, 2, ".example.calendar.Req");
    proto_string(&mut delete, 3, ".example.calendar.Res");
    let mut service = Vec::new();
    proto_string(&mut service, 1, "Calendar");
    proto_message(&mut service, 2, &read);
    proto_message(&mut service, 2, &delete);
    let mut file = Vec::new();
    proto_string(&mut file, 1, "calendar.proto");
    proto_string(&mut file, 2, "example.calendar");
    proto_message(&mut file, 6, &service);
    let mut set = Vec::new();
    proto_message(&mut set, 1, &file);
    set
}

fn proto_string(out: &mut Vec<u8>, field: u32, value: &str) {
    proto_message(out, field, value.as_bytes());
}

fn proto_message(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    out.push(u8::try_from((field << 3) | 2).expect("small field"));
    let mut length = value.len();
    while length > 0x7f {
        out.push(u8::try_from((length & 0x7f) | 0x80).expect("varint"));
        length >>= 7;
    }
    out.push(u8::try_from(length).expect("varint tail"));
    out.extend_from_slice(value);
}

#[derive(Clone)]
struct Keys(Vec<TrustedIssuerKeys>);
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        for snapshot in &self.0 {
            match snapshot.key(issuer, dwk, kid) {
                Err(TokenError::UntrustedIssuer | TokenError::InvalidDiscoveryDocument) => continue,
                other => return other,
            }
        }
        Err(TokenError::UntrustedIssuer)
    }
}

fn issuer_key(issuer: &str, dwk: &str, seed: u8, kid: &str) -> TrustedIssuerKeys {
    let mut jwk = serde_json::to_value(SigningKey::from_seed([seed; 32]).public_jwk()).unwrap();
    jwk["kid"] = json!(kid);
    TrustedIssuerKeys::from_documents(
        issuer,
        dwk,
        &serde_json::to_vec(&json!({"issuer":issuer,"jwks_uri":format!("{issuer}/keys")})).unwrap(),
        &serde_json::to_vec(&json!({"keys":[jwk]})).unwrap(),
    )
    .unwrap()
}

fn keys() -> Keys {
    Keys(vec![
        issuer_key(AP, "aauth-agent.json", 1, "ap-1"),
        issuer_key(PS, "aauth-person.json", 3, "ps-1"),
        issuer_key(RESOURCE, "aauth-resource.json", 4, "resource-1"),
    ])
}

#[derive(Default)]
struct Documents(Mutex<BTreeMap<String, R3DocumentRecord>>);
impl R3DocumentStore for Documents {
    fn commit(&self, record: &R3DocumentRecord) -> Result<(), R3StoreError> {
        let mut records = self.0.lock().unwrap();
        match records.get(record.reference.uri()) {
            Some(existing) if existing != record => Err(R3StoreError::Conflict),
            _ => {
                records.insert(record.reference.uri().to_owned(), record.clone());
                Ok(())
            }
        }
    }
    fn load(&self, uri: &str) -> Result<Option<R3DocumentRecord>, R3StoreError> {
        Ok(self.0.lock().unwrap().get(uri).cloned())
    }
}

type Resource = PsAuthorizationResource<Keys, BoxedAuthAdmissionPolicy<String>>;

fn operation(profile: &Profile, raw: &str) -> Operation {
    Operation::new(&profile.vocabulary, raw.as_bytes()).expect(raw)
}

fn resource_for(profile: &Profile) -> (Arc<Resource>, Arc<AtomicUsize>) {
    let permit = operation(profile, profile.operations[0]);
    let refuse = operation(profile, profile.operations[1]);
    let mapper: BoxedR3OperationMapper = Box::new(move |request: &Request<Vec<u8>>| {
        Ok(match request.uri().path() {
            "/op/permit" => Some(permit.clone()),
            "/op/refuse" => Some(refuse.clone()),
            _ => None,
        })
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = {
        let calls = calls.clone();
        Box::new(
            move |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| -> Result<String, Deny> {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok("receipt".into())
            },
        ) as BoxedAuthAdmissionPolicy<String>
    };
    let resource = Arc::new(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: RESOURCE.into(),
                signed_origin: RESOURCE.into(),
                kid: "resource-1".into(),
                signing_key: SigningKey::from_seed([4; 32]),
                scopes: vec!["records.read".into()],
            },
            keys(),
            policy,
        )
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(R3Config {
            registry: standard_registry().unwrap(),
            definitions: DefinitionRegistry::new(std::slice::from_ref(&profile.registration))
                .unwrap(),
            vocabularies: vec![R3Vocabulary {
                definition: profile.snapshot.clone(),
                display: None,
            }],
            documents: Arc::new(Documents::default()),
            operation_for_request: mapper,
            require_core_scope: false,
        })
        .unwrap(),
    );
    (resource, calls)
}

struct InProcess(Arc<Resource>);
struct Buffered(Vec<u8>, usize);
impl FetchBody for Buffered {
    fn read(&mut self, output: &mut [u8], _: Instant) -> std::io::Result<usize> {
        let count = (self.0.len() - self.1).min(output.len());
        output[..count].copy_from_slice(&self.0[self.1..self.1 + count]);
        self.1 += count;
        Ok(count)
    }
}
impl FetchTransport for InProcess {
    fn send(&self, request: Request<Vec<u8>>, _: Instant) -> std::io::Result<FetchResponse> {
        let (parts, body) = self.0.r3_document(&request, NOW).into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(Buffered(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

struct TlsFetch(Arc<parser_tls::TlsServer>);
impl FetchTransport for TlsFetch {
    fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> std::io::Result<FetchResponse> {
        if Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let response = self
            .0
            .send(&request)
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(Buffered(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

struct HostPolicy;
impl Policy for HostPolicy {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "directed-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

fn agent() -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let token = AgentProvider::new(AP, "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:reader@ap.example".into(),
            jti: "agent-1".into(),
            iat: NOW,
            exp: NOW + 1800,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, token).unwrap()
}

fn post(agent: &Agent, uri: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut request, NOW).unwrap();
    request
}

fn member(response: &Response<Vec<u8>>, name: &str) -> Option<String> {
    serde_json::from_slice::<Value>(response.body())
        .ok()?
        .get(name)?
        .as_str()
        .map(str::to_owned)
}

#[test]
fn parsers_feed_existing_resource_and_person_server_paths() {
    for profile in profiles() {
        let (resource, calls) = resource_for(&profile);
        let agent = agent();
        let ids = AtomicUsize::new(0);
        let permit = operation(&profile, profile.operations[0]);
        let vocabulary = profile.vocabulary.clone();
        let ps = PersonServer::new(
            Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
            keys(),
            MemoryStore::default(),
            HostPolicy,
            Box::new(|| NOW) as BoxedClock,
            Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst))) as BoxedTokenIds,
        )
        .unwrap()
        .with_r3(R3IssuerConfig {
            registry: standard_registry().unwrap(),
            egress: Box::new(|uri: &str, _: Instant| {
                if uri.starts_with(&format!("{RESOURCE}/r3/c.")) {
                    Ok(())
                } else {
                    Err(std::io::Error::other("egress refused"))
                }
            }),
            transport: Box::new(InProcess(resource.clone())),
            limits: FetchLimits::default(),
            policy: Box::new(
                move |_: &R3AuthorizationRequest<'_>| -> Result<R3Decision, PolicyError> {
                    Ok(R3Decision {
                        granted: GrantedOperations::new(&vocabulary, std::slice::from_ref(&permit))
                            .unwrap(),
                        per_call: None,
                        scopes: Vec::new(),
                        lifetime: 600,
                    })
                },
            ),
            audit: Arc::new(Audit),
        })
        .unwrap();

        let person = member(
            &ps.handle(&post(
                &agent,
                &format!("{PS}/person"),
                json!({ "resource": RESOURCE }),
            )),
            "person_token",
        )
        .expect("person token");
        let presented = agent.with_token(person.clone()).unwrap();
        let authorize = post(
            &presented,
            &format!("{RESOURCE}/authorize"),
            json!({ "r3_operations": {
                "vocabulary": profile.vocabulary.uri().as_str(),
                "operations": [
                    serde_json::from_str::<Value>(profile.operations[0]).unwrap(),
                    serde_json::from_str::<Value>(profile.operations[1]).unwrap(),
                ],
            } }),
        );
        let issued = resource
            .authorize_endpoint(&authorize, NOW, "rt-1")
            .into_response();
        assert_eq!(issued.status(), 200, "{}", profile.name);
        let resource_token = member(&issued, "resource_token").expect("resource token");
        let exchanged = ps.handle(&post(
            &agent,
            &format!("{PS}/token"),
            json!({ "resource_token": resource_token, "presented_token": person }),
        ));
        assert_eq!(exchanged.status(), 200, "{}", profile.name);
        let auth = member(&exchanged, "auth_token").expect("auth token");

        match resource.authorize(&signed_call("/op/permit", &auth), NOW, "unused") {
            AuthDecision::Granted(admitted) => {
                assert_eq!(admitted.admitted(), "receipt");
                let grant = admitted.r3_grant().expect("class grant");
                assert_eq!(
                    grant.operation().json().expect("grant json"),
                    profile.operations[0].as_bytes()
                );
            }
            other => panic!("{} permit: {other:?}", profile.name),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{}", profile.name);
        let refused = resource
            .authorize(&signed_call("/op/refuse", &auth), NOW, "unused")
            .into_response();
        assert_eq!(refused.status(), 403, "{}", profile.name);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{}", profile.name);
    }
}

#[test]
fn parsers_admit_and_refuse_over_real_tls() {
    for profile in profiles() {
        let (resource, calls) = resource_for(&profile);
        let api = resource.clone();
        let resource_tls = Arc::new(
            parser_tls::TlsServer::start("resource.example", move |request| {
                let path = request.uri().path().to_owned();
                match path.as_str() {
                    "/authorize" => api
                        .authorize_endpoint(&request, NOW, "rt-http")
                        .into_response(),
                    p if p.starts_with("/r3/") => api.r3_document(&request, NOW),
                    "/op/permit" | "/op/refuse" => {
                        match api.authorize(&request, NOW, "http-call") {
                            AuthDecision::Granted(admitted) => {
                                let bytes = admitted
                                    .r3_grant()
                                    .expect("class grant")
                                    .operation()
                                    .json()
                                    .expect("grant json");
                                Response::builder().status(200).body(bytes).unwrap()
                            }
                            other => other.into_response(),
                        }
                    }
                    _ => Response::builder().status(404).body(Vec::new()).unwrap(),
                }
            })
            .expect("resource tls"),
        );
        let ids = AtomicUsize::new(0);
        let permit = operation(&profile, profile.operations[0]);
        let vocabulary = profile.vocabulary.clone();
        let fetched = resource_tls.clone();
        let ps = Arc::new(
            PersonServer::new(
                Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
                keys(),
                MemoryStore::default(),
                HostPolicy,
                Box::new(|| NOW) as BoxedClock,
                Box::new(move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)))
                    as BoxedTokenIds,
            )
            .unwrap()
            .with_r3(R3IssuerConfig {
                registry: standard_registry().unwrap(),
                egress: Box::new(|uri: &str, _: Instant| {
                    if uri.starts_with(&format!("{RESOURCE}/r3/c.")) {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("egress refused"))
                    }
                }),
                transport: Box::new(TlsFetch(fetched)),
                limits: FetchLimits::default(),
                policy: Box::new(
                    move |_: &R3AuthorizationRequest<'_>| -> Result<R3Decision, PolicyError> {
                        Ok(R3Decision {
                            granted: GrantedOperations::new(
                                &vocabulary,
                                std::slice::from_ref(&permit),
                            )
                            .unwrap(),
                            per_call: None,
                            scopes: Vec::new(),
                            lifetime: 600,
                        })
                    },
                ),
                audit: Arc::new(Audit),
            })
            .unwrap(),
        );
        let served = ps.clone();
        let ps_tls =
            parser_tls::TlsServer::start("ps.example", move |request| served.handle(&request))
                .expect("person server tls");
        let signer = agent();
        let person_http = ps_tls
            .send(&post(
                &signer,
                &format!("{PS}/person"),
                json!({ "resource": RESOURCE }),
            ))
            .expect("person http");
        assert_eq!(person_http.status(), 200, "{}", profile.name);
        let person = member(&person_http, "person_token").expect("person token");
        let presented = signer.with_token(person.clone()).unwrap();
        let authorize = post(
            &presented,
            &format!("{RESOURCE}/authorize"),
            json!({ "r3_operations": {
                "vocabulary": profile.vocabulary.uri().as_str(),
                "operations": [
                    serde_json::from_str::<Value>(profile.operations[0]).unwrap(),
                    serde_json::from_str::<Value>(profile.operations[1]).unwrap(),
                ],
            } }),
        );
        let issued = resource_tls.send(&authorize).expect("authorize http");
        assert_eq!(issued.status(), 200, "{}", profile.name);
        let resource_token = member(&issued, "resource_token").expect("resource token");
        let exchanged = ps_tls
            .send(&post(
                &signer,
                &format!("{PS}/token"),
                json!({ "resource_token": resource_token, "presented_token": person }),
            ))
            .expect("token http");
        assert_eq!(exchanged.status(), 200, "{}", profile.name);
        let auth = member(&exchanged, "auth_token").expect("auth token");
        let permitted = resource_tls
            .send(&signed_call("/op/permit", &auth))
            .expect("permit http");
        assert_eq!(permitted.status(), 200, "{}", profile.name);
        assert_eq!(
            permitted.body().as_slice(),
            profile.operations[0].as_bytes()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{}", profile.name);
        let refused = resource_tls
            .send(&signed_call("/op/refuse", &auth))
            .expect("refuse http");
        assert_eq!(refused.status(), 403, "{}", profile.name);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{}", profile.name);
    }
}

fn signed_call(path: &str, token: &str) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri(format!("{RESOURCE}{path}"))
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt(token.into()),
        NOW,
    )
    .unwrap();
    request
}

#[derive(Default)]
struct Audit;
impl aauth_rust_r3::IssuanceStore for Audit {
    fn commit(
        &self,
        _: &aauth_rust_r3::IssuanceRecord,
    ) -> Result<(), aauth_rust_r3::IssuanceError> {
        Ok(())
    }
}

#[test]
fn parser_profiles_refuse_imports_malformed_input_and_unproven_methods() {
    let reference = br#"<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:Reference Uri="types.xml"/><edmx:DataServices/></edmx:Edmx>"#;
    assert_eq!(
        kind(ODataCodec::parse_definition(
            &format!("{RESOURCE}/odata"),
            &ODataMetadataSource::new(reference)
        )),
        DefinitionErrorKind::UnresolvedDependency
    );
    assert_eq!(
        kind(ODataCodec::parse_definition(
            &format!("{RESOURCE}/odata"),
            &ODataMetadataSource::new(b"<")
        )),
        DefinitionErrorKind::InvalidSource
    );
    let odata = odata_profile();
    let methods = Operation::new(
        &odata.vocabulary,
        br#"{"operation":"Events","methods":["GET"]}"#,
    )
    .unwrap();
    let declared = aauth_rust_r3::OperationSet::new(&[methods]).unwrap();
    assert_eq!(
        odata
            .snapshot
            .validate_defined(&declared)
            .expect_err("methods")
            .definition_kind(),
        Some(DefinitionErrorKind::OperationNotDefined)
    );

    assert_eq!(
        kind(GrpcCodec::parse_definition(
            &format!("{RESOURCE}/grpc"),
            &GrpcDefinitionSource::hosted_proto_text(b"syntax = \"proto3\";")
        )),
        DefinitionErrorKind::SourceKindUnsupported
    );
    assert_eq!(
        kind(GrpcCodec::parse_definition(
            &format!("{RESOURCE}/grpc"),
            &GrpcDefinitionSource::server_reflection()
        )),
        DefinitionErrorKind::SourceKindUnsupported
    );
    assert_eq!(
        kind(GrpcCodec::parse_definition(
            &format!("{RESOURCE}/grpc"),
            &GrpcDefinitionSource::descriptor_set(&[0xff])
        )),
        DefinitionErrorKind::InvalidSource
    );
    let mut missing = Vec::new();
    proto_string(&mut missing, 1, "calendar.proto");
    proto_string(&mut missing, 2, "example.calendar");
    proto_string(&mut missing, 3, "missing.proto");
    let mut missing_set = Vec::new();
    proto_message(&mut missing_set, 1, &missing);
    assert_eq!(
        kind(GrpcCodec::parse_definition(
            &format!("{RESOURCE}/grpc"),
            &GrpcDefinitionSource::descriptor_set(&missing_set)
        )),
        DefinitionErrorKind::UnresolvedDependency
    );

    let imported = br#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:test"><import location="other.wsdl"/></definitions>"#;
    assert_eq!(
        kind(WsdlCodec::parse_definition(
            &format!("{RESOURCE}/wsdl"),
            &WsdlDocumentSource::new(imported)
        )),
        DefinitionErrorKind::UnresolvedDependency
    );
    let included = br#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:test"><include location="other.wsdl"/></definitions>"#;
    assert_eq!(
        kind(WsdlCodec::parse_definition(
            &format!("{RESOURCE}/wsdl"),
            &WsdlDocumentSource::new(included)
        )),
        DefinitionErrorKind::UnresolvedDependency
    );
    assert_eq!(
        kind(WsdlCodec::parse_definition(
            &format!("{RESOURCE}/wsdl"),
            &WsdlDocumentSource::new(b"<")
        )),
        DefinitionErrorKind::InvalidSource
    );
}

#[test]
fn odata_sibling_xmlns_does_not_leak_and_deep_nesting_fails_closed() {
    let rebound = br#"
<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0">
  <edmx:DataServices>
    <Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" xmlns:edm="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar">
      <EntityType Name="Event"/>
      <EntityContainer Name="Service">
        <EntitySet Name="Events" EntityType="Calendar.Event">
          <wrapper xmlns:edm="http://example.invalid/leaked">
            <edm:Annotation Term="AAuth.AccessMode" String="person-token"/>
          </wrapper>
        </EntitySet>
        <edm:EntitySet xmlns:edm="http://example.invalid/sibling" Name="Hidden" EntityType="Calendar.Event"/>
        <edm:EntitySet Name="Places" EntityType="Calendar.Event"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#;
    let snapshot = ODataCodec::parse_definition(
        &format!("{RESOURCE}/odata"),
        &ODataMetadataSource::new(rebound),
    )
    .expect("sibling xmlns stays on its element");
    let mut names: Vec<String> = snapshot
        .operations()
        .operations()
        .expect("operations")
        .iter()
        .map(|operation| String::from_utf8(operation.json().expect("json")).expect("utf8"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            r#"{"operation":"Events"}"#.to_owned(),
            r#"{"operation":"Places"}"#.to_owned(),
        ]
    );

    let depth = 80;
    let mut xml = String::new();
    for index in 0..depth {
        xml.push_str(&format!("<e{index}>"));
    }
    for index in (0..depth).rev() {
        xml.push_str(&format!("</e{index}>"));
    }
    let err = match ODataCodec::parse_definition(
        &format!("{RESOURCE}/odata"),
        &ODataMetadataSource::new(xml.as_bytes()),
    ) {
        Err(err) => err,
        Ok(_) => panic!("deep nesting"),
    };
    assert_eq!(err.kind(), DefinitionErrorKind::InvalidSource);
    assert_eq!(err.reason(), "OData metadata XML exceeds the nesting limit");
}

fn kind(
    result: Result<AuthoritativeSnapshot, aauth_rust_r3::DefinitionError>,
) -> DefinitionErrorKind {
    match result {
        Err(err) => err.kind(),
        Ok(_) => panic!("expected a definition refusal"),
    }
}
