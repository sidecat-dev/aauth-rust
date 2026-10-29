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
use aauth_rust_budgets::{Budget, IssuerPolicy, UnitDeclaration};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, Confirmation, ResourceToken, TokenError, TrustedIssuerKeys,
    VerifiedAuthToken,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, BoxedClock, BoxedTokenIds, Config, Grant, MemoryStore, Person,
    PersonRequest, PersonServer, Policy, PolicyError, R3AuthorizationRequest, R3Decision,
    R3IssuerConfig, R3Policy, R3ProposalDecision, R3ProposalRequest,
};
use aauth_rust_r3::{
    AuthoritativeSnapshot, DefinitionErrorKind, DefinitionRegistration, DefinitionRegistry,
    FetchBody, FetchLimits, FetchResponse, FetchTransport, GrantedOperations, GrpcCodec,
    GrpcDefinitionSource, ODataCodec, ODataMetadataSource, Operation, Vocabulary, WsdlCodec,
    Parameters, PresentedParameter, Proposal, ProposalOptions, Reference,
    WsdlDocumentSource, digest,
    mint_budget_resource_token, mint_proposal_resource_token, standard_registry,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthAdmissionPolicy, BoxedR3Describe, BoxedR3OperationMapper,
    BoxedR3Present, Deny, PsAuthorizationConfig, PsAuthorizationResource, R3CallResult,
    R3CallStore, R3CallToken, R3Claim, R3Config, R3DocumentRecord, R3DocumentStore, R3HostError,
    R3PerCallConfig, R3ProposalRecord, R3StoreError, R3Vocabulary,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, AtomicUsize, Ordering},
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

fn resource_for(
    profile: &Profile,
    meter: bool,
) -> (Arc<Resource>, Arc<AtomicUsize>, Arc<Documents>) {
    resource_with(profile, meter, false, Arc::new(Documents::default()))
}

fn resource_with(
    profile: &Profile,
    meter: bool,
    revocation: bool,
    documents: Arc<Documents>,
) -> (Arc<Resource>, Arc<AtomicUsize>, Arc<Documents>) {
    resource_with_ledger(profile, meter, revocation, documents, None, None)
}

fn resource_with_ledger(
    profile: &Profile,
    meter: bool,
    revocation: bool,
    documents: Arc<Documents>,
    ledger: Option<Arc<Mutex<aauth_rust_budgets::Ledger>>>,
    deny_first: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> (Arc<Resource>, Arc<AtomicUsize>, Arc<Documents>) {
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
                if deny_first
                    .as_ref()
                    .is_some_and(|flag| flag.swap(false, Ordering::SeqCst))
                {
                    return Err(Deny);
                }
                calls.fetch_add(1, Ordering::SeqCst);
                Ok("receipt".into())
            },
        ) as BoxedAuthAdmissionPolicy<String>
    };
    let resource = PsAuthorizationResource::new(
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
            documents: documents.clone(),
            operation_for_request: mapper,
            require_core_scope: false,
        })
        .unwrap();
    let resource = if meter {
        let units = vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()];
        match ledger {
            Some(ledger) => resource
                .with_budget_ledger(units, "https://resource.example/usage", 500, 500, ledger)
                .unwrap(),
            None => resource
                .with_budgets(units, "https://resource.example/usage", 500, 500)
                .unwrap(),
        }
    } else {
        resource
    };
    let resource = if revocation {
        resource.with_revocation()
    } else {
        resource
    };
    (Arc::new(resource), calls, documents)
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

struct CoreGrant;
impl Policy for CoreGrant {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "directed-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
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
        let (resource, calls, _) = resource_for(&profile, false);
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
fn class_resource_token_with_budget_offer_is_authorized() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, calls, documents) = resource_for(&profile, false);
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 6, 10_000_000, "dollars").unwrap()],
    ))
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
            "operations": [serde_json::from_str::<Value>(profile.operations[0]).unwrap()],
        } }),
    );
    let issued = resource
        .authorize_endpoint(&authorize, NOW, "rt-budget")
        .into_response();
    assert_eq!(issued.status(), 200);
    let resource_token = member(&issued, "resource_token").expect("resource token");
    let plain = ps.handle(&post(
        &agent,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person }),
    ));
    assert_eq!(plain.status(), 200, "r3-only with budgets enabled");
    let plain_auth = member(&plain, "auth_token").expect("r3-only auth token");
    assert!(
        aauth_rust_core::AuthToken::parse(&plain_auth)
            .unwrap()
            .unverified_claims()
            .extra
            .get("budget")
            .is_none()
    );

    let stored = documents
        .0
        .lock()
        .unwrap()
        .values()
        .next()
        .expect("stored class document")
        .clone();
    let mut claims = ResourceToken::parse(&resource_token)
        .unwrap()
        .unverified_claims()
        .clone();
    claims.extra.remove("r3_uri");
    claims.extra.remove("r3_s256");
    let offer = Budget::new(500, "USD", 6).unwrap();
    let (combined, _) = mint_budget_resource_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &claims,
        stored.reference.uri(),
        &stored.exact_json,
        &offer,
        None,
    )
    .expect("combined resource token");
    let exchanged = ps.handle(&post(
        &agent,
        &format!("{PS}/token"),
        json!({ "resource_token": combined, "presented_token": person }),
    ));
    assert_eq!(exchanged.status(), 200, "class token with budget offer");
    let auth = member(&exchanged, "auth_token").expect("budget auth token");
    let budget = aauth_rust_core::AuthToken::parse(&auth)
        .unwrap()
        .unverified_claims()
        .extra
        .get("budget")
        .cloned()
        .expect("signed budget grant");
    assert_eq!(
        budget,
        json!({"amount": 500, "unit": "USD", "decimals": 6})
    );
    let record = aauth_rust_budgets::ConsumptionRecord::new(claims.presented_jti.clone(), 1)
        .expect("consumption record");
    let (with_record, _) = mint_budget_resource_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &claims,
        stored.reference.uri(),
        &stored.exact_json,
        &offer,
        Some(&record),
    )
    .expect("combined token with a consumption record");
    let unresolved = ps.handle(&post(
        &agent,
        &format!("{PS}/token"),
        json!({ "resource_token": with_record, "presented_token": person }),
    ));
    assert_eq!(unresolved.status(), 400, "well-formed consumption record");
    assert_eq!(
        member(&unresolved, "error").as_deref(),
        Some("invalid_resource_token")
    );
    let mut malformed = ResourceToken::parse(&resource_token)
        .unwrap()
        .unverified_claims()
        .clone();
    malformed.extra.insert(
        "budget".into(),
        json!({"amount": 500, "unit": "USD", "decimals": 6}),
    );
    malformed
        .extra
        .insert("budget_consumed".into(), json!("nope"));
    let bad = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &malformed,
    )
    .expect("resource token with a malformed consumption record");
    let malformed_response = ps.handle(&post(
        &agent,
        &format!("{PS}/token"),
        json!({ "resource_token": bad, "presented_token": person }),
    ));
    assert_eq!(malformed_response.status(), 400, "malformed consumption record");
    assert_eq!(
        member(&malformed_response, "error").as_deref(),
        Some("invalid_budget")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "issuance does not run the tool");
}

#[test]
fn resource_issued_budget_token_is_exchanged_and_admitted() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, calls, _) = resource_for(&profile, true);
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
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
        json!({
            "r3_operations": {
                "vocabulary": profile.vocabulary.uri().as_str(),
                "operations": [serde_json::from_str::<Value>(profile.operations[0]).unwrap()],
            },
            "budget": {"amount": 500, "unit": "USD", "decimals": 2}
        }),
    );
    let issued = resource
        .authorize_endpoint(&authorize, NOW, "rt-joined")
        .into_response();
    assert_eq!(issued.status(), 200, "resource issues the combined token");
    let resource_token = member(&issued, "resource_token").expect("resource token");
    let exchanged = ps.handle(&post(
        &agent,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person }),
    ));
    assert_eq!(exchanged.status(), 200, "person server signs the grant");
    let auth = member(&exchanged, "auth_token").expect("auth token");
    assert_eq!(
        aauth_rust_core::AuthToken::parse(&auth)
            .unwrap()
            .unverified_claims()
            .extra
            .get("budget")
            .cloned(),
        Some(json!({"amount": 500, "unit": "USD", "decimals": 2}))
    );
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "unused") {
        AuthDecision::Granted(admitted) => assert_eq!(admitted.admitted(), "receipt"),
        other => panic!("joined admission: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn per_call_with_a_budget_offer_is_refused() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, calls, _) = resource_for(&profile, true);
    let signer = agent();
    let ids = AtomicUsize::new(0);
    let permit = operation(&profile, profile.operations[0]);
    let per_call = operation(&profile, profile.operations[1]);
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
                    per_call: Some(
                        GrantedOperations::new(&vocabulary, std::slice::from_ref(&per_call))
                            .unwrap(),
                    ),
                    scopes: Vec::new(),
                    lifetime: 600,
                })
            },
        ),
        audit: Arc::new(Audit),
    })
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let authorize = post(
        &presented,
        &format!("{RESOURCE}/authorize"),
        json!({
            "r3_operations": {
                "vocabulary": profile.vocabulary.uri().as_str(),
                "operations": [
                    serde_json::from_str::<Value>(profile.operations[0]).unwrap(),
                    serde_json::from_str::<Value>(profile.operations[1]).unwrap(),
                ],
            },
            "budget": {"amount": 500, "unit": "USD", "decimals": 2}
        }),
    );
    let issued = resource
        .authorize_endpoint(&authorize, NOW, "rt-per-call-budget")
        .into_response();
    assert_eq!(issued.status(), 200, "resource still issues the combined token");
    let resource_token = member(&issued, "resource_token").expect("resource token");
    let exchanged = ps.handle(&post(
        &signer,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person }),
    ));
    assert_eq!(exchanged.status(), 400);
    assert_eq!(
        member(&exchanged, "error").as_deref(),
        Some("invalid_resource_token")
    );
    assert!(member(&exchanged, "auth_token").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0, "refusal does not run the tool");
}

#[test]
fn fresh_resource_spends_the_same_grant_again() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let documents = Arc::new(Documents::default());
    let (resource, calls, _) = resource_with(&profile, true, false, documents.clone());
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-ledger-restart",
    );
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "admit-ledger") {
        AuthDecision::Granted(admitted) => assert_eq!(admitted.admitted(), "receipt"),
        other => panic!("first admission: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "again-ledger") {
        AuthDecision::AuthTokenRequired { budget_reason, .. } => {
            assert_eq!(budget_reason.as_deref(), Some("budget-exhausted"));
        }
        other => panic!("spent ledger: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the spent ledger does not run the tool");
    let (restarted, restarted_calls, _) = resource_with(&profile, true, false, documents);
    match restarted.authorize(&signed_call("/op/permit", &auth), NOW, "restarted-ledger") {
        AuthDecision::Granted(admitted) => {
            assert_eq!(admitted.admitted(), "receipt");
            let header = admitted.budget_header().expect("metered admission");
            assert!(header.contains("remaining=0"), "{header}");
        }
        other => panic!("fresh ledger: {other:?}"),
    }
    assert_eq!(restarted_calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn shared_budget_ledger_continues_after_recomposition() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let documents = Arc::new(Documents::default());
    let (resource, calls, _) = resource_with(&profile, true, false, documents.clone());
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-shared-ledger",
    );
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "admit-shared") {
        AuthDecision::Granted(admitted) => assert_eq!(admitted.admitted(), "receipt"),
        other => panic!("first admission: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let ledger = resource.budget_ledger().expect("metered ledger");
    let (continued, continued_calls, _) =
        resource_with_ledger(&profile, true, false, documents, Some(ledger), None);
    match continued.authorize(&signed_call("/op/permit", &auth), NOW, "continued-ledger") {
        AuthDecision::AuthTokenRequired { budget_reason, .. } => {
            assert_eq!(budget_reason.as_deref(), Some("budget-exhausted"));
        }
        other => panic!("shared ledger: {other:?}"),
    }
    assert_eq!(
        continued_calls.load(Ordering::SeqCst),
        0,
        "the continued ledger does not run the tool"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct OneCall(Mutex<Option<R3ProposalRecord>>);
impl R3CallStore for OneCall {
    fn commit(&self, record: &R3ProposalRecord) -> Result<(), R3StoreError> {
        let mut slot = self.0.lock().unwrap();
        if slot.is_some() {
            return Err(R3StoreError::Conflict);
        }
        *slot = Some(record.clone());
        Ok(())
    }
    fn load(&self, uri: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .filter(|record| record.reference.uri() == uri)
            .cloned())
    }
    fn load_pending(&self, _: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        Ok(None)
    }
    fn claim(&self, _: &str, _: &R3CallToken, _: i64) -> Result<R3Claim, R3StoreError> {
        Err(R3StoreError::Unavailable(R3HostError::new("unused")))
    }
    fn retain(&self, _: &str, _: &str, _: &R3CallResult) -> Result<R3CallResult, R3StoreError> {
        Err(R3StoreError::Unavailable(R3HostError::new("unused")))
    }
    fn held_releases(
        &self,
        _: &str,
        _: &str,
        _: i64,
    ) -> Result<Vec<R3ProposalRecord>, R3StoreError> {
        Ok(Vec::new())
    }
    fn supersede(&self, _: &str, _: &R3ProposalRecord, _: i64) -> Result<(), R3StoreError> {
        Err(R3StoreError::Conflict)
    }
}

struct SplitPolicy {
    proposals: Arc<AtomicUsize>,
    vocabulary: Vocabulary,
    granted: Operation,
    per_call: Operation,
}
impl R3Policy for SplitPolicy {
    fn authorize_document(
        &self,
        _: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError> {
        Ok(R3Decision {
            granted: GrantedOperations::new(&self.vocabulary, std::slice::from_ref(&self.granted))
                .unwrap(),
            per_call: Some(
                GrantedOperations::new(&self.vocabulary, std::slice::from_ref(&self.per_call))
                    .unwrap(),
            ),
            scopes: Vec::new(),
            lifetime: 600,
        })
    }
    fn authorize_proposal(
        &self,
        _: &R3ProposalRequest<'_>,
    ) -> Result<R3ProposalDecision, PolicyError> {
        self.proposals.fetch_add(1, Ordering::SeqCst);
        Ok(R3ProposalDecision {
            scopes: Vec::new(),
            lifetime: 600,
        })
    }
}

fn proposal_artifact_uri(exact: &[u8], jti: &str) -> String {
    let entitlement = serde_json::to_vec(&json!(["aauth-r3-entitlement-v1", PS, PS])).unwrap();
    let lineage = format!("aauth-r3-proposal-v1\0{jti}");
    format!(
        "{RESOURCE}/r3/p.{}.{}.{}",
        digest(exact),
        digest(&entitlement),
        digest(lineage.as_bytes())
    )
}

#[test]
fn proposal_with_a_budget_offer_is_refused_before_approval() {
    let profile = odata_profile();
    let documents = Arc::new(Documents::default());
    let calls = Arc::new(OneCall(Mutex::new(None)));
    let proposals = Arc::new(AtomicUsize::new(0));
    let permit = operation(&profile, profile.operations[0]);
    let per_call = operation(&profile, profile.operations[1]);
    let present: BoxedR3Present = Box::new(|_: &Request<Vec<u8>>, _: &Operation| {
        Err(R3HostError::new("unused"))
    });
    let describe: BoxedR3Describe =
        Box::new(|_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Err(R3HostError::new("unused"))
        });
    let permit_for_map = permit.clone();
    let per_call_for_map = per_call.clone();
    let mapper: BoxedR3OperationMapper = Box::new(move |request: &Request<Vec<u8>>| {
        Ok(match request.uri().path() {
            "/op/permit" => Some(permit_for_map.clone()),
            "/op/refuse" => Some(per_call_for_map.clone()),
            _ => None,
        })
    });
    let effects = Arc::new(AtomicUsize::new(0));
    let admission = {
        let effects = effects.clone();
        Box::new(move |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok("receipt".to_owned())
        }) as BoxedAuthAdmissionPolicy<String>
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
            admission,
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
            documents: documents.clone(),
            operation_for_request: mapper,
            require_core_scope: false,
        })
        .unwrap()
        .with_r3_per_call(R3PerCallConfig {
            present,
            describe,
            calls: calls.clone(),
            hold: false,
            release: None,
            held_result_lifetime: 300,
        })
        .unwrap()
        .with_budgets(
            vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
            "https://resource.example/usage",
            500,
            500,
        )
        .unwrap(),
    );
    let signer = agent();
    let ids = AtomicUsize::new(0);
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
            if uri.starts_with(&format!("{RESOURCE}/r3/")) {
                Ok(())
            } else {
                Err(std::io::Error::other("egress refused"))
            }
        }),
        transport: Box::new(InProcess(resource.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(SplitPolicy {
            proposals: proposals.clone(),
            vocabulary: profile.vocabulary.clone(),
            granted: permit.clone(),
            per_call: per_call.clone(),
        }),
        audit: Arc::new(Audit),
    })
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let authorize = post(
        &presented,
        &format!("{RESOURCE}/authorize"),
        json!({
            "r3_operations": {
                "vocabulary": profile.vocabulary.uri().as_str(),
                "operations": [
                    serde_json::from_str::<Value>(profile.operations[0]).unwrap(),
                    serde_json::from_str::<Value>(profile.operations[1]).unwrap(),
                ],
            }
        }),
    );
    let issued = resource
        .authorize_endpoint(&authorize, NOW, "rt-class-for-proposal")
        .into_response();
    assert_eq!(
        issued.status(),
        200,
        "{}",
        String::from_utf8_lossy(issued.body())
    );
    let class_resource = member(&issued, "resource_token").expect("class resource token");
    let class_exchange = ps.handle(&post(
        &signer,
        &format!("{PS}/token"),
        json!({ "resource_token": class_resource, "presented_token": person }),
    ));
    assert_eq!(
        class_exchange.status(),
        200,
        "{}",
        String::from_utf8_lossy(class_exchange.body())
    );
    let class_auth = member(&class_exchange, "auth_token").expect("class auth token");
    let class_jti = aauth_rust_core::AuthToken::parse(&class_auth)
        .unwrap()
        .unverified_claims()
        .jti
        .clone();
    let parameters = Parameters::new(std::iter::empty()).expect("empty parameters");
    let proposal = Proposal::new(&per_call, &parameters, ProposalOptions::default()).unwrap();
    let exact = serde_json::to_vec(&proposal).unwrap();
    let jti = "rt-proposal";
    let uri = proposal_artifact_uri(&exact, jti);
    let mut claims = ResourceToken::parse(&class_resource)
        .unwrap()
        .unverified_claims()
        .clone();
    claims.jti = jti.into();
    claims.presented_jti = class_jti;
    claims.iat = NOW;
    claims.exp = NOW + 300;
    claims.extra.clear();
    claims.scope = None;
    let (plain, reference) = mint_proposal_resource_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &claims,
        &uri,
        &exact,
    )
    .expect("proposal resource token");
    calls
        .commit(&R3ProposalRecord {
            reference: reference.clone(),
            exact_json: exact.clone(),
            person_server: PS.into(),
            auth_token_issuer: PS.into(),
            resource_token_jti: jti.into(),
            resource_token: plain.clone(),
            class_reference: Reference::new(
                "https://resource.example/r3/c.class",
                digest(b"class"),
            )
            .unwrap(),
            presented_jti: claims.presented_jti.clone(),
            subject: claims.sub.clone(),
            agent_jkt: claims.agent_jkt.clone(),
            tenant: claims.tenant.clone(),
            account: claims.account.clone(),
            scope: None,
            issued_at: claims.iat,
            expires_at: claims.exp,
            held: None,
            released: None,
            release_until: None,
            supersedes: None,
        })
        .unwrap();
    let approved = ps.handle(&post(
        &signer,
        &format!("{PS}/token"),
        json!({ "resource_token": plain, "presented_token": class_auth }),
    ));
    assert_eq!(
        approved.status(),
        200,
        "{}",
        String::from_utf8_lossy(approved.body())
    );
    assert_eq!(proposals.load(Ordering::SeqCst), 1, "the plain proposal is approved");
    claims.extra.insert(
        "budget".into(),
        json!({"amount": 500, "unit": "USD", "decimals": 2}),
    );
    claims.extra.insert("r3_uri".into(), json!(uri));
    claims
        .extra
        .insert("r3_s256".into(), json!(reference.digest()));
    let with_budget = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &claims,
    )
    .expect("proposal token with a budget offer");
    let refused = ps.handle(&post(
        &signer,
        &format!("{PS}/token"),
        json!({ "resource_token": with_budget, "presented_token": class_auth }),
    ));
    assert_eq!(
        refused.status(),
        400,
        "{}",
        String::from_utf8_lossy(refused.body())
    );
    assert_eq!(
        member(&refused, "error").as_deref(),
        Some("invalid_resource_token")
    );
    assert!(member(&refused, "auth_token").is_none());
    assert_eq!(
        proposals.load(Ordering::SeqCst),
        1,
        "the budget offer does not record another approval"
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[test]
fn later_class_grant_is_narrowed_to_the_remaining_cap() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, _, _) = resource_for(&profile, true);
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        800,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let first = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-cap-1");
    let second = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-cap-2");
    let amount = |token: &str| {
        aauth_rust_core::AuthToken::parse(token)
            .unwrap()
            .unverified_claims()
            .extra
            .get("budget")
            .and_then(|budget| budget.get("amount"))
            .and_then(Value::as_i64)
    };
    assert_eq!(amount(&first), Some(500));
    assert_eq!(amount(&second), Some(300));
}

#[test]
fn failed_r3_audit_does_not_reserve_the_budget_cap() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, _, _) = resource_for(&profile, true);
    let signer = agent();
    let ids = AtomicUsize::new(0);
    let permit = operation(&profile, profile.operations[0]);
    let vocabulary = profile.vocabulary.clone();
    let audit = Arc::new(GatedAudit(Mutex::new(true)));
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
        audit: audit.clone(),
    })
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        800,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let withheld = exchange_budget_response(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-audit-fail",
    );
    assert_eq!(withheld.status(), 500, "{}", String::from_utf8_lossy(withheld.body()));
    assert_eq!(member(&withheld, "error").as_deref(), Some("server_error"));
    assert!(member(&withheld, "auth_token").is_none());
    assert_eq!(ps.budget_accounted(), Some(0));
    *audit.0.lock().unwrap() = false;
    let released = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-audit-ok",
    );
    let amount = aauth_rust_core::AuthToken::parse(&released)
        .unwrap()
        .unverified_claims()
        .extra
        .get("budget")
        .and_then(|budget| budget.get("amount"))
        .and_then(Value::as_i64);
    assert_eq!(amount, Some(500));
    assert_eq!(ps.budget_accounted(), Some(500));
}

#[test]
fn reserved_class_call_settles_below_the_hold() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let documents = Arc::new(Documents::default());
    let (resource, calls, _) = resource_with(&profile, true, false, documents.clone());
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-settle",
    );
    let held = match resource.authorize_reserved(&signed_call("/op/permit", &auth), NOW, "hold-1") {
        AuthDecision::Held(held) => held,
        other => panic!("reserve: {other:?}"),
    };
    assert_eq!(held.admitted(), "receipt");
    assert!(held.r3_grant().is_some(), "the hold keeps the class grant");
    assert_eq!(held.admitted_maximum(), 500);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let streamed = resource
        .budget_stream_header(held.reservation())
        .expect("reserved header");
    assert!(streamed.contains("reserved=500"), "{streamed}");
    assert!(streamed.contains("remaining=0"), "{streamed}");
    let settled = resource
        .budget_commit(held.reservation(), 200, NOW)
        .expect("settle below the hold");
    assert!(settled.contains("cost=200"), "{settled}");
    assert!(settled.contains("remaining=300"), "{settled}");
    drop(held);
    match resource.authorize(
        &signed_call_cost("/op/permit", &auth, 200),
        NOW,
        "after-settle",
    ) {
        AuthDecision::Granted(admitted) => assert_eq!(admitted.admitted(), "receipt"),
        other => panic!("room after settle: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "over-remaining") {
        AuthDecision::AuthTokenRequired { budget_reason, .. } => {
            assert_eq!(budget_reason.as_deref(), Some("insufficient-budget"));
        }
        other => panic!("over remaining: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the refusal does not run the tool");
}

#[test]
fn concurrent_class_calls_spend_the_grant_once() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let documents = Arc::new(Documents::default());
    let (resource, calls, _) = resource_with(&profile, true, false, documents.clone());
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-concurrent",
    );
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for index in 0..2 {
        let resource = Arc::clone(&resource);
        let auth = auth.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            resource.authorize(
                &signed_call("/op/permit", &auth),
                NOW,
                &format!("race-{index}"),
            )
        }));
    }
    let mut granted = 0;
    let mut exhausted = 0;
    for handle in handles {
        match handle.join().expect("call thread") {
            AuthDecision::Granted(admitted) => {
                assert_eq!(admitted.admitted(), "receipt");
                granted += 1;
            }
            AuthDecision::AuthTokenRequired { budget_reason, .. } => {
                assert_eq!(budget_reason.as_deref(), Some("budget-exhausted"));
                exhausted += 1;
            }
            other => panic!("concurrent call: {other:?}"),
        }
    }
    assert_eq!(granted, 1);
    assert_eq!(exhausted, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one call runs the tool");
}

#[test]
fn dropping_a_class_hold_releases_the_grant() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let documents = Arc::new(Documents::default());
    let (resource, calls, _) = resource_with(&profile, true, false, documents.clone());
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-drop-hold",
    );
    let held = resource.authorize_reserved(&signed_call("/op/permit", &auth), NOW, "hold-drop");
    let AuthDecision::Held(held) = held else {
        panic!("reserve: {held:?}");
    };
    assert!(held.r3_grant().is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(held);
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "after-drop") {
        AuthDecision::Granted(admitted) => {
            let header = admitted.budget_header().expect("committed field");
            assert!(header.contains("cost=500"), "{header}");
            assert!(header.contains("remaining=0"), "{header}");
        }
        other => panic!("released grant: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn denied_class_consent_writes_no_audit_and_reserves_nothing() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, _, _) = resource_for(&profile, true);
    let signer = agent();
    let ids = AtomicUsize::new(0);
    let permit = operation(&profile, profile.operations[0]);
    let vocabulary = profile.vocabulary.clone();
    let phase = Arc::new(AtomicUsize::new(0));
    let denials = Arc::new(AtomicUsize::new(0));
    let audits = Arc::new(AtomicUsize::new(0));
    let policy_phase = Arc::clone(&phase);
    let policy_denials = Arc::clone(&denials);
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
                if policy_phase.load(Ordering::SeqCst) == 0 {
                    policy_denials.fetch_add(1, Ordering::SeqCst);
                    return Err(PolicyError::Denied);
                }
                Ok(R3Decision {
                    granted: GrantedOperations::new(&vocabulary, std::slice::from_ref(&permit))
                        .unwrap(),
                    per_call: None,
                    scopes: Vec::new(),
                    lifetime: 600,
                })
            },
        ),
        audit: Arc::new(CountAudit(Arc::clone(&audits))),
    })
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        800,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let denied = exchange_budget_response(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-deny",
    );
    assert_eq!(denied.status(), 403, "{}", String::from_utf8_lossy(denied.body()));
    assert_eq!(member(&denied, "error").as_deref(), Some("access_denied"));
    assert!(member(&denied, "auth_token").is_none());
    assert_eq!(denials.load(Ordering::SeqCst), 1);
    assert_eq!(audits.load(Ordering::SeqCst), 0);
    assert_eq!(ps.budget_accounted(), Some(0));
    phase.store(1, Ordering::SeqCst);
    let released = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-after-deny",
    );
    let amount = aauth_rust_core::AuthToken::parse(&released)
        .unwrap()
        .unverified_claims()
        .extra
        .get("budget")
        .and_then(|budget| budget.get("amount"))
        .and_then(Value::as_i64);
    assert_eq!(amount, Some(500));
    assert_eq!(audits.load(Ordering::SeqCst), 1);
    assert_eq!(ps.budget_accounted(), Some(500));
}

#[test]
fn class_grant_outside_the_document_writes_no_audit_and_reserves_nothing() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, _, _) = resource_for(&profile, true);
    let signer = agent();
    let ids = AtomicUsize::new(0);
    let permit = operation(&profile, profile.operations[0]);
    let vocabulary = profile.vocabulary.clone();
    let registry = standard_registry().unwrap();
    let mcp_document = registry
        .parse_document(
            br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"},{"tool":"records.delete"}]}"#,
        )
        .unwrap();
    let outside = registry
        .parse_grant(
            br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"}]}"#,
            &mcp_document,
        )
        .unwrap()
        .granted_operations();
    let phase = Arc::new(AtomicUsize::new(0));
    let decisions = Arc::new(AtomicUsize::new(0));
    let audits = Arc::new(AtomicUsize::new(0));
    let policy_phase = Arc::clone(&phase);
    let policy_decisions = Arc::clone(&decisions);
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
                policy_decisions.fetch_add(1, Ordering::SeqCst);
                if policy_phase.load(Ordering::SeqCst) == 0 {
                    return Ok(R3Decision {
                        granted: outside.clone(),
                        per_call: None,
                        scopes: Vec::new(),
                        lifetime: 600,
                    });
                }
                Ok(R3Decision {
                    granted: GrantedOperations::new(&vocabulary, std::slice::from_ref(&permit))
                        .unwrap(),
                    per_call: None,
                    scopes: Vec::new(),
                    lifetime: 600,
                })
            },
        ),
        audit: Arc::new(CountAudit(Arc::clone(&audits))),
    })
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        800,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let refused = exchange_budget_response(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-outside",
    );
    assert_eq!(refused.status(), 500, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(member(&refused, "error").as_deref(), Some("server_error"));
    assert!(member(&refused, "auth_token").is_none());
    assert_eq!(decisions.load(Ordering::SeqCst), 1);
    assert_eq!(audits.load(Ordering::SeqCst), 0);
    assert_eq!(ps.budget_accounted(), Some(0));
    phase.store(1, Ordering::SeqCst);
    let released = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-inside",
    );
    let amount = aauth_rust_core::AuthToken::parse(&released)
        .unwrap()
        .unverified_claims()
        .extra
        .get("budget")
        .and_then(|budget| budget.get("amount"))
        .and_then(Value::as_i64);
    assert_eq!(amount, Some(500));
    assert_eq!(audits.load(Ordering::SeqCst), 1);
    assert_eq!(ps.budget_accounted(), Some(500));
}

#[test]
fn core_budget_with_r3_enabled_skips_the_class_path_and_a_failed_commit_reserves_nothing() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, _, _) = resource_for(&profile, true);
    let signer = agent();
    let ids = AtomicUsize::new(0);
    let permit = operation(&profile, profile.operations[0]);
    let vocabulary = profile.vocabulary.clone();
    let r3_calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&r3_calls);
    let fail_commit = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
        keys(),
        GatedStore {
            inner: MemoryStore::default(),
            fail_commit: Arc::clone(&fail_commit),
        },
        CoreGrant,
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
                seen.fetch_add(1, Ordering::SeqCst);
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        800,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    fail_commit.store(true, std::sync::atomic::Ordering::SeqCst);
    let withheld = exchange_core_budget_response(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-core-fail",
    );
    assert_eq!(withheld.status(), 500, "{}", String::from_utf8_lossy(withheld.body()));
    assert_eq!(member(&withheld, "error").as_deref(), Some("server_error"));
    assert!(member(&withheld, "auth_token").is_none());
    assert_eq!(ps.budget_accounted(), Some(0));
    assert_eq!(r3_calls.load(Ordering::SeqCst), 0);
    let released = exchange_core_budget_response(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-core-ok",
    );
    assert_eq!(released.status(), 200, "{}", String::from_utf8_lossy(released.body()));
    let auth = member(&released, "auth_token").expect("core auth token");
    let extra = aauth_rust_core::AuthToken::parse(&auth)
        .unwrap()
        .unverified_claims()
        .extra
        .clone();
    assert!(extra.get("r3_uri").is_none());
    assert_eq!(
        extra.get("budget").and_then(|budget| budget.get("amount")).and_then(Value::as_i64),
        Some(500)
    );
    assert_eq!(ps.budget_accounted(), Some(500));
    assert_eq!(r3_calls.load(Ordering::SeqCst), 0);
    let class = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-after-core",
    );
    let class_amount = aauth_rust_core::AuthToken::parse(&class)
        .unwrap()
        .unverified_claims()
        .extra
        .get("budget")
        .and_then(|budget| budget.get("amount"))
        .and_then(Value::as_i64);
    assert_eq!(class_amount, Some(300));
    assert_eq!(r3_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ps.budget_accounted(), Some(800));
}

fn exchange_core_budget_response<S: aauth_rust_person_server::Store, P: Policy>(
    resource: &Resource,
    ps: &PersonServer<Keys, S, P, BoxedClock, BoxedTokenIds>,
    presented: &Agent,
    signer: &Agent,
    person: &str,
    resource_jti: &str,
) -> Response<Vec<u8>> {
    let authorize = post(
        presented,
        &format!("{RESOURCE}/authorize"),
        json!({
            "scope": "records.read",
            "budget": {"amount": 500, "unit": "USD", "decimals": 2}
        }),
    );
    let issued = resource
        .authorize_endpoint(&authorize, NOW, resource_jti)
        .into_response();
    assert_eq!(issued.status(), 200, "{resource_jti}");
    let resource_token = member(&issued, "resource_token").expect("resource token");
    ps.handle(&post(
        signer,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person }),
    ))
}

#[test]
fn denied_class_call_releases_the_budget_hold() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let documents = Arc::new(Documents::default());
    let deny = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (resource, calls, _) =
        resource_with_ledger(&profile, true, false, documents.clone(), None, Some(Arc::clone(&deny)));
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-deny-call",
    );
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "denied-call") {
        AuthDecision::Forbidden { .. } => {}
        other => panic!("denied call: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "denial does not run the tool");
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "after-denial") {
        AuthDecision::Granted(admitted) => {
            let header = admitted.budget_header().expect("committed field");
            assert!(header.contains("cost=500"), "{header}");
            assert!(header.contains("remaining=0"), "{header}");
        }
        other => panic!("grant after denial: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn class_budget_grant_stops_at_period_end() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, _, _) = resource_for(&profile, true);
    let signer = agent();
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
    .unwrap()
    .with_budgets(
        IssuerPolicy::capped(
            2_000_000,
            vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
        )
        .until(NOW + 120),
    )
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-period");
    let claims = aauth_rust_core::AuthToken::parse(&auth)
        .unwrap()
        .unverified_claims()
        .clone();
    assert_eq!(claims.exp, NOW + 120, "period_end caps a 600-second decision");
    assert_eq!(
        claims.extra.get("budget").and_then(|budget| budget.get("amount")).and_then(Value::as_i64),
        Some(500)
    );
}

#[test]
fn class_grant_signs_zero_when_the_cap_is_spent() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, calls, _) = resource_for(&profile, true);
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        500,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let first = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-zero-1");
    let second = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-zero-2");
    let amount = |token: &str| {
        aauth_rust_core::AuthToken::parse(token)
            .unwrap()
            .unverified_claims()
            .extra
            .get("budget")
            .and_then(|budget| budget.get("amount"))
            .and_then(Value::as_i64)
    };
    assert_eq!(amount(&first), Some(500));
    assert_eq!(amount(&second), Some(0));
    match resource.authorize(&signed_call("/op/permit", &second), NOW, "zero-grant") {
        AuthDecision::AuthTokenRequired { budget_reason, .. } => {
            assert_eq!(budget_reason.as_deref(), Some("budget-exhausted"));
        }
        other => panic!("zero grant: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "a zero grant does not run the tool");
}

#[test]
fn class_cap_is_free_again_after_the_grant_expires() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, _, _) = resource_for(&profile, true);
    let signer = agent();
    let ids = AtomicUsize::new(0);
    let clock = Arc::new(AtomicI64::new(NOW));
    let permit = operation(&profile, profile.operations[0]);
    let vocabulary = profile.vocabulary.clone();
    let ps_clock = clock.clone();
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::from_seed([3; 32])),
        keys(),
        MemoryStore::default(),
        HostPolicy,
        Box::new(move || ps_clock.load(Ordering::SeqCst)) as BoxedClock,
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
                    lifetime: 50,
                })
            },
        ),
        audit: Arc::new(Audit),
    })
    .unwrap()
    .with_budgets(
        IssuerPolicy::capped(
            500,
            vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
        )
        .until(NOW + 600),
    )
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let first = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-settle-1");
    let first_claims = aauth_rust_core::AuthToken::parse(&first)
        .unwrap()
        .unverified_claims()
        .clone();
    assert_eq!(
        first_claims.extra.get("budget").and_then(|budget| budget.get("amount")).and_then(Value::as_i64),
        Some(500)
    );
    assert_eq!(first_claims.exp, NOW + 50);
    clock.store(first_claims.exp, Ordering::SeqCst);
    let second = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-settle-2");
    let second_claims = aauth_rust_core::AuthToken::parse(&second)
        .unwrap()
        .unverified_claims()
        .clone();
    assert_eq!(
        second_claims.extra.get("budget").and_then(|budget| budget.get("amount")).and_then(Value::as_i64),
        Some(500),
        "the cap is free once the first grant reaches exp"
    );
    assert_eq!(second_claims.exp, NOW + 100);
}

#[test]
fn r3_only_class_token_is_unchanged_when_budgets_are_enabled() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, calls, _) = resource_for(&profile, true);
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let authorize = post(
        &presented,
        &format!("{RESOURCE}/authorize"),
        json!({
            "r3_operations": {
                "vocabulary": profile.vocabulary.uri().as_str(),
                "operations": [serde_json::from_str::<Value>(profile.operations[0]).unwrap()],
            }
        }),
    );
    let issued = resource
        .authorize_endpoint(&authorize, NOW, "rt-r3-only")
        .into_response();
    assert_eq!(issued.status(), 200, "{}", String::from_utf8_lossy(issued.body()));
    let resource_token = member(&issued, "resource_token").expect("resource token");
    assert!(
        ResourceToken::parse(&resource_token)
            .unwrap()
            .unverified_claims()
            .extra
            .get("budget")
            .is_none()
    );
    let exchanged = ps.handle(&post(
        &signer,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person }),
    ));
    assert_eq!(exchanged.status(), 200, "{}", String::from_utf8_lossy(exchanged.body()));
    let auth = member(&exchanged, "auth_token").expect("auth token");
    assert!(
        aauth_rust_core::AuthToken::parse(&auth)
            .unwrap()
            .unverified_claims()
            .extra
            .get("budget")
            .is_none()
    );
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "r3-only") {
        AuthDecision::Granted(admitted) => assert_eq!(admitted.admitted(), "receipt"),
        other => panic!("r3-only admission: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn budgets_before_r3_still_exchange_and_admit() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, calls, _) = resource_for(&profile, true);
    let signer = agent();
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
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
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
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();
    let auth = exchange_budget_auth(
        &resource,
        &ps,
        &presented,
        &signer,
        &person,
        "rt-budgets-first",
    );
    assert_eq!(
        aauth_rust_core::AuthToken::parse(&auth)
            .unwrap()
            .unverified_claims()
            .extra
            .get("budget")
            .cloned(),
        Some(json!({"amount": 500, "unit": "USD", "decimals": 2}))
    );
    match resource.authorize(&signed_call("/op/permit", &auth), NOW, "admit-budgets-first") {
        AuthDecision::Granted(admitted) => assert_eq!(admitted.admitted(), "receipt"),
        other => panic!("budgets-first admission: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn combined_budget_auth_expires_and_a_later_grant_revokes() {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let (resource, calls, _) = resource_with(
        &profile,
        true,
        true,
        Arc::new(Documents::default()),
    );
    let signer = agent();
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
    .unwrap()
    .with_budgets(IssuerPolicy::capped(
        2_000_000,
        vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()],
    ))
    .unwrap();
    let person = member(
        &ps.handle(&post(
            &signer,
            &format!("{PS}/person"),
            json!({ "resource": RESOURCE }),
        )),
        "person_token",
    )
    .expect("person token");
    let presented = signer.with_token(person.clone()).unwrap();

    let first = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-expire");
    match resource.authorize(&signed_call_at("/op/permit", &first, NOW), NOW, "admit-1") {
        AuthDecision::Granted(admitted) => {
            assert_eq!(admitted.admitted(), "receipt");
            let header = admitted.budget_header().expect("metered admission");
            assert!(header.contains("remaining=0"), "{header}");
        }
        other => panic!("first admission: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let first_claims = aauth_rust_core::AuthToken::parse(&first)
        .unwrap()
        .unverified_claims()
        .clone();
    assert!(first_claims.exp > NOW, "grant is live at issuance");
    let expired = resource
        .authorize(
            &signed_call_at("/op/permit", &first, first_claims.exp),
            first_claims.exp,
            "after-exp",
        )
        .into_response();
    assert_eq!(expired.status(), 401);
    assert_eq!(expired.headers()["signature-error"], "error=expired_jwt");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "expiry does not run the tool");

    let second = exchange_budget_auth(&resource, &ps, &presented, &signer, &person, "rt-revoke");
    let second_claims = aauth_rust_core::AuthToken::parse(&second)
        .unwrap()
        .unverified_claims()
        .clone();
    match resource.authorize(&signed_call_at("/op/permit", &second, NOW), NOW, "admit-2") {
        AuthDecision::Granted(admitted) => {
            assert_eq!(admitted.admitted(), "receipt");
            let header = admitted.budget_header().expect("metered admission");
            assert!(header.contains("remaining=0"), "{header}");
        }
        other => panic!("second admission: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let recorded = resource.revoke(&ps_revocation(&second_claims.jti, second_claims.exp), NOW);
    assert_eq!(recorded.status(), 200, "person server revocation is recorded");
    let revoked = resource
        .authorize(
            &signed_call_at("/op/permit", &second, NOW),
            NOW,
            "after-revoke",
        )
        .into_response();
    assert_eq!(revoked.status(), 401);
    assert_eq!(revoked.headers()["signature-error"], "error=revoked_jwt");
    assert_eq!(
        revoked.headers()["aauth-requirement"],
        "requirement=person-token"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "revocation does not run the tool"
    );
}

fn exchange_budget_auth<S: aauth_rust_person_server::Store, P: Policy>(
    resource: &Resource,
    ps: &PersonServer<Keys, S, P, BoxedClock, BoxedTokenIds>,
    presented: &Agent,
    signer: &Agent,
    person: &str,
    resource_jti: &str,
) -> String {
    let exchanged = exchange_budget_response(resource, ps, presented, signer, person, resource_jti);
    assert_eq!(exchanged.status(), 200, "{resource_jti}");
    member(&exchanged, "auth_token").expect("auth token")
}

fn exchange_budget_response<S: aauth_rust_person_server::Store, P: Policy>(
    resource: &Resource,
    ps: &PersonServer<Keys, S, P, BoxedClock, BoxedTokenIds>,
    presented: &Agent,
    signer: &Agent,
    person: &str,
    resource_jti: &str,
) -> Response<Vec<u8>> {
    let profile = profiles().into_iter().next().expect("one parser profile");
    let authorize = post(
        presented,
        &format!("{RESOURCE}/authorize"),
        json!({
            "r3_operations": {
                "vocabulary": profile.vocabulary.uri().as_str(),
                "operations": [serde_json::from_str::<Value>(profile.operations[0]).unwrap()],
            },
            "budget": {"amount": 500, "unit": "USD", "decimals": 2}
        }),
    );
    let issued = resource
        .authorize_endpoint(&authorize, NOW, resource_jti)
        .into_response();
    assert_eq!(issued.status(), 200, "{resource_jti}");
    let resource_token = member(&issued, "resource_token").expect("resource token");
    ps.handle(&post(
        signer,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person }),
    ))
}

fn ps_revocation(jti: &str, exp: i64) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{RESOURCE}/revoke"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"jti": jti, "exp": exp})).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        NOW,
    )
    .unwrap();
    request
}

#[test]
fn parsers_admit_and_refuse_over_real_tls() {
    for profile in profiles() {
        let (resource, calls, _) = resource_for(&profile, false);
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
    signed_call_at(path, token, NOW)
}

fn signed_call_cost(path: &str, token: &str, cost: i64) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri(format!("{RESOURCE}{path}"))
        .header("aauth-max-cost", cost.to_string())
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

fn signed_call_at(path: &str, token: &str, now: i64) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri(format!("{RESOURCE}{path}"))
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt(token.into()),
        now,
    )
    .unwrap();
    request
}

struct GatedStore {
    inner: MemoryStore,
    fail_commit: Arc<std::sync::atomic::AtomicBool>,
}
impl aauth_rust_person_server::Store for GatedStore {
    fn binding(
        &self,
        issuer: &str,
        agent: &aauth_rust_person_server::AgentIdentity,
    ) -> Result<Option<aauth_rust_person_server::Binding>, aauth_rust_person_server::StoreError>
    {
        self.inner.binding(issuer, agent)
    }
    fn token(
        &self,
        reference: &aauth_rust_person_server::TokenReference,
    ) -> Result<Option<aauth_rust_person_server::TokenRecord>, aauth_rust_person_server::StoreError>
    {
        self.inner.token(reference)
    }
    fn commit(
        &self,
        record: aauth_rust_person_server::TokenRecord,
        establish_binding: bool,
    ) -> Result<(), aauth_rust_person_server::StoreError> {
        if self
            .fail_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(aauth_rust_person_server::StoreError::Unavailable);
        }
        self.inner.commit(record, establish_binding)
    }
    fn revoke_binding(
        &self,
        issuer: &str,
        agent: &aauth_rust_person_server::AgentIdentity,
    ) -> Result<(), aauth_rust_person_server::StoreError> {
        self.inner.revoke_binding(issuer, agent)
    }
}

struct CountAudit(Arc<AtomicUsize>);
impl aauth_rust_r3::IssuanceStore for CountAudit {
    fn commit(
        &self,
        _: &aauth_rust_r3::IssuanceRecord,
    ) -> Result<(), aauth_rust_r3::IssuanceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct GatedAudit(Mutex<bool>);
impl aauth_rust_r3::IssuanceStore for GatedAudit {
    fn commit(
        &self,
        _: &aauth_rust_r3::IssuanceRecord,
    ) -> Result<(), aauth_rust_r3::IssuanceError> {
        if *self.0.lock().unwrap() {
            return Err(aauth_rust_r3::IssuanceError::Store(Box::new(
                std::io::Error::other("audit unavailable"),
            )));
        }
        Ok(())
    }
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
