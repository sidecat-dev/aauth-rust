//! Immediate class R3 on the direct Person-Server Resource.
//!
//! `VolatileTestStore` is a test double with injected faults. It is process
//! memory and does not satisfy the durable `R3DocumentStore` contract.
use aauth_rust_budgets::UnitDeclaration;
use aauth_rust_core::{
    AgentKeyResolver, AuthClaims, Confirmation, PersonClaims, ResourceToken, TokenError,
    TrustedIssuerKeys, VerifiedAuthToken, mint_auth_token, mint_person_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_r3::{
    AuthoritativeSnapshot, Authorization, DefinitionRegistry, Display as R3Display,
    GrantedOperations, McpCodec, Operation, OperationSet, ToolsListPage, ToolsListSnapshot, digest,
    standard_registry, verify_budget_resource_token, verify_resource_token,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthAdmissionPolicy, BoxedR3OperationMapper, Deny, ProactiveDecision,
    PsAuthorizationConfig, PsAuthorizationResource, PsConfigurationError, R3Config,
    R3DocumentRecord, R3DocumentStore, R3HostError, R3StoreError, R3Vocabulary,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

const NOW: i64 = 1000;
const RESOURCE: &str = "https://resource.example";
const ORIGIN: &str = "https://resource.example:8443";
const PS: &str = "https://ps.example";
const OTHER_PS: &str = "https://other-ps.example";
const AP: &str = "https://ap.example";
const MCP_URI: &str = "urn:aauth:vocabulary:mcp";
const MCP_ENDPOINT: &str = "https://resource.example/mcp";
const TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"}},{"name":"records.delete","inputSchema":{"type":"object"}}]}"#;

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
        issuer_key(OTHER_PS, "aauth-person.json", 5, "ops-1"),
    ])
}

#[derive(Clone, Copy)]
enum Fault {
    Conflict,
    Unavailable,
}
#[derive(Default)]
struct VolatileTestStore {
    records: Mutex<BTreeMap<String, R3DocumentRecord>>,
    commit_fault: Mutex<Option<Fault>>,
    load_fails: AtomicBool,
}
impl R3DocumentStore for VolatileTestStore {
    fn commit(&self, record: &R3DocumentRecord) -> Result<(), R3StoreError> {
        match *self.commit_fault.lock().unwrap() {
            Some(Fault::Conflict) => return Err(R3StoreError::Conflict),
            Some(Fault::Unavailable) => {
                return Err(R3StoreError::Unavailable(R3HostError::new("injected")));
            }
            None => {}
        }
        let mut records = self.records.lock().unwrap();
        match records.get(record.reference.uri()) {
            Some(existing) if existing != record => Err(R3StoreError::Conflict),
            _ => {
                records.insert(record.reference.uri().to_owned(), record.clone());
                Ok(())
            }
        }
    }
    fn load(&self, uri: &str) -> Result<Option<R3DocumentRecord>, R3StoreError> {
        if self.load_fails.load(Ordering::SeqCst) {
            return Err(R3StoreError::Unavailable(R3HostError::new("injected")));
        }
        Ok(self.records.lock().unwrap().get(uri).cloned())
    }
}

fn mcp(tool: &str) -> Operation {
    Operation::new(
        &McpCodec::vocabulary().unwrap(),
        format!(r#"{{"tool":"{tool}"}}"#).as_bytes(),
    )
    .unwrap()
}
fn snapshot() -> AuthoritativeSnapshot {
    McpCodec::parse_definition(
        MCP_ENDPOINT,
        &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
    )
    .unwrap()
}
fn mapper() -> BoxedR3OperationMapper {
    Box::new(|request: &Request<Vec<u8>>| Ok(request.uri().path().strip_prefix("/mcp/").map(mcp)))
}
fn r3_config(store: &Arc<VolatileTestStore>, require_core_scope: bool) -> R3Config {
    R3Config {
        registry: standard_registry().unwrap(),
        definitions: DefinitionRegistry::new(&[McpCodec::definition_registration().unwrap()])
            .unwrap(),
        vocabularies: vec![R3Vocabulary {
            definition: snapshot(),
            display: Some(Box::new(|_: &OperationSet| {
                R3Display::new("Read your records", None, Some("Record titles"), None)
                    .map_err(|_| R3HostError::new("display"))
            })),
        }],
        documents: store.clone() as Arc<dyn R3DocumentStore>,
        operation_for_request: mapper(),
        require_core_scope,
    }
}
fn config() -> PsAuthorizationConfig {
    config_at(ORIGIN)
}
fn config_at(signed_origin: &str) -> PsAuthorizationConfig {
    PsAuthorizationConfig {
        issuer: RESOURCE.into(),
        signed_origin: signed_origin.into(),
        kid: "resource-1".into(),
        signing_key: SigningKey::from_seed([4; 32]),
        scopes: vec!["records.read".into()],
    }
}
type Policy = BoxedAuthAdmissionPolicy<String>;
type Resource = PsAuthorizationResource<Keys, Policy>;
fn policy(calls: &Arc<AtomicUsize>) -> Policy {
    let calls = calls.clone();
    Box::new(
        move |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| -> Result<String, Deny> {
            // The application effect: one receipt per admitted request.
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("receipt".into())
        },
    )
}
fn core_resource(calls: &Arc<AtomicUsize>) -> Resource {
    PsAuthorizationResource::new(config(), keys(), policy(calls))
        .unwrap()
        .with_authorization_endpoint()
}
fn resource(
    store: &Arc<VolatileTestStore>,
    calls: &Arc<AtomicUsize>,
    require_core_scope: bool,
) -> Resource {
    core_resource(calls)
        .with_r3(r3_config(store, require_core_scope))
        .unwrap()
}

fn person() -> String {
    mint_person_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &PersonClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: "directed-person".into(),
            jti: "person-1".into(),
            iat: NOW,
            exp: 3000,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([2; 32]).public_jwk(),
            },
            nbf: None,
            tenant: Some("team".into()),
            mission_s256: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}
fn auth_claims(scope: Option<&str>) -> AuthClaims {
    AuthClaims {
        iss: PS.into(),
        dwk: "aauth-person.json".into(),
        aud: RESOURCE.into(),
        sub: "directed-person".into(),
        jti: "auth-1".into(),
        iat: NOW,
        exp: 2500,
        ps: PS.into(),
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        scope: scope.map(Into::into),
        account: None,
        nbf: None,
        tenant: Some("team".into()),
        mission_s256: None,
        extra: Default::default(),
    }
}
fn authorize(body: Value) -> Request<Vec<u8>> {
    authorize_at(ORIGIN, body)
}
fn authorize_at(origin: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{origin}/authorize"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt(person()),
        NOW,
    )
    .unwrap();
    request
}
fn operations(tools: &[&str]) -> Value {
    let operations: Vec<Value> = tools.iter().map(|tool| json!({ "tool": tool })).collect();
    json!({ "vocabulary": MCP_URI, "operations": operations })
}
fn has_resource_token(response: &Response<Vec<u8>>) -> bool {
    response
        .body()
        .windows(14)
        .any(|bytes| bytes == b"resource_token")
}
/// `POST /authorize` with `r3_operations`; returns the committed record.
fn issue(
    resource: &Resource,
    store: &VolatileTestStore,
    tools: &[&str],
    jti: &str,
) -> R3DocumentRecord {
    let response = resource
        .authorize_endpoint(
            &authorize(json!({ "r3_operations": operations(tools) })),
            NOW,
            jti,
        )
        .into_response();
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let verified =
        verify_resource_token(body["resource_token"].as_str().unwrap(), &keys(), NOW).unwrap();
    store.records.lock().unwrap()[verified.reference().uri()].clone()
}
fn class_token(
    record: &R3DocumentRecord,
    granted: &[&str],
    per_call: &[&str],
    claims: &AuthClaims,
    seed: u8,
    kid: &str,
) -> String {
    let registry = standard_registry().unwrap();
    let document = registry
        .parse_referenced_document(&record.reference, &record.exact_json)
        .unwrap();
    let vocabulary = McpCodec::vocabulary().unwrap();
    let granted: Vec<Operation> = granted.iter().map(|tool| mcp(tool)).collect();
    let per_call: Vec<Operation> = per_call.iter().map(|tool| mcp(tool)).collect();
    let authorization = Authorization::new(
        &GrantedOperations::new(&vocabulary, &granted).unwrap(),
        &GrantedOperations::new(&vocabulary, &per_call).unwrap(),
        &document,
    )
    .unwrap();
    aauth_rust_r3::mint_auth_token(
        &registry,
        &SigningKey::from_seed([seed; 32]),
        kid,
        claims,
        &record.reference,
        &record.exact_json,
        &authorization,
    )
    .unwrap()
}
/// A PS-signed token whose R3 members were not proven against the document.
fn forged(record: &R3DocumentRecord, s256: &str, tools: &[&str], account: Option<&str>) -> String {
    let mut claims = auth_claims(None);
    claims.account = account.map(Into::into);
    claims
        .extra
        .insert("r3_uri".into(), json!(record.reference.uri()));
    claims.extra.insert("r3_s256".into(), json!(s256));
    claims.extra.insert("r3_granted".into(), operations(tools));
    mint_auth_token(&SigningKey::from_seed([3; 32]), "ps-1", &claims).unwrap()
}
fn call(path: &str, token: &str, seed: u8) -> Request<Vec<u8>> {
    call_at(ORIGIN, path, token, seed)
}
fn call_at(origin: &str, path: &str, token: &str, seed: u8) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .uri(format!("{origin}{path}"))
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::Jwt(token.into()),
        NOW,
    )
    .unwrap();
    request
}
fn fetch(record: &R3DocumentRecord, id: &str, dwk: &str, kid: &str, seed: u8) -> Request<Vec<u8>> {
    fetch_uri(record.reference.uri(), id, dwk, kid, seed)
}
/// Signs a GET of `uri` exactly as advertised; nothing rewrites it.
fn fetch_uri(uri: &str, id: &str, dwk: &str, kid: &str, seed: u8) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("accept", "application/json")
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([seed; 32]),
        KeyMaterial::JwksUri {
            id: id.into(),
            dwk: dwk.into(),
            kid: kid.into(),
        },
        NOW,
    )
    .unwrap();
    request
}
fn discloses(response: &Response<Vec<u8>>, record: &R3DocumentRecord) -> bool {
    response.body() == &record.exact_json
        || response
            .body()
            .windows(12)
            .any(|bytes| bytes == b"records.read")
}

#[test]
fn metadata_advertises_the_selected_definition_and_core_metadata_is_unchanged() {
    let calls = Arc::new(AtomicUsize::new(0));
    let core: Value = serde_json::from_slice(&core_resource(&calls).metadata().unwrap()).unwrap();
    assert!(core.get("r3_vocabularies").is_none());
    let store = Arc::new(VolatileTestStore::default());
    let r3: Value =
        serde_json::from_slice(&resource(&store, &calls, false).metadata().unwrap()).unwrap();
    assert_eq!(r3["r3_vocabularies"], json!({ MCP_URI: MCP_ENDPOINT }));
    // Core metadata keeps the issuer form; R3 names the endpoint it serves.
    assert_eq!(
        core["authorization_endpoint"],
        format!("{RESOURCE}/authorize")
    );
    assert_eq!(r3["authorization_endpoint"], format!("{ORIGIN}/authorize"));
    let mut without = r3.clone();
    without.as_object_mut().unwrap().remove("r3_vocabularies");
    without["authorization_endpoint"] = core["authorization_endpoint"].clone();
    assert_eq!(without, core);
}

#[test]
fn r3_operations_commit_exact_document_and_lineage_before_the_token_is_released() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    let response = resource
        .authorize_endpoint(
            &authorize(json!({ "r3_operations": operations(&["records.read"]) })),
            NOW,
            "rt-1",
        )
        .into_response();
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let compact = body["resource_token"].as_str().unwrap();
    let verified = verify_resource_token(compact, &keys(), NOW).unwrap();
    let claims = verified.claims();
    assert_eq!((claims.aud.as_str(), claims.ps.as_str()), (PS, PS));
    assert!(claims.scope.is_none(), "no Core scope was requested");
    assert!(
        verified
            .reference()
            .uri()
            .starts_with(&format!("{ORIGIN}/r3/c."))
    );
    let records = store.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[verified.reference().uri()];
    assert_eq!(&record.reference, verified.reference());
    assert_eq!(digest(&record.exact_json), verified.reference().digest());
    assert_eq!(record.resource_token, compact);
    assert_eq!(
        (
            record.person_server.as_str(),
            record.auth_token_issuer.as_str(),
            record.auth_token_issuer_document.as_str(),
            record.resource_token_jti.as_str(),
            record.presented_jti.as_str(),
            record.subject.as_str(),
            record.tenant.as_deref(),
        ),
        (
            PS,
            PS,
            "aauth-person.json",
            "rt-1",
            "person-1",
            "directed-person",
            Some("team")
        )
    );
    assert_eq!(
        record.agent_jkt,
        SigningKey::from_seed([2; 32])
            .public_jwk()
            .thumbprint()
            .unwrap()
    );
    let document = standard_registry()
        .unwrap()
        .parse_referenced_document(&record.reference, &record.exact_json)
        .unwrap();
    assert_eq!(document.display().unwrap().summary(), "Read your records");
    assert!(document.account().is_none());
    drop(records);

    let scoped = resource
        .authorize_endpoint(
            &authorize(json!({
                "scope": "records.read",
                "r3_operations": operations(&["records.read"]),
            })),
            NOW,
            "rt-2",
        )
        .into_response();
    let body: Value = serde_json::from_slice(scoped.body()).unwrap();
    let verified =
        verify_resource_token(body["resource_token"].as_str().unwrap(), &keys(), NOW).unwrap();
    assert_eq!(verified.claims().scope.as_deref(), Some("records.read"));
    assert_eq!(store.records.lock().unwrap().len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_r3_requests_release_no_token_and_retain_nothing() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    for (body, code) in [
        (
            json!({ "r3_operations": operations(&["records.purge"]) }),
            "invalid_request",
        ),
        (
            json!({ "r3_operations": {
                "vocabulary": "urn:aauth:vocabulary:openapi",
                "operations": [{ "operationId": "listRecords" }],
            } }),
            "invalid_request",
        ),
        (
            json!({ "r3_operations": { "vocabulary": MCP_URI, "operations": [] } }),
            "invalid_request",
        ),
        (json!({ "r3_operations": null }), "invalid_request"),
        (
            json!({ "account": "acct-1", "r3_operations": operations(&["records.read"]) }),
            "invalid_request",
        ),
        (
            json!({ "budget": {}, "r3_operations": operations(&["records.read"]) }),
            "invalid_request",
        ),
        (
            json!({ "scope": "records.write", "r3_operations": operations(&["records.read"]) }),
            "invalid_scope",
        ),
    ] {
        let response = resource
            .authorize_endpoint(&authorize(body.clone()), NOW, "rt-1")
            .into_response();
        assert_eq!(response.status(), 400, "{body}");
        let problem: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(problem["error"], code, "{body}");
        assert!(!has_resource_token(&response));
    }
    let required = self::resource(&store, &calls, true);
    let response = required
        .authorize_endpoint(
            &authorize(json!({ "r3_operations": operations(&["records.read"]) })),
            NOW,
            "rt-1",
        )
        .into_response();
    let problem: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(
        (response.status().as_u16(), &problem["error"]),
        (400, &json!("invalid_scope"))
    );
    assert!(store.records.lock().unwrap().is_empty());

    // Core scope requests stay Core: no R3 claims and no retained document.
    let core = resource
        .authorize_endpoint(&authorize(json!({ "scope": "records.read" })), NOW, "rt-3")
        .into_response();
    assert_eq!(core.status(), 200);
    let body: Value = serde_json::from_slice(core.body()).unwrap();
    let compact = body["resource_token"].as_str().unwrap();
    assert!(verify_resource_token(compact, &keys(), NOW).is_err());
    let plain = ResourceToken::parse(compact)
        .unwrap()
        .verify(&keys(), NOW)
        .unwrap();
    assert_eq!(plain.claims().scope.as_deref(), Some("records.read"));
    assert!(!plain.claims().extra.contains_key("r3_uri"));
    assert!(store.records.lock().unwrap().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn conflicting_or_uncertain_commits_withhold_the_resource_token() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    for fault in [Fault::Conflict, Fault::Unavailable] {
        *store.commit_fault.lock().unwrap() = Some(fault);
        let request = authorize(json!({ "r3_operations": operations(&["records.read"]) }));
        let decision = resource.authorize_endpoint(&request, NOW, "rt-1");
        assert!(matches!(decision, ProactiveDecision::RetentionFailed));
        let response = decision.into_response();
        assert_eq!(response.status(), 500);
        assert!(!has_resource_token(&response));
        // A Person challenge on a mapped route withholds its token the same way.
        let challenged = resource
            .authorize(&call("/mcp/records.read", &person(), 2), NOW, "rt-2")
            .into_response();
        assert_eq!(challenged.status(), 500);
        assert!(!challenged.headers().contains_key("aauth-requirement"));
    }
    *store.commit_fault.lock().unwrap() = None;
    assert!(store.records.lock().unwrap().is_empty());
    // A different record at an already retained URI is a conflict, not an overwrite.
    let record = issue(&resource, &store, &["records.read"], "rt-1");
    let mut changed = record.clone();
    changed.subject = "someone-else".into();
    assert!(matches!(
        store.commit(&changed),
        Err(R3StoreError::Conflict)
    ));
    assert_eq!(
        store.records.lock().unwrap()[record.reference.uri()],
        record
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn signed_fetch_serves_exact_bytes_only_to_the_entitled_person_server() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    let record = issue(&resource, &store, &["records.read"], "rt-1");

    let served = resource.r3_document(&fetch(&record, PS, "aauth-person.json", "ps-1", 3), NOW);
    assert_eq!(served.status(), 200);
    assert_eq!(served.body(), &record.exact_json);
    assert_eq!(served.headers()["content-type"], "application/json");
    assert_eq!(
        served.headers()["cache-control"],
        "private, no-store, no-transform"
    );

    // Verified signers who are not entitled see the same answer as a missing document.
    for request in [
        fetch(&record, OTHER_PS, "aauth-person.json", "ops-1", 5),
        fetch(&record, AP, "aauth-agent.json", "ap-1", 1),
        fetch_uri(
            &format!("{}A", record.reference.uri()),
            PS,
            "aauth-person.json",
            "ps-1",
            3,
        ),
        fetch_uri(
            &format!("{}?x=1", record.reference.uri()),
            PS,
            "aauth-person.json",
            "ps-1",
            3,
        ),
    ] {
        let response = resource.r3_document(&request, NOW);
        assert_eq!(response.status(), 404);
        assert!(!discloses(&response, &record));
    }
    // Wrong key, an Agent-style JWT proof, and no proof are authentication failures.
    let mut agent_signed = Request::builder()
        .method("GET")
        .uri(record.reference.uri())
        .body(Vec::new())
        .unwrap();
    sign_request(
        &mut agent_signed,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt(person()),
        NOW,
    )
    .unwrap();
    let unsigned = Request::builder()
        .method("GET")
        .uri(record.reference.uri())
        .body(Vec::new())
        .unwrap();
    for request in [
        fetch(&record, PS, "aauth-person.json", "ps-1", 9),
        agent_signed,
        unsigned,
    ] {
        let response = resource.r3_document(&request, NOW);
        assert_eq!(response.status(), 401);
        assert!(!discloses(&response, &record));
    }

    // Load failure and changed retained bytes disclose nothing.
    store.load_fails.store(true, Ordering::SeqCst);
    let failed = resource.r3_document(&fetch(&record, PS, "aauth-person.json", "ps-1", 3), NOW);
    assert_eq!(failed.status(), 500);
    assert!(!discloses(&failed, &record));
    store.load_fails.store(false, Ordering::SeqCst);
    let mut tampered = record.clone();
    tampered.exact_json.push(b' ');
    store
        .records
        .lock()
        .unwrap()
        .insert(record.reference.uri().to_owned(), tampered);
    let changed = resource.r3_document(&fetch(&record, PS, "aauth-person.json", "ps-1", 3), NOW);
    assert_eq!(changed.status(), 500);
    assert!(!discloses(&changed, &record));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // A Resource without R3 publishes no document route.
    let core =
        core_resource(&calls).r3_document(&fetch(&record, PS, "aauth-person.json", "ps-1", 3), NOW);
    assert_eq!(core.status(), 404);
}

#[test]
fn class_grant_admits_only_the_mapped_granted_operation() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-1",
    );
    let token = class_token(
        &record,
        &["records.read"],
        &[],
        &auth_claims(None),
        3,
        "ps-1",
    );

    match resource.authorize(&call("/mcp/records.read", &token, 2), NOW, "unused") {
        AuthDecision::Granted(admitted) => {
            assert_eq!(admitted.admitted(), "receipt");
            let grant = admitted.r3_grant().unwrap();
            assert_eq!(grant.reference(), &record.reference);
            assert_eq!(
                grant.operation().json().unwrap(),
                br#"{"tool":"records.read"}"#
            );
        }
        other => panic!("expected a grant, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // In the document but not granted, a Core-only route, and an undefined mapping.
    for (path, status) in [
        ("/mcp/records.delete", 403),
        ("/records", 403),
        ("/mcp/records.purge", 500),
    ] {
        let response = resource
            .authorize(&call(path, &token, 2), NOW, "unused")
            .into_response();
        assert_eq!(response.status(), status, "{path}");
    }
    // A Core-scope token cannot reach an R3 route; it still reaches its Core route.
    let core = mint_auth_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &auth_claims(Some("records.read")),
    )
    .unwrap();
    let substituted = resource
        .authorize(&call("/mcp/records.read", &core, 2), NOW, "unused")
        .into_response();
    assert_eq!(substituted.status(), 403);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (_, receipt) = resource
        .authorize(&call("/records", &core, 2), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(receipt, "receipt");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn wrong_signer_audience_key_lineage_digest_or_grant_has_no_application_effect() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    let record = issue(&resource, &store, &["records.read"], "rt-1");
    let path = "/mcp/records.read";

    let mut audience = auth_claims(None);
    audience.aud = "https://elsewhere.example".into();
    let mut other_ps = auth_claims(None);
    other_ps.iss = OTHER_PS.into();
    other_ps.ps = OTHER_PS.into();
    let mut other_agent = auth_claims(None);
    other_agent.cnf.jwk = SigningKey::from_seed([6; 32]).public_jwk();
    let mut other_subject = auth_claims(None);
    other_subject.sub = "someone-else".into();
    let cases = [
        // Audience and issuer signature are verified before policy.
        (
            call(
                path,
                &class_token(&record, &["records.read"], &[], &audience, 3, "ps-1"),
                2,
            ),
            401,
        ),
        (
            call(
                path,
                &class_token(
                    &record,
                    &["records.read"],
                    &[],
                    &auth_claims(None),
                    5,
                    "ps-1",
                ),
                2,
            ),
            401,
        ),
        // The HTTP request proof must use the token's confirmation key.
        (
            call(
                path,
                &class_token(
                    &record,
                    &["records.read"],
                    &[],
                    &auth_claims(None),
                    3,
                    "ps-1",
                ),
                7,
            ),
            401,
        ),
        // A trusted but different Person Server is not the document's entitlement.
        (
            call(
                path,
                &class_token(&record, &["records.read"], &[], &other_ps, 5, "ops-1"),
                2,
            ),
            403,
        ),
        // The grant is bound to the agent key and subject the document was issued for.
        (
            call(
                path,
                &class_token(&record, &["records.read"], &[], &other_agent, 3, "ps-1"),
                6,
            ),
            403,
        ),
        (
            call(
                path,
                &class_token(&record, &["records.read"], &[], &other_subject, 3, "ps-1"),
                2,
            ),
            403,
        ),
        // A grant beyond the document, a changed digest, or an added account.
        (
            call(
                path,
                &forged(
                    &record,
                    record.reference.digest(),
                    &["records.read", "records.delete"],
                    None,
                ),
                2,
            ),
            403,
        ),
        (
            call(
                path,
                &forged(&record, &digest(b"{}"), &["records.read"], None),
                2,
            ),
            403,
        ),
        (
            call(
                path,
                &forged(
                    &record,
                    record.reference.digest(),
                    &["records.read"],
                    Some("acct-1"),
                ),
                2,
            ),
            403,
        ),
    ];
    for (index, (request, status)) in cases.into_iter().enumerate() {
        let response = resource.authorize(&request, NOW, "unused").into_response();
        assert_eq!(response.status(), status, "case {index}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // An unknown reference at this Resource and a load failure are refused too.
    let mut gone = record.clone();
    gone.reference = aauth_rust_r3::Reference::new(
        format!("{}A", record.reference.uri()),
        record.reference.digest(),
    )
    .unwrap();
    let unknown = forged(&gone, record.reference.digest(), &["records.read"], None);
    let response = resource
        .authorize(&call(path, &unknown, 2), NOW, "unused")
        .into_response();
    assert_eq!(response.status(), 403);
    let token = class_token(
        &record,
        &["records.read"],
        &[],
        &auth_claims(None),
        3,
        "ps-1",
    );
    store.load_fails.store(true, Ordering::SeqCst);
    let response = resource
        .authorize(&call(path, &token, 2), NOW, "unused")
        .into_response();
    assert_eq!(response.status(), 500);
    store.load_fails.store(false, Ordering::SeqCst);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    resource
        .authorize(&call(path, &token, 2), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn core_scope_is_enforced_independently_when_configured() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, true);
    let response = resource
        .authorize_endpoint(
            &authorize(json!({
                "scope": "records.read",
                "r3_operations": operations(&["records.read"]),
            })),
            NOW,
            "rt-1",
        )
        .into_response();
    assert_eq!(response.status(), 200);
    let record = store
        .records
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(record.scope.as_deref(), Some("records.read"));
    let without_scope = class_token(
        &record,
        &["records.read"],
        &[],
        &auth_claims(None),
        3,
        "ps-1",
    );
    let refused = resource
        .authorize(&call("/mcp/records.read", &without_scope, 2), NOW, "unused")
        .into_response();
    assert_eq!(refused.status(), 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let scoped = class_token(
        &record,
        &["records.read"],
        &[],
        &auth_claims(Some("records.read")),
        3,
        "ps-1",
    );
    resource
        .authorize(&call("/mcp/records.read", &scoped, 2), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Without the requirement, the operation grant alone admits the R3 route.
    let relaxed_store = Arc::new(VolatileTestStore::default());
    let relaxed = self::resource(&relaxed_store, &calls, false);
    let record = issue(&relaxed, &relaxed_store, &["records.read"], "rt-2");
    let token = class_token(
        &record,
        &["records.read"],
        &[],
        &auth_claims(None),
        3,
        "ps-1",
    );
    relaxed
        .authorize(&call("/mcp/records.read", &token, 2), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn person_challenge_on_a_mapped_route_issues_a_retained_class_document() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    let response = resource
        .authorize(&call("/mcp/records.read", &person(), 2), NOW, "rt-1")
        .into_response();
    assert_eq!(response.status(), 401);
    let compact = response.headers()["aauth-requirement"]
        .to_str()
        .unwrap()
        .strip_prefix("requirement=auth-token;resource-token=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap()
        .to_owned();
    let verified = verify_resource_token(&compact, &keys(), NOW).unwrap();
    let record = store.records.lock().unwrap()[verified.reference().uri()].clone();
    let document = standard_registry()
        .unwrap()
        .parse_referenced_document(&record.reference, &record.exact_json)
        .unwrap();
    let operations = document.operation_set().operations().unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].json().unwrap(), br#"{"tool":"records.read"}"#);
    // An unmapped route keeps its Core challenge and retains nothing new.
    let core = resource
        .authorize(&call("/records", &person(), 2), NOW, "rt-2")
        .into_response();
    assert_eq!(core.status(), 401);
    assert_eq!(store.records.lock().unwrap().len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn per_call_and_unsupported_compositions_are_refused_explicitly() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = resource(&store, &calls, false);
    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-1",
    );
    let token = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &auth_claims(None),
        3,
        "ps-1",
    );
    let per_call = resource
        .authorize(&call("/mcp/records.delete", &token, 2), NOW, "unused")
        .into_response();
    assert_eq!(per_call.status(), 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    resource
        .authorize(&call("/mcp/records.read", &token, 2), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let federated = PsAuthorizationResource::new_federated(
        config(),
        "https://as.example",
        keys(),
        policy(&calls),
    )
    .unwrap()
    .with_r3(r3_config(&store, false));
    assert!(matches!(
        federated,
        Err(PsConfigurationError::InvalidR3Profile)
    ));
    let missionful = core_resource(&calls)
        .with_mission_context()
        .with_r3(r3_config(&store, false));
    assert!(matches!(
        missionful,
        Err(PsConfigurationError::InvalidR3Profile)
    ));
    let metered = self::resource(&store, &calls, false).with_budgets(
        Vec::new(),
        "https://resource.example/usage",
        1,
        1,
    );
    assert!(matches!(
        metered,
        Err(PsConfigurationError::InvalidBudgetProfile)
    ));
    let mut duplicate = r3_config(&store, false);
    duplicate.vocabularies.push(R3Vocabulary {
        definition: snapshot(),
        display: None,
    });
    assert!(matches!(
        core_resource(&calls).with_r3(duplicate),
        Err(PsConfigurationError::InvalidR3Profile)
    ));
    let mut unregistered = r3_config(&store, false);
    unregistered.definitions = DefinitionRegistry::new(&[]).unwrap();
    assert!(matches!(
        core_resource(&calls).with_r3(unregistered),
        Err(PsConfigurationError::InvalidR3Profile)
    ));

    // A mission composition added after R3 makes every R3-capable path a 500.
    let late = self::resource(&store, &calls, false).with_mission_context();
    let response = late
        .authorize_endpoint(
            &authorize(json!({ "r3_operations": operations(&["records.read"]) })),
            NOW,
            "rt-9",
        )
        .into_response();
    assert_eq!(response.status(), 500);
    assert!(!has_resource_token(&response));
    let fetched = late.r3_document(&fetch(&record, PS, "aauth-person.json", "ps-1", 3), NOW);
    assert_eq!(fetched.status(), 500);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn r3_and_budgets_issue_a_combined_resource_token() {
    let store = Arc::new(VolatileTestStore::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let units = vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()];
    let resource = resource(&store, &calls, false)
        .with_budgets(
            units.clone(),
            "https://resource.example/usage",
            1_000,
            1_000,
        )
        .unwrap();
    let also = core_resource(&calls)
        .with_budgets(units, "https://resource.example/usage", 1_000, 1_000)
        .unwrap()
        .with_r3(r3_config(&store, false));
    assert!(also.is_ok());
    let response = resource
        .authorize_endpoint(
            &authorize(json!({
                "r3_operations": operations(&["records.read"]),
                "budget": {"amount": 500, "unit": "USD", "decimals": 2}
            })),
            NOW,
            "rt-budget",
        )
        .into_response();
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let compact = body["resource_token"].as_str().unwrap();
    assert!(verify_resource_token(compact, &keys(), NOW).is_err());
    let (_verified, offer, consumed) =
        verify_budget_resource_token(compact, &keys(), NOW).unwrap();
    assert!(consumed.is_none());
    assert_eq!(offer.amount(), 500);
    assert_eq!(offer.unit(), "USD");
    assert_eq!(offer.decimals(), 2);
}

#[test]
fn literal_reference_fetch_and_grant_compose_on_a_differing_signed_origin() {
    // Different host and nondefault port from the published issuer identity.
    const SIGNED: &str = "https://api.resource-host.example:9443";
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = PsAuthorizationResource::new(config_at(SIGNED), keys(), policy(&calls))
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(r3_config(&store, false))
        .unwrap();
    let response = resource
        .authorize_endpoint(
            &authorize_at(
                SIGNED,
                json!({ "r3_operations": operations(&["records.read"]) }),
            ),
            NOW,
            "rt-1",
        )
        .into_response();
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let verified =
        verify_resource_token(body["resource_token"].as_str().unwrap(), &keys(), NOW).unwrap();
    // JWT identity stays the published issuer; the document URI is the signed origin.
    assert_eq!(verified.claims().iss, RESOURCE);
    assert!(
        verified
            .reference()
            .uri()
            .starts_with(&format!("{SIGNED}/r3/c."))
    );
    let record = store.records.lock().unwrap()[verified.reference().uri()].clone();

    // The literal advertised URI is served; the same path under the issuer host is not.
    let served = resource.r3_document(&fetch(&record, PS, "aauth-person.json", "ps-1", 3), NOW);
    assert_eq!(served.status(), 200);
    assert_eq!(served.body(), &record.exact_json);
    let issuer_host = record.reference.uri().replacen(SIGNED, RESOURCE, 1);
    let elsewhere = resource.r3_document(
        &fetch_uri(&issuer_host, PS, "aauth-person.json", "ps-1", 3),
        NOW,
    );
    assert_eq!(elsewhere.status(), 404);
    assert!(!discloses(&elsewhere, &record));

    // The PS grant over that literal reference admits a call at the signed origin.
    let token = class_token(
        &record,
        &["records.read"],
        &[],
        &auth_claims(None),
        3,
        "ps-1",
    );
    match resource.authorize(
        &call_at(SIGNED, "/mcp/records.read", &token, 2),
        NOW,
        "unused",
    ) {
        AuthDecision::Granted(admitted) => {
            assert_eq!(admitted.token().claims().aud, RESOURCE);
            assert_eq!(admitted.r3_grant().unwrap().reference(), &record.reference);
        }
        other => panic!("expected a grant, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The same digest under the issuer host is not a document of this Resource.
    let mut moved = record.clone();
    moved.reference =
        aauth_rust_r3::Reference::new(issuer_host, record.reference.digest()).unwrap();
    let foreign = forged(&moved, record.reference.digest(), &["records.read"], None);
    let refused = resource
        .authorize(
            &call_at(SIGNED, "/mcp/records.read", &foreign, 2),
            NOW,
            "unused",
        )
        .into_response();
    assert_eq!(refused.status(), 403);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
