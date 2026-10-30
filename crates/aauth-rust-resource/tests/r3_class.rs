//! Immediate class R3 on the direct Person-Server Resource.
//!
//! `VolatileTestStore` is a test double with injected faults. It is process
//! memory and does not satisfy the durable `R3DocumentStore` contract.
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_budgets::UnitDeclaration;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthClaims, Confirmation, PersonClaims, ResourceToken,
    TokenError, TrustedIssuerKeys, VerifiedAuthToken, mint_auth_token, mint_person_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_r3::{
    AccessMode, AnnotationEncoding, AuthoritativeSnapshot, Authorization, Codec, DefinedOperation,
    DefinitionCodec, DefinitionError, DefinitionMaterial, DefinitionParser, DefinitionRegistry,
    Display as R3Display, Error as R3Error, GrantedOperations, McpCodec, Operation, OperationSet,
    Parameters, PresentedParameter, ProposalDisplay, ProposalResult, Registry, SourceEncoding,
    ToolsListPage, ToolsListSnapshot, Vocabulary, VocabularyUri, digest, standard_registry,
    standard_vocabularies, verify_budget_resource_token, verify_resource_token,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthAdmissionPolicy, BoxedR3Describe, BoxedR3OperationMapper,
    BoxedR3Present, BoxedR3Release, Deny, ProactiveDecision, PsAuthorizationConfig,
    PsAuthorizationResource, PsConfigurationError, R3CallResult, R3CallStore, R3CallToken, R3Claim,
    R3Config, R3Definitions, R3DocumentRecord, R3DocumentStore, R3HostError, R3PerCallConfig,
    R3ProposalRecord, R3Release, R3StoreError, R3Vocabulary,
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
        scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
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
    person_on_mission(None)
}
fn person_on_mission(mission: Option<&str>) -> String {
    person_on_mission_until(mission, 3000)
}
fn person_on_mission_until(mission: Option<&str>, exp: i64) -> String {
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
            exp,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([2; 32]).public_jwk(),
            },
            nbf: None,
            tenant: Some("team".into()),
            mission_s256: mission.map(Into::into),
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
    authorize_as(origin, person(), body)
}
fn authorize_as(origin: &str, person: String, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{origin}/authorize"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([2; 32]),
        KeyMaterial::Jwt(person),
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
fn call_method(method: &str, path: &str, token: &str, seed: u8) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("{ORIGIN}{path}"))
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
/// The pending path a held `202` names in its `Location`, at the signed origin.
fn pending_path(response: &Response<Vec<u8>>) -> String {
    let location = response.headers()["location"].to_str().unwrap();
    location
        .strip_prefix(ORIGIN)
        .expect("pending URL at the signed origin")
        .to_owned()
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
fn operations_from_several_internal_definitions_reference_one_composed_document() {
    let set = |tools: &[&str]| {
        OperationSet::new(&tools.iter().map(|tool| mcp(tool)).collect::<Vec<_>>()).unwrap()
    };
    let read = R3Display::new("Read your records", None, Some("Record titles"), None).unwrap();
    let delete = R3Display::new(
        "Delete your records",
        Some("Records are removed"),
        Some("Record titles"),
        Some("Deleted records cannot be restored"),
    )
    .unwrap();
    assert!(
        R3Definitions::new(vec![
            (set(&["records.read"]), read.clone()),
            (set(&["records.read", "records.delete"]), delete.clone()),
        ])
        .is_err(),
        "an operation belongs to one definition"
    );
    let definitions = R3Definitions::new(vec![
        (set(&["records.read"]), read),
        (set(&["records.delete"]), delete),
    ])
    .unwrap();
    let store = Arc::new(VolatileTestStore::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut config = r3_config(&store, false);
    config.vocabularies[0].display = Some(definitions.into_display());
    let resource = core_resource(&calls).with_r3(config).unwrap();
    let issue_for = |tools: &[&str], jti: &str| {
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
        let record = store.records.lock().unwrap()[verified.reference().uri()].clone();
        standard_registry()
            .unwrap()
            .parse_referenced_document(&record.reference, &record.exact_json)
            .unwrap()
    };

    let single = issue_for(&["records.read"], "rt-single");
    assert_eq!(single.display().unwrap().summary(), "Read your records");
    assert_eq!(single.display().unwrap().implications(), None);

    let composed = issue_for(&["records.read", "records.delete"], "rt-composed");
    assert!(
        composed
            .operation_set()
            .equal(&set(&["records.read", "records.delete"]))
            .unwrap()
    );
    let display = composed.display().unwrap();
    assert_eq!(display.summary(), "Read your records; Delete your records");
    assert_eq!(display.implications(), Some("Records are removed"));
    assert_eq!(display.data_accessed(), Some("Record titles"));
    assert_eq!(
        display.irreversible(),
        Some("Deleted records cannot be restored")
    );
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
            "invalid_budget",
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

    // Missions compose only with direct class R3.
    assert!(
        core_resource(&calls)
            .with_mission_context()
            .with_r3(r3_config(&store, false))
            .is_ok()
    );
    let federated =
        PsAuthorizationResource::new_federated(config(), AS, federated_keys(), policy(&calls))
            .unwrap()
            .with_mission_context()
            .with_r3(r3_config(&store, false));
    assert!(matches!(
        federated,
        Err(PsConfigurationError::InvalidR3Profile)
    ));
    let per_call_mission = core_resource(&calls)
        .with_mission_context()
        .with_r3(r3_config(&store, false))
        .unwrap()
        .with_r3_per_call(missionless_per_call());
    assert!(matches!(
        per_call_mission,
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

    // Mission context added after per-call proposals makes every R3-capable path a 500.
    let late = self::resource(&store, &calls, false)
        .with_r3_per_call(missionless_per_call())
        .unwrap()
        .with_mission_context();
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
        .with_budgets(units.clone(), "https://resource.example/usage", 500, 500)
        .unwrap()
        .with_r3_per_call(missionless_per_call())
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
    let (_verified, offer, consumed) = verify_budget_resource_token(compact, &keys(), NOW).unwrap();
    assert!(consumed.is_none());
    assert_eq!(offer.amount(), 500);
    assert_eq!(offer.unit(), "USD");
    assert_eq!(offer.decimals(), 2);
    let record = store.records.lock().unwrap()[_verified.reference().uri()].clone();
    let registry = standard_registry().unwrap();
    let document = registry
        .parse_referenced_document(&record.reference, &record.exact_json)
        .unwrap();
    let vocabulary = McpCodec::vocabulary().unwrap();
    let granted = GrantedOperations::new(&vocabulary, &[mcp("records.read")]).unwrap();
    let class_grant = aauth_rust_r3::Grant::new(&granted, &document).unwrap();
    let budget = aauth_rust_budgets::Budget::new(500, "USD", 2).unwrap();
    let token = aauth_rust_r3::mint_budget_auth_token(
        &registry,
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &auth_claims(None),
        &record.reference,
        &record.exact_json,
        &class_grant,
        &budget,
    )
    .unwrap();
    resource
        .authorize(&call("/mcp/records.read", &token, 2), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The R3 gate refuses an operation outside the grant before metering, and
    // still reports what the budget has left.
    let denied = resource
        .authorize(&call("/mcp/records.delete", &token, 2), NOW, "unused")
        .into_response();
    assert_eq!(denied.status(), 403);
    assert!(denied.headers().contains_key("aauth-budget"));
    // So does a pending URL that the same token is sent to.
    let posted = resource
        .authorize(
            &call_method("POST", "/r3/pending/unknown", &token, 2),
            NOW,
            "unused",
        )
        .into_response();
    assert_eq!(posted.status(), 405);
    assert!(posted.headers().contains_key("aauth-budget"));
    let gone = resource
        .authorize(&call("/r3/pending/unknown", &token, 2), NOW, "unused")
        .into_response();
    assert_eq!(gone.status(), 410);
    assert!(gone.headers().contains_key("aauth-budget"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
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

const AS: &str = "https://as.example";

fn federated_keys() -> Keys {
    let mut trusted = keys().0;
    trusted.push(issuer_key(AS, "aauth-access.json", 7, "as-key"));
    // The wrong discovery role must verify and then be refused, not fail closed
    // as an unknown key.
    trusted.push(issuer_key(AS, "aauth-person.json", 7, "as-key"));
    Keys(trusted)
}

fn access_claims(jti: &str) -> AuthClaims {
    let mut claims = auth_claims(None);
    claims.iss = AS.into();
    claims.dwk = "aauth-access.json".into();
    claims.jti = jti.into();
    claims
}

/// Claim token, fence and retained result of one proposal URI.
type ClaimedCall = (R3CallToken, String, Option<R3CallResult>);

/// Process-memory proposals for one test. Not a durable `R3CallStore`.
struct MemoryCalls {
    records: Mutex<BTreeMap<String, R3ProposalRecord>>,
    calls: Mutex<BTreeMap<String, ClaimedCall>>,
}
impl MemoryCalls {
    fn new() -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            calls: Mutex::new(BTreeMap::new()),
        }
    }
    fn only(&self) -> R3ProposalRecord {
        let records = self.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        records.values().next().expect("proposal").clone()
    }
}
impl R3CallStore for MemoryCalls {
    fn commit(&self, record: &R3ProposalRecord) -> Result<(), R3StoreError> {
        let mut records = self.records.lock().unwrap();
        let uri = record.reference.uri().to_owned();
        if records.contains_key(&uri) {
            return Err(R3StoreError::Conflict);
        }
        records.insert(uri, record.clone());
        Ok(())
    }
    fn load(&self, uri: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        Ok(self.records.lock().unwrap().get(uri).cloned())
    }
    fn load_pending(&self, id: &str) -> Result<Option<R3ProposalRecord>, R3StoreError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .values()
            .find(|record| {
                record
                    .held
                    .as_ref()
                    .is_some_and(|held| held.pending_id == id)
            })
            .cloned())
    }
    fn claim(&self, uri: &str, token: &R3CallToken, now: i64) -> Result<R3Claim, R3StoreError> {
        if self.load(uri)?.is_none() {
            return Err(R3StoreError::Unavailable(R3HostError::new(
                "missing proposal",
            )));
        }
        if now >= token.retain_until {
            return Ok(R3Claim::Expired);
        }
        let mut calls = self.calls.lock().unwrap();
        let Some(bound) = calls.get_mut(uri) else {
            calls.insert(
                uri.to_owned(),
                (token.clone(), format!("fence-{uri}"), None),
            );
            return Ok(R3Claim::Execute {
                fence: format!("fence-{uri}"),
            });
        };
        if bound.0.compact_sha256 != token.compact_sha256 || bound.0.jti != token.jti {
            return Ok(R3Claim::DifferentToken);
        }
        Ok(match bound.2.clone() {
            Some(result) => R3Claim::Replay(result),
            None => R3Claim::Unfinished,
        })
    }
    fn retain(
        &self,
        uri: &str,
        fence: &str,
        result: &R3CallResult,
    ) -> Result<R3CallResult, R3StoreError> {
        let mut calls = self.calls.lock().unwrap();
        let Some(bound) = calls.get_mut(uri) else {
            return Err(R3StoreError::Conflict);
        };
        if bound.1 != fence || bound.2.is_some() {
            return Err(R3StoreError::Conflict);
        }
        bound.2 = Some(result.clone());
        Ok(result.clone())
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

#[test]
fn federated_access_server_serves_and_admits_class_and_per_call_r3() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let proposals = Arc::new(MemoryCalls::new());
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: None,
            })
        },
    );
    let resource =
        PsAuthorizationResource::new_federated(config(), AS, federated_keys(), policy(&calls))
            .unwrap()
            .with_authorization_endpoint()
            .with_r3(r3_config(&store, false))
            .unwrap()
            .with_r3_per_call(R3PerCallConfig {
                present,
                describe,
                calls: proposals.clone(),
                hold: false,
                release: None,
                held_result_lifetime: 300,
            })
            .unwrap();

    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-as",
    );
    assert_eq!(record.person_server, PS);
    assert_eq!(record.auth_token_issuer, AS);
    assert_eq!(record.auth_token_issuer_document, "aauth-access.json");
    let issued = verify_resource_token(&record.resource_token, &keys(), NOW).unwrap();
    assert_eq!(issued.claims().aud, AS);
    assert_eq!(issued.claims().ps, PS);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let served = resource.r3_document(&fetch(&record, AS, "aauth-access.json", "as-key", 7), NOW);
    assert_eq!(served.status(), 200);
    assert_eq!(served.body(), &record.exact_json);
    let person_fetch =
        resource.r3_document(&fetch(&record, PS, "aauth-person.json", "ps-1", 3), NOW);
    assert_eq!(person_fetch.status(), 200);
    assert_eq!(person_fetch.body(), &record.exact_json);
    let wrong_role =
        resource.r3_document(&fetch(&record, AS, "aauth-person.json", "as-key", 7), NOW);
    assert_eq!(wrong_role.status(), 404);
    assert!(!discloses(&wrong_role, &record));
    let stranger = resource.r3_document(
        &fetch(&record, OTHER_PS, "aauth-person.json", "ops-1", 5),
        NOW,
    );
    assert_eq!(stranger.status(), 404);
    assert!(!discloses(&stranger, &record));

    let class_as = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &access_claims("auth-as"),
        7,
        "as-key",
    );
    resource
        .authorize(&call("/mcp/records.read", &class_as, 2), NOW, "unused")
        .into_result()
        .expect("access-server class grant");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let class_ps = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &auth_claims(None),
        3,
        "ps-1",
    );
    match resource.authorize(&call("/mcp/records.read", &class_ps, 2), NOW, "unused") {
        AuthDecision::SignatureFailure(_) => {}
        other => panic!("person-signed auth token on a federated resource: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let proposal_token = match resource.authorize(
        &call("/mcp/records.delete", &class_as, 2),
        NOW,
        "challenge-1",
    ) {
        AuthDecision::AuthTokenRequired { resource_token, .. } => resource_token,
        other => panic!("per-call challenge: {other:?}"),
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let proposal = verify_resource_token(&proposal_token, &keys(), NOW).unwrap();
    assert_eq!(proposal.claims().aud, AS);
    assert_eq!(proposal.claims().ps, PS);
    let stored = proposals.only();
    assert_eq!(stored.reference.uri(), proposal.reference().uri());
    assert_eq!(stored.auth_token_issuer, AS);
    assert_eq!(stored.person_server, PS);
    let proposal_fetch = resource.r3_document(
        &fetch_uri(stored.reference.uri(), AS, "aauth-access.json", "as-key", 7),
        NOW,
    );
    assert_eq!(proposal_fetch.status(), 200);
    assert_eq!(proposal_fetch.body(), &stored.exact_json);
    let proposal_ps = resource.r3_document(
        &fetch_uri(stored.reference.uri(), PS, "aauth-person.json", "ps-1", 3),
        NOW,
    );
    assert_eq!(proposal_ps.status(), 200);
    assert_eq!(proposal_ps.body(), &stored.exact_json);
    let proposal_stranger = resource.r3_document(
        &fetch_uri(
            stored.reference.uri(),
            OTHER_PS,
            "aauth-person.json",
            "ops-1",
            5,
        ),
        NOW,
    );
    assert_eq!(proposal_stranger.status(), 404);

    let completion = aauth_rust_r3::mint_per_call_auth_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([7; 32]),
        "as-key",
        &access_claims("per-call-1"),
        &stored.reference,
        &stored.exact_json,
    )
    .expect("per-call auth token");
    let grant = match resource.authorize(&call("/mcp/records.delete", &completion, 2), NOW, "run-1")
    {
        AuthDecision::Granted(admitted) => {
            let grant = admitted.r3_grant().expect("per-call grant").clone();
            assert!(grant.is_per_call());
            grant
        }
        other => panic!("first completion: {other:?}"),
    };
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let retained = resource.r3_retain(
        &grant,
        Response::builder()
            .status(200)
            .body(b"deleted".to_vec())
            .unwrap(),
    );
    assert_eq!(retained.body(), b"deleted");
    match resource.authorize(&call("/mcp/records.delete", &completion, 2), NOW, "run-2") {
        AuthDecision::Replayed(response) => assert_eq!(response.body(), b"deleted"),
        other => panic!("replay: {other:?}"),
    }
}

#[test]
fn qa_d1_budgeted_mapped_person_challenge_is_unauthorized() {
    let store = Arc::new(VolatileTestStore::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let units = vec![UnitDeclaration::with_max("USD", 2, 10_000_000, "dollars").unwrap()];
    let resource = core_resource(&calls)
        .with_budgets(units, "https://resource.example/usage", 500, 500)
        .unwrap()
        .with_r3(r3_config(&store, false))
        .unwrap();
    let response = resource
        .authorize(&call("/mcp/records.read", &person(), 2), NOW, "rt-reactive")
        .into_response();
    assert_eq!(
        response.status(),
        401,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["error"], "auth_token_required");
    let compact = response.headers()["aauth-requirement"]
        .to_str()
        .unwrap()
        .strip_prefix("requirement=auth-token;resource-token=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();
    let verified = verify_resource_token(compact, &keys(), NOW).unwrap();
    assert!(!verified.claims().extra.contains_key("budget"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let proactive = resource
        .authorize_endpoint(
            &authorize(json!({ "r3_operations": operations(&["records.read"]) })),
            NOW,
            "rt-plain",
        )
        .into_response();
    assert_eq!(
        proactive.status(),
        200,
        "{}",
        String::from_utf8_lossy(proactive.body())
    );
    let issued: Value = serde_json::from_slice(proactive.body()).unwrap();
    verify_resource_token(issued["resource_token"].as_str().unwrap(), &keys(), NOW).unwrap();
}

#[test]
fn qa_d2_held_pending_post_is_method_not_allowed_and_unknown_id_is_gone() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let proposals = Arc::new(MemoryCalls::new());
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: None,
            })
        },
    );
    let resource = PsAuthorizationResource::new(config(), keys(), policy(&calls))
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(r3_config(&store, false))
        .unwrap()
        .with_r3_per_call(R3PerCallConfig {
            present,
            describe,
            calls: proposals.clone(),
            hold: true,
            release: None,
            held_result_lifetime: 300,
        })
        .unwrap();
    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-held",
    );
    let class = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &auth_claims(None),
        3,
        "ps-1",
    );
    let held = resource
        .authorize(
            &call("/mcp/records.delete", &class, 2),
            NOW,
            "challenge-hold",
        )
        .into_response();
    assert_eq!(
        held.status(),
        202,
        "{}",
        String::from_utf8_lossy(held.body())
    );
    let pending = pending_path(&held);
    assert!(pending.starts_with("/r3/pending/"), "{pending}");
    let stored = proposals.only();
    let mut claims = auth_claims(None);
    claims.jti = "per-call-1".into();
    let per_call = aauth_rust_r3::mint_per_call_auth_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &claims,
        &stored.reference,
        &stored.exact_json,
    )
    .expect("per-call auth token");
    let pending = pending.as_str();
    let before = calls.load(Ordering::SeqCst);
    let posted = resource
        .authorize(
            &call_method("POST", pending, &per_call, 2),
            NOW,
            "poll-post",
        )
        .into_response();
    assert_eq!(
        posted.status(),
        405,
        "{}",
        String::from_utf8_lossy(posted.body())
    );
    let posted_body: Value = serde_json::from_slice(posted.body()).unwrap();
    assert_eq!(posted_body["error"], "method_not_allowed");
    assert_eq!(
        posted.headers().get("allow").unwrap().to_str().unwrap(),
        "GET"
    );
    assert_eq!(calls.load(Ordering::SeqCst), before);
    let missing = resource
        .authorize(
            &call("/r3/pending/not-this-held-call", &per_call, 2),
            NOW,
            "poll-missing",
        )
        .into_response();
    assert_eq!(
        missing.status(),
        410,
        "{}",
        String::from_utf8_lossy(missing.body())
    );
    let missing_body: Value = serde_json::from_slice(missing.body()).unwrap();
    assert_eq!(missing_body["error"], "gone");
    let grant = match resource.authorize(&call(pending, &per_call, 2), NOW, "poll-get") {
        AuthDecision::Granted(admitted) => admitted.r3_grant().expect("held completion").clone(),
        other => panic!("pending GET: {other:?}"),
    };
    let stored_response = resource.r3_retain(
        &grant,
        Response::builder()
            .status(200)
            .body(b"held".to_vec())
            .unwrap(),
    );
    assert_eq!(stored_response.body(), b"held");
    let mut other_claims = claims.clone();
    other_claims.jti = "per-call-2".into();
    let other = aauth_rust_r3::mint_per_call_auth_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &other_claims,
        &stored.reference,
        &stored.exact_json,
    )
    .expect("different per-call token");
    match resource.authorize(&call(pending, &other, 2), NOW, "poll-other") {
        AuthDecision::Forbidden { .. } => {}
        other => panic!("different token on the pending URL: {other:?}"),
    }
    let replay_post = resource
        .authorize(
            &call_method("POST", pending, &per_call, 2),
            NOW,
            "poll-post-2",
        )
        .into_response();
    assert_eq!(
        replay_post.status(),
        405,
        "{}",
        String::from_utf8_lossy(replay_post.body())
    );
    assert_eq!(
        replay_post
            .headers()
            .get("allow")
            .unwrap()
            .to_str()
            .unwrap(),
        "GET"
    );
    match resource.authorize(&call(pending, &per_call, 2), NOW, "poll-replay") {
        AuthDecision::Replayed(response) => assert_eq!(response.body(), b"held"),
        other => panic!("GET replay: {other:?}"),
    }
}

// Core Pending URL Security: pending URLs are unguessable. A held call's
// pending id is drawn from the system random source. It is not the challenge
// identifier, which the proposal Resource token carries as its `jti`, nor the
// presented Auth token's `jti`, nor derived from anything else in the request:
// two Resources that hold the same call under the same challenge identifier
// name different pending URLs.
#[test]
fn a_held_pending_id_is_random_and_not_the_token_jti() {
    let hold = || {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(VolatileTestStore::default());
        let proposals = Arc::new(MemoryCalls::new());
        let resource = resource(&store, &calls, false)
            .with_r3_per_call(R3PerCallConfig {
                calls: proposals.clone(),
                hold: true,
                ..missionless_per_call()
            })
            .unwrap();
        let record = issue(
            &resource,
            &store,
            &["records.read", "records.delete"],
            "rt-random",
        );
        let class = class_token(
            &record,
            &["records.read"],
            &["records.delete"],
            &auth_claims(None),
            3,
            "ps-1",
        );
        let held = resource
            .authorize(
                &call("/mcp/records.delete", &class, 2),
                NOW,
                "challenge-hold",
            )
            .into_response();
        assert_eq!(
            held.status(),
            202,
            "{}",
            String::from_utf8_lossy(held.body())
        );
        let id = pending_path(&held)
            .strip_prefix("/r3/pending/")
            .expect("held pending path")
            .to_owned();
        let stored = proposals.only();
        assert_eq!(stored.held.as_ref().expect("held call").pending_id, id);
        let challenge = verify_resource_token(&stored.resource_token, &keys(), NOW).unwrap();
        assert_eq!(challenge.claims().jti, "challenge-hold");
        assert_eq!(challenge.claims().presented_jti, "auth-1");
        id
    };
    let first = hold();
    let second = hold();
    for id in [&first, &second] {
        assert_eq!(id.len(), 22, "{id}");
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "{id}"
        );
        assert!(
            !id.contains("challenge-hold") && !id.contains("auth-1"),
            "{id}"
        );
    }
    assert_ne!(first, second);
}

#[test]
fn held_poll_while_the_grant_is_unretained_stays_pending() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let proposals = Arc::new(MemoryCalls::new());
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: None,
            })
        },
    );
    let resource = PsAuthorizationResource::new(config(), keys(), policy(&calls))
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(r3_config(&store, false))
        .unwrap()
        .with_r3_per_call(R3PerCallConfig {
            present,
            describe,
            calls: proposals.clone(),
            hold: true,
            release: None,
            held_result_lifetime: 300,
        })
        .unwrap();
    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-live",
    );
    let class = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &auth_claims(None),
        3,
        "ps-1",
    );
    let held = resource
        .authorize(
            &call("/mcp/records.delete", &class, 2),
            NOW,
            "challenge-live",
        )
        .into_response();
    assert_eq!(
        held.status(),
        202,
        "{}",
        String::from_utf8_lossy(held.body())
    );
    let stored = proposals.only();
    let mut claims = auth_claims(None);
    claims.jti = "per-call-live".into();
    let per_call = aauth_rust_r3::mint_per_call_auth_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &claims,
        &stored.reference,
        &stored.exact_json,
    )
    .expect("per-call auth token");
    let pending = pending_path(&held);
    let pending = pending.as_str();
    let grant = match resource.authorize(&call(pending, &per_call, 2), NOW, "poll-grant") {
        AuthDecision::Granted(admitted) => admitted.r3_grant().expect("held completion").clone(),
        other => panic!("first poll: {other:?}"),
    };
    let before = calls.load(Ordering::SeqCst);
    match resource.authorize(&call(pending, &per_call, 2), NOW, "poll-live") {
        AuthDecision::StillPending { location } => {
            assert_eq!(location, format!("{ORIGIN}{pending}"));
        }
        other => panic!("poll while the grant is held: {other:?}"),
    }
    let response = resource
        .authorize(&call(pending, &per_call, 2), NOW, "poll-live-http")
        .into_response();
    assert_eq!(
        response.status(),
        202,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert_eq!(
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("{ORIGIN}{pending}").as_str()
    );
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );
    assert!(response.headers().get("aauth-requirement").is_none());
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["status"], "pending");
    assert!(calls.load(Ordering::SeqCst) >= before);
    let retained = resource.r3_retain(
        &grant,
        Response::builder()
            .status(200)
            .body(b"held-once".to_vec())
            .unwrap(),
    );
    assert_eq!(retained.body(), b"held-once");
    match resource.authorize(&call(pending, &per_call, 2), NOW, "poll-after") {
        AuthDecision::Replayed(replay) => assert_eq!(replay.body(), b"held-once"),
        other => panic!("replay after retain: {other:?}"),
    }

    let dropped = resource
        .authorize(
            &call("/mcp/records.delete", &class, 2),
            NOW,
            "challenge-drop",
        )
        .into_response();
    assert_eq!(
        dropped.status(),
        202,
        "{}",
        String::from_utf8_lossy(dropped.body())
    );
    let stored = proposals
        .records
        .lock()
        .unwrap()
        .values()
        .find(|record| record.resource_token_jti == "challenge-drop")
        .cloned()
        .expect("dropped proposal");
    let mut dropped_claims = auth_claims(None);
    dropped_claims.jti = "per-call-drop".into();
    let dropped_token = aauth_rust_r3::mint_per_call_auth_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &dropped_claims,
        &stored.reference,
        &stored.exact_json,
    )
    .expect("dropped per-call auth token");
    let dropped_pending = pending_path(&dropped);
    let dropped_pending = dropped_pending.as_str();
    match resource.authorize(
        &call(dropped_pending, &dropped_token, 2),
        NOW,
        "poll-drop-grant",
    ) {
        AuthDecision::Granted(_) => {}
        other => panic!("grant that will be dropped: {other:?}"),
    }
    match resource.authorize(
        &call(dropped_pending, &dropped_token, 2),
        NOW,
        "poll-dropped",
    ) {
        AuthDecision::InternalError => {}
        other => panic!("poll after the grant was dropped: {other:?}"),
    }
    let abandoned = resource
        .authorize(
            &call(dropped_pending, &dropped_token, 2),
            NOW,
            "poll-dropped-http",
        )
        .into_response();
    assert_eq!(
        abandoned.status(),
        500,
        "{}",
        String::from_utf8_lossy(abandoned.body())
    );
    let abandoned_body: Value = serde_json::from_slice(abandoned.body()).unwrap();
    assert_eq!(abandoned_body["error"], "server_error");
    match resource.authorize(&call(pending, &per_call, 2), NOW, "poll-first-intact") {
        AuthDecision::Replayed(replay) => assert_eq!(replay.body(), b"held-once"),
        other => panic!("first result changed: {other:?}"),
    }
}

#[test]
fn a_retry_while_the_grant_is_unretained_is_unavailable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let proposals = Arc::new(MemoryCalls::new());
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: None,
            })
        },
    );
    let resource = PsAuthorizationResource::new(config(), keys(), policy(&calls))
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(r3_config(&store, false))
        .unwrap()
        .with_r3_per_call(R3PerCallConfig {
            present,
            describe,
            calls: proposals.clone(),
            hold: false,
            release: None,
            held_result_lifetime: 300,
        })
        .unwrap();
    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-retry",
    );
    let class = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &auth_claims(None),
        3,
        "ps-1",
    );
    match resource.authorize(
        &call("/mcp/records.delete", &class, 2),
        NOW,
        "challenge-retry",
    ) {
        AuthDecision::AuthTokenRequired { .. } => {}
        other => panic!("retry challenge: {other:?}"),
    }
    let stored = proposals.only();
    let mut claims = auth_claims(None);
    claims.jti = "per-call-retry".into();
    let per_call = aauth_rust_r3::mint_per_call_auth_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &claims,
        &stored.reference,
        &stored.exact_json,
    )
    .expect("per-call auth token");
    let route = "/mcp/records.delete";
    let grant = match resource.authorize(&call(route, &per_call, 2), NOW, "run-grant") {
        AuthDecision::Granted(admitted) => admitted.r3_grant().expect("retry completion").clone(),
        other => panic!("first completion: {other:?}"),
    };
    match resource.authorize(&call(route, &per_call, 2), NOW, "run-live") {
        AuthDecision::TemporarilyUnavailable => {}
        other => panic!("completion while the grant is held: {other:?}"),
    }
    let response = resource
        .authorize(&call(route, &per_call, 2), NOW, "run-live-http")
        .into_response();
    assert_eq!(
        response.status(),
        503,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );
    assert!(response.headers().get("location").is_none());
    assert!(response.headers().get("aauth-requirement").is_none());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/problem+json"
    );
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    let retained = resource.r3_retain(
        &grant,
        Response::builder()
            .status(200)
            .body(b"ran-once".to_vec())
            .unwrap(),
    );
    assert_eq!(retained.body(), b"ran-once");
    match resource.authorize(&call(route, &per_call, 2), NOW, "run-after") {
        AuthDecision::Replayed(replay) => assert_eq!(replay.body(), b"ran-once"),
        other => panic!("replay after retain: {other:?}"),
    }

    match resource.authorize(&call(route, &class, 2), NOW, "challenge-drop") {
        AuthDecision::AuthTokenRequired { .. } => {}
        other => panic!("second challenge: {other:?}"),
    }
    let stored = proposals
        .records
        .lock()
        .unwrap()
        .values()
        .find(|record| record.resource_token_jti == "challenge-drop")
        .cloned()
        .expect("dropped proposal");
    let mut dropped_claims = auth_claims(None);
    dropped_claims.jti = "per-call-drop".into();
    let dropped_token = aauth_rust_r3::mint_per_call_auth_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &dropped_claims,
        &stored.reference,
        &stored.exact_json,
    )
    .expect("dropped per-call auth token");
    match resource.authorize(&call(route, &dropped_token, 2), NOW, "run-drop-grant") {
        AuthDecision::Granted(_) => {}
        other => panic!("grant that will be dropped: {other:?}"),
    }
    match resource.authorize(&call(route, &dropped_token, 2), NOW, "run-dropped") {
        AuthDecision::InternalError => {}
        other => panic!("completion after the grant was dropped: {other:?}"),
    }
    let abandoned = resource
        .authorize(&call(route, &dropped_token, 2), NOW, "run-dropped-http")
        .into_response();
    assert_eq!(
        abandoned.status(),
        500,
        "{}",
        String::from_utf8_lossy(abandoned.body())
    );
    let abandoned_body: Value = serde_json::from_slice(abandoned.body()).unwrap();
    assert_eq!(abandoned_body["error"], "server_error");
    match resource.authorize(&call(route, &per_call, 2), NOW, "run-first-intact") {
        AuthDecision::Replayed(replay) => assert_eq!(replay.body(), b"ran-once"),
        other => panic!("first result changed: {other:?}"),
    }
}

#[test]
fn an_application_202_replays_with_its_pending_headers_or_as_server_error() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let proposals = Arc::new(MemoryCalls::new());
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: None,
            })
        },
    );
    let resource = PsAuthorizationResource::new(config(), keys(), policy(&calls))
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(r3_config(&store, false))
        .unwrap()
        .with_r3_per_call(R3PerCallConfig {
            present,
            describe,
            calls: proposals.clone(),
            hold: false,
            release: None,
            held_result_lifetime: 300,
        })
        .unwrap();
    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-pending",
    );
    let class = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &auth_claims(None),
        3,
        "ps-1",
    );
    let route = "/mcp/records.delete";
    let completion = |challenge: &str, jti: &str| {
        match resource.authorize(&call(route, &class, 2), NOW, challenge) {
            AuthDecision::AuthTokenRequired { .. } => {}
            other => panic!("challenge {challenge}: {other:?}"),
        }
        let stored = proposals
            .records
            .lock()
            .unwrap()
            .values()
            .find(|record| record.resource_token_jti == challenge)
            .cloned()
            .expect("stored proposal");
        let mut claims = auth_claims(None);
        claims.jti = jti.into();
        let per_call = aauth_rust_r3::mint_per_call_auth_token(
            &standard_registry().unwrap(),
            &SigningKey::from_seed([3; 32]),
            "ps-1",
            &claims,
            &stored.reference,
            &stored.exact_json,
        )
        .expect("per-call auth token");
        let grant = match resource.authorize(&call(route, &per_call, 2), NOW, jti) {
            AuthDecision::Granted(admitted) => admitted.r3_grant().expect("completion").clone(),
            other => panic!("completion {jti}: {other:?}"),
        };
        (per_call, grant)
    };
    let application_202 = |location: &str| {
        Response::builder()
            .status(202)
            .header("location", location)
            .header("retry-after", "5")
            .header("cache-control", "private")
            .header("cache-control", "no-store")
            .header("content-type", "application/json")
            .body(br#"{"status":"pending"}"#.to_vec())
            .unwrap()
    };
    let pending_headers = |response: &Response<Vec<u8>>| {
        let values = |name: &str| -> Vec<String> {
            response
                .headers()
                .get_all(name)
                .iter()
                .map(|value| value.to_str().unwrap().to_owned())
                .collect()
        };
        (
            values("location"),
            values("retry-after"),
            values("cache-control"),
            values("content-type"),
        )
    };
    let expected = (
        vec![format!("{ORIGIN}/jobs/7")],
        vec!["5".to_owned()],
        vec!["private".to_owned(), "no-store".to_owned()],
        vec!["application/json".to_owned()],
    );

    let (per_call, grant) = completion("challenge-pending", "per-call-pending");
    let retained = resource.r3_retain(&grant, application_202(&format!("{ORIGIN}/jobs/7")));
    assert_eq!(
        retained.status(),
        202,
        "{}",
        String::from_utf8_lossy(retained.body())
    );
    assert_eq!(pending_headers(&retained), expected);
    for nonce in ["replay-pending", "replay-pending-again"] {
        match resource.authorize(&call(route, &per_call, 2), NOW, nonce) {
            AuthDecision::Replayed(replay) => {
                assert_eq!(replay.status(), 202);
                assert_eq!(pending_headers(&replay), expected);
                assert_eq!(replay.body(), br#"{"status":"pending"}"#);
            }
            other => panic!("replay of the pending result: {other:?}"),
        }
    }

    let (cross, grant) = completion("challenge-cross", "per-call-cross");
    let refused = resource.r3_retain(&grant, application_202("https://elsewhere.example/jobs/7"));
    assert_eq!(
        refused.status(),
        500,
        "{}",
        String::from_utf8_lossy(refused.body())
    );
    assert!(refused.headers().get("location").is_none());
    let refused_body: Value = serde_json::from_slice(refused.body()).unwrap();
    assert_eq!(refused_body["error"], "server_error");
    match resource.authorize(&call(route, &cross, 2), NOW, "replay-cross") {
        AuthDecision::Replayed(replay) => {
            assert_eq!(replay.status(), 500);
            assert!(replay.headers().get("location").is_none());
            assert!(replay.headers().get("retry-after").is_none());
            assert_eq!(replay.body(), refused.body());
        }
        other => panic!("replay of the stored refusal: {other:?}"),
    }
    match resource.authorize(&call(route, &per_call, 2), NOW, "replay-pending-intact") {
        AuthDecision::Replayed(replay) => assert_eq!(pending_headers(&replay), expected),
        other => panic!("first pending result changed: {other:?}"),
    }
}

#[test]
fn a_released_application_202_replays_with_its_pending_headers_or_as_server_error() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let proposals = Arc::new(MemoryCalls::new());
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: None,
            })
        },
    );
    // The first computation answers a same-origin pending 202, the second a cross-origin one.
    let computed = Arc::new(AtomicUsize::new(0));
    let runs = Arc::clone(&computed);
    let release: aauth_rust_resource::BoxedR3Release = Box::new(
        move |_: &Request<Vec<u8>>,
              _: &Operation,
              _: &BTreeMap<String, PresentedParameter>,
              _: Option<&str>| {
            let location = if runs.fetch_add(1, Ordering::SeqCst) == 0 {
                format!("{ORIGIN}/jobs/released")
            } else {
                "https://elsewhere.example/jobs/released".to_owned()
            };
            Ok(Some(aauth_rust_resource::R3Release {
                result: aauth_rust_r3::ProposalResult::new(b"{}").unwrap(),
                display: aauth_rust_r3::ProposalDisplay::new(
                    &R3Display::new("The call already ran", None, None, None).unwrap(),
                    None,
                )
                .unwrap(),
                response: Response::builder()
                    .status(202)
                    .header("location", location)
                    .header("retry-after", "5")
                    .header("cache-control", "no-store")
                    .header("content-type", "application/json")
                    .body(br#"{"status":"pending"}"#.to_vec())
                    .unwrap(),
            }))
        },
    );
    let resource = PsAuthorizationResource::new(config(), keys(), policy(&calls))
        .unwrap()
        .with_authorization_endpoint()
        .with_r3(r3_config(&store, false))
        .unwrap()
        .with_r3_per_call(R3PerCallConfig {
            present,
            describe,
            calls: proposals.clone(),
            hold: true,
            release: Some(release),
            held_result_lifetime: 300,
        })
        .unwrap();
    let record = issue(
        &resource,
        &store,
        &["records.read", "records.delete"],
        "rt-released",
    );
    let class = class_token(
        &record,
        &["records.read"],
        &["records.delete"],
        &auth_claims(None),
        3,
        "ps-1",
    );
    // Approve one release and present its per-call token twice at the pending URL.
    let release_twice = |challenge: &str, jti: &str| {
        let held = resource
            .authorize(&call("/mcp/records.delete", &class, 2), NOW, challenge)
            .into_response();
        assert_eq!(
            held.status(),
            202,
            "{}",
            String::from_utf8_lossy(held.body())
        );
        let stored = proposals
            .records
            .lock()
            .unwrap()
            .values()
            .find(|record| record.resource_token_jti == challenge)
            .cloned()
            .expect("held release");
        let mut claims = auth_claims(None);
        claims.jti = jti.into();
        let per_call = aauth_rust_r3::mint_per_call_auth_token(
            &standard_registry().unwrap(),
            &SigningKey::from_seed([3; 32]),
            "ps-1",
            &claims,
            &stored.reference,
            &stored.exact_json,
        )
        .expect("per-call auth token");
        let pending = pending_path(&held);
        ["release", "replay"].map(|presentation| {
            match resource.authorize(
                &call(&pending, &per_call, 2),
                NOW,
                &format!("{jti}-{presentation}"),
            ) {
                AuthDecision::Replayed(response) => *response,
                other => panic!("{presentation} of {challenge}: {other:?}"),
            }
        })
    };

    for response in release_twice("challenge-released", "per-call-released") {
        assert_eq!(
            response.status(),
            202,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        assert_eq!(
            response.headers()["location"],
            format!("{ORIGIN}/jobs/released").as_str()
        );
        assert_eq!(response.headers()["retry-after"], "5");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.body(), br#"{"status":"pending"}"#);
    }
    for response in release_twice("challenge-cross", "per-call-cross") {
        assert_eq!(
            response.status(),
            500,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        assert!(response.headers().get("location").is_none());
        assert!(response.headers().get("retry-after").is_none());
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"], "server_error");
    }
    assert_eq!(computed.load(Ordering::SeqCst), 2);
}

fn missionless_per_call() -> R3PerCallConfig {
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |_: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: None,
            })
        },
    );
    R3PerCallConfig {
        present,
        describe,
        calls: Arc::new(MemoryCalls::new()),
        hold: false,
        release: None,
        held_result_lifetime: 300,
    }
}

#[test]
fn a_mission_resource_token_ends_with_the_person_token() {
    const MISSION: &str = "N1fWRFx_bLw1RcyTspTOoOuN1ct9hw7mEHZuGFMTmhw";
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = core_resource(&calls)
        .with_mission_context()
        .with_r3(r3_config(&store, false))
        .unwrap();
    let expiry = |response: Response<Vec<u8>>, proactive: bool| -> i64 {
        let compact = if proactive {
            assert_eq!(response.status(), 200);
            let body: Value = serde_json::from_slice(response.body()).unwrap();
            body["resource_token"].as_str().unwrap().to_owned()
        } else {
            assert_eq!(response.status(), 401);
            response.headers()["aauth-requirement"]
                .to_str()
                .unwrap()
                .strip_prefix("requirement=auth-token;resource-token=\"")
                .unwrap()
                .strip_suffix('"')
                .unwrap()
                .to_owned()
        };
        verify_resource_token(&compact, &keys(), NOW)
            .unwrap()
            .claims()
            .exp
    };
    // A two-minute mission: the Resource token ends with the Person token.
    let person = person_on_mission_until(Some(MISSION), NOW + 120);
    let proactive = resource
        .authorize_endpoint(
            &authorize_as(
                ORIGIN,
                person.clone(),
                json!({ "r3_operations": operations(&["records.read"]) }),
            ),
            NOW,
            "rt-short",
        )
        .into_response();
    assert_eq!(expiry(proactive, true), NOW + 120);
    let reactive = resource
        .authorize(&call("/mcp/records.read", &person, 2), NOW, "rt-short-2")
        .into_response();
    assert_eq!(expiry(reactive, false), NOW + 120);
    // A missionless Person token keeps the ordinary five-minute challenge.
    let reactive = resource
        .authorize(
            &call(
                "/mcp/records.read",
                &person_on_mission_until(None, NOW + 120),
                2,
            ),
            NOW,
            "rt-short-3",
        )
        .into_response();
    assert_eq!(expiry(reactive, false), NOW + 300);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_mission_class_document_admits_only_an_auth_token_for_that_mission() {
    const MISSION: &str = "N1fWRFx_bLw1RcyTspTOoOuN1ct9hw7mEHZuGFMTmhw";
    const OTHER: &str = "6rh4HpwC-a-8Yw6vPZ6KtVQBQ1qD09a0DG7Ol2QRoCk";
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let resource = core_resource(&calls)
        .with_mission_context()
        .with_r3(r3_config(&store, false))
        .unwrap();
    let response = resource
        .authorize_endpoint(
            &authorize_as(
                ORIGIN,
                person_on_mission(Some(MISSION)),
                json!({ "r3_operations": operations(&["records.read"]) }),
            ),
            NOW,
            "rt-mission",
        )
        .into_response();
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let verified =
        verify_resource_token(body["resource_token"].as_str().unwrap(), &keys(), NOW).unwrap();
    assert_eq!(verified.claims().mission_s256.as_deref(), Some(MISSION));
    let record = store.records.lock().unwrap()[verified.reference().uri()].clone();
    assert_eq!(record.mission_s256.as_deref(), Some(MISSION));

    for (mission, admitted) in [(Some(MISSION), true), (None, false), (Some(OTHER), false)] {
        let mut claims = auth_claims(None);
        claims.mission_s256 = mission.map(Into::into);
        let token = class_token(&record, &["records.read"], &[], &claims, 3, "ps-1");
        let before = calls.load(Ordering::SeqCst);
        let decision = resource.authorize(&call("/mcp/records.read", &token, 2), NOW, "unused");
        if admitted {
            decision
                .into_result()
                .expect("the mission's own Auth token");
            assert_eq!(calls.load(Ordering::SeqCst), before + 1);
        } else {
            assert_eq!(decision.into_response().status(), 403, "{mission:?}");
            assert_eq!(calls.load(Ordering::SeqCst), before, "{mission:?}");
        }
    }

    // A missionless class document refuses a mission-bound Auth token.
    let missionless = issue(&resource, &store, &["records.read"], "rt-missionless");
    assert_eq!(missionless.mission_s256, None);
    let mut claims = auth_claims(None);
    claims.mission_s256 = Some(MISSION.into());
    let token = class_token(&missionless, &["records.read"], &[], &claims, 3, "ps-1");
    let before = calls.load(Ordering::SeqCst);
    let refused = resource
        .authorize(&call("/mcp/records.read", &token, 2), NOW, "unused")
        .into_response();
    assert_eq!(refused.status(), 403);
    assert_eq!(calls.load(Ordering::SeqCst), before);
}

fn mcp_snapshot(tools: &[u8]) -> AuthoritativeSnapshot {
    McpCodec::parse_definition(
        MCP_ENDPOINT,
        &ToolsListSnapshot::new(vec![ToolsListPage::initial(tools)]),
    )
    .unwrap()
}
fn r3_config_for(store: &Arc<VolatileTestStore>, tools: &[u8]) -> R3Config {
    let mut config = r3_config(store, false);
    config.vocabularies = vec![R3Vocabulary {
        definition: mcp_snapshot(tools),
        display: None,
    }];
    config
}
fn agent_token() -> String {
    AgentProvider::new(AP, "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:reader@ap.example".into(),
            jti: "agent-1".into(),
            iat: NOW,
            exp: 4000,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([2; 32]).public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap()
}
fn outcome(decision: AuthDecision<String>) -> &'static str {
    match decision {
        AuthDecision::PersonTokenRequired => "person-token required",
        AuthDecision::AuthTokenRequired { .. } => "auth-token required",
        AuthDecision::Forbidden { .. } => "forbidden",
        AuthDecision::Granted(_) => "granted",
        other => panic!("unexpected decision: {other:?}"),
    }
}

/// The same two tools, annotated: the read says an agent token is enough, and
/// the delete says it is approved per call and draws down a budget.
const ANNOTATED_TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"agent-token"}},{"name":"records.delete","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"per-call","aauth.dev/budget":true}}]}"#;

// R3 Operation Access Annotations Are Not Authorization: an annotation is a
// published expectation, not evidence about the caller. Each request is
// enforced against the credential presented, so the same requests get the
// same answers whether or not the definition carries annotations.
#[test]
fn annotations_in_the_definition_change_no_enforcement_decision() {
    let annotated = mcp_snapshot(ANNOTATED_TOOLS);
    let read = annotated.hints_for(&mcp("records.read")).unwrap().unwrap();
    assert_eq!(read.access_mode(), Some(AccessMode::AgentToken));
    let delete = annotated
        .hints_for(&mcp("records.delete"))
        .unwrap()
        .unwrap();
    assert_eq!(delete.access_mode(), Some(AccessMode::PerCall));
    assert_eq!(delete.budget(), Some(true));
    assert!(
        mcp_snapshot(TOOLS)
            .hints_for(&mcp("records.read"))
            .unwrap()
            .is_none()
    );

    let run = |tools: &[u8]| {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(VolatileTestStore::default());
        let resource = core_resource(&calls)
            .with_r3(r3_config_for(&store, tools))
            .unwrap();
        let record = issue(
            &resource,
            &store,
            &["records.read", "records.delete"],
            "rt-annotations",
        );
        // The class token grants the delete and leaves the read per call.
        let class = class_token(
            &record,
            &["records.delete"],
            &["records.read"],
            &auth_claims(None),
            3,
            "ps-1",
        );
        let core = mint_auth_token(
            &SigningKey::from_seed([3; 32]),
            "ps-1",
            &auth_claims(Some("records.read")),
        )
        .unwrap();
        let outcomes = [
            ("agent token, read", "/mcp/records.read", agent_token()),
            ("person token, read", "/mcp/records.read", person()),
            ("core auth token, read", "/mcp/records.read", core.clone()),
            ("core auth token, delete", "/mcp/records.delete", core),
            ("class token, read", "/mcp/records.read", class.clone()),
            ("class token, delete", "/mcp/records.delete", class),
        ]
        .map(|(label, path, token)| {
            let decision = resource.authorize(&call(path, &token, 2), NOW, "challenge-annotations");
            (label, outcome(decision))
        });
        (outcomes, calls.load(Ordering::SeqCst))
    };
    let (outcomes, admitted) = run(ANNOTATED_TOOLS);
    assert_eq!((outcomes, admitted), run(TOOLS));
    assert_eq!(
        outcomes,
        [
            ("agent token, read", "person-token required"),
            ("person token, read", "auth-token required"),
            ("core auth token, read", "forbidden"),
            ("core auth token, delete", "forbidden"),
            ("class token, read", "forbidden"),
            ("class token, delete", "granted"),
        ]
    );
    // Host policy ran once, for the delete the class token grants, although
    // no budget was presented for it.
    assert_eq!(admitted, 1);
}

/// Tools for release gating. Only `records.export` is annotated: running it
/// draws down a budget.
const RELEASE_TOOLS: &[u8] = br#"{"tools":[{"name":"records.query","inputSchema":{"type":"object"}},{"name":"records.count","inputSchema":{"type":"object"}},{"name":"records.export","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}},{"name":"records.audit","inputSchema":{"type":"object"}}]}"#;
const RELEASE_OPERATIONS: [&str; 4] = [
    "records.query",
    "records.count",
    "records.export",
    "records.audit",
];
const RELEASE_STATEMENT: &str = "## Action\nThis operation has already run. What you are approving is release of its result to the agent.";

fn tool_name(operation: &Operation) -> String {
    let value: Value = serde_json::from_slice(&operation.json().unwrap()).unwrap();
    value["tool"].as_str().unwrap().to_owned()
}

/// A held per-call Resource whose release hook runs, before approval, every
/// call it is asked to run, except `records.audit`: the host's audit regime
/// records that call, so the hook keeps it for execution approval.
struct ReleaseHost {
    resource: Resource,
    proposals: Arc<MemoryCalls>,
    record: R3DocumentRecord,
    class: String,
    /// Calls the release hook was asked to run.
    asked: Arc<Mutex<Vec<String>>>,
    /// Every execution, in order.
    ran: Arc<Mutex<Vec<String>>>,
}
fn release_host() -> ReleaseHost {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let proposals = Arc::new(MemoryCalls::new());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let ran = Arc::new(Mutex::new(Vec::new()));
    let present: BoxedR3Present =
        Box::new(|_: &Request<Vec<u8>>, _: &Operation| Ok(BTreeMap::new()));
    let describe: BoxedR3Describe = Box::new(
        |operation: &Operation, _: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
            let summary = format!("Run {}", tool_name(operation));
            Ok(aauth_rust_resource::R3CallDescription {
                parameters: Parameters::new(std::iter::empty()).expect("empty parameters"),
                display: Some(
                    ProposalDisplay::new(&R3Display::new(summary, None, None, None).unwrap(), None)
                        .unwrap(),
                ),
            })
        },
    );
    let release: BoxedR3Release = {
        let (asked, ran) = (Arc::clone(&asked), Arc::clone(&ran));
        Box::new(
            move |_: &Request<Vec<u8>>,
                  operation: &Operation,
                  _: &BTreeMap<String, PresentedParameter>,
                  _: Option<&str>| {
                let tool = tool_name(operation);
                asked.lock().unwrap().push(tool.clone());
                if tool == "records.audit" {
                    return Ok(None);
                }
                ran.lock().unwrap().push(format!("{tool} before approval"));
                let detail = (tool == "records.query")
                    .then_some("## Details\nOne record, with a national identifier.");
                Ok(Some(R3Release {
                    result: ProposalResult::new(br#"{"records":1}"#).unwrap(),
                    display: ProposalDisplay::new(
                        &R3Display::new(
                            format!("Release the result of {tool}"),
                            None,
                            Some("One record"),
                            None,
                        )
                        .unwrap(),
                        detail,
                    )
                    .unwrap(),
                    response: Response::builder()
                        .status(200)
                        .body(format!("{tool} result").into_bytes())
                        .unwrap(),
                }))
            },
        )
    };
    let resource = core_resource(&calls)
        .with_r3(r3_config_for(&store, RELEASE_TOOLS))
        .unwrap()
        .with_r3_per_call(R3PerCallConfig {
            present,
            describe,
            calls: proposals.clone(),
            hold: true,
            release: Some(release),
            held_result_lifetime: 300,
        })
        .unwrap();
    let record = issue(&resource, &store, &RELEASE_OPERATIONS, "rt-release");
    let class = class_token(
        &record,
        &[],
        &RELEASE_OPERATIONS,
        &auth_claims(None),
        3,
        "ps-1",
    );
    ReleaseHost {
        resource,
        proposals,
        record,
        class,
        asked,
        ran,
    }
}
impl ReleaseHost {
    /// Call `tool` with the class token and return its held proposal.
    fn hold(&self, tool: &str) -> R3ProposalRecord {
        self.hold_with(
            tool,
            &self.class,
            &format!("challenge-{}", tool.replace('.', "-")),
        )
    }
    /// Call `tool` with `class` under `challenge` and return the held proposal.
    fn hold_with(&self, tool: &str, class: &str, challenge: &str) -> R3ProposalRecord {
        let held = self
            .resource
            .authorize(&call(&format!("/mcp/{tool}"), class, 2), NOW, challenge)
            .into_response();
        assert_eq!(
            held.status(),
            202,
            "{}",
            String::from_utf8_lossy(held.body())
        );
        let pending = pending_path(&held);
        self.proposals
            .records
            .lock()
            .unwrap()
            .values()
            .find(|record| {
                record.resource_token_jti == challenge
                    && record.held.as_ref().is_some_and(|stored| {
                        pending == format!("/r3/pending/{}", stored.pending_id)
                    })
            })
            .cloned()
            .expect("held proposal")
    }
    /// The proposal as its Person Server fetches it.
    fn fetched(&self, record: &R3ProposalRecord) -> Value {
        let response = self.resource.r3_document(
            &fetch_uri(record.reference.uri(), PS, "aauth-person.json", "ps-1", 3),
            NOW,
        );
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), &record.exact_json);
        serde_json::from_slice(response.body()).unwrap()
    }
    /// Present the per-call Auth token approving `record` at its pending URL.
    fn complete(&self, record: &R3ProposalRecord, jti: &str) -> AuthDecision<String> {
        let mut claims = auth_claims(None);
        claims.jti = jti.into();
        let token = aauth_rust_r3::mint_per_call_auth_token(
            &standard_registry().unwrap(),
            &SigningKey::from_seed([3; 32]),
            "ps-1",
            &claims,
            &record.reference,
            &record.exact_json,
        )
        .expect("per-call auth token");
        let pending = format!("/r3/pending/{}", record.held.as_ref().unwrap().pending_id);
        self.resource
            .authorize(&call(&pending, &token, 2), NOW, &format!("{jti}-poll"))
    }
}

// R3 Approving Release Rather Than Execution: when the Resource has run the
// call before seeking approval, `display` states that it has run and that what
// is approved is release of its result.
#[test]
fn a_release_proposal_display_states_the_call_ran_and_approval_releases_its_result() {
    let host = release_host();
    // The statement opens `detail`, and the host's own detail follows it.
    let query = host.hold("records.query");
    let proposal = host.fetched(&query);
    assert_eq!(proposal["result"], json!({ "records": 1 }));
    assert_eq!(
        proposal["display"]["summary"],
        "Release the result of records.query"
    );
    assert_eq!(proposal["display"]["data_accessed"], "One record");
    assert_eq!(
        proposal["display"]["detail"],
        format!("{RELEASE_STATEMENT}\n\n## Details\nOne record, with a national identifier.")
    );
    // Without host detail, `detail` is the statement.
    let count = host.hold("records.count");
    let proposal = host.fetched(&count);
    assert_eq!(proposal["result"], json!({ "records": 1 }));
    assert_eq!(proposal["display"]["detail"], RELEASE_STATEMENT);
    // A proposal seeking execution approval does not say the call has run.
    let audit = host.hold("records.audit");
    let proposal = host.fetched(&audit);
    assert!(proposal.get("result").is_none());
    assert_eq!(
        proposal["display"],
        json!({ "summary": "Run records.audit" })
    );
    // Approval releases the result computed before approval. Nothing runs again.
    match host.complete(&query, "per-call-query") {
        AuthDecision::Replayed(response) => assert_eq!(response.body(), b"records.query result"),
        other => panic!("release: {other:?}"),
    }
    assert_eq!(
        *host.ran.lock().unwrap(),
        [
            "records.query before approval",
            "records.count before approval"
        ]
    );
}

// R3 Approving Release Rather Than Execution: a Resource does not execute
// before approval where execution is the audited, metered or billed event;
// approval precedes it. The definition publishes `records.export` with
// `budget: true`, so the Resource never asks the release hook to run it,
// although the hook would. The host's audit regime records `records.audit`,
// and its hook declines to run it.
#[test]
fn a_metered_or_audited_call_runs_only_after_approval() {
    let host = release_host();
    for tool in ["records.export", "records.audit"] {
        let held = host.hold(tool);
        // Held for execution approval: no computed result, and nothing ran.
        assert!(held.released.is_none(), "{tool}");
        assert!(held.release_until.is_none(), "{tool}");
        let proposal = host.fetched(&held);
        assert!(proposal.get("result").is_none(), "{tool}");
        assert_eq!(
            proposal["display"],
            json!({ "summary": format!("Run {tool}") })
        );
        assert!(
            !host
                .ran
                .lock()
                .unwrap()
                .iter()
                .any(|run| run.starts_with(tool)),
            "{tool}"
        );
        // The approved per-call token admits the held call, which runs now.
        let jti = format!("per-call-{}", tool.replace('.', "-"));
        let grant = match host.complete(&held, &jti) {
            AuthDecision::Granted(admitted) => admitted.r3_grant().expect("held call").clone(),
            other => panic!("{tool} completion: {other:?}"),
        };
        host.ran
            .lock()
            .unwrap()
            .push(format!("{tool} after approval"));
        let response = Response::builder()
            .status(200)
            .body(format!("{tool} result").into_bytes())
            .unwrap();
        let stored = host.resource.r3_retain(&grant, response);
        assert_eq!(stored.body(), format!("{tool} result").as_bytes());
    }
    assert_eq!(*host.asked.lock().unwrap(), ["records.audit"]);
    assert_eq!(
        *host.ran.lock().unwrap(),
        [
            "records.export after approval",
            "records.audit after approval"
        ]
    );
}

// Core Scopes, on the per-call path: the proposal Resource token carries the
// presented class token's scope, so the Resource issues one only when it
// describes every value in that scope.
#[test]
fn a_per_call_resource_token_carries_only_described_scopes() {
    let host = release_host();
    let mut described = auth_claims(Some("records.read"));
    described.jti = "auth-described".into();
    let class = class_token(
        &host.record,
        &[],
        &RELEASE_OPERATIONS,
        &described,
        3,
        "ps-1",
    );
    let held = host.hold_with("records.export", &class, "challenge-described");
    let issued = verify_resource_token(&held.resource_token, &keys(), NOW).unwrap();
    assert_eq!(issued.claims().scope.as_deref(), Some("records.read"));

    let mut undescribed = auth_claims(Some("records.read admin"));
    undescribed.jti = "auth-undescribed".into();
    let class = class_token(
        &host.record,
        &[],
        &RELEASE_OPERATIONS,
        &undescribed,
        3,
        "ps-1",
    );
    let refused = host.resource.authorize(
        &call("/mcp/records.query", &class, 2),
        NOW,
        "challenge-undescribed",
    );
    assert!(matches!(refused, AuthDecision::Forbidden { .. }));
    // No proposal was committed, and the release hook was not asked to run.
    assert_eq!(host.proposals.records.lock().unwrap().len(), 1);
    assert!(host.asked.lock().unwrap().is_empty());
    assert!(host.ran.lock().unwrap().is_empty());
}

const WIDGETS_URI: &str = "https://vocabulary.example/widgets";
const WIDGETS_ENDPOINT: &str = "https://resource.example/widgets";

/// A proprietary `{"widget": name}` vocabulary, named by the URI it is given.
struct WidgetCodec(&'static str);
fn widget_operation(name: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "widget": name })).unwrap()
}
impl Codec for WidgetCodec {
    type Set = Vec<String>;
    fn uri(&self) -> VocabularyUri {
        VocabularyUri::parse(self.0).unwrap()
    }
    fn annotation_encoding(&self) -> AnnotationEncoding {
        AnnotationEncoding::UNAVAILABLE
    }
    fn validate_discovery_endpoint(&self, endpoint: &str) -> Result<(), R3Error> {
        if endpoint.starts_with("https://") {
            Ok(())
        } else {
            Err(R3Error::new("widget definitions are served over HTTPS"))
        }
    }
    fn parse_set(&self, raw: &[Vec<u8>]) -> Result<Self::Set, R3Error> {
        let mut names: Vec<String> = Vec::new();
        for operation in raw {
            let value: Value = serde_json::from_slice(operation)
                .map_err(|_| R3Error::new("widget operation is not JSON"))?;
            let name = match value.as_object() {
                Some(members) if members.len() == 1 => {
                    members.get("widget").and_then(Value::as_str)
                }
                _ => None,
            };
            match name {
                Some(name) if !name.is_empty() && !names.iter().any(|seen| seen == name) => {
                    names.push(name.to_owned());
                }
                _ => return Err(R3Error::new("widget operation must be one new widget name")),
            }
        }
        Ok(names)
    }
    fn marshal_set(&self, set: &Self::Set) -> Result<Vec<Vec<u8>>, R3Error> {
        Ok(set.iter().map(|name| widget_operation(name)).collect())
    }
    fn union_sets<'a>(
        &self,
        sets: impl IntoIterator<Item = &'a Self::Set>,
    ) -> Result<Self::Set, R3Error>
    where
        Self::Set: 'a,
    {
        let mut union: Vec<String> = Vec::new();
        for name in sets.into_iter().flatten() {
            if !union.contains(name) {
                union.push(name.clone());
            }
        }
        Ok(union)
    }
    fn sets_equal(&self, left: &Self::Set, right: &Self::Set) -> bool {
        self.is_subset(left, right) && self.is_subset(right, left)
    }
    fn is_subset(&self, subset: &Self::Set, superset: &Self::Set) -> bool {
        subset.iter().all(|name| superset.contains(name))
    }
    fn is_disjoint(&self, left: &Self::Set, right: &Self::Set) -> bool {
        !left.iter().any(|name| right.contains(name))
    }
}
/// A widget definition source: a JSON array of the widget names it serves.
struct WidgetDefinition(Vocabulary);
impl DefinitionCodec<[u8]> for WidgetDefinition {
    fn vocabulary(&self) -> Result<Vocabulary, R3Error> {
        Ok(self.0.clone())
    }
    fn parse_definition(&self, source: &[u8]) -> Result<DefinitionMaterial, DefinitionError> {
        let names: Vec<String> = serde_json::from_slice(source)
            .map_err(|_| R3Error::new("widget definition must be an array of names"))?;
        let operations = names
            .iter()
            .map(|name| DefinedOperation::new(&widget_operation(name), None))
            .collect::<Result<Vec<_>, _>>()?;
        let encoding = SourceEncoding::new("application/json")?;
        DefinitionMaterial::new(encoding, source.to_vec(), operations)
            .map_err(DefinitionError::from)
    }
}

// R3 Resource Metadata Extensions: `r3_vocabularies` keys are standard
// vocabulary URIs from the `urn:aauth:vocabulary:` namespace, or URIs in a
// third party's own namespace for proprietary vocabularies.
#[test]
fn r3_vocabularies_keys_are_standard_urns_or_third_party_uris() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(VolatileTestStore::default());
    let widgets = Vocabulary::new(WidgetCodec(WIDGETS_URI)).unwrap();
    let parser = DefinitionParser::new(WidgetDefinition(widgets.clone())).unwrap();
    let mut config = r3_config(&store, false);
    config.registry = Registry::new(&[McpCodec::vocabulary().unwrap(), widgets]).unwrap();
    config.definitions = DefinitionRegistry::new(&[
        McpCodec::definition_registration().unwrap(),
        parser.registration(),
    ])
    .unwrap();
    config.vocabularies.push(R3Vocabulary {
        definition: parser
            .parse(WIDGETS_ENDPOINT, &br#"["blue","red"]"#[..])
            .unwrap(),
        display: None,
    });
    let resource = core_resource(&calls).with_r3(config).unwrap();
    let metadata: Value = serde_json::from_slice(&resource.metadata().unwrap()).unwrap();
    assert_eq!(
        metadata["r3_vocabularies"],
        json!({ MCP_URI: MCP_ENDPOINT, WIDGETS_URI: WIDGETS_ENDPOINT })
    );
    let standard = standard_vocabularies().unwrap();
    for key in metadata["r3_vocabularies"].as_object().unwrap().keys() {
        let is_standard = standard
            .iter()
            .any(|vocabulary| vocabulary.uri().as_str() == key);
        let in_namespace = key
            .to_ascii_lowercase()
            .starts_with("urn:aauth:vocabulary:");
        assert_eq!(is_standard, in_namespace, "{key}");
    }
    // A proprietary vocabulary cannot be registered, and so cannot be
    // advertised, in the standard namespace.
    for uri in [
        "urn:aauth:vocabulary:widgets",
        "URN:AAUTH:VOCABULARY:widgets",
    ] {
        assert!(Vocabulary::new(WidgetCodec(uri)).is_err(), "{uri}");
    }
}
