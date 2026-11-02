use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentClaims, AgentProviderKeys, Confirmation};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Binding, BoxedClock, BoxedTokenIds, Config, Grant,
    MemoryStore, MissionAudit, MissionAuditError, MissionEdit, MissionStore, Person, PersonRequest,
    PersonServer, Policy, PolicyError, Store, StoreError, TokenRecord, TokenReference,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{Request, Response};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

struct Host;
impl Policy for Host {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Err(PolicyError::Denied)
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

struct Fixture {
    server: PersonServer<AgentProviderKeys, MemoryStore, Host, BoxedClock, BoxedTokenIds>,
    owner: Agent,
    other: Agent,
}

fn issue(ap: &AgentProvider, seed: [u8; 32], sub: &str, jti: &str) -> Agent {
    let key = SigningKey::from_seed(seed);
    let token = ap
        .issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: sub.into(),
            jti: jti.into(),
            iat: 1000,
            exp: 2000,
            cnf: Confirmation {
                jwk: key.public_jwk(),
            },
            ps: Some("https://ps.example".into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(key, token).unwrap()
}

fn fixture(missions: bool) -> Fixture {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    let owner = issue(&ap, [2; 32], "aauth:Agent@ap.example", "agent-1");
    let other = issue(&ap, [9; 32], "aauth:Other@ap.example", "agent-2");
    let ids = Arc::new(AtomicUsize::new(0));
    let mut server = PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
        keys,
        MemoryStore::default(),
        Host,
        Box::new(|| 1000i64) as BoxedClock,
        Box::new(move || format!("proposal-{}", ids.fetch_add(1, Ordering::SeqCst)))
            as BoxedTokenIds,
    )
    .unwrap();
    if missions {
        server = server.with_missions();
    }
    Fixture {
        server,
        owner,
        other,
    }
}

fn signed(agent: &Agent, method: &str, path: &str, body: Option<Value>) -> Request<Vec<u8>> {
    let bytes = body
        .as_ref()
        .map(|value| serde_json::to_vec(value).unwrap())
        .unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://ps.example{path}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut request = builder.body(bytes).unwrap();
    agent.sign(&mut request, 1000).unwrap();
    request
}

fn approver(path: &str, body: Value, seed: [u8; 32]) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("https://ps.example{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed(seed),
        KeyMaterial::JwksUri {
            id: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        1000,
    )
    .unwrap();
    request
}

fn json_body(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap_or_else(|_| {
        panic!(
            "status {} body {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        )
    })
}

fn error_of(response: &Response<Vec<u8>>) -> String {
    json_body(response)["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn propose(server: &Fixture, description: &str) -> String {
    let response = server.server.handle(&signed(
        &server.owner,
        "POST",
        "/mission",
        Some(serde_json::json!({ "description": description, "tools": ["ignored"] })),
    ));
    assert_eq!(response.status(), 202, "{}", error_of(&response));
    assert_eq!(response.headers()["retry-after"], "5");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("https://ps.example/mission/proposal/"));
    location.rsplit('/').next().unwrap().to_owned()
}

fn approve(server: &Fixture, proposal: &str) -> Value {
    let response = server.server.handle(&approver(
        &format!("/mission/proposal/{proposal}/approval"),
        serde_json::json!({ "decision": "approve" }),
        [3; 32],
    ));
    assert_eq!(response.status(), 200, "{}", error_of(&response));
    let acknowledged = json_body(&response);
    assert_eq!(acknowledged["decision"], "approved");
    assert!(acknowledged.get("s256").is_none());
    assert!(acknowledged.get("mission").is_none());
    let poll = server.server.handle(&signed(
        &server.owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(poll.status(), 200, "{}", error_of(&poll));
    json_body(&poll)
}

#[test]
fn disabled_mission_endpoint_is_not_advertised() {
    let fixture = fixture(false);
    let published: Value = serde_json::from_slice(&fixture.server.metadata()).unwrap();
    assert!(published.get("mission_endpoint").is_none());
    let response = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        "/mission",
        Some(serde_json::json!({ "description": "draft the note" })),
    ));
    assert_eq!(response.status(), 404);
    assert_eq!(error_of(&response), "not_found");
}

#[test]
fn agent_proposal_requires_a_signed_jwt_post() {
    let fixture = fixture(true);
    let published: Value = serde_json::from_slice(&fixture.server.metadata()).unwrap();
    assert_eq!(published["mission_endpoint"], "https://ps.example/mission");
    let unsigned = Request::builder()
        .method("POST")
        .uri("https://ps.example/mission")
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&serde_json::json!({ "description": "draft the note" })).unwrap())
        .unwrap();
    assert_eq!(fixture.server.handle(&unsigned).status(), 401);
    let mut server_signed = Request::builder()
        .method("POST")
        .uri("https://ps.example/mission")
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&serde_json::json!({ "description": "draft the note" })).unwrap())
        .unwrap();
    sign_request(
        &mut server_signed,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        1000,
    )
    .unwrap();
    let refused = fixture.server.handle(&server_signed);
    assert_eq!(refused.status(), 401);
    assert_eq!(error_of(&refused), "unsupported_scheme");
    assert_eq!(refused.headers()["accept-signature-scheme"], "jwt");
    let created = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        "/mission",
        Some(serde_json::json!({ "description": "draft the note" })),
    ));
    assert_eq!(created.status(), 202, "{}", error_of(&created));
    let location = created.headers()["location"].to_str().unwrap();
    let id = location
        .strip_prefix("https://ps.example/mission/proposal/")
        .unwrap();
    // A pending URL carries 128 random bits, not the host's token-ID source.
    assert_eq!(id.len(), 22, "{location}");
    assert!(!id.starts_with("proposal-"));
    let waiting = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        &format!("/mission/proposal/{id}"),
        None,
    ));
    assert_eq!(waiting.status(), 202);
    assert_eq!(waiting.headers()["cache-control"], "no-store");
}

#[test]
fn approval_requires_the_server_signature_before_returning_the_blob() {
    let fixture = fixture(true);
    let proposal = propose(&fixture, "draft the note");
    let path = format!("/mission/proposal/{proposal}/approval");
    let body = serde_json::json!({ "decision": "approve" });
    let unsigned = Request::builder()
        .method("POST")
        .uri(format!("https://ps.example{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    assert_eq!(fixture.server.handle(&unsigned).status(), 401);
    let by_agent =
        fixture
            .server
            .handle(&signed(&fixture.owner, "POST", &path, Some(body.clone())));
    assert_eq!(by_agent.status(), 401);
    assert_eq!(error_of(&by_agent), "unsupported_scheme");
    assert_eq!(by_agent.headers()["accept-signature-scheme"], "jwks_uri");
    let wrong_key = fixture.server.handle(&approver(&path, body, [9; 32]));
    assert_eq!(wrong_key.status(), 401);
    let approved = approve(&fixture, &proposal);
    let s256 = approved["s256"].as_str().unwrap();
    let encoded = approved["mission"].as_str().unwrap();
    assert!(!encoded.contains('='));
    let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)), s256);
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["agent"], "aauth:Agent@ap.example");
    assert_eq!(document["approved_at"], "1970-01-01T00:16:40Z");
    assert_eq!(document["description"], "draft the note");
    assert!(approved.get("person_tokens").is_none());
    let stranger = fixture.server.handle(&signed(
        &fixture.other,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(stranger.status(), 404);
    assert_eq!(error_of(&stranger), "mission_not_found");
    let again = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(again.status(), 410);
    assert_eq!(error_of(&again), "gone");
    let kept = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        &format!("/mission/{s256}"),
        None,
    ));
    assert_eq!(kept.status(), 200, "{}", error_of(&kept));
    assert_eq!(json_body(&kept)["mission"], encoded);
}

#[test]
fn denial_removes_the_proposal_without_a_mission_document() {
    let fixture = fixture(true);
    let proposal = propose(&fixture, "draft the note");
    let path = format!("/mission/proposal/{proposal}/approval");
    let denied = fixture.server.handle(&approver(
        &path,
        serde_json::json!({ "decision": "deny" }),
        [3; 32],
    ));
    assert_eq!(denied.status(), 200);
    assert_eq!(json_body(&denied)["decision"], "denied");
    let agent_poll = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(agent_poll.status(), 403);
    assert_eq!(error_of(&agent_poll), "access_denied");
    let again_poll = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(again_poll.status(), 410);
    assert_eq!(error_of(&again_poll), "gone");
    let again = fixture.server.handle(&approver(
        &path,
        serde_json::json!({ "decision": "approve" }),
        [3; 32],
    ));
    assert_eq!(again.status(), 404);
    assert_eq!(error_of(&again), "mission_not_found");
}

#[test]
fn an_approval_may_set_the_missions_expiry() {
    let fixture = fixture(true);
    let proposal = propose(&fixture, "draft the note");
    let path = format!("/mission/proposal/{proposal}/approval");
    // The clock reads 1000 (1970-01-01T00:16:40Z). An expiry that is not a
    // string, not RFC 3339, not after now, or sent with a denial is refused
    // and the proposal stays pending.
    for body in [
        serde_json::json!({ "decision": "approve", "expires_at": 1200 }),
        serde_json::json!({ "decision": "approve", "expires_at": "tomorrow" }),
        serde_json::json!({ "decision": "approve", "expires_at": "1970-01-01T00:16:40Z" }),
        serde_json::json!({ "decision": "approve", "expires_at": "1970-01-01T00:10:00Z" }),
        serde_json::json!({ "decision": "deny", "expires_at": "1970-01-01T00:20:00Z" }),
    ] {
        let refused = fixture
            .server
            .handle(&approver(&path, body.clone(), [3; 32]));
        assert_eq!(refused.status(), 400, "{body}");
        assert_eq!(error_of(&refused), "invalid_request", "{body}");
        let poll = fixture.server.handle(&signed(
            &fixture.owner,
            "GET",
            &format!("/mission/proposal/{proposal}"),
            None,
        ));
        assert_eq!(poll.status(), 202, "{body}");
    }
    let approved = fixture.server.handle(&approver(
        &path,
        serde_json::json!({ "decision": "approve", "expires_at": "1970-01-01T00:20:00Z" }),
        [3; 32],
    ));
    assert_eq!(approved.status(), 200, "{}", error_of(&approved));
    let poll = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(poll.status(), 200, "{}", error_of(&poll));
    let body = json_body(&poll);
    let mission = aauth_rust_core::ApprovedMission::decode(
        body["s256"].as_str().unwrap(),
        body["mission"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(mission.approved_at(), 1000);
    assert_eq!(mission.expires_at(), Some(1200));
    let blob: Value = serde_json::from_slice(mission.exact_json()).unwrap();
    assert_eq!(blob["expires_at"], "1970-01-01T00:20:00Z");
    // Without one, the mission runs until it is completed or revoked.
    let open = approve(&fixture, &propose(&fixture, "draft another note"));
    let open = aauth_rust_core::ApprovedMission::decode(
        open["s256"].as_str().unwrap(),
        open["mission"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(open.expires_at(), None);
}

#[test]
fn mission_actions_reject_a_missing_or_unknown_action() {
    let fixture = fixture(true);
    let approved = approve(&fixture, &propose(&fixture, "draft the note"));
    let path = format!("/mission/{}", approved["s256"].as_str().unwrap());
    let missing = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &path,
        Some(serde_json::json!({})),
    ));
    assert_eq!(missing.status(), 400);
    assert_eq!(error_of(&missing), "invalid_request");
    let unknown = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &path,
        Some(serde_json::json!({ "action": "nope" })),
    ));
    assert_eq!(unknown.status(), 400);
    assert_eq!(error_of(&unknown), "invalid_request");
    let audit = fixture
        .server
        .handle(&signed(&fixture.owner, "GET", &path, None));
    assert_eq!(audit.status(), 200);
    assert_eq!(json_body(&audit)["mission"], approved["mission"]);
    assert!(json_body(&audit).get("mission_status").is_none());
}

#[test]
fn update_requires_description_and_audit_returns_the_same_blob() {
    let fixture = fixture(true);
    let approved = approve(&fixture, &propose(&fixture, "draft the note"));
    let s256 = approved["s256"].as_str().unwrap();
    let path = format!("/mission/{s256}");
    let missing = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &path,
        Some(serde_json::json!({ "action": "update" })),
    ));
    assert_eq!(missing.status(), 400);
    assert_eq!(error_of(&missing), "invalid_request");
    let updated = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &path,
        Some(serde_json::json!({ "action": "update", "description": "add the appendix" })),
    ));
    assert_eq!(updated.status(), 200, "{}", error_of(&updated));
    let update_s256 = json_body(&updated)["s256"].as_str().unwrap().to_owned();
    assert_ne!(update_s256, s256);
    let audit = fixture
        .server
        .handle(&signed(&fixture.owner, "GET", &path, None));
    assert_eq!(audit.status(), 200, "{}", error_of(&audit));
    let audit = json_body(&audit);
    assert_eq!(audit["s256"], s256);
    assert_eq!(audit["mission"], approved["mission"]);
    assert_eq!(audit["updates"][0]["s256"], update_s256);
    let update_bytes = URL_SAFE_NO_PAD
        .decode(audit["updates"][0]["encoded"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(&update_bytes)),
        update_s256
    );
    // The persisted entry is the update object itself, `action` included, so
    // any reader decodes it as an update.
    assert_eq!(
        update_bytes,
        br#"{"action":"update","description":"add the appendix"}"#
    );
    let update_json: Value = serde_json::from_slice(&update_bytes).unwrap();
    assert_eq!(update_json["action"], "update");
    assert_eq!(update_json["description"], "add the appendix");
    let unknown = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        "/mission/unknown-mission",
        None,
    ));
    let wrong_owner = fixture
        .server
        .handle(&signed(&fixture.other, "GET", &path, None));
    assert_eq!(unknown.status(), wrong_owner.status());
    assert_eq!(unknown.headers(), wrong_owner.headers());
    assert_eq!(unknown.body(), wrong_owner.body());
    assert_eq!(unknown.status(), 404);
    assert_eq!(error_of(&unknown), "mission_not_found");
}

#[test]
fn completion_requires_summary_and_terminates() {
    let fixture = fixture(true);
    let approved = approve(&fixture, &propose(&fixture, "draft the note"));
    let path = format!("/mission/{}", approved["s256"].as_str().unwrap());
    let missing = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &path,
        Some(serde_json::json!({ "action": "completion" })),
    ));
    assert_eq!(missing.status(), 400);
    assert_eq!(error_of(&missing), "invalid_request");
    let completed = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &path,
        Some(serde_json::json!({ "action": "completion", "summary": "the note is filed" })),
    ));
    assert_eq!(completed.status(), 200, "{}", error_of(&completed));
    assert_eq!(json_body(&completed)["termination_reason"], "completed");
    let again = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &path,
        Some(serde_json::json!({ "action": "update", "description": "too late" })),
    ));
    assert_eq!(again.status(), 403);
    assert_eq!(error_of(&again), "mission_terminated");
    assert_eq!(json_body(&again)["termination_reason"], "completed");
    let audit = json_body(
        &fixture
            .server
            .handle(&signed(&fixture.owner, "GET", &path, None)),
    );
    assert_eq!(audit["mission"], approved["mission"]);
    assert_eq!(audit["termination_reason"], "completed");
    let summary_bytes = URL_SAFE_NO_PAD
        .decode(audit["summary"]["encoded"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        summary_bytes,
        br#"{"action":"completion","summary":"the note is filed"}"#
    );
    assert_eq!(
        audit["summary"]["s256"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(&summary_bytes))
    );
}

#[test]
fn child_agent_token_does_not_open_a_mission() {
    let fixture = fixture(true);
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let parent = issue(&ap, [2; 32], "aauth:Agent@ap.example", "parent-mission");
    let child_key = SigningKey::from_seed([4; 32]);
    let child = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:Agent+worker@ap.example".into(),
        jti: "child-mission".into(),
        iat: 1000,
        exp: 2000,
        cnf: Confirmation {
            jwk: child_key.public_jwk(),
        },
        ps: Some("https://ps.example".into()),
        parent_agent: Some("aauth:Agent@ap.example".into()),
        nbf: None,
        extra: Default::default(),
    };
    let compact = ap.issue_subagent(&child, parent.token(), 1000).unwrap();
    let child = Agent::new(child_key, compact).unwrap();
    let response = fixture.server.handle(&signed(
        &child,
        "POST",
        "/mission",
        Some(serde_json::json!({ "description": "a child must not propose" })),
    ));
    assert_eq!(response.status(), 401, "{}", error_of(&response));
    assert_eq!(error_of(&response), "invalid_jwt");
    assert_eq!(propose(&fixture, "the parent still proposes").len(), 22);
}

struct PauseStore {
    inner: MemoryStore,
    writes: Arc<AtomicUsize>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl Store for PauseStore {
    fn missions(&self) -> Option<&dyn MissionStore> {
        self.inner.missions()
    }
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        self.inner.binding(issuer, agent)
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        self.inner.token(reference)
    }
    fn commit(&self, record: TokenRecord, establish_binding: bool) -> Result<(), StoreError> {
        self.inner.commit(record, establish_binding)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        self.inner.revoke_binding(issuer, agent)
    }
    fn retained(&self) -> Result<Vec<TokenRecord>, StoreError> {
        self.inner.retained()
    }
    fn write_mission_audit(&self, audit: &MissionAudit) -> Result<(), StoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let (lock, cv) = &*self.release;
        let guard = lock.lock().unwrap_or_else(|poison| poison.into_inner());
        let (guard, _) = cv
            .wait_timeout_while(guard, Duration::from_secs(2), |ready| !*ready)
            .unwrap_or_else(|poison| poison.into_inner());
        drop(guard);
        self.inner.write_mission_audit(audit)
    }
    fn read_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
    ) -> Result<Option<MissionAudit>, StoreError> {
        self.inner
            .read_mission_audit(person_server, owner_issuer, owner_subject, s256)
    }
    fn edit_mission_audit(
        &self,
        person_server: &str,
        owner_issuer: &str,
        owner_subject: &str,
        s256: &str,
        edit: MissionEdit,
    ) -> Result<MissionAudit, MissionAuditError> {
        self.inner
            .edit_mission_audit(person_server, owner_issuer, owner_subject, s256, edit)
    }
}

#[test]
fn simultaneous_approvals_write_one_audit() {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    let owner = issue(&ap, [2; 32], "aauth:Agent@ap.example", "agent-1");
    let writes = Arc::new(AtomicUsize::new(0));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let ids = Arc::new(AtomicUsize::new(0));
    let server = Arc::new(
        PersonServer::new(
            Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
            keys,
            PauseStore {
                inner: MemoryStore::default(),
                writes: Arc::clone(&writes),
                release: Arc::clone(&release),
            },
            Host,
            Box::new(|| 1000i64) as BoxedClock,
            Box::new({
                let ids = Arc::clone(&ids);
                move || format!("proposal-{}", ids.fetch_add(1, Ordering::SeqCst))
            }) as BoxedTokenIds,
        )
        .unwrap()
        .with_missions(),
    );
    let created = server.handle(&signed(
        &owner,
        "POST",
        "/mission",
        Some(serde_json::json!({ "description": "draft the note" })),
    ));
    assert_eq!(created.status(), 202, "{}", error_of(&created));
    let proposal = created.headers()["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let path = format!("/mission/proposal/{proposal}/approval");
    let first = approver(&path, serde_json::json!({ "decision": "approve" }), [3; 32]);
    let second = approver(&path, serde_json::json!({ "decision": "approve" }), [3; 32]);
    let server_a = Arc::clone(&server);
    let (tx_a, rx_a) = mpsc::channel();
    thread::spawn(move || {
        let response = server_a.handle(&first);
        let _ = tx_a.send((response.status().as_u16(), error_of(&response)));
    });
    let started = Instant::now();
    while writes.load(Ordering::SeqCst) < 1 {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "first approval did not reach the audit write"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let server_b = Arc::clone(&server);
    let (tx_b, rx_b) = mpsc::channel();
    thread::spawn(move || {
        let response = server_b.handle(&second);
        let _ = tx_b.send((response.status().as_u16(), error_of(&response)));
    });
    let (status_b, error_b) = rx_b
        .recv_timeout(Duration::from_millis(800))
        .expect("second approval blocked inside the audit write");
    assert_eq!(status_b, 404, "{error_b}");
    assert_eq!(error_b, "mission_not_found");
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    {
        let (lock, cv) = &*release;
        let mut ready = lock.lock().unwrap_or_else(|poison| poison.into_inner());
        *ready = true;
        cv.notify_all();
    }
    let (status_a, error_a) = rx_a.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(status_a, 200, "{error_a}");
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    let poll = server.handle(&signed(
        &owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(poll.status(), 200, "{}", error_of(&poll));
    let again = server.handle(&signed(
        &owner,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    assert_eq!(again.status(), 410);
    assert_eq!(error_of(&again), "gone");
}

fn same_response(left: &Response<Vec<u8>>, right: &Response<Vec<u8>>) {
    assert_eq!(left.status(), right.status());
    assert_eq!(left.headers(), right.headers());
    assert_eq!(left.body(), right.body());
}

#[test]
fn missing_and_unowned_missions_match_and_auth_precedes_lookup() {
    let fixture = fixture(true);
    let proposal = propose(&fixture, "draft the note");
    let stranger_poll = fixture.server.handle(&signed(
        &fixture.other,
        "GET",
        &format!("/mission/proposal/{proposal}"),
        None,
    ));
    let missing_poll = fixture.server.handle(&signed(
        &fixture.owner,
        "GET",
        "/mission/proposal/no-such-proposal",
        None,
    ));
    same_response(&stranger_poll, &missing_poll);
    assert_eq!(stranger_poll.status(), 404);
    assert_eq!(error_of(&stranger_poll), "mission_not_found");

    let approved = approve(&fixture, &proposal);
    let s256 = approved["s256"].as_str().unwrap();
    let body = serde_json::json!({ "action": "update", "description": "add the appendix" });
    let stranger_post = fixture.server.handle(&signed(
        &fixture.other,
        "POST",
        &format!("/mission/{s256}"),
        Some(body.clone()),
    ));
    let missing_post = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        "/mission/no-such-mission",
        Some(body),
    ));
    same_response(&stranger_post, &missing_post);
    assert_eq!(stranger_post.status(), 404);
    assert_eq!(error_of(&stranger_post), "mission_not_found");

    let bad_existing = Request::builder()
        .method("GET")
        .uri(format!("https://ps.example/mission/proposal/{proposal}"))
        .body(Vec::new())
        .unwrap();
    let bad_missing = Request::builder()
        .method("GET")
        .uri("https://ps.example/mission/proposal/no-such-proposal")
        .body(Vec::new())
        .unwrap();
    let existing = fixture.server.handle(&bad_existing);
    let missing = fixture.server.handle(&bad_missing);
    same_response(&existing, &missing);
    assert_eq!(existing.status(), 401);
    assert_ne!(error_of(&existing), "mission_not_found");

    let approval = serde_json::json!({ "decision": "approve" });
    let bad_approval_existing = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        &format!("/mission/proposal/{proposal}/approval"),
        Some(approval.clone()),
    ));
    let bad_approval_missing = fixture.server.handle(&signed(
        &fixture.owner,
        "POST",
        "/mission/proposal/no-such-proposal/approval",
        Some(approval),
    ));
    same_response(&bad_approval_existing, &bad_approval_missing);
    assert_eq!(bad_approval_existing.status(), 401);
    assert_ne!(error_of(&bad_approval_existing), "mission_not_found");
}
