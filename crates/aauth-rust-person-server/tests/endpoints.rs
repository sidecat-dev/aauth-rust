use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AgentProviderKeys, AuthToken, Confirmation, PersonToken,
    ResourceClaims, TokenError, TrustedIssuerKeys, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy,
    PolicyError, Store,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicUsize, Ordering},
};

struct Keys {
    ap: AgentProviderKeys,
    resource: Jwk,
}
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if issuer == "https://resource.example"
            && dwk == "aauth-resource.json"
            && kid == "resource-1"
        {
            return Ok(self.resource.clone());
        }
        self.ap.key(issuer, dwk, kid)
    }
}
struct Host {
    bound: Arc<AtomicUsize>,
    authorized: Arc<AtomicUsize>,
    now: Arc<AtomicI64>,
    late: bool,
}
impl Policy for Host {
    fn bind_person(&self, req: &PersonRequest) -> Result<Person, PolicyError> {
        self.bound.fetch_add(1, Ordering::SeqCst);
        Ok(Person {
            id: "internal-person".into(),
            subject: format!("directed-{}", req.resource),
            tenant: Some("tenant-1".into()),
        })
    }
    fn authorize(&self, req: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.authorized.fetch_add(1, Ordering::SeqCst);
        if self.late {
            self.now.store(2000, Ordering::SeqCst);
        }
        if req.scopes.iter().any(|s| s == "admin") {
            return Err(PolicyError::Denied);
        }
        Ok(Grant {
            scopes: req.scopes.clone(),
            lifetime: 3600,
        })
    }
}
fn agent() -> (Agent, AgentProviderKeys) {
    let ap =
        AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32])).unwrap();
    let key = SigningKey::from_seed([2; 32]);
    let token = ap
        .issue(&AgentClaims {
            iss: "https://ap.example".into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:Agent@ap.example".into(),
            jti: "agent-1".into(),
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
    let keys = AgentProviderKeys::from_documents(
        "https://ap.example",
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    (Agent::new(key, token).unwrap(), keys)
}
fn signed(agent: &Agent, path: &str, body: Value) -> Request<Vec<u8>> {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("https://ps.example{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut req, 1000).unwrap();
    req
}
fn value(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap()
}
fn resource(agent: &Agent, person: &str, scope: &str) -> String {
    let person = PersonToken::parse(person).unwrap();
    let p = person.unverified_claims();
    mint_resource_token(
        &SigningKey::from_seed([4; 32]),
        "resource-1",
        &ResourceClaims {
            iss: "https://resource.example".into(),
            dwk: "aauth-resource.json".into(),
            aud: "https://ps.example".into(),
            sub: p.sub.clone(),
            jti: "resource-1".into(),
            iat: 1000,
            exp: 1300,
            ps: p.iss.clone(),
            presented_jti: p.jti.clone(),
            agent_jkt: agent.public_jwk().thumbprint().unwrap(),
            nbf: None,
            tenant: p.tenant.clone(),
            mission_s256: None,
            scope: Some(scope.into()),
            account: None,
            login_hint: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}

#[test]
fn person_binding_and_direct_grant_retain_identity_and_clip_parent_expiry() {
    let (agent, ap) = agent();
    let store = MemoryStore::default();
    let bound = Arc::new(AtomicUsize::new(0));
    let authorized = Arc::new(AtomicUsize::new(0));
    let now = Arc::new(AtomicI64::new(1000));
    let ids = AtomicUsize::new(0);
    let clock = now.clone();
    let server = PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
        Keys {
            ap,
            resource: SigningKey::from_seed([4; 32]).public_jwk(),
        },
        store.clone(),
        Host {
            bound: bound.clone(),
            authorized: authorized.clone(),
            now,
            late: false,
        },
        move || clock.load(Ordering::SeqCst),
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap();
    let person_response = server.handle(&signed(
        &agent,
        "/person",
        json!({"resource":"https://resource.example"}),
    ));
    assert_eq!(
        person_response.status(),
        200,
        "{}",
        String::from_utf8_lossy(person_response.body())
    );
    assert_eq!(person_response.headers()["cache-control"], "no-store");
    let published: Value = serde_json::from_slice(&server.metadata()).unwrap();
    assert_eq!(
        published,
        json!({
            "issuer": "https://ps.example",
            "jwks_uri": "https://ps.example/.well-known/jwks.json",
            "person_token_endpoint": "https://ps.example/person",
            "auth_token_endpoint": "https://ps.example/token"
        })
    );
    let person = value(&person_response)["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let pskeys = TrustedIssuerKeys::from_documents(
        "https://ps.example",
        "aauth-person.json",
        &server.metadata(),
        &server.jwks(),
    )
    .unwrap();
    let verified = PersonToken::parse(&person)
        .unwrap()
        .verify(&pskeys, 1000)
        .unwrap();
    assert_eq!(verified.claims().exp, 2000);
    assert_eq!(value(&person_response)["expires_in"], 1000);
    let request = signed(
        &agent,
        "/token",
        json!({"resource_token":resource(&agent,&person,"read"),"presented_token":person}),
    );
    let response = server.handle(&request);
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let output = value(&response);
    let auth = AuthToken::parse(output["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&pskeys, 1000)
        .unwrap();
    assert_eq!(auth.claims().exp, 2000); // Not clipped to Resource-token exp1300.
    assert_eq!(auth.claims().scope.as_deref(), Some("read"));
    assert_eq!(auth.claims().sub, verified.claims().sub);
    assert_eq!(auth.claims().ps, "https://ps.example");
    assert_eq!(bound.load(Ordering::SeqCst), 1);
    assert_eq!(authorized.load(Ordering::SeqCst), 1);
    let reference = aauth_rust_person_server::TokenReference {
        issuer: auth.claims().iss.clone(),
        jti: auth.claims().jti.clone(),
    };
    let record = store.token(&reference).unwrap().unwrap();
    assert_eq!(record.person_id, "internal-person");
    assert!(record.presented.is_some());
}

#[test]
fn bad_proofs_targets_media_types_and_content_never_reach_binding_policy() {
    let (agent, ap) = agent();
    let count = Arc::new(AtomicUsize::new(0));
    let now = Arc::new(AtomicI64::new(1000));
    let server = PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
        Keys {
            ap,
            resource: SigningKey::from_seed([4; 32]).public_jwk(),
        },
        MemoryStore::default(),
        Host {
            bound: count.clone(),
            authorized: Arc::new(AtomicUsize::new(0)),
            now,
            late: false,
        },
        || 1000,
        || "person-1".into(),
    )
    .unwrap();
    let good = signed(
        &agent,
        "/person",
        json!({"resource":"https://resource.example"}),
    );
    let mut changed = good.clone();
    *changed.body_mut() = br#"{"resource":"https://attacker.example"}"#.to_vec();
    let refused = server.handle(&changed);
    assert_eq!(
        refused.headers()["signature-error"],
        "error=invalid_signature"
    );
    let problem: Value = serde_json::from_slice(refused.body()).unwrap();
    assert_eq!(
        problem["type"],
        "urn:ietf:params:sig-error:invalid_signature"
    );
    let mut foreign = good.clone();
    *foreign.uri_mut() = "https://other.example/person".parse().unwrap();
    agent.sign(&mut foreign, 1000).unwrap();
    assert_eq!(server.handle(&foreign).status(), 401);
    let mut no_type = good.clone();
    no_type.headers_mut().remove("content-type");
    agent.sign(&mut no_type, 1000).unwrap();
    let response = server.handle(&no_type);
    assert_eq!(response.status(), 401);
    assert!(
        response.headers()["signature-error"]
            .to_str()
            .unwrap()
            .contains("content-type")
    );
    let mut wrong_type = good;
    wrong_type
        .headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    agent.sign(&mut wrong_type, 1000).unwrap();
    assert_eq!(server.handle(&wrong_type).status(), 400);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn device_platform_capabilities_and_justification_are_not_grant_inputs() {
    let (agent, ap) = agent();
    let bound = Arc::new(AtomicUsize::new(0));
    let authorized = Arc::new(AtomicUsize::new(0));
    let ids = AtomicUsize::new(0);
    let server = PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
        Keys {
            ap,
            resource: SigningKey::from_seed([4; 32]).public_jwk(),
        },
        MemoryStore::default(),
        Host {
            bound: bound.clone(),
            authorized: authorized.clone(),
            now: Arc::new(AtomicI64::new(1000)),
            late: false,
        },
        || 1000,
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap();
    let refuse = |body: Value| {
        let response = server.handle(&signed(&agent, "/person", body));
        assert_eq!(
            response.status(),
            400,
            "{}",
            String::from_utf8_lossy(response.body())
        );
        assert_eq!(value(&response)["error"], "invalid_request");
    };
    refuse(json!({
        "resource": "https://resource.example",
        "device": "a".repeat(65)
    }));
    refuse(json!({
        "resource": "https://resource.example",
        "device": "line\n"
    }));
    refuse(json!({
        "resource": "https://resource.example",
        "platform": "browser"
    }));
    refuse(json!({
        "resource": "https://resource.example",
        "capabilities": ["interaction", "interaction"]
    }));
    refuse(json!({
        "resource": "https://resource.example",
        "capabilities": [""]
    }));
    refuse(json!({
        "resource": "https://resource.example",
        "capabilities": "interaction"
    }));
    assert_eq!(bound.load(Ordering::SeqCst), 0);
    let person_response = server.handle(&signed(
        &agent,
        "/person",
        json!({
            "resource": "https://resource.example",
            "device": "a".repeat(64),
            "platform": "self-hosted",
            "capabilities": ["interaction", "not-a-registered-capability"],
            "justification": "please grant admin"
        }),
    ));
    assert_eq!(
        person_response.status(),
        200,
        "{}",
        String::from_utf8_lossy(person_response.body())
    );
    assert_eq!(bound.load(Ordering::SeqCst), 1);
    let person = value(&person_response)["person_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = server.handle(&signed(
        &agent,
        "/token",
        json!({
            "resource_token": resource(&agent, &person, "read"),
            "presented_token": person,
            "justification": "grant admin",
            "platform": "web",
            "device": "desk"
        }),
    ));
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    let pskeys = TrustedIssuerKeys::from_documents(
        "https://ps.example",
        "aauth-person.json",
        &server.metadata(),
        &server.jwks(),
    )
    .unwrap();
    let auth = AuthToken::parse(value(&response)["auth_token"].as_str().unwrap())
        .unwrap()
        .verify(&pskeys, 1000)
        .unwrap();
    assert_eq!(auth.claims().scope.as_deref(), Some("read"));
    assert_eq!(authorized.load(Ordering::SeqCst), 1);
}

#[test]
fn person_endpoint_requires_an_https_origin_resource() {
    let (agent, ap) = agent();
    let bound = Arc::new(AtomicUsize::new(0));
    let server = PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::from_seed([3; 32])),
        Keys {
            ap,
            resource: SigningKey::from_seed([4; 32]).public_jwk(),
        },
        MemoryStore::default(),
        Host {
            bound: bound.clone(),
            authorized: Arc::new(AtomicUsize::new(0)),
            now: Arc::new(AtomicI64::new(1000)),
            late: false,
        },
        || 1000,
        || "person-1".into(),
    )
    .unwrap();
    let refuse = |resource: &str| {
        let response = server.handle(&signed(&agent, "/person", json!({"resource": resource})));
        assert_eq!(response.status(), 400, "{resource}");
        assert_eq!(value(&response)["error"], "invalid_request", "{resource}");
    };
    let missing = server.handle(&signed(&agent, "/person", json!({})));
    assert_eq!(missing.status(), 400);
    assert_eq!(value(&missing)["error"], "invalid_request");
    for resource in [
        "http://resource.example",
        "https://Resource.example",
        "https://resource.example/",
        "https://resource.example:443",
        "https://resource.example?x=1",
        "https://resource.example#x",
        "https://user@resource.example",
    ] {
        refuse(resource);
    }
    assert_eq!(bound.load(Ordering::SeqCst), 0);
    let response = server.handle(&signed(
        &agent,
        "/person",
        json!({"resource": "https://resource.example"}),
    ));
    assert_eq!(response.status(), 200);
    let pskeys = TrustedIssuerKeys::from_documents(
        "https://ps.example",
        "aauth-person.json",
        &server.metadata(),
        &server.jwks(),
    )
    .unwrap();
    let person = PersonToken::parse(value(&response)["person_token"].as_str().unwrap())
        .unwrap()
        .verify(&pskeys, 1000)
        .unwrap();
    assert_eq!(person.claims().aud, "https://resource.example");
    assert_eq!(bound.load(Ordering::SeqCst), 1);
}
