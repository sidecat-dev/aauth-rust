#![cfg(unix)]

use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonToken, ResourceClaims,
    TokenError, mint_resource_token,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, BoxedTokenIds, Config, Grant, Person, PersonRequest,
    PersonServer, Policy, PolicyError, Store, TokenReference,
};
use aauth_rust_person_server_redb::RedbStore;
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const PS: &str = "https://ps.example";
const ORDERS: &str = "https://orders.example";
const INVENTORY: &str = "https://inventory.example";
const NOW: i64 = 1000;
struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "ap") => 1,
            (PS, "aauth-person.json", "ps") => 3,
            (ORDERS, "aauth-agent.json" | "aauth-resource.json", "orders") => 4,
            (INVENTORY, "aauth-resource.json", "inventory") => 5,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}
#[derive(Default)]
struct Counts {
    binding: AtomicUsize,
    grant: AtomicUsize,
    chain: AtomicUsize,
}
struct Host(Arc<Counts>);
fn directed(resource: &str) -> Person {
    Person {
        id: "internal-person".into(),
        subject: if resource == ORDERS {
            "orders-person"
        } else {
            "inventory-person"
        }
        .into(),
        tenant: None,
    }
}
impl Policy for Host {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.0.binding.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.agent.claims().iss, "https://ap.example");
        Ok(directed(&request.resource))
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.0.grant.fetch_add(1, Ordering::SeqCst);
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn bind_upstream(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.0.chain.fetch_add(1, Ordering::SeqCst);
        assert!(request.binding.is_none());
        assert_eq!(
            request.upstream.as_ref().unwrap().record.person_id,
            "internal-person"
        );
        Ok(directed(&request.resource))
    }
    fn authorize_upstream(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.0.chain.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            request.upstream.as_ref().unwrap().scope.as_deref(),
            Some("orders.read")
        );
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 900,
        })
    }
}
type Server = PersonServer<Keys, RedbStore, Host, fn() -> i64, BoxedTokenIds>;
fn server(path: &Path, counts: &Arc<Counts>, epoch: &'static str) -> Server {
    let ids = AtomicUsize::new(0);
    PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        Keys,
        RedbStore::open(path).unwrap(),
        Host(counts.clone()),
        (|| NOW) as fn() -> i64,
        Box::new(move || format!("{epoch}-{}", ids.fetch_add(1, Ordering::SeqCst)))
            as BoxedTokenIds,
    )
    .unwrap()
}
fn agent(intermediary: bool) -> Agent {
    let (issuer, kid, provider_seed, holder_seed, subject) = if intermediary {
        (ORDERS, "orders", 4, 6, "aauth:Orders@orders.example")
    } else {
        ("https://ap.example", "ap", 1, 2, "aauth:Caller@ap.example")
    };
    let holder = SigningKey::from_seed([holder_seed; 32]);
    let compact = AgentProvider::new(issuer, kid, SigningKey::from_seed([provider_seed; 32]))
        .unwrap()
        .issue(&AgentClaims {
            iss: issuer.into(),
            dwk: "aauth-agent.json".into(),
            sub: subject.into(),
            jti: "agent-token".into(),
            iat: NOW,
            exp: 5000,
            cnf: Confirmation {
                jwk: holder.public_jwk(),
            },
            ps: Some(
                if intermediary {
                    "https://another-ps.example"
                } else {
                    PS
                }
                .into(),
            ),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    Agent::new(holder, compact).unwrap()
}
fn call(server: &Server, agent: &Agent, path: &str, body: Value) -> Response<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .unwrap();
    agent.sign(&mut request, NOW).unwrap();
    server.handle(&request)
}
fn output(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap()
}
fn compact(response: Response<Vec<u8>>, name: &str) -> String {
    assert_eq!(
        response.status(),
        200,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    output(&response)[name].as_str().unwrap().into()
}
fn challenge(agent: &Agent, presented: &str, scope: &str) -> String {
    let parsed = PersonToken::parse(presented).unwrap();
    let p = parsed.unverified_claims();
    let (seed, kid) = if p.aud == ORDERS {
        (4, "orders")
    } else {
        (5, "inventory")
    };
    mint_resource_token(
        &SigningKey::from_seed([seed; 32]),
        kid,
        &ResourceClaims {
            iss: p.aud.clone(),
            dwk: "aauth-resource.json".into(),
            aud: PS.into(),
            sub: p.sub.clone(),
            jti: "resource-challenge".into(),
            iat: NOW,
            exp: 1300,
            ps: PS.into(),
            presented_jti: p.jti.clone(),
            agent_jkt: agent.public_jwk().thumbprint().unwrap(),
            scope: Some(scope.into()),
            nbf: None,
            tenant: None,
            mission_s256: None,
            account: None,
            login_hint: None,
            extra: Default::default(),
        },
    )
    .unwrap()
}
fn principal() -> AgentIdentity {
    AgentIdentity {
        issuer: "https://ap.example".into(),
        subject: "aauth:Caller@ap.example".into(),
    }
}

#[test]
fn reconstructed_ps_exchanges_the_original_person_then_preserves_revocation_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let counts = Arc::new(Counts::default());
    let a = agent(false);
    let before = server(&path, &counts, "before");
    let person = compact(
        call(&before, &a, "/person", json!({"resource":ORDERS})),
        "person_token",
    );
    drop(before); // No store clones remain; the next open must acquire the file anew.
    let restored = server(&path, &counts, "restored");
    let resource = challenge(&a, &person, "orders.read");
    let request = json!({"resource_token":resource,"presented_token":person});
    let auth = compact(call(&restored, &a, "/token", request.clone()), "auth_token");
    let verified = AuthToken::parse(&auth).unwrap().verify(&Keys, NOW).unwrap();
    assert_eq!(verified.claims().aud, ORDERS);
    assert_eq!(verified.claims().scope.as_deref(), Some("orders.read"));
    assert_eq!(counts.binding.load(Ordering::SeqCst), 1);
    assert_eq!(counts.grant.load(Ordering::SeqCst), 1);
    drop(restored);
    let store = RedbStore::open(&path).unwrap();
    let record = store
        .token(&TokenReference {
            issuer: PS.into(),
            jti: verified.claims().jti.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(record.person_id, "internal-person");
    assert_eq!(
        record.presented.unwrap().reference.jti,
        PersonToken::parse(&person).unwrap().unverified_claims().jti
    );
    store.revoke_binding(PS, &principal()).unwrap();
    drop(store);
    let revoked = server(&path, &counts, "revoked");
    let response = call(&revoked, &a, "/token", request);
    assert_eq!(response.status(), 400);
    assert_eq!(output(&response)["error"], "revoked_presented_token");
    assert!(output(&response).get("auth_token").is_none());
    let response = call(&revoked, &a, "/person", json!({"resource":ORDERS}));
    assert_eq!(response.status(), 403);
    assert_eq!(output(&response)["error"], "denied");
    assert_eq!(counts.binding.load(Ordering::SeqCst), 1);
    assert_eq!(counts.grant.load(Ordering::SeqCst), 1);
}

#[test]
fn reconstructed_ps_chains_retained_original_authority_without_binding_the_intermediary() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let counts = Arc::new(Counts::default());
    let a = agent(false);
    let before = server(&path, &counts, "upstream");
    let person = compact(
        call(&before, &a, "/person", json!({"resource":ORDERS})),
        "person_token",
    );
    let upstream = compact(
        call(
            &before,
            &a,
            "/token",
            json!({"resource_token":challenge(&a,&person,"orders.read"),"presented_token":person}),
        ),
        "auth_token",
    );
    let original = AuthToken::parse(&upstream)
        .unwrap()
        .verify(&Keys, NOW)
        .unwrap();
    drop(before);
    let intermediary = agent(true);
    let restored = server(&path, &counts, "chain-person");
    let downstream = compact(
        call(
            &restored,
            &intermediary,
            "/person",
            json!({"resource":INVENTORY,"upstream_token":upstream}),
        ),
        "person_token",
    );
    drop(restored);
    let restored_again = server(&path, &counts, "chain-auth");
    let auth = compact(
        call(
            &restored_again,
            &intermediary,
            "/token",
            json!({"resource_token":challenge(&intermediary,&downstream,"inventory.write"),"presented_token":downstream,"upstream_token":upstream}),
        ),
        "auth_token",
    );
    let verified = AuthToken::parse(&auth).unwrap().verify(&Keys, NOW).unwrap();
    assert_eq!(verified.claims().aud, INVENTORY);
    assert_eq!(verified.claims().scope.as_deref(), Some("inventory.write"));
    assert_ne!(verified.claims().sub, original.claims().sub);
    assert!(verified.claims().exp <= original.claims().exp);
    assert_eq!(
        verified.claims().cnf.jwk.thumbprint().unwrap(),
        intermediary.public_jwk().thumbprint().unwrap()
    );
    drop(restored_again);
    let store = RedbStore::open(&path).unwrap();
    assert_eq!(
        store
            .binding(
                PS,
                &AgentIdentity {
                    issuer: ORDERS.into(),
                    subject: "aauth:Orders@orders.example".into()
                }
            )
            .unwrap(),
        None
    );
    let retained = store
        .token(&TokenReference {
            issuer: PS.into(),
            jti: verified.claims().jti.clone(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(retained.principal, principal());
    assert_eq!(retained.agent.issuer, ORDERS);
    assert_eq!(
        retained.upstream.unwrap().reference.jti,
        original.claims().jti
    );
    store.revoke_binding(PS, &principal()).unwrap();
    drop(store);
    let revoked = server(&path, &counts, "chain-revoked");
    let response = call(
        &revoked,
        &intermediary,
        "/person",
        json!({"resource":INVENTORY,"upstream_token":upstream}),
    );
    assert_eq!(response.status(), 400);
    assert_eq!(output(&response)["error"], "revoked_upstream_token");
    assert_eq!(counts.chain.load(Ordering::SeqCst), 2);
}
