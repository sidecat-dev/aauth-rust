//! Real TLS three-party authorization and one Orders-to-Inventory chained POST.
#[path = "../support/tls.rs"]
mod tls;

use aauth_rust_agent::{Agent, Requirement};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, Confirmation, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
    metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonRequest,
    PersonServer, Policy, PolicyError, Store,
};
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tls::TlsServer;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PS: &str = "https://ps.example";
const ORDERS: &str = "https://orders.example";
const INVENTORY: &str = "https://inventory.example";

/// Observable application result, asserted by the integration test.
pub struct Transcript {
    pub unsigned_status: u16,
    pub person_challenge_status: u16,
    pub tampered_status: u16,
    pub authorized_status: u16,
    pub order_count: usize,
    pub inventory_count: usize,
    pub upstream_subject: String,
    pub downstream_subject: String,
    pub upstream_expiry: i64,
    pub downstream_expiry: i64,
    pub intermediary_has_binding: bool,
    pub untrusted_tls_refused: bool,
}

// Only this fixed demonstration's explicitly admitted issuers are inserted.
// An Internet service also supplies deadlines, egress admission and refresh.
#[derive(Clone, Default)]
struct Trust(Arc<RwLock<BTreeMap<(String, String), TrustedIssuerKeys>>>);
impl AgentKeyResolver for Trust {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> std::result::Result<Jwk, TokenError> {
        self.0
            .read()
            .map_err(|_| TokenError::InvalidKey)?
            .get(&(issuer.into(), dwk.into()))
            .ok_or(TokenError::UntrustedIssuer)?
            .key(issuer, dwk, kid)
    }
}
impl Trust {
    fn discover(&self, server: &TlsServer, issuer: &str, dwk: &str) -> Result<()> {
        let metadata = server.send(&get(&format!("{issuer}/.well-known/{dwk}"))?)?;
        if metadata.status() != 200 {
            return Err("metadata discovery failed".into());
        }
        let uri = metadata_jwks_uri(issuer, metadata.body())?;
        let jwks = server.send(&get(&uri)?)?;
        if jwks.status() != 200 {
            return Err("JWKS discovery failed".into());
        }
        let snapshot =
            TrustedIssuerKeys::from_documents(issuer, dwk, metadata.body(), jwks.body())?;
        self.0
            .write()
            .map_err(|_| "trust snapshot lock poisoned")?
            .insert((issuer.into(), dwk.into()), snapshot);
        Ok(())
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_secs() as i64
}
fn get(uri: &str) -> Result<Request<Vec<u8>>> {
    Ok(Request::builder().uri(uri).body(Vec::new())?)
}
fn json_response(status: u16, value: Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .unwrap()
}
fn json_document(bytes: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .header("content-type", "application/json")
        .body(bytes)
        .unwrap()
}
fn signed(agent: &Agent, uri: &str, value: Value) -> Result<Request<Vec<u8>>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&value)?)?;
    agent.sign(&mut request, now())?;
    Ok(request)
}
fn successful(response: Response<Vec<u8>>) -> Result<Value> {
    if response.status() != 200 {
        return Err(format!("protocol operation refused with HTTP{}", response.status()).into());
    }
    Ok(serde_json::from_slice(response.body())?)
}
fn token_from(value: &Value, member: &str) -> Result<String> {
    Ok(value
        .get(member)
        .and_then(Value::as_str)
        .ok_or("successful response omitted token")?
        .to_owned())
}
fn resource_challenge(response: &Response<Vec<u8>>) -> Result<String> {
    if response.status() != 401 {
        return Err("this immediate flow requires a 401 challenge".into());
    }
    match Requirement::from_headers(response.headers())? {
        Some(Requirement::AuthToken { resource_token }) => Ok(resource_token),
        _ => Err("expected an auth-token Resource challenge".into()),
    }
}
fn enrolled(
    provider: &AgentProvider,
    issuer: &str,
    subject: &str,
    ps: &str,
    jti: &str,
) -> Result<Agent> {
    let key = SigningKey::generate();
    let issued = now();
    let token = provider.issue(&AgentClaims {
        iss: issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: subject.into(),
        jti: jti.into(),
        iat: issued,
        exp: issued + 1800,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: Some(ps.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    Ok(Agent::new(key, token)?)
}

struct HostPolicy;
fn directed(resource: &str) -> std::result::Result<Person, PolicyError> {
    // Demonstration of host-owned, stable pairwise identifiers for one already
    // authenticated person. A real host persists this mapping across restarts.
    let subject = match resource {
        ORDERS => "orders-pairwise-person",
        INVENTORY => "inventory-pairwise-person",
        _ => return Err(PolicyError::Denied),
    };
    Ok(Person {
        id: "host-internal-person".into(),
        subject: subject.into(),
        tenant: None,
    })
}
impl Policy for HostPolicy {
    fn bind_person(&self, request: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        if request.agent.claims().sub != "aauth:customer@ap.example" || request.resource != ORDERS {
            return Err(PolicyError::Denied);
        }
        directed(&request.resource)
    }
    fn authorize(&self, request: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        if request.resource.claims().iss != ORDERS || request.scopes != ["orders.write"] {
            return Err(PolicyError::Denied);
        }
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn bind_upstream(&self, request: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        let upstream = request.upstream.as_ref().ok_or(PolicyError::Denied)?;
        if request.resource != INVENTORY
            || upstream.record.resource != ORDERS
            || upstream.record.person_id != "host-internal-person"
        {
            return Err(PolicyError::Denied);
        }
        directed(&request.resource)
    }
    fn authorize_upstream(
        &self,
        request: &AuthorizationRequest,
    ) -> std::result::Result<Grant, PolicyError> {
        let upstream = request.upstream.as_ref().ok_or(PolicyError::Denied)?;
        if request.resource.claims().iss != INVENTORY
            || request.scopes != ["inventory.reserve"]
            || upstream.scope.as_deref() != Some("orders.write")
        {
            return Err(PolicyError::Denied);
        }
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
}

fn downstream(
    agent: &Agent,
    ps: &TlsServer,
    inventory: &TlsServer,
    trust: &Trust,
    upstream: &str,
) -> Result<(Value, VerifiedAuthToken)> {
    let person = token_from(
        &successful(ps.send(&signed(
            agent,
            &format!("{PS}/person"),
            json!({"resource":INVENTORY,"upstream_token":upstream}),
        )?)?)?,
        "person_token",
    )?;
    let holder = agent.with_token(person.clone())?;
    let request = signed(
        &holder,
        &format!("{INVENTORY}/reserve"),
        json!({"item":"tree","quantity":2}),
    )?;
    let challenge = inventory.send(&request)?;
    let resource = resource_challenge(&challenge)?;
    let verified =
        agent.verify_resource_challenge(&resource, INVENTORY, PS, &person, trust, now())?;
    let auth = token_from(
        &successful(ps.send(&signed(
            agent,
            &format!("{PS}/token"),
            json!({"resource_token":resource,"presented_token":person,"upstream_token":upstream}),
        )?)?)?,
        "auth_token",
    )?;
    let verified_auth =
        agent.verify_auth_delivery(&auth, INVENTORY, &verified, &person, trust, now())?;
    let holder = agent.with_token(auth)?;
    let response = inventory.send(&signed(
        &holder,
        &format!("{INVENTORY}/reserve"),
        json!({"item":"tree","quantity":2}),
    )?)?;
    Ok((successful(response)?, verified_auth))
}

pub fn run() -> Result<Transcript> {
    run_requests(1)
}

#[cfg(test)]
pub fn run_replayed() -> Result<Transcript> {
    run_requests(2)
}

fn run_requests(authorized_requests: usize) -> Result<Transcript> {
    let trust = Trust::default();
    let provider = Arc::new(AgentProvider::new(
        "https://ap.example",
        "ap-1",
        SigningKey::generate(),
    )?);
    let agent = enrolled(
        &provider,
        "https://ap.example",
        "aauth:customer@ap.example",
        PS,
        "agent-1",
    )?;
    let serving = provider.clone();
    let ap_tls = TlsServer::start("ap.example", move |req| match req.uri().path() {
        "/.well-known/aauth-agent.json" => json_document(serving.metadata().unwrap()),
        "/.well-known/jwks.json" => json_document(serving.jwks().unwrap()),
        _ => json_response(404, json!({"error":"not_found"})),
    })?;
    trust.discover(&ap_tls, "https://ap.example", "aauth-agent.json")?;

    let store = MemoryStore::default();
    let stored = store.clone();
    let ids = AtomicUsize::new(0);
    let ps = PersonServer::new(
        Config::new(PS, "ps-1", SigningKey::generate()),
        trust.clone(),
        store,
        HostPolicy,
        now,
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )?;
    let ps_tls = Arc::new(TlsServer::start("ps.example", move |request| {
        ps.handle(&request)
    })?);
    trust.discover(&ps_tls, PS, "aauth-person.json")?;

    let inventory_count = Arc::new(AtomicUsize::new(0));
    let inventory_effects = inventory_count.clone();
    let inventory = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: INVENTORY.into(),
            signed_origin: INVENTORY.into(),
            kid: "inventory-resource-1".into(),
            signing_key: SigningKey::generate(),
            scopes: vec!["inventory.reserve".into()],
            scope_descriptions: BTreeMap::from([(
                "inventory.reserve".into(),
                "Reserve inventory".into(),
            )]),
        },
        trust.clone(),
        |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true,
    )?;
    let inventory_ids = AtomicUsize::new(0);
    let inventory_tls = Arc::new(TlsServer::start("inventory.example", move |request| {
        match request.uri().path() {
            "/.well-known/aauth-resource.json" => {
                return json_document(inventory.metadata().unwrap());
            }
            "/.well-known/jwks.json" => return json_document(inventory.jwks().unwrap()),
            _ => {}
        }
        match inventory
            .authorize(
                &request,
                now(),
                &format!("inventory-{}", inventory_ids.fetch_add(1, Ordering::SeqCst)),
            )
            .into_result()
        {
            Ok((_token, ())) => {
                if request.method() != "POST"
                    || request.uri().path() != "/reserve"
                    || request.body() != br#"{"item":"tree","quantity":2}"#
                {
                    return json_response(400, json!({"error":"invalid_order"}));
                }
                inventory_effects.fetch_add(1, Ordering::SeqCst);
                json_response(200, json!({"reserved":2}))
            }
            Err(response) => *response,
        }
    })?);
    trust.discover(&inventory_tls, INVENTORY, "aauth-resource.json")?;

    let intermediary_ap = Arc::new(AgentProvider::new(
        ORDERS,
        "orders-agent-1",
        SigningKey::generate(),
    )?);
    let intermediary = enrolled(
        &intermediary_ap,
        ORDERS,
        "aauth:orders@orders.example",
        "https://intermediary-person.example",
        "intermediary-1",
    )?;
    let orders = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: ORDERS.into(),
            signed_origin: ORDERS.into(),
            kid: "orders-resource-1".into(),
            signing_key: SigningKey::generate(),
            scopes: vec!["orders.write".into()],
            scope_descriptions: BTreeMap::from([("orders.write".into(), "Place orders".into())]),
        },
        trust.clone(),
        |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true,
    )?;
    // Both default role documents name this origin's same JWKS URL. Publish all
    // role keys together under unique kids; serving either role's set alone
    // would make the other role unverifiable. See the service guide's JWKS section.
    let mut combined_keys: Value = serde_json::from_slice(&orders.jwks()?)?;
    let ap_keys: Value = serde_json::from_slice(&intermediary_ap.jwks()?)?;
    combined_keys["keys"]
        .as_array_mut()
        .unwrap()
        .extend(ap_keys["keys"].as_array().unwrap().iter().cloned());
    let combined_keys = serde_json::to_vec(&combined_keys)?;
    let order_count = Arc::new(AtomicUsize::new(0));
    let order_effects = order_count.clone();
    let ps_client = ps_tls.clone();
    let inventory_client = inventory_tls.clone();
    let call_trust = trust.clone();
    let orders_ids = AtomicUsize::new(0);
    let orders_tls = TlsServer::start("orders.example", move |request| {
        match request.uri().path() {
            "/.well-known/aauth-resource.json" => return json_document(orders.metadata().unwrap()),
            "/.well-known/aauth-agent.json" => {
                return json_document(intermediary_ap.metadata().unwrap());
            }
            "/.well-known/jwks.json" => return json_document(combined_keys.clone()),
            _ => {}
        }
        let (upstream, ()) = match orders
            .authorize(
                &request,
                now(),
                &format!("orders-{}", orders_ids.fetch_add(1, Ordering::SeqCst)),
            )
            .into_result()
        {
            Ok(value) => value,
            Err(response) => return *response,
        };
        match downstream(
            &intermediary,
            &ps_client,
            &inventory_client,
            &call_trust,
            upstream.compact(),
        ) {
            Ok((inventory, auth)) => {
                order_effects.fetch_add(1, Ordering::SeqCst);
                json_response(
                    200,
                    json!({"order":"accepted","inventory":inventory,"upstream_sub":upstream.claims().sub,"downstream_sub":auth.claims().sub,"upstream_exp":upstream.claims().exp,"downstream_exp":auth.claims().exp}),
                )
            }
            Err(error) => json_response(
                500,
                json!({"error":"downstream_failed","detail":error.to_string()}),
            ),
        }
    })?;
    trust.discover(&orders_tls, ORDERS, "aauth-resource.json")?;
    trust.discover(&orders_tls, ORDERS, "aauth-agent.json")?;

    let untrusted_tls_refused = orders_tls.refuses_untrusted_certificate();
    let unsigned = orders_tls.send(&get(&format!("{ORDERS}/orders"))?)?;
    let person = token_from(
        &successful(ps_tls.send(&signed(
            &agent,
            &format!("{PS}/person"),
            json!({"resource":ORDERS}),
        )?)?)?,
        "person_token",
    )?;
    let holder = agent.with_token(person.clone())?;
    let person_challenge = orders_tls.send(&signed(
        &holder,
        &format!("{ORDERS}/orders"),
        json!({"item":"tree","quantity":2}),
    )?)?;
    let resource = resource_challenge(&person_challenge)?;
    let verified =
        agent.verify_resource_challenge(&resource, ORDERS, PS, &person, &trust, now())?;
    let auth = token_from(
        &successful(ps_tls.send(&signed(
            &agent,
            &format!("{PS}/token"),
            json!({"resource_token":resource,"presented_token":person}),
        )?)?)?,
        "auth_token",
    )?;
    agent.verify_auth_delivery(&auth, ORDERS, &verified, &person, &trust, now())?;
    let holder = agent.with_token(auth)?;
    let request = signed(
        &holder,
        &format!("{ORDERS}/orders"),
        json!({"item":"tree","quantity":2}),
    )?;
    let mut tampered = request.clone();
    *tampered.body_mut() = br#"{"item":"tree","quantity":200}"#.to_vec();
    let tampered_response = orders_tls.send(&tampered)?;
    let response = orders_tls.send(&request)?;
    let authorized_status = response.status().as_u16();
    let result = successful(response)?;
    // Deliberately no host idempotency: reuse these exact signed bytes, including
    // the holder credential and proof. Every accepted request repeats the chain.
    for _ in 1..authorized_requests {
        successful(orders_tls.send(&request)?)?;
    }
    let intermediary_has_binding = stored
        .binding(
            PS,
            &AgentIdentity {
                issuer: ORDERS.into(),
                subject: "aauth:orders@orders.example".into(),
            },
        )?
        .is_some();
    Ok(Transcript {
        unsigned_status: unsigned.status().as_u16(),
        person_challenge_status: person_challenge.status().as_u16(),
        tampered_status: tampered_response.status().as_u16(),
        authorized_status,
        order_count: order_count.load(Ordering::SeqCst),
        inventory_count: inventory_count.load(Ordering::SeqCst),
        upstream_subject: result["upstream_sub"]
            .as_str()
            .ok_or("missing upstream subject")?
            .into(),
        downstream_subject: result["downstream_sub"]
            .as_str()
            .ok_or("missing downstream subject")?
            .into(),
        upstream_expiry: result["upstream_exp"]
            .as_i64()
            .ok_or("missing upstream expiry")?,
        downstream_expiry: result["downstream_exp"]
            .as_i64()
            .ok_or("missing downstream expiry")?,
        intermediary_has_binding,
        untrusted_tls_refused,
    })
}
