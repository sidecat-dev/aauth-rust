//! Immediate four-party scope authorization over verified loopback TLS.
#[path = "../support/tls.rs"]
mod tls;
use aauth_rust_access_server::{
    AccessServer, Config as AccessConfig, Decision, PolicyError as AccessPolicyError,
};
use aauth_rust_agent::{Agent, FederatedContext, Requirement};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, Confirmation, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
    metadata_jwks_uri,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Federation, FederationError, Grant, MemoryStore, Person,
    PersonRequest, PersonServer, Policy, PolicyError, Store, TokenReference,
};
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest, sign_request};
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
const AS: &str = "https://as.example";
const ORDERS: &str = "https://orders.example";
/// Observed wire and application facts asserted by the integration test.
pub struct Transcript {
    pub unsigned_status: u16,
    pub challenge_status: u16,
    pub authorized_status: u16,
    pub tampered_status: u16,
    pub denied_status: u16,
    pub bad_delivery_status: u16,
    pub untrusted_ps_status: u16,
    pub effect_count: usize,
    pub auth_issuer: String,
    pub auth_document: String,
    pub subject: String,
    pub auth_expiry: i64,
    pub challenge_expiry: i64,
    pub ps_proof_verified: bool,
    pub as_token_retained: bool,
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
impl Policy for HostPolicy {
    fn bind_person(&self, r: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        // This fixture stands for a host-authenticated person's established mapping.
        // login_hint is never used to authenticate the person.
        if r.agent.claims().sub != "aauth:customer@ap.example" || r.resource != ORDERS {
            return Err(PolicyError::Denied);
        }
        Ok(Person {
            id: "internal-person".into(),
            subject: "orders-pairwise-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
    fn consent(&self, r: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        if r.resource.claims().iss == ORDERS
            && r.resource.claims().aud == AS
            && r.scopes == ["orders.write"]
        {
            Ok(())
        } else {
            Err(PolicyError::Denied)
        }
    }
}
struct AccessTransport {
    server: Arc<TlsServer>,
    endpoint: String,
}
impl Federation for AccessTransport {
    fn endpoint(&self, issuer: &str) -> std::result::Result<String, FederationError> {
        if issuer != AS {
            return Err(FederationError);
        }
        Ok(self.endpoint.clone())
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        self.server.send(request).map_err(|_| FederationError)
    }
}

/// Run one immediate grant, one POST effect and negative wire checks. Every TLS
/// server owns a bounded loopback listener and joins its thread when dropped.
pub fn run() -> Result<Transcript> {
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
    let ap_tls = TlsServer::start("ap.example", move |r| match r.uri().path() {
        "/.well-known/aauth-agent.json" => json_document(serving.metadata().unwrap()),
        "/.well-known/jwks.json" => json_document(serving.jwks().unwrap()),
        _ => json_response(404, json!({"error":"not_found"})),
    })?;
    trust.discover(&ap_tls, "https://ap.example", "aauth-agent.json")?;
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let as_policy = mode.clone();
    let proof_checks = Arc::new(AtomicUsize::new(0));
    let proof_count = proof_checks.clone();
    let proof_keys = trust.clone();
    let as_ids = AtomicUsize::new(0);
    let access = AccessServer::new(
        AccessConfig::new(AS, "as-1", SigningKey::generate()),
        trust.clone(),
        move |r: &aauth_rust_access_server::AuthorizationRequest| {
            if as_policy.load(Ordering::SeqCst) == 2
                || r.person_server != PS
                || r.resource.claims().iss != ORDERS
                || r.scopes != ["orders.write"]
            {
                return Err(AccessPolicyError::Denied);
            }
            Ok(Decision {
                scopes: r.scopes.clone(),
                lifetime: 600,
            })
        },
        now,
        move || format!("as-{}", as_ids.fetch_add(1, Ordering::SeqCst)),
    )?;
    let as_tls = Arc::new(TlsServer::start("as.example", move |request| {
        if request.uri().path() == "/token" {
            // Independent observer of actual incoming service proof and body coverage.
            if let Ok(proof) =
                PreparedRequest::prepare_with_schemes(&request, "sig", now(), 60, &["jwks_uri"])
                && let KeyMaterial::JwksUri { id, dwk, kid } = proof.key()
                && id == PS
                && dwk == "aauth-person.json"
                && let Ok(key) = proof_keys.key(id, dwk, kid)
                && proof.verify(&key).is_ok()
            {
                proof_count.fetch_add(1, Ordering::SeqCst);
            }
        }
        let response = access.handle(&request);
        if request.uri().path() == "/token"
            && selected.load(Ordering::SeqCst) == 1
            && response.status() == 200
        {
            return json_response(200, json!({"auth_token":"not-a-signed-grant"}));
        }
        response
    })?);
    trust.discover(&as_tls, AS, "aauth-access.json")?;
    let metadata = successful(as_tls.send(&get(&format!("{AS}/.well-known/aauth-access.json"))?)?)?;
    if metadata["issuer"] != AS {
        return Err("AS metadata identity mismatch".into());
    }
    let endpoint = metadata["auth_token_endpoint"]
        .as_str()
        .ok_or("missing AS endpoint")?
        .to_owned();
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
    )?
    .with_federation(AccessTransport {
        server: as_tls.clone(),
        endpoint,
    });
    let ps_tls = TlsServer::start("ps.example", move |r| ps.handle(&r))?;
    trust.discover(&ps_tls, PS, "aauth-person.json")?;
    let effects = Arc::new(AtomicUsize::new(0));
    let effect_count = effects.clone();
    let resource = PsAuthorizationResource::new_federated(
        PsAuthorizationConfig {
            issuer: ORDERS.into(),
            signed_origin: ORDERS.into(),
            kid: "orders-1".into(),
            signing_key: SigningKey::generate(),
            scopes: vec!["orders.write".into()],
        },
        AS,
        trust.clone(),
        |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true,
    )?;
    let ids = AtomicUsize::new(0);
    let orders_tls = TlsServer::start("orders.example", move |request| {
        match request.uri().path() {
            "/.well-known/aauth-resource.json" => {
                return json_document(resource.metadata().unwrap());
            }
            "/.well-known/jwks.json" => return json_document(resource.jwks().unwrap()),
            _ => {}
        }
        match resource
            .authorize(
                &request,
                now(),
                &format!("orders-{}", ids.fetch_add(1, Ordering::SeqCst)),
            )
            .into_result()
        {
            Ok((_token, ())) => {
                if request.method() != "POST"
                    || request.uri().path() != "/orders"
                    || request.body() != br#"{"quantity":2}"#
                {
                    return json_response(400, json!({"error":"invalid_order"}));
                }
                effects.fetch_add(1, Ordering::SeqCst);
                json_response(200, json!({"order":"accepted"}))
            }
            Err(response) => *response,
        }
    })?;
    trust.discover(&orders_tls, ORDERS, "aauth-resource.json")?;
    let unsigned = orders_tls.send(&get(&format!("{ORDERS}/orders"))?)?;
    let person = token_from(
        &successful(ps_tls.send(&signed(
            &agent,
            &format!("{PS}/person"),
            json!({"resource":ORDERS}),
        )?)?)?,
        "person_token",
    )?;
    let person_holder = agent.with_token(person.clone())?;
    let challenge = orders_tls.send(&signed(
        &person_holder,
        &format!("{ORDERS}/orders"),
        json!({"quantity":2}),
    )?)?;
    let resource = resource_challenge(&challenge)?;
    let context = FederatedContext {
        resource: ORDERS,
        person_server: PS,
        access_server: AS,
        presented_token: &person,
    };
    let verified = agent.verify_federated_resource_challenge(&resource, &context, &trust, now())?;
    let exchange = || {
        signed(
            &agent,
            &format!("{PS}/token"),
            json!({"resource_token":resource,"presented_token":person}),
        )
    };
    let grant = token_from(&successful(ps_tls.send(&exchange()?)?)?, "auth_token")?;
    let auth = agent.verify_federated_auth_delivery(&grant, &verified, &context, &trust, now())?;
    let holder = agent.with_token(grant.clone())?;
    let request = signed(&holder, &format!("{ORDERS}/orders"), json!({"quantity":2}))?;
    let mut tampered = request.clone();
    *tampered.body_mut() = br#"{"quantity":3}"#.to_vec();
    let tampered = orders_tls.send(&tampered)?;
    let authorized = orders_tls.send(&request)?;
    let retained = stored.token(&TokenReference {
        issuer: AS.into(),
        jti: auth.claims().jti.clone(),
    })?;
    let retained =
        retained.is_some_and(|r| r.person_server.as_deref() == Some(PS) && r.presented.is_some());
    mode.store(2, Ordering::SeqCst);
    let denied = ps_tls.send(&exchange()?)?;
    mode.store(1, Ordering::SeqCst);
    let bad_delivery = ps_tls.send(&exchange()?)?;
    mode.store(0, Ordering::SeqCst);
    let mut foreign = Request::builder()
        .method("POST")
        .uri(format!("{AS}/token"))
        .header("content-type", "application/json")
        .body(b"{}".to_vec())?;
    sign_request(
        &mut foreign,
        &SigningKey::generate(),
        KeyMaterial::JwksUri {
            id: "https://attacker.example".into(),
            dwk: "aauth-person.json".into(),
            kid: "attacker".into(),
        },
        now(),
    )?;
    let foreign = as_tls.send(&foreign)?;
    Ok(Transcript {
        unsigned_status: unsigned.status().as_u16(),
        challenge_status: challenge.status().as_u16(),
        authorized_status: authorized.status().as_u16(),
        tampered_status: tampered.status().as_u16(),
        denied_status: denied.status().as_u16(),
        bad_delivery_status: bad_delivery.status().as_u16(),
        untrusted_ps_status: foreign.status().as_u16(),
        effect_count: effect_count.load(Ordering::SeqCst),
        auth_issuer: auth.claims().iss.clone(),
        auth_document: auth.claims().dwk.clone(),
        subject: auth.claims().sub.clone(),
        auth_expiry: auth.claims().exp,
        challenge_expiry: verified.claims().exp,
        ps_proof_verified: proof_checks.load(Ordering::SeqCst) == 3,
        as_token_retained: retained,
        untrusted_tls_refused: orders_tls.refuses_untrusted_certificate(),
    })
}
