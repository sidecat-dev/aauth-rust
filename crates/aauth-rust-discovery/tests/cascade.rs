//! Revocation delivery over loopback TLS: a Person Server's cascade from its
//! own records, and a deferred answer polled to its end.
mod support;

use aauth_rust_access_server::{AccessServer, Config as AccessConfig, Decision};
use aauth_rust_agent::{Agent, Requirement};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AuthToken, CallOutcome, Confirmation, PersonToken, RevocationDirectory,
    RevocationSender, RevocationTarget, VerifiedAuthToken,
};
use aauth_rust_discovery::{DeliveryCause, DiscoveryClient, KeyResolver, RevocationClient};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Federation, FederationError, Grant, MemoryStore, Person,
    PersonRequest, PersonServer, Policy, PolicyError,
};
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest};
use http::{Request, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use support::{Net, json, now};

const AP: &str = "https://ap.test";
const PS: &str = "https://ps.test";
const AS: &str = "https://as.test";
const ORDERS: &str = "https://orders.test";

struct Host;
impl Policy for Host {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "orders-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
    fn consent(&self, _: &AuthorizationRequest) -> Result<(), PolicyError> {
        Ok(())
    }
}

/// Person Server to Access Server over the same admitted client.
struct Federated(DiscoveryClient);
impl Federation for Federated {
    fn endpoint(&self, access_server: &str) -> Result<String, FederationError> {
        let metadata = self
            .0
            .fetch_metadata(access_server, "aauth-access.json")
            .map_err(|_| FederationError)?;
        metadata
            .string("auth_token_endpoint")
            .map(str::to_owned)
            .ok_or(FederationError)
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        self.0.send(request).map_err(|_| FederationError)
    }
}

fn ids(prefix: &'static str) -> impl Fn() -> String + Send + Sync {
    let next = AtomicUsize::new(0);
    move || format!("{prefix}-{}", next.fetch_add(1, Ordering::SeqCst))
}

fn signed(agent: &Agent, uri: &str, body: Value) -> Request<Vec<u8>> {
    let mut request = Request::post(uri)
        .header("content-type", "application/json")
        .body(body.to_string().into_bytes())
        .unwrap();
    agent.sign(&mut request, now()).unwrap();
    request
}

fn call(holder: &Agent) -> Request<Vec<u8>> {
    let mut request = Request::get(format!("{ORDERS}/orders"))
        .body(Vec::new())
        .unwrap();
    holder.sign(&mut request, now()).unwrap();
    request
}

fn body(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body())
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(response.body())))
}

#[test]
fn person_server_cascade_reaches_every_recipient_over_tls() {
    let mut net = Net::new(&["ap.test", "ps.test", "as.test", "orders.test"]);
    let client = net.client();
    let keys = Arc::new(
        KeyResolver::new(client.clone())
            .trust(AP, "aauth-agent.json")
            .trust(PS, "aauth-person.json")
            .trust(AS, "aauth-access.json")
            .trust(ORDERS, "aauth-resource.json"),
    );
    // The one piece of revocation transport every role is given.
    let revocations = Arc::new(RevocationClient::new(client.clone()));

    let provider = Arc::new(AgentProvider::new(AP, "ap-1", SigningKey::generate()).unwrap());
    let agent_key = SigningKey::generate();
    let issued = now();
    let token = provider
        .issue(&AgentClaims {
            iss: AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:customer@ap.test".into(),
            jti: "agent-1".into(),
            iat: issued,
            exp: issued + 600,
            cnf: Confirmation {
                jwk: agent_key.public_jwk(),
            },
            ps: Some(PS.into()),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })
        .unwrap();
    let agent = Agent::new(agent_key, token).unwrap();
    let serving = provider.clone();
    net.serve("ap.test", move |request| match request.uri().path() {
        "/.well-known/aauth-agent.json" => json(200, serving.metadata().unwrap()),
        "/.well-known/jwks.json" => json(200, serving.jwks().unwrap()),
        _ => json(404, "{}"),
    });

    let access = Arc::new(
        AccessServer::new(
            AccessConfig::new(AS, "as-1", SigningKey::generate()),
            keys.clone(),
            |request: &aauth_rust_access_server::AuthorizationRequest| {
                Ok(Decision {
                    scopes: request.scopes.clone(),
                    lifetime: 600,
                })
            },
            now,
            ids("as"),
        )
        .unwrap()
        .with_revocation_directory(revocations.clone()),
    );
    let serving = access.clone();
    net.serve("as.test", move |request| serving.handle(&request));

    let ps = Arc::new(
        PersonServer::new(
            Config::new(PS, "ps-1", SigningKey::generate()),
            keys.clone(),
            MemoryStore::default(),
            Host,
            now,
            ids("ps"),
        )
        .unwrap()
        .with_federation(Federated(client.clone()))
        .with_revocation_directory(revocations.clone()),
    );
    let serving = ps.clone();
    net.serve("ps.test", move |request| serving.handle(&request));

    let orders = Arc::new(
        PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: ORDERS.into(),
                signed_origin: ORDERS.into(),
                kid: "orders-1".into(),
                signing_key: SigningKey::generate(),
                scopes: vec!["orders.read".into()],
                scope_descriptions: BTreeMap::from([("orders.read".into(), "Read orders".into())]),
            },
            AS,
            keys.clone(),
            |_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true,
        )
        .unwrap()
        .with_revocation(),
    );
    let serving = orders.clone();
    net.serve("orders.test", move |request| match request.uri().path() {
        "/.well-known/aauth-resource.json" => json(200, serving.metadata().unwrap()),
        "/.well-known/jwks.json" => json(200, serving.jwks().unwrap()),
        path if path.starts_with("/revoke") => serving.revoke(&request, now()),
        _ => json(404, "{}"),
    });

    // A person token, the API's challenge, and an auth token from the Access
    // Server through the Person Server. Each server finds the others' keys
    // by discovery.
    let person = ps.handle(&signed(
        &agent,
        &format!("{PS}/person"),
        json!({ "resource": ORDERS }),
    ));
    assert_eq!(person.status(), 200, "{}", body(&person));
    let person_token = body(&person)["person_token"].as_str().unwrap().to_owned();
    let challenge = match orders
        .authorize(
            &call(&agent.with_token(person_token.clone()).unwrap()),
            now(),
            "challenge-1",
        )
        .into_result()
    {
        Err(response) => response,
        Ok(_) => panic!("a person token alone was admitted"),
    };
    let Some(Requirement::AuthToken { resource_token }) =
        Requirement::from_headers(challenge.headers()).unwrap()
    else {
        panic!("expected an auth-token challenge");
    };
    let granted = ps.handle(&signed(
        &agent,
        &format!("{PS}/token"),
        json!({ "resource_token": resource_token, "presented_token": person_token }),
    ));
    assert_eq!(granted.status(), 200, "{}", body(&granted));
    let auth_token = body(&granted)["auth_token"].as_str().unwrap().to_owned();
    let holder = agent.with_token(auth_token.clone()).unwrap();
    assert!(
        orders
            .authorize(&call(&holder), now(), "challenge-2")
            .into_result()
            .is_ok()
    );

    // Revoking the person token cascades from the Person Server's records:
    // to the API, and to the Access Server, which revokes its auth token at
    // the API in turn. No host code sends any of it.
    let person_claims = PersonToken::parse(&person_token)
        .unwrap()
        .unverified_claims()
        .clone();
    let auth_claims = AuthToken::parse(&auth_token)
        .unwrap()
        .unverified_claims()
        .clone();
    let cascade = ps.revoke_person_token(&person_claims.jti);
    assert_eq!(cascade.status(), 200, "{}", body(&cascade));
    assert_eq!(
        body(&cascade),
        json!({ "downstream": [{ "recipient": ORDERS }, { "recipient": AS }] })
    );
    assert_eq!(
        orders.revocation_exp(PS, &person_claims.jti),
        Some(person_claims.exp)
    );
    assert_eq!(
        access.revocation_exp(PS, &person_claims.jti),
        Some(person_claims.exp)
    );
    assert_eq!(
        orders.revocation_exp(AS, &auth_claims.jti),
        Some(auth_claims.exp)
    );
    assert_eq!(net.count("POST orders.test/revoke"), 2);
    assert_eq!(net.count("POST as.test/revoke"), 1);
    let Err(refused) = orders
        .authorize(&call(&holder), now(), "challenge-3")
        .into_result()
    else {
        panic!("the revoked auth token was admitted");
    };
    assert_eq!(refused.status(), 401);
    assert!(
        refused.headers()["signature-error"]
            .to_str()
            .unwrap()
            .contains("revoked_jwt")
    );
}

#[test]
fn a_deferred_revocation_is_polled_with_a_signed_get() {
    let mut net = Net::new(&["slow.test", "bare.test"]);
    let sender_key = SigningKey::generate();
    let sender_public = sender_key.public_jwk();
    let verified = Arc::new(AtomicUsize::new(0));
    let seen = verified.clone();
    net.serve("slow.test", move |request| {
        let path = request.uri().path().to_owned();
        if path == "/.well-known/aauth-access.json" {
            return json(
                200,
                json!({ "issuer": "https://slow.test", "revocation_endpoint": "https://slow.test/revoke" })
                    .to_string(),
            );
        }
        // Answer only a request signed as the sender under jwks_uri.
        let proof =
            PreparedRequest::prepare_with_schemes(&request, "sig", now(), 60, &["jwks_uri"]).unwrap();
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return json(401, "{}");
        };
        if (id.as_str(), dwk.as_str(), kid.as_str()) != (PS, "aauth-person.json", "ps-1")
            || proof.verify(&sender_public).is_err()
        {
            return json(401, "{}");
        }
        seen.fetch_add(1, Ordering::SeqCst);
        match (request.method().as_str(), path.as_str()) {
            ("POST", "/revoke") => Response::builder()
                .status(202)
                .header("location", "/revoke/pending/p1")
                .header("retry-after", "0")
                .body(Vec::new())
                .unwrap(),
            ("GET", "/revoke/pending/p1") if request.body().is_empty() => {
                Response::builder().status(200).body(Vec::new()).unwrap()
            }
            _ => json(400, r#"{"error":"invalid_request"}"#),
        }
    });
    net.serve("bare.test", |_| {
        json(200, json!({ "issuer": "https://bare.test" }).to_string())
    });
    let revocations = RevocationClient::new(net.client());
    let sender = RevocationSender {
        issuer: PS,
        dwk: "aauth-person.json",
        kid: "ps-1",
        key: &sender_key,
    };
    let target = RevocationTarget {
        recipient: "https://slow.test",
        dwk: "aauth-access.json",
        jti: "person-1",
        exp: now() + 300,
    };
    assert_eq!(revocations.revoke(&sender, &target), CallOutcome::Deferred);
    assert_eq!(revocations.revoke(&sender, &target), CallOutcome::Recorded);
    assert_eq!(
        net.log(),
        [
            "GET slow.test/.well-known/aauth-access.json",
            "POST slow.test/revoke",
            "GET slow.test/revoke/pending/p1",
        ]
    );
    assert_eq!(verified.load(Ordering::SeqCst), 2);

    let unsupported = revocations.deliver(
        &sender,
        &RevocationTarget {
            recipient: "https://bare.test",
            ..target
        },
    );
    assert_eq!(unsupported.outcome, CallOutcome::Unsupported);
    assert!(matches!(unsupported.cause, Some(DeliveryCause::NoEndpoint)));
}
