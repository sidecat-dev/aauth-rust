use aauth_rust_access_server::{AccessServer, Config as AccessConfig, Decision};
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AuthToken, Confirmation, PersonToken, ResourceToken, TokenError,
    TrustedIssuerKeys, VerifiedAuthToken,
};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, Config, Federation, FederationError, Grant, MemoryStore,
    Person, PersonRequest, PersonServer, Policy, PolicyError, Store,
};
use aauth_rust_resource::{
    BoxedAuthAdmissionPolicy, PsAuthorizationConfig, PsAuthorizationResource,
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
};

const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const AS: &str = "https://as.example";
const RESOURCE: &str = "https://resource.example";
const PARENT: &str = "aauth:parent@ap.example";
const CHILD: &str = "aauth:parent+worker@ap.example";
const SUBJECT: &str = "directed-person";
const SCOPE: &str = "records.read";
const NOW: i64 = 1000;

#[derive(Clone, Default)]
struct Keys(Arc<RwLock<BTreeMap<(String, String), TrustedIssuerKeys>>>);
impl Keys {
    fn admit(&self, issuer: &str, role: &str, metadata: &[u8], jwks: &[u8]) {
        let admitted = TrustedIssuerKeys::from_documents(issuer, role, metadata, jwks).unwrap();
        self.0
            .write()
            .unwrap()
            .insert((issuer.into(), role.into()), admitted);
    }
}
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, role: &str, kid: &str) -> Result<Jwk, TokenError> {
        self.0
            .read()
            .unwrap()
            .get(&(issuer.into(), role.into()))
            .ok_or(TokenError::UntrustedIssuer)?
            .key(issuer, role, kid)
    }
}

#[derive(Default)]
struct Consent {
    persons: AtomicUsize,
    grants: AtomicUsize,
}
struct ConsentPolicy(Arc<Consent>);
impl Policy for ConsentPolicy {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.0.persons.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.agent.claims().sub, PARENT);
        assert_eq!(request.subagent.as_ref().unwrap().claims().sub, CHILD);
        assert_eq!(request.resource, RESOURCE);
        Ok(Person {
            id: "account".into(),
            subject: SUBJECT.into(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.consent(request)?;
        Ok(Grant {
            scopes: vec![SCOPE.into()],
            lifetime: 600,
        })
    }
    fn consent(&self, request: &AuthorizationRequest) -> Result<(), PolicyError> {
        self.0.grants.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.agent.claims().sub, PARENT);
        assert_eq!(request.subagent.as_ref().unwrap().claims().sub, CHILD);
        assert_eq!(request.scopes, [SCOPE]);
        Ok(())
    }
}

type Handler = Arc<dyn Fn(&Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>;
struct NativeAccess(Handler);
impl Federation for NativeAccess {
    fn endpoint(&self, issuer: &str) -> Result<String, FederationError> {
        if issuer != AS {
            return Err(FederationError);
        }
        Ok(format!("{AS}/token"))
    }
    fn send(&self, request: &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, FederationError> {
        Ok((self.0)(request))
    }
}

fn signed(agent: &Agent, endpoint: &str, body: Option<Value>, now: i64) -> Request<Vec<u8>> {
    let mut request = if let Some(body) = body {
        Request::post(endpoint)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap()
    } else {
        Request::get(endpoint).body(Vec::new()).unwrap()
    };
    agent.sign(&mut request, now).unwrap();
    request
}
fn output(response: &Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).unwrap()
}
fn response_token(response: &Response<Vec<u8>>, name: &str) -> String {
    assert_eq!(response.status(), 200, "{}", output(response));
    output(response)[name].as_str().unwrap().into()
}
fn challenge(response: &Response<Vec<u8>>) -> String {
    assert_eq!(response.status(), 401);
    assert!(!response.headers().contains_key("signature-error"));
    response.headers()["aauth-requirement"]
        .to_str()
        .unwrap()
        .strip_prefix("requirement=auth-token;resource-token=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap()
        .into()
}

// A binding withdrawal stops subsequent parent-mediated issuance. It does not
// revoke a previously issued, child-held Auth token at the Resource.
fn existing_child_auth_expires_normally(federated: bool) {
    let now = Arc::new(AtomicI64::new(NOW));
    let keys = Keys::default();
    let provider = AgentProvider::new(AP, "ap", SigningKey::from_seed([1; 32])).unwrap();
    keys.admit(
        AP,
        "aauth-agent.json",
        &provider.metadata().unwrap(),
        &provider.jwks().unwrap(),
    );
    let parent_claims = AgentClaims {
        iss: AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: PARENT.into(),
        jti: "parent".into(),
        iat: NOW,
        exp: 4000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        ps: Some(PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let parent = Agent::new(
        SigningKey::from_seed([2; 32]),
        provider.issue(&parent_claims).unwrap(),
    )
    .unwrap();
    let mut child_claims = parent_claims.clone();
    child_claims.sub = CHILD.into();
    child_claims.parent_agent = Some(PARENT.into());
    child_claims.jti = "child".into();
    child_claims.exp = 1250;
    child_claims.cnf.jwk = SigningKey::from_seed([7; 32]).public_jwk();
    let child = Agent::new(
        SigningKey::from_seed([7; 32]),
        provider
            .issue_subagent(&child_claims, parent.token(), NOW)
            .unwrap(),
    )
    .unwrap();

    let store = Arc::new(MemoryStore::default());
    let consent = Arc::new(Consent::default());
    let clock = now.clone();
    let ids = AtomicUsize::new(0);
    let mut ps = PersonServer::new(
        Config::new(PS, "ps", SigningKey::from_seed([3; 32])),
        keys.clone(),
        store.clone(),
        ConsentPolicy(consent.clone()),
        move || clock.load(Ordering::SeqCst),
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap();
    keys.admit(PS, "aauth-person.json", &ps.metadata(), &ps.jwks());
    let access_calls = Arc::new(AtomicUsize::new(0));
    if federated {
        let clock = now.clone();
        let access = AccessServer::new(
            AccessConfig::new(AS, "as", SigningKey::from_seed([5; 32])),
            keys.clone(),
            |request: &aauth_rust_access_server::AuthorizationRequest| {
                assert_eq!(request.agent.claims().sub, PARENT);
                assert_eq!(request.subagent.as_ref().unwrap().claims().sub, CHILD);
                Ok(Decision {
                    scopes: vec![SCOPE.into()],
                    lifetime: 600,
                })
            },
            move || clock.load(Ordering::SeqCst),
            || "as-auth".into(),
        )
        .unwrap();
        keys.admit(AS, "aauth-access.json", &access.metadata(), &access.jwks());
        let calls = access_calls.clone();
        let expected_parent = parent.token().to_owned();
        let expected_child = child.token().to_owned();
        ps = ps.with_federation(NativeAccess(Arc::new(move |request| {
            calls.fetch_add(1, Ordering::SeqCst);
            let body: Value = serde_json::from_slice(request.body()).unwrap();
            assert_eq!(body["agent_token"], expected_parent);
            assert_eq!(body["subagent_token"], expected_child);
            access.handle(request)
        })));
    }

    let policy_calls = Arc::new(AtomicUsize::new(0));
    let calls = policy_calls.clone();
    let child_jkt = child.public_jwk().thumbprint().unwrap();
    let policy: BoxedAuthAdmissionPolicy<()> = Box::new(
        move |token: &VerifiedAuthToken, request: &Request<Vec<u8>>| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(token.claims().sub, SUBJECT);
            assert_eq!(token.claims().cnf.jwk.thumbprint().unwrap(), child_jkt);
            assert_eq!(request.uri().path(), "/records");
            Ok(())
        },
    );
    let config = PsAuthorizationConfig {
        issuer: RESOURCE.into(),
        signed_origin: RESOURCE.into(),
        kid: "resource".into(),
        signing_key: SigningKey::from_seed([4; 32]),
        scopes: vec![SCOPE.into()],
    };
    let resource = if federated {
        PsAuthorizationResource::new_federated(config, AS, keys.clone(), policy).unwrap()
    } else {
        PsAuthorizationResource::new(config, keys.clone(), policy).unwrap()
    };
    keys.admit(
        RESOURCE,
        "aauth-resource.json",
        &resource.metadata().unwrap(),
        &resource.jwks().unwrap(),
    );

    let person_request = json!({"resource":RESOURCE,"subagent_token":child.token()});
    let person = response_token(
        &ps.handle(&signed(
            &parent,
            &format!("{PS}/person"),
            Some(person_request.clone()),
            NOW,
        )),
        "person_token",
    );
    let verified_person = PersonToken::parse(&person)
        .unwrap()
        .verify(&keys, NOW)
        .unwrap();
    assert_eq!(verified_person.claims().exp, 1250);
    let person_holder = child.with_token(person.clone()).unwrap();
    let path = format!("{RESOURCE}/records");
    let challenge_compact = challenge(
        &resource
            .authorize(
                &signed(&person_holder, &path, None, NOW),
                NOW,
                "initial-challenge",
            )
            .into_response(),
    );
    let verified_challenge = ResourceToken::parse(&challenge_compact)
        .unwrap()
        .verify(&keys, NOW)
        .unwrap();
    assert_eq!(
        verified_challenge.claims().agent_jkt,
        child.public_jwk().thumbprint().unwrap()
    );
    assert_eq!(policy_calls.load(Ordering::SeqCst), 0);
    let exchange = json!({"resource_token":challenge_compact,"presented_token":person,"subagent_token":child.token()});
    let auth = response_token(
        &ps.handle(&signed(
            &parent,
            &format!("{PS}/token"),
            Some(exchange),
            NOW,
        )),
        "auth_token",
    );
    let verified_auth = AuthToken::parse(&auth).unwrap().verify(&keys, NOW).unwrap();
    assert_eq!(verified_auth.claims().iss, if federated { AS } else { PS });
    assert_eq!(verified_auth.claims().exp, 1250);
    assert_eq!(
        parent.with_token(auth.clone()).err().unwrap(),
        TokenError::ConfirmationKeyMismatch
    );
    let holder = child.with_token(auth.clone()).unwrap();
    let (accepted, ()) = resource
        .authorize(&signed(&holder, &path, None, NOW), NOW, "unused")
        .into_result()
        .unwrap();
    assert_eq!(accepted.compact(), auth);
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);

    now.store(1249, Ordering::SeqCst);
    store
        .revoke_binding(
            PS,
            &AgentIdentity {
                issuer: AP.into(),
                subject: PARENT.into(),
            },
        )
        .unwrap();
    let fresh_challenge = challenge(
        &resource
            .authorize(
                &signed(&person_holder, &path, None, 1249),
                1249,
                "after-revocation",
            )
            .into_response(),
    );
    let refused = ps.handle(&signed(&parent, &format!("{PS}/token"), Some(json!({"resource_token":fresh_challenge,"presented_token":person_holder.token(),"subagent_token":child.token()})), 1249));
    assert_eq!(refused.status(), 400);
    assert_eq!(output(&refused)["error"], "revoked_presented_token");
    assert!(output(&refused).get("auth_token").is_none());
    let new_person = ps.handle(&signed(
        &parent,
        &format!("{PS}/person"),
        Some(person_request),
        1249,
    ));
    assert_eq!(new_person.status(), 403);
    assert!(output(&new_person).get("person_token").is_none());
    assert_eq!(consent.persons.load(Ordering::SeqCst), 1);
    assert_eq!(consent.grants.load(Ordering::SeqCst), 1);
    assert_eq!(access_calls.load(Ordering::SeqCst), usize::from(federated));

    let (accepted, ()) = resource
        .authorize(&signed(&holder, &path, None, 1249), 1249, "unused")
        .into_result()
        .unwrap();
    assert_eq!(accepted.compact(), auth);
    assert_eq!(policy_calls.load(Ordering::SeqCst), 2);
    now.store(1250, Ordering::SeqCst);
    let expired = resource
        .authorize(&signed(&holder, &path, None, 1250), 1250, "unused")
        .into_response();
    assert_eq!(expired.status(), 401);
    assert_eq!(expired.headers()["signature-error"], "error=expired_jwt");
    assert_eq!(
        policy_calls.load(Ordering::SeqCst),
        2,
        "expiry must refuse before Resource admission policy"
    );
}

#[test]
fn direct_child_auth_survives_parent_binding_revocation_until_resource_expiry() {
    existing_child_auth_expires_normally(false);
}

#[test]
fn federated_child_auth_survives_parent_binding_revocation_until_resource_expiry() {
    existing_child_auth_expires_normally(true);
}
