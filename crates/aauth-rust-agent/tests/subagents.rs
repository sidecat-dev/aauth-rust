use aauth_rust_agent::{Agent, FederatedContext, ResourceTokenAttempts, Subagent};
use aauth_rust_core::{AgentKeyResolver, TokenError};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest};
use serde_json::{Value, json};

const RESOURCE: &str = "https://resource.example";
const PS: &str = "https://ps.example";
const AS: &str = "https://as.example";
struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "key") => 1,
            (PS, "aauth-person.json", "key") => 4,
            (RESOURCE, "aauth-resource.json", "key") => 5,
            (AS, "aauth-access.json", "key") => 6,
            _ => return Err(TokenError::UntrustedIssuer),
        };
        Ok(SigningKey::from_seed([seed; 32]).public_jwk())
    }
}
fn signed(role: &str, value: &Value, seed: u8) -> String {
    Jws::sign(
        &json!({"alg":"Ed25519","typ":format!("aa-{role}+jwt"),"kid":"key"}),
        &serde_json::to_vec(value).unwrap(),
        &SigningKey::from_seed([seed; 32]),
    )
    .unwrap()
}
fn agent_claims(child: bool) -> Value {
    let mut c = json!({"iss":"https://ap.example","dwk":"aauth-agent.json",
        "sub":"aauth:parent@ap.example","jti":"parent","iat":1000,"exp":1900,
        "ps":PS,"cnf":{"jwk":SigningKey::from_seed([2;32]).public_jwk()}});
    if child {
        c["sub"] = json!("aauth:parent+worker@ap.example");
        c["parent_agent"] = json!("aauth:parent@ap.example");
        c["jti"] = json!("child");
        c["exp"] = json!(1800);
        c["cnf"] = json!({"jwk":SigningKey::from_seed([3;32]).public_jwk()});
        c.as_object_mut().unwrap().remove("ps");
    }
    c
}
fn fixture() -> (Agent, Subagent) {
    let parent = signed("agent", &agent_claims(false), 1);
    let child = signed("agent", &agent_claims(true), 1);
    let context = Subagent::verify(&parent, &child, &Keys, 1000).unwrap();
    (
        Agent::new(SigningKey::from_seed([2; 32]), parent).unwrap(),
        context,
    )
}
fn person() -> Value {
    json!({"iss":PS,"dwk":"aauth-person.json","aud":RESOURCE,"sub":"directed-person",
        "jti":"person","iat":1000,"exp":1700,
        "cnf":{"jwk":SigningKey::from_seed([3;32]).public_jwk()}})
}
fn resource(federated: bool) -> Value {
    json!({"iss":RESOURCE,"dwk":"aauth-resource.json","aud":if federated {AS} else {PS},
        "ps":PS,"sub":"directed-person","jti":"resource","iat":1000,"exp":1300,
        "presented_jti":"person","agent_jkt":SigningKey::from_seed([3;32]).public_jwk().thumbprint().unwrap(),
        "scope":"read write","account":"account-1","login_hint":"person@example.com"})
}
fn auth(federated: bool) -> Value {
    let mut c = person();
    c["iss"] = json!(if federated { AS } else { PS });
    c["dwk"] = json!(if federated {
        "aauth-access.json"
    } else {
        "aauth-person.json"
    });
    c["jti"] = json!("auth");
    c["exp"] = json!(1600);
    c["ps"] = json!(PS);
    c["scope"] = json!("read");
    c["account"] = json!("account-1");
    c
}

#[test]
fn admits_exact_parent_and_child_without_a_child_private_key() {
    let (parent, child) = fixture();
    assert_eq!(child.parent().compact(), parent.token());
    assert_eq!(child.token().claims().sub, "aauth:parent+worker@ap.example");
    let forged = signed("agent", &agent_claims(false), 9);
    assert!(Subagent::verify(&forged, child.token().compact(), &Keys, 1000).is_err());
    assert!(!format!("{child:?}").contains(child.token().compact()));
}

#[test]
fn parent_host_authenticates_child_person_delivery_and_expected_destination() {
    let (_, child) = fixture();
    let compact = signed("person", &person(), 4);
    assert_eq!(
        child
            .verify_person_delivery(&compact, RESOURCE, PS, &Keys, 1000)
            .unwrap()
            .compact(),
        compact
    );
    for (resource, ps) in [
        ("https://other.example", PS),
        (RESOURCE, "https://other.example"),
    ] {
        assert!(
            child
                .verify_person_delivery(&compact, resource, ps, &Keys, 1000)
                .is_err()
        );
    }
    let mut wrong = person();
    wrong["cnf"] = json!({"jwk":SigningKey::from_seed([2;32]).public_jwk()});
    assert!(
        child
            .verify_person_delivery(&signed("person", &wrong, 4), RESOURCE, PS, &Keys, 1000)
            .is_err()
    );
}

#[test]
fn child_delivery_caps_both_agent_lifetimes_and_stays_missionless() {
    let (_, child) = fixture();
    for (field, value) in [
        ("exp", json!(1801)),
        (
            "mission_s256",
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ),
    ] {
        let mut wrong = person();
        wrong[field] = value;
        assert!(
            child
                .verify_person_delivery(&signed("person", &wrong, 4), RESOURCE, PS, &Keys, 1000)
                .is_err()
        );
    }
    let mut parent = agent_claims(false);
    parent["exp"] = json!(1500);
    let child = Subagent::verify(
        &signed("agent", &parent, 1),
        &signed("agent", &agent_claims(true), 1),
        &Keys,
        1000,
    )
    .unwrap();
    assert!(
        child
            .verify_person_delivery(&signed("person", &person(), 4), RESOURCE, PS, &Keys, 1000)
            .is_err()
    );
}

#[test]
fn parent_host_verifies_child_bound_direct_challenge_and_grant() {
    let (parent, child) = fixture();
    let person = signed("person", &person(), 4);
    let challenge = signed("resource", &resource(false), 5);
    let verified = child
        .verify_resource_challenge(&challenge, RESOURCE, PS, &person, &Keys, 1000)
        .unwrap();
    assert!(
        parent
            .verify_resource_challenge(&challenge, RESOURCE, PS, &person, &Keys, 1000)
            .is_err()
    );
    let compact = signed("auth", &auth(false), 4);
    assert_eq!(
        child
            .verify_auth_delivery(&compact, RESOURCE, &verified, &person, &Keys, 1000)
            .unwrap()
            .compact(),
        compact
    );
    // The challenge expires first; that does not shorten a valid delivered grant.
    assert!(
        child
            .verify_auth_delivery(&compact, RESOURCE, &verified, &person, &Keys, 1300)
            .is_ok()
    );
}

#[test]
fn direct_child_grant_refuses_changed_key_lineage_scope_account_and_lifetime() {
    let (_, child) = fixture();
    let person = signed("person", &person(), 4);
    let challenge = child
        .verify_resource_challenge(
            &signed("resource", &resource(false), 5),
            RESOURCE,
            PS,
            &person,
            &Keys,
            1000,
        )
        .unwrap();
    for (field, value) in [
        (
            "cnf",
            json!({"jwk":SigningKey::from_seed([2;32]).public_jwk()}),
        ),
        ("sub", json!("another-person")),
        ("scope", json!("admin")),
        ("account", json!("other-account")),
        ("exp", json!(1701)),
    ] {
        let mut wrong = auth(false);
        wrong[field] = value;
        assert!(
            child
                .verify_auth_delivery(
                    &signed("auth", &wrong, 4),
                    RESOURCE,
                    &challenge,
                    &person,
                    &Keys,
                    1000
                )
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn parent_host_verifies_child_bound_federation_and_as_step_up() {
    let (_, child) = fixture();
    let person = signed("person", &person(), 4);
    let context = FederatedContext {
        resource: RESOURCE,
        person_server: PS,
        access_server: AS,
        presented_token: &person,
    };
    let challenge = child
        .verify_federated_resource_challenge(
            &signed("resource", &resource(true), 5),
            &context,
            &Keys,
            1000,
        )
        .unwrap();
    let compact = signed("auth", &auth(true), 6);
    assert_eq!(
        child
            .verify_federated_auth_delivery(&compact, &challenge, &context, &Keys, 1000)
            .unwrap()
            .compact(),
        compact
    );
    let context = FederatedContext {
        presented_token: &compact,
        ..context
    };
    let mut next = resource(true);
    next["presented_jti"] = json!("auth");
    let challenge = child
        .verify_federated_resource_challenge(&signed("resource", &next, 5), &context, &Keys, 1000)
        .unwrap();
    let mut grant = auth(true);
    grant["exp"] = json!(1500);
    assert!(
        child
            .verify_federated_auth_delivery(
                &signed("auth", &grant, 6),
                &challenge,
                &context,
                &Keys,
                1000
            )
            .is_ok()
    );
}

#[test]
fn request_builders_preserve_exact_child_credentials_and_use_parent_proof() {
    let (parent, child) = fixture();
    let person_request = child
        .person_request(&parent, "https://ps.example/person", RESOURCE, &Keys, 1000)
        .unwrap();
    let body: Value = serde_json::from_slice(person_request.body()).unwrap();
    assert_eq!(
        body,
        json!({"resource":RESOURCE,"subagent_token":child.token().compact(),"capabilities":["budget"]})
    );
    assert_eq!(person_request.headers()["aauth-capabilities"], "budget");
    let person = signed("person", &person(), 4);
    let resource = child
        .verify_resource_challenge(
            &signed("resource", &resource(false), 5),
            RESOURCE,
            PS,
            &person,
            &Keys,
            1000,
        )
        .unwrap();
    let auth_request = child
        .auth_request(
            &parent,
            "https://ps.example/auth",
            &resource,
            &person,
            &Keys,
            1000,
            &ResourceTokenAttempts::new(),
        )
        .unwrap();
    let body: Value = serde_json::from_slice(auth_request.body()).unwrap();
    assert_eq!(body["resource_token"], resource.compact());
    assert_eq!(body["presented_token"], person);
    assert_eq!(body["subagent_token"], child.token().compact());
    assert_eq!(body["login_hint"], "person@example.com");
    assert_eq!(body["capabilities"], json!(["budget"]));
    assert_eq!(auth_request.headers()["aauth-capabilities"], "budget");
    assert!(body.get("justification").is_none());
    let explained = child
        .auth_request_with_justification(
            &parent,
            "https://ps.example/auth",
            &resource,
            &person,
            &Keys,
            1000,
            &ResourceTokenAttempts::new(),
            Some("the grant is spent"),
        )
        .unwrap();
    let explained_body: Value = serde_json::from_slice(explained.body()).unwrap();
    assert_eq!(explained_body["justification"], "the grant is spent");
    assert_eq!(explained_body["resource_token"], resource.compact());
    assert!(
        child
            .auth_request_with_justification(
                &parent,
                "https://ps.example/auth",
                &resource,
                &person,
                &Keys,
                1000,
                &ResourceTokenAttempts::new(),
                Some(""),
            )
            .is_err()
    );
    for request in [person_request, auth_request] {
        let proof = PreparedRequest::prepare(&request, "sig", 1000, 60).unwrap();
        assert!(
            matches!(proof.key(), KeyMaterial::Jwt { jwt: token, .. } if token == parent.token())
        );
        proof.verify(&parent.public_jwk()).unwrap();
        assert!(proof.verify(&child.token().claims().cnf.jwk).is_err());
    }
}

#[test]
fn requests_refuse_wrong_parent_endpoint_and_expired_dependencies() {
    let (parent, child) = fixture();
    let mut other_claims = agent_claims(false);
    other_claims["jti"] = json!("other-parent-token");
    let other = Agent::new(
        SigningKey::from_seed([2; 32]),
        signed("agent", &other_claims, 1),
    )
    .unwrap();
    assert!(
        child
            .person_request(&other, "https://ps.example/person", RESOURCE, &Keys, 1000)
            .is_err()
    );
    for endpoint in [
        "http://ps.example/person",
        "https://ps.example/person?x=1",
        "https://ps.example/person#x",
        "https://user@ps.example/person",
    ] {
        assert!(
            child
                .person_request(&parent, endpoint, RESOURCE, &Keys, 1000)
                .is_err(),
            "{endpoint}"
        );
    }
    assert_eq!(
        child
            .person_request(&parent, "https://ps.example/person", RESOURCE, &Keys, 1800)
            .unwrap_err(),
        TokenError::ExpiredJwt
    );
    assert_eq!(
        child
            .verify_person_delivery(&signed("person", &person(), 4), RESOURCE, PS, &Keys, 1800)
            .unwrap_err(),
        TokenError::ExpiredJwt
    );
    let person = signed("person", &person(), 4);
    let resource = child
        .verify_resource_challenge(
            &signed("resource", &resource(false), 5),
            RESOURCE,
            PS,
            &person,
            &Keys,
            1000,
        )
        .unwrap();
    assert!(
        child
            .auth_request(
                &parent,
                "https://ps.example/auth",
                &resource,
                &person,
                &Keys,
                1300,
                &ResourceTokenAttempts::new(),
            )
            .is_err()
    );
}
