//! A revoked resource token is not built into another Auth request.
use aauth_rust_agent::{Agent, ResourceTokenAttempts, Subagent};
use aauth_rust_core::{AgentKeyResolver, TokenError};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use serde_json::{Value, json};

const RESOURCE: &str = "https://resource.example";
const PS: &str = "https://ps.example";

struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        let seed = match (issuer, dwk, kid) {
            ("https://ap.example", "aauth-agent.json", "key") => 1,
            (PS, "aauth-person.json", "key") => 4,
            (RESOURCE, "aauth-resource.json", "key") => 5,
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
    let mut claims = json!({"iss":"https://ap.example","dwk":"aauth-agent.json",
        "sub":"aauth:parent@ap.example","jti":"parent","iat":1000,"exp":1900,
        "ps":PS,"cnf":{"jwk":SigningKey::from_seed([2;32]).public_jwk()}});
    if child {
        claims["sub"] = json!("aauth:parent+worker@ap.example");
        claims["parent_agent"] = json!("aauth:parent@ap.example");
        claims["jti"] = json!("child");
        claims["exp"] = json!(1800);
        claims["cnf"] = json!({"jwk":SigningKey::from_seed([3;32]).public_jwk()});
        claims.as_object_mut().unwrap().remove("ps");
    }
    claims
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

#[test]
fn revoked_resource_token_is_not_resubmitted() {
    let mut attempts = ResourceTokenAttempts::new();
    assert!(attempts.may_submit("resource-a"));
    attempts.observe_error("resource-a", "invalid_resource_token");
    attempts.observe_token_response("resource-a", b"not-json");
    assert!(attempts.may_submit("resource-a"));
    attempts.observe_token_response("resource-a", br#"{"error":"expired_resource_token"}"#);
    assert!(attempts.may_submit("resource-a"));
    attempts.observe_token_response("resource-a", br#"{"error":"revoked_resource_token"}"#);
    assert!(!attempts.may_submit("resource-a"));
    assert!(attempts.may_submit("resource-b"));
    attempts.observe_error("resource-b", "revoked_resource_token");
    assert!(!attempts.may_submit("resource-b"));
    assert!(!attempts.may_submit("resource-a"));

    let (parent, child) = fixture();
    let person = signed(
        "person",
        &json!({"iss":PS,"dwk":"aauth-person.json","aud":RESOURCE,"sub":"directed-person",
            "jti":"person","iat":1000,"exp":1700,
            "cnf":{"jwk":SigningKey::from_seed([3;32]).public_jwk()}}),
        4,
    );
    let challenge = signed(
        "resource",
        &json!({"iss":RESOURCE,"dwk":"aauth-resource.json","aud":PS,
            "ps":PS,"sub":"directed-person","jti":"resource","iat":1000,"exp":1300,
            "presented_jti":"person",
            "agent_jkt":SigningKey::from_seed([3;32]).public_jwk().thumbprint().unwrap(),
            "scope":"read","login_hint":"person@example.com"}),
        5,
    );
    let resource = child
        .verify_resource_challenge(&challenge, RESOURCE, PS, &person, &Keys, 1000)
        .unwrap();
    let mut live = ResourceTokenAttempts::new();
    let built = child
        .auth_request(
            &parent,
            "https://ps.example/auth",
            &resource,
            &person,
            &Keys,
            1000,
            &live,
        )
        .unwrap();
    let body: Value = serde_json::from_slice(built.body()).unwrap();
    assert_eq!(body["resource_token"], resource.compact());
    live.observe_token_response(resource.compact(), br#"{"error":"revoked_resource_token"}"#);
    assert_eq!(
        child
            .auth_request(
                &parent,
                "https://ps.example/auth",
                &resource,
                &person,
                &Keys,
                1000,
                &live,
            )
            .unwrap_err(),
        TokenError::InvalidJwt
    );
    let other = signed(
        "resource",
        &json!({"iss":RESOURCE,"dwk":"aauth-resource.json","aud":PS,
            "ps":PS,"sub":"directed-person","jti":"resource-b","iat":1000,"exp":1300,
            "presented_jti":"person",
            "agent_jkt":SigningKey::from_seed([3;32]).public_jwk().thumbprint().unwrap(),
            "scope":"read"}),
        5,
    );
    let other = child
        .verify_resource_challenge(&other, RESOURCE, PS, &person, &Keys, 1000)
        .unwrap();
    assert!(
        child
            .auth_request(
                &parent,
                "https://ps.example/auth",
                &other,
                &person,
                &Keys,
                1000,
                &live,
            )
            .is_ok()
    );
}
