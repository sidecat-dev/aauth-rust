//! A `401` from the R3 authorization endpoint is read from `Signature-Error`,
//! never from the response body.
use std::collections::BTreeMap;
use std::convert::Infallible;

use aauth_rust_agent::{Agent, R3AgentError};
use aauth_rust_core::{Confirmation, PersonClaims, mint_person_token};
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_r3::standard_registry;
use http::Response;
use serde_json::json;

const NOW: i64 = 1_700_000_000;
const RESOURCE: &str = "https://resource.example";
const PS: &str = "https://ps.example";

fn agent() -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let token = Jws::sign(
        &json!({"typ": "aa-agent+jwt", "alg": "Ed25519", "kid": "ap"}),
        json!({
            "iss": "https://ap.example",
            "dwk": "aauth-agent.json",
            "sub": "aauth:caller@ap.example",
            "jti": "agent-1",
            "iat": NOW,
            "exp": NOW + 3600,
            "ps": PS,
            "cnf": {"jwk": key.public_jwk()}
        })
        .to_string()
        .as_bytes(),
        &SigningKey::from_seed([1; 32]),
    )
    .unwrap();
    Agent::new(key, token).unwrap()
}

/// Send one authorization request and return how the Agent read the answer.
fn refusal(response: Response<Vec<u8>>) -> (u16, Option<String>) {
    let agent = agent();
    let person = mint_person_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &PersonClaims {
            iss: PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RESOURCE.into(),
            sub: "person-1".into(),
            jti: "person-1".into(),
            iat: NOW,
            exp: NOW + 3600,
            cnf: Confirmation {
                jwk: agent.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )
    .unwrap();
    let operations = standard_registry()
        .unwrap()
        .parse_operation_set(
            br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}"#,
        )
        .unwrap();
    match agent.r3_authorize(
        |_request| Ok::<_, Infallible>(response),
        "https://resource.example/authorize",
        &person,
        &operations,
        None,
        NOW,
    ) {
        Err(R3AgentError::Refused { status, error }) => (status, error),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn problem(status: u16) -> http::response::Builder {
    Response::builder()
        .status(status)
        .header("content-type", "application/problem+json")
}

fn body(error: &str) -> Vec<u8> {
    json!({"error": error, "detail": "from the body"})
        .to_string()
        .into_bytes()
}

#[test]
fn a_401_takes_its_error_from_signature_error_never_the_body() {
    // The header carries the code; a disagreeing body is not consulted.
    assert_eq!(
        refusal(
            problem(401)
                .header("signature-error", "error=clock_skew")
                .body(body("invalid_request"))
                .unwrap()
        ),
        (401, Some("clock_skew".into()))
    );
    // Field lines combine as one dictionary; other members are ignored.
    assert_eq!(
        refusal(
            problem(401)
                .header("signature-error", "note=1")
                .header(
                    "signature-error",
                    "error=invalid_input, required_input=(\"content-digest\")"
                )
                .body(body("invalid_request"))
                .unwrap()
        ),
        (401, Some("invalid_input".into()))
    );
    // Without a usable header the error is unknown; the body is no fallback.
    assert_eq!(
        refusal(problem(401).body(body("invalid_signature")).unwrap()),
        (401, None)
    );
    assert_eq!(
        refusal(
            problem(401)
                .header("signature-error", "error=\"invalid_key\"")
                .body(body("invalid_key"))
                .unwrap()
        ),
        (401, None)
    );
    // Other refusals still carry the problem body's error member.
    assert_eq!(
        refusal(problem(400).body(body("invalid_request")).unwrap()),
        (400, Some("invalid_request".into()))
    );
}
