//! A Resource's `additional_signature_components` are covered on every
//! request the Agent signs for it, or signing is refused.
use std::collections::BTreeMap;

use aauth_rust_agent::{Agent, PollError, PollSession, R3AgentError};
use aauth_rust_core::continuation::{PendingResponse, Requirement};
use aauth_rust_core::{Confirmation, PersonClaims, mint_person_token};
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_r3::standard_registry;
use aauth_rust_signature_key::{Error, PreparedRequest};
use http::Request;
use serde_json::{Value, json};

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

fn person(agent: &Agent) -> String {
    mint_person_token(
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
    .unwrap()
}

/// The published array, read from the Resource's metadata document.
fn published(metadata: &Value) -> Vec<&str> {
    metadata["additional_signature_components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component.as_str().unwrap())
        .collect()
}

fn covered(request: &Request<Vec<u8>>) -> &str {
    request.headers()["signature-input"].to_str().unwrap()
}

fn base(request: &Request<Vec<u8>>, signer: &Agent, now: i64) -> String {
    let proof = PreparedRequest::prepare(request, "sig", now, 60).unwrap();
    proof.verify(&signer.public_jwk()).unwrap();
    String::from_utf8(proof.signature_base().to_vec()).unwrap()
}

#[test]
fn an_agent_covers_a_resources_additional_signature_components() {
    let plain = agent();
    let metadata = json!({
        "issuer": RESOURCE,
        "additional_signature_components": ["x-tenant", "content-digest"]
    });
    let agent = plain.with_additional_signature_components(published(&metadata));

    // An application call carrying the listed field.
    let mut call = Request::get("https://resource.example/records?id=7")
        .header("x-tenant", "acme")
        .body(Vec::new())
        .unwrap();
    agent.sign(&mut call, NOW).unwrap();
    assert_eq!(
        covered(&call),
        format!(
            "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\" \"x-tenant\" \"signature-key\");created={NOW}"
        )
    );
    assert!(base(&call, &agent, NOW).contains("\n\"x-tenant\": acme\n"));
    call.headers_mut()
        .insert("x-tenant", "other".parse().unwrap());
    assert!(
        PreparedRequest::prepare(&call, "sig", NOW, 60)
            .unwrap()
            .verify(&agent.public_jwk())
            .is_err()
    );

    // Without the list, the same call covers only the base components.
    let mut call = Request::get("https://resource.example/records?id=7")
        .header("x-tenant", "acme")
        .body(Vec::new())
        .unwrap();
    plain.sign(&mut call, NOW).unwrap();
    assert_eq!(
        covered(&call),
        format!(
            "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created={NOW}"
        )
    );

    // Presenting a Person token keeps the list.
    let presenting = agent.with_token(person(&plain)).unwrap();
    let mut call = Request::post("https://resource.example/records")
        .header("content-type", "application/json")
        .header("x-tenant", "acme")
        .body(br#"{"title":"draft"}"#.to_vec())
        .unwrap();
    presenting.sign(&mut call, NOW).unwrap();
    assert_eq!(
        covered(&call),
        format!(
            "sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"x-tenant\" \"signature-key\");created={NOW}"
        )
    );
    base(&call, &presenting, NOW);

    // A call without the listed field is refused, not signed without it.
    let mut call = Request::get("https://resource.example/records")
        .body(Vec::new())
        .unwrap();
    assert_eq!(agent.sign(&mut call, NOW), Err(Error::InvalidInput));
    assert!(!call.headers().contains_key("signature-input"));
    for listed in ["X-Tenant", "@target-uri", "signature"] {
        let mut call = Request::get("https://resource.example/records")
            .header("x-tenant", "acme")
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            plain
                .with_additional_signature_components([listed])
                .sign(&mut call, NOW),
            Err(Error::InvalidInput),
            "{listed}"
        );
    }
}

#[test]
fn r3_authorization_and_polls_cover_the_listed_components() {
    let plain = agent();
    let person = person(&plain);
    let operations = standard_registry()
        .unwrap()
        .parse_operation_set(
            br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}"#,
        )
        .unwrap();

    // The authorization endpoint request carries a body, so a listed
    // content-type and content-digest are covered; a listed @query is added.
    let agent =
        plain.with_additional_signature_components(["content-type", "content-digest", "@query"]);
    let request = agent
        .r3_authorization_request(
            "https://resource.example/authorize",
            &person,
            &operations,
            None,
            NOW,
        )
        .unwrap();
    assert_eq!(
        covered(&request),
        format!(
            "sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"@query\" \"signature-key\");created={NOW}"
        )
    );
    assert!(base(&request, &plain, NOW).contains("\n\"@query\": ?\n"));

    // A listed field the library cannot add to its own request refuses signing.
    assert!(matches!(
        plain
            .with_additional_signature_components(["x-tenant"])
            .r3_authorization_request(
                "https://resource.example/authorize",
                &person,
                &operations,
                None,
                NOW,
            ),
        Err(R3AgentError::Signing(Error::InvalidInput))
    ));

    // A poll of the Resource's pending URL covers the list too.
    let held = PendingResponse::new(
        "https://resource.example/records",
        "/pending/opaque",
        5,
        Requirement::Approval,
    )
    .unwrap()
    .response()
    .unwrap();
    let session =
        PollSession::new("https://resource.example/records", &held, NOW, NOW + 100).unwrap();
    let agent = plain.with_additional_signature_components(["content-digest", "@query"]);
    let poll = session.request(&agent, NOW + 5).unwrap();
    assert_eq!(poll.uri(), "https://resource.example/pending/opaque");
    assert_eq!(
        covered(&poll),
        format!(
            "sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"@query\" \"signature-key\");created={}",
            NOW + 5
        )
    );
    base(&poll, &plain, NOW + 5);
    assert!(matches!(
        session.request(
            &plain.with_additional_signature_components(["x-tenant"]),
            NOW + 5
        ),
        Err(PollError::Signing)
    ));
}
