//! A Resource's `additional_signature_components` are covered on every
//! request the Agent signs for it, or signing is refused. The Agent reads
//! them from the Resource's metadata document or from an `invalid_input`
//! refusal.
use std::collections::BTreeMap;

use aauth_rust_agent::{Agent, PollError, PollSession, R3AgentError, SignatureComponentsError};
use aauth_rust_core::continuation::{PendingResponse, Requirement};
use aauth_rust_core::{Confirmation, PersonClaims, mint_person_token};
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_r3::standard_registry;
use aauth_rust_signature_key::{Error, PreparedRequest};
use http::{HeaderMap, Request};
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
    let agent = plain
        .with_resource_metadata(RESOURCE, metadata.to_string().as_bytes())
        .unwrap();

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

#[test]
fn metadata_is_used_only_when_it_is_the_resources_own() {
    let plain = agent();
    // aauth-go's agent-identity Resource can list content-digest, so an empty
    // GET must carry a digest of the empty body.
    let metadata =
        br#"{"issuer":"https://resource.example","additional_signature_components":["content-digest"]}"#;
    let agent = plain.with_resource_metadata(RESOURCE, metadata).unwrap();
    let mut call = Request::get("https://resource.example/hello")
        .body(Vec::new())
        .unwrap();
    agent.sign(&mut call, NOW).unwrap();
    assert_eq!(
        covered(&call),
        format!(
            "sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"signature-key\");created={NOW}"
        )
    );
    base(&call, &agent, NOW);

    // A document without the member lists nothing, replacing the earlier list.
    let bare = agent
        .with_resource_metadata(RESOURCE, br#"{"issuer":"https://resource.example"}"#)
        .unwrap();
    let mut call = Request::get("https://resource.example/hello")
        .body(Vec::new())
        .unwrap();
    bare.sign(&mut call, NOW).unwrap();
    assert!(!covered(&call).contains("content-digest"));

    let refused: [(&[u8], SignatureComponentsError); 6] = [
        (
            br#"{"additional_signature_components":["content-digest"]}"#,
            SignatureComponentsError::IssuerMissing,
        ),
        (
            br#"{"issuer":"https://resource.example/","additional_signature_components":[]}"#,
            SignatureComponentsError::IssuerMismatch,
        ),
        (
            br#"{"issuer":"https://other.example"}"#,
            SignatureComponentsError::IssuerMismatch,
        ),
        (
            br#"{"issuer":"https://resource.example","additional_signature_components":"content-digest"}"#,
            SignatureComponentsError::MalformedMetadata,
        ),
        (
            br#"{"issuer":"https://resource.example","additional_signature_components":[7]}"#,
            SignatureComponentsError::MalformedMetadata,
        ),
        (
            br#"["https://resource.example"]"#,
            SignatureComponentsError::MalformedMetadata,
        ),
    ];
    for (document, error) in refused {
        assert_eq!(
            plain.with_resource_metadata(RESOURCE, document).err(),
            Some(error),
            "{}",
            String::from_utf8_lossy(document)
        );
    }
}

fn refusal(field: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("signature-error", field.parse().unwrap());
    headers
}

#[test]
fn an_invalid_input_refusal_adds_what_the_refused_signature_missed() {
    let plain = agent();
    let mut call = Request::get("https://resource.example/records")
        .header("x-tenant", "acme")
        .body(Vec::new())
        .unwrap();
    plain.sign(&mut call, NOW).unwrap();
    // As a Resource requiring a digest and a tenant header answers.
    let refused = refusal(
        r#"error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key" "content-digest" "x-tenant")"#,
    );
    let retry = plain.with_required_input(&call, &refused).unwrap();
    retry.sign(&mut call, NOW).unwrap();
    assert_eq!(
        covered(&call),
        format!(
            "sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"x-tenant\" \"signature-key\");created={NOW}"
        )
    );
    base(&call, &retry, NOW);
    // The retried request covers it all, so the same refusal teaches nothing.
    assert_eq!(
        retry.with_required_input(&call, &refused).err(),
        Some(SignatureComponentsError::AlreadyCovered)
    );
    // A component the signature covered because the request had it is not
    // added: a later call without a query still signs.
    let mut queried = Request::get("https://resource.example/records?id=7")
        .body(Vec::new())
        .unwrap();
    plain.sign(&mut queried, NOW).unwrap();
    let learned = plain
        .with_required_input(
            &queried,
            &refusal(
                r#"error=invalid_input, required_input=("@method" "@authority" "@path" "@query" "signature-key" "content-digest")"#,
            ),
        )
        .unwrap();
    let mut later = Request::get("https://resource.example/records")
        .body(Vec::new())
        .unwrap();
    learned.sign(&mut later, NOW).unwrap();
    assert!(!covered(&later).contains("@query"));
    assert!(covered(&later).contains("content-digest"));

    for (headers, error) in [
        (
            refusal("error=invalid_signature"),
            SignatureComponentsError::NoRequiredInput,
        ),
        (
            refusal("error=invalid_input"),
            SignatureComponentsError::NoRequiredInput,
        ),
        (
            refusal(r#"error=invalid_input, required_input=(content-digest)"#),
            SignatureComponentsError::NoRequiredInput,
        ),
        (HeaderMap::new(), SignatureComponentsError::NoRequiredInput),
    ] {
        assert_eq!(
            plain.with_required_input(&queried, &headers).err(),
            Some(error)
        );
    }
    let unsigned = Request::get("https://resource.example/records")
        .body(Vec::<u8>::new())
        .unwrap();
    assert_eq!(
        plain.with_required_input(&unsigned, &refused).err(),
        Some(SignatureComponentsError::Unsigned)
    );
}
