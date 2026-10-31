use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::{
    Error, KeyMaterial, PreparedResponse, accept_signature_components, sign_request, sign_response,
};
use http::{Request, Response};

const COVERED: [&str; 6] = [
    "@status",
    "content-type",
    "content-digest",
    "content-digest;req",
    "@authority;req",
    "@path;req",
];

fn exchange() -> (Request<Vec<u8>>, Response<Vec<u8>>, SigningKey) {
    let mut request = Request::builder()
        .method("POST")
        .uri("https://ss.example/decision")
        .header("content-type", "application/json")
        .body(br#"{"sdi":"d-1"}"#.to_vec())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([3; 32]),
        KeyMaterial::JwksUri {
            id: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-1".into(),
        },
        1000,
    )
    .unwrap();
    let mut response = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(br#"{"sdi":"d-1","decision":"allow"}"#.to_vec())
        .unwrap();
    let key = SigningKey::from_seed([9; 32]);
    sign_response(
        &mut response,
        &request,
        &key,
        KeyMaterial::JwksUri {
            id: "https://ss.example".into(),
            dwk: "aauth-supervisor.json".into(),
            kid: "ss-1".into(),
        },
        &COVERED,
        1010,
    )
    .unwrap();
    (request, response, key)
}

#[test]
fn a_response_signature_names_its_signer_and_binds_its_request() {
    let (request, response, key) = exchange();
    assert_eq!(
        response.headers()["signature-key"],
        "sig=jwks_uri;id=\"https://ss.example\";dwk=\"aauth-supervisor.json\";kid=\"ss-1\""
    );
    let prepared = PreparedResponse::prepare(&response, &request, "sig", &["jwks_uri"]).unwrap();
    prepared.verify(&key.public_jwk()).unwrap();
    assert_eq!(prepared.created(), 1010);
    assert!(COVERED.iter().all(|c| prepared.covers(c)));
    let digest = response.headers()["content-digest"].to_str().unwrap();
    let request_digest = request.headers()["content-digest"].to_str().unwrap();
    let expected = format!(
        "\"@status\": 200\n\"content-type\": application/json\n\"content-digest\": {digest}\n\"content-digest\";req: {request_digest}\n\"@authority\";req: ss.example\n\"@path\";req: /decision\n\"@signature-params\": (\"@status\" \"content-type\" \"content-digest\" \"content-digest\";req \"@authority\";req \"@path\";req);created=1010;keyid=\"ss-1\""
    );
    assert_eq!(prepared.signature_base(), expected.as_bytes());

    // Another request, another status, or other content does not verify.
    let mut other = request.clone();
    *other.uri_mut() = "https://ss.example/mission".parse().unwrap();
    let mut refused = response.clone();
    *refused.status_mut() = http::StatusCode::CREATED;
    let mut altered = response.clone();
    *altered.body_mut() = br#"{"sdi":"d-1","decision":"deny"}"#.to_vec();
    for (response, request) in [(&response, &other), (&refused, &request)] {
        let prepared = PreparedResponse::prepare(response, request, "sig", &["jwks_uri"]).unwrap();
        assert_eq!(
            prepared.verify(&key.public_jwk()),
            Err(Error::InvalidSignature)
        );
    }
    assert_eq!(
        PreparedResponse::prepare(&altered, &request, "sig", &["jwks_uri"]).unwrap_err(),
        Error::InvalidDigest
    );
    assert_eq!(
        PreparedResponse::prepare(&response, &request, "sig", &["hwk"]).unwrap_err(),
        Error::UnsupportedScheme
    );
}

#[test]
fn only_coverable_components_are_signed() {
    let (request, _, key) = exchange();
    let material = || KeyMaterial::JwksUri {
        id: "https://ss.example".into(),
        dwk: "aauth-supervisor.json".into(),
        kid: "ss-1".into(),
    };
    for listed in [
        &["@status", "@status"][..],
        &["@method"],
        &["@status;req"],
        &["x-absent"],
        &["x-absent;req"],
        &[],
    ] {
        let mut response = Response::builder().status(200).body(Vec::new()).unwrap();
        assert_eq!(
            sign_response(&mut response, &request, &key, material(), listed, 1010),
            Err(Error::InvalidInput),
            "{listed:?}"
        );
        assert!(!response.headers().contains_key("signature"));
    }
    assert_eq!(
        accept_signature_components(
            "sig=(\"@status\" \"content-digest\";req \"@path\";req)",
            "sig"
        )
        .unwrap(),
        ["@status", "content-digest;req", "@path;req"]
    );
}
