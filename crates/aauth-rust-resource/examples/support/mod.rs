mod tls;
use aauth_rust_agent::Agent;
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentProviderKeys, Confirmation, VerifiedAgentToken, metadata_jwks_uri,
};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::AgentIdentityResource;
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest, sign_request};
use http::{Request, Response};
use std::sync::Arc;

pub struct Observation {
    pub scenario: &'static str,
    pub status: u16,
    pub detail: String,
}
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn request(uri: &str) -> Request<Vec<u8>> {
    Request::builder().uri(uri).body(Vec::new()).unwrap()
}
fn observe(scenario: &'static str, response: Response<Vec<u8>>) -> Observation {
    let detail = if response.status() == 403 {
        "no signature diagnostics".into()
    } else if let Some(h) = response
        .headers()
        .get("aauth-requirement")
        .or_else(|| response.headers().get("signature-error"))
    {
        h.to_str().unwrap().split(',').next().unwrap().to_owned()
    } else {
        String::from_utf8_lossy(response.body()).into_owned()
    };
    Observation {
        scenario,
        status: response.status().as_u16(),
        detail,
    }
}
fn agent(ap: &AgentProvider, key: SigningKey, name: &str, iat: i64, exp: i64) -> Result<Agent> {
    let claims = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: format!("aauth:{name}@ap.example"),
        jti: format!("{name}-{iat}-{exp}"),
        iat,
        exp,
        cnf: Confirmation {
            jwk: key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    Ok(Agent::new(key, ap.issue(&claims)?)?)
}
/// All sockets, certificates and keys are scoped to this invocation. Fixed time
/// makes refusal boundaries reproducible; random keys are generated each run.
pub fn run() -> Result<Vec<Observation>> {
    let ap = Arc::new(AgentProvider::new(
        "https://ap.example",
        "ap-1",
        SigningKey::generate(),
    )?);
    let serving = ap.clone();
    let ap_tls = tls::TlsServer::start("ap.example", move |req| {
        let body = match req.uri().path() {
            "/.well-known/aauth-agent.json" => serving.metadata(),
            "/.well-known/jwks.json" => serving.jwks(),
            _ => return Response::builder().status(404).body(Vec::new()).unwrap(),
        };
        Response::builder()
            .header("content-type", "application/json")
            .body(body.unwrap())
            .unwrap()
    })?;
    let metadata = ap_tls.send(&request("https://ap.example/.well-known/aauth-agent.json"))?;
    if metadata.status() != 200 {
        return Err("AP metadata unavailable".into());
    }
    let jwks_uri = metadata_jwks_uri("https://ap.example", metadata.body())?;
    // No redirects or open-ended egress: exactly this configured AP endpoint.
    if jwks_uri != "https://ap.example/.well-known/jwks.json" {
        return Err("JWKS egress admission refused".into());
    }
    let jwks = ap_tls.send(&request(&jwks_uri))?;
    if jwks.status() != 200 {
        return Err("AP JWKS unavailable".into());
    }
    let keys =
        AgentProviderKeys::from_documents("https://ap.example", metadata.body(), jwks.body())?;
    let resource = AgentIdentityResource::new(
        "https://resource.example/whoami",
        keys,
        |token: &VerifiedAgentToken, _request: &Request<Vec<u8>>| {
            token.claims().sub != "aauth:Denied@ap.example"
        },
    )?;
    let resource_tls = tls::TlsServer::start("resource.example", move |req| {
        if req.uri().path() == "/proof" {
            let valid = PreparedRequest::prepare(&req, "sig", 1000, 60).is_ok_and(|proof| {
                match proof.key() {
                    KeyMaterial::Hwk(key) => proof.verify(key).is_ok(),
                    _ => false,
                }
            });
            return Response::builder()
                .status(if valid { 200 } else { 401 })
                .body(b"pseudonymous proof verified".to_vec())
                .unwrap();
        }
        resource.authorize(&req, 1000).into_response()
    })?;
    let mut observations = vec![
        Observation {
            scenario: "ap-metadata",
            status: 200,
            detail: "issuer and jwks_uri".into(),
        },
        Observation {
            scenario: "ap-jwks",
            status: 200,
            detail: "Ed25519 issuer key".into(),
        },
    ];
    let valid = agent(&ap, SigningKey::generate(), "Agent", 1000, 2000)?;
    let send = |name, req: &Request<Vec<u8>>| -> Result<Observation> {
        Ok(observe(name, resource_tls.send(req)?))
    };
    let fresh = || request("https://resource.example/whoami");
    observations.push(send("unsigned", &fresh())?);
    let mut req = fresh();
    valid.sign(&mut req, 1000)?;
    observations.push(send("valid-identity", &req)?);
    let hwk = SigningKey::generate();
    let mut req = request("https://resource.example/proof");
    sign_request(&mut req, &hwk, KeyMaterial::Hwk(hwk.public_jwk()), 1000)?;
    observations.push(send("hwk-proof", &req)?);
    let mut req = fresh();
    sign_request(&mut req, &hwk, KeyMaterial::Hwk(hwk.public_jwk()), 1000)?;
    observations.push(send("hwk-identity", &req)?);
    let mut req = fresh();
    valid.sign(&mut req, 1000)?;
    let mut corrupted = req.headers()["signature"].as_bytes().to_vec();
    corrupted[5] = if corrupted[5] == b'A' { b'B' } else { b'A' };
    req.headers_mut()
        .insert("signature", http::HeaderValue::from_bytes(&corrupted)?);
    observations.push(send("tampered-signature", &req)?);
    let expired = agent(&ap, SigningKey::generate(), "Expired", 900, 999)?;
    let mut req = fresh();
    expired.sign(&mut req, 1000)?;
    observations.push(send("expired-token", &req)?);
    let mut req = fresh();
    valid.sign(&mut req, 1000)?;
    let input = req.headers()["signature-input"]
        .to_str()?
        .replace(" \"signature-key\"", "");
    req.headers_mut().insert("signature-input", input.parse()?);
    observations.push(send("uncovered-key", &req)?);
    let mut req = fresh();
    valid.sign(&mut req, 1061)?;
    observations.push(send("future-created", &req)?);
    let future = agent(&ap, SigningKey::generate(), "Future", 1061, 2000)?;
    let mut req = fresh();
    future.sign(&mut req, 1000)?;
    observations.push(send("future-iat", &req)?);
    let mut req = fresh();
    sign_request(
        &mut req,
        &SigningKey::generate(),
        KeyMaterial::Jwt {
            jwt: valid.token().into(),
            cache: false,
        },
        1000,
    )?;
    observations.push(send("wrong-confirmation-key", &req)?);
    let denied = agent(&ap, SigningKey::generate(), "Denied", 1000, 2000)?;
    let mut req = fresh();
    denied.sign(&mut req, 1000)?;
    let response = resource_tls.send(&req)?;
    if response.headers().contains_key("signature-error")
        || response.headers().contains_key("accept-signature-alg")
        || response.headers().contains_key("accept-signature-scheme")
    {
        return Err("policy denial leaked signature diagnostics".into());
    }
    observations.push(observe("policy-denial", response));
    if !resource_tls.refuses_untrusted_certificate() {
        return Err("untrusted TLS certificate was not refused as UnknownIssuer".into());
    }
    observations.push(Observation {
        scenario: "untrusted-tls",
        status: 0,
        detail: "certificate refused".into(),
    });
    Ok(observations)
}
