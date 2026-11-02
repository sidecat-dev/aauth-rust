use aauth_rust_agent::{BootstrapClient, BootstrapError, Subagent, issued_agent_token};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::bootstrap::{
    AgentGrant, BootstrapEndpoints, BootstrapPolicy, BootstrapService, BootstrapStore, Denial,
    EnrollmentApproval, EnrollmentRequest, EnrollmentState, MemoryBootstrapStore, RefreshRequest,
    SubagentRequest, thumbprint_local_part,
};
use aauth_rust_core::{AgentProviderKeys, AgentToken, TokenError};
use aauth_rust_jose::{Jws, SigningKey};
use http::Request;
use serde_json::{Value, json};

const AP: &str = "https://ap.example";
const PS: &str = "https://ps.example";
const NOW: i64 = 1_800_000_000;

struct Policy;
impl BootstrapPolicy for Policy {
    fn enroll(&self, request: &EnrollmentRequest<'_>) -> Result<EnrollmentApproval, Denial> {
        if request.evidence.get("blocked").is_some() {
            return Err(Denial::default());
        }
        Ok(EnrollmentApproval {
            local: thumbprint_local_part(request),
            account: Some("account-1".into()),
        })
    }
    fn refresh(&self, request: &RefreshRequest<'_>) -> Result<AgentGrant, Denial> {
        let grant = AgentGrant::new(3600);
        Ok(match request.ps {
            Some(ps) => grant.with_ps(ps),
            None => grant,
        })
    }
    fn subagent(&self, request: &SubagentRequest<'_>) -> Result<i64, Denial> {
        if request.live.len() >= 2 {
            return Err(Denial {
                reason: Some("two live sub-agents at most".into()),
            });
        }
        Ok(7200)
    }
}

fn provider() -> AgentProvider {
    AgentProvider::new(AP, "ap-1", SigningKey::from_seed([1; 32])).unwrap()
}

fn service() -> BootstrapService<MemoryBootstrapStore, Policy> {
    BootstrapService::new(
        provider(),
        BootstrapEndpoints {
            enrollment: format!("{AP}/enroll"),
            refresh: format!("{AP}/refresh"),
            single_key_refresh: Some(format!("{AP}/refresh-single-key")),
            subagent: Some(format!("{AP}/subagent")),
        },
        MemoryBootstrapStore::new(),
        Policy,
    )
    .unwrap()
}

fn keys(service: &BootstrapService<MemoryBootstrapStore, Policy>) -> AgentProviderKeys {
    let provider = service.provider();
    AgentProviderKeys::from_documents(AP, &provider.metadata().unwrap(), &provider.jwks().unwrap())
        .unwrap()
}

fn status(
    service: &BootstrapService<MemoryBootstrapStore, Policy>,
    request: &Request<Vec<u8>>,
) -> u16 {
    service
        .handle(request, NOW)
        .into_response()
        .status()
        .as_u16()
}

#[test]
fn an_install_enrolls_refreshes_with_fresh_keys_and_keeps_its_identifier() {
    let service = service();
    let keys = keys(&service);
    let mut client = BootstrapClient::new(SigningKey::from_seed([2; 32]), AP).unwrap();
    assert!(client.needs_refresh(NOW));

    let enroll = client
        .enrollment_request(&format!("{AP}/enroll"), &json!({}), NOW)
        .unwrap();
    let answer = service.handle(&enroll, NOW).into_response();
    assert_eq!(answer.status(), 201);
    assert_eq!(
        status(&service, &enroll),
        200,
        "a repeated enrollment answers its record"
    );

    let first = client
        .refresh_request(&format!("{AP}/refresh"), Some(PS), &json!({}), NOW)
        .unwrap();
    let answer = service.handle(first.request(), NOW).into_response();
    assert_eq!(answer.headers()["cache-control"], "no-store");
    let replay = service.handle(first.request(), NOW).into_response();
    assert_eq!(replay.status(), 401, "a naming JWT names one refresh");
    let agent = client.complete_refresh(first, &answer, &keys, NOW).unwrap();
    let claims = AgentToken::parse(agent.token())
        .unwrap()
        .verify(&keys, NOW)
        .unwrap()
        .claims()
        .clone();
    assert_eq!(claims.ps.as_deref(), Some(PS));
    assert_eq!(claims.exp - claims.iat, 3600);
    assert_ne!(
        claims.cnf.jwk.thumbprint().unwrap(),
        client.durable_jwk().thumbprint().unwrap()
    );
    assert!(!client.needs_refresh(NOW));
    assert!(client.needs_refresh(NOW + 3600 - 299));

    let second = client
        .refresh_request(&format!("{AP}/refresh"), Some(PS), &json!({}), NOW)
        .unwrap();
    let answer = service.handle(second.request(), NOW).into_response();
    let rotated = client
        .complete_refresh(second, &answer, &keys, NOW)
        .unwrap();
    let rotated = AgentToken::parse(rotated.token()).unwrap();
    assert_eq!(rotated.unverified_claims().sub, claims.sub);
    assert_ne!(
        rotated.unverified_claims().cnf.jwk.thumbprint().unwrap(),
        claims.cnf.jwk.thumbprint().unwrap()
    );

    let single = client
        .single_key_refresh_request(&format!("{AP}/refresh-single-key"), None, &json!({}), NOW)
        .unwrap();
    let answer = service.handle(single.request(), NOW).into_response();
    let single = client
        .complete_refresh(single, &answer, &keys, NOW)
        .unwrap();
    assert_eq!(
        single.public_jwk().thumbprint().unwrap(),
        client.durable_jwk().thumbprint().unwrap()
    );

    let thumbprint = client.durable_jwk().thumbprint().unwrap();
    service
        .store()
        .set_state(&thumbprint, EnrollmentState::Revoked)
        .unwrap();
    let refused = client
        .refresh_request(&format!("{AP}/refresh"), Some(PS), &json!({}), NOW)
        .unwrap();
    assert_eq!(status(&service, refused.request()), 403);
    assert_eq!(status(&service, &enroll), 403);
}

#[test]
fn installs_get_their_own_identifiers_and_unknown_or_forged_keys_are_refused() {
    let service = service();
    let keys = keys(&service);
    let mut subjects = Vec::new();
    for seed in [2, 3] {
        let mut client = BootstrapClient::new(SigningKey::from_seed([seed; 32]), AP).unwrap();
        let enroll = client
            .enrollment_request(&format!("{AP}/enroll"), &json!({}), NOW)
            .unwrap();
        assert_eq!(status(&service, &enroll), 201);
        let pending = client
            .refresh_request(&format!("{AP}/refresh"), None, &json!({}), NOW)
            .unwrap();
        let answer = service.handle(pending.request(), NOW).into_response();
        client
            .complete_refresh(pending, &answer, &keys, NOW)
            .unwrap();
        subjects.push(client.agent().unwrap().to_owned());
    }
    assert_ne!(subjects[0], subjects[1]);

    let stranger = BootstrapClient::new(SigningKey::from_seed([4; 32]), AP).unwrap();
    let pending = stranger
        .refresh_request(&format!("{AP}/refresh"), None, &json!({}), NOW)
        .unwrap();
    let answer = service.handle(pending.request(), NOW).into_response();
    assert_eq!(answer.status(), 404);
    let body: Value = serde_json::from_slice(answer.body()).unwrap();
    assert_eq!(body["error"], "enrollment_not_found");

    let blocked = stranger
        .enrollment_request(&format!("{AP}/enroll"), &json!({"blocked": true}), NOW)
        .unwrap();
    assert_eq!(status(&service, &blocked), 403);

    // An enrolled durable key's refresh whose naming JWT is swapped for one
    // with an iss that names another key. The signer refuses to produce
    // one, so the Signature-Key field is replaced after signing.
    let enrolled = BootstrapClient::new(SigningKey::from_seed([2; 32]), AP).unwrap();
    let pending = enrolled
        .refresh_request(&format!("{AP}/refresh"), None, &json!({}), NOW)
        .unwrap();
    let durable = SigningKey::from_seed([2; 32]);
    let other = SigningKey::from_seed([9; 32])
        .public_jwk()
        .thumbprint()
        .unwrap();
    let naming = Jws::sign(
        &json!({"typ":"jkt-s256+jwt","alg":"Ed25519","jwk":durable.public_jwk()}),
        &serde_json::to_vec(&json!({"iss":format!("urn:jkt:sha-256:{other}"),"iat":NOW,
            "exp":NOW+60,"jti":"forged","cnf":{"jwk":SigningKey::generate().public_jwk()}}))
        .unwrap(),
        &durable,
    )
    .unwrap();
    let signed = pending.request();
    let mut forged = Request::builder()
        .method("POST")
        .uri(signed.uri())
        .body(signed.body().clone())
        .unwrap();
    *forged.headers_mut() = signed.headers().clone();
    forged.headers_mut().insert(
        "signature-key",
        format!("sig=jkt-jwt;jwt=\"{naming}\"").parse().unwrap(),
    );
    let answer = service.handle(&forged, NOW).into_response();
    assert_eq!(answer.status(), 401);
    assert_eq!(answer.headers()["signature-error"], "error=invalid_jwt");
}

#[test]
fn a_parent_gets_sub_agents_that_cannot_outlive_it_or_have_their_own() {
    let service = service();
    let keys = keys(&service);
    let mut client = BootstrapClient::new(SigningKey::from_seed([2; 32]), AP).unwrap();
    let enroll = client
        .enrollment_request(&format!("{AP}/enroll"), &json!({}), NOW)
        .unwrap();
    assert_eq!(status(&service, &enroll), 201);
    let pending = client
        .refresh_request(&format!("{AP}/refresh"), Some(PS), &json!({}), NOW)
        .unwrap();
    let answer = service.handle(pending.request(), NOW).into_response();
    let parent = client
        .complete_refresh(pending, &answer, &keys, NOW)
        .unwrap();

    let child_key = SigningKey::from_seed([5; 32]);
    let request = parent
        .subagent_request(
            &format!("{AP}/subagent"),
            &child_key.public_jwk(),
            Some("search1"),
            NOW,
        )
        .unwrap();
    let child = issued_agent_token(&service.handle(&request, NOW).into_response()).unwrap();
    let verified = Subagent::verify(parent.token(), &child, &keys, NOW).unwrap();
    let child_claims = verified.token().claims();
    let parent_claims = verified.parent().claims();
    assert!(
        child_claims
            .sub
            .starts_with(&parent_claims.sub[..parent_claims.sub.find('@').unwrap()])
    );
    assert!(child_claims.sub.contains("+search1@"));
    assert_eq!(child_claims.ps, parent_claims.ps);
    assert_eq!(
        child_claims.exp, parent_claims.exp,
        "7200 s is capped at the parent's exp"
    );

    // The same discriminator while the first is live: the provider picks one.
    let again = parent
        .subagent_request(
            &format!("{AP}/subagent"),
            &SigningKey::from_seed([6; 32]).public_jwk(),
            Some("search1"),
            NOW,
        )
        .unwrap();
    let second = issued_agent_token(&service.handle(&again, NOW).into_response()).unwrap();
    let second = AgentToken::parse(&second).unwrap();
    assert_ne!(second.unverified_claims().sub, child_claims.sub);

    // Policy allows two live sub-agents.
    let third = parent
        .subagent_request(
            &format!("{AP}/subagent"),
            &SigningKey::from_seed([7; 32]).public_jwk(),
            None,
            NOW,
        )
        .unwrap();
    assert_eq!(status(&service, &third), 403);

    // A sub-agent asking for its own sub-agent.
    let nested = aauth_rust_agent::Agent::new(child_key, child)
        .unwrap()
        .subagent_request(
            &format!("{AP}/subagent"),
            &SigningKey::from_seed([8; 32]).public_jwk(),
            None,
            NOW,
        )
        .unwrap();
    assert_eq!(status(&service, &nested), 403);

    // A parent token from another provider.
    let foreign = AgentProvider::new(
        "https://other.example",
        "ap-1",
        SigningKey::from_seed([1; 32]),
    )
    .unwrap();
    let foreign_token = foreign
        .issue_to(
            "aauth:parent@other.example",
            &SigningKey::from_seed([2; 32]).public_jwk(),
            &AgentGrant::new(3600),
            NOW,
        )
        .unwrap();
    let foreign_parent =
        aauth_rust_agent::Agent::new(SigningKey::from_seed([2; 32]), foreign_token.token).unwrap();
    let request = foreign_parent
        .subagent_request(
            &format!("{AP}/subagent"),
            &SigningKey::from_seed([9; 32]).public_jwk(),
            None,
            NOW,
        )
        .unwrap();
    assert_eq!(status(&service, &request), 401);
}

#[test]
fn a_self_hosted_domain_issues_each_agent_a_token_and_publishes_only_its_key() {
    let ap = provider();
    let planner = ap
        .issue_to(
            "aauth:planner@ap.example",
            &SigningKey::from_seed([2; 32]).public_jwk(),
            &AgentGrant::new(3600).with_ps(PS),
            NOW,
        )
        .unwrap();
    let researcher = ap
        .issue_to(
            "aauth:research@ap.example",
            &SigningKey::from_seed([3; 32]).public_jwk(),
            &AgentGrant::new(3600).with_ps(PS),
            NOW,
        )
        .unwrap();
    assert_ne!(planner.claims.sub, researcher.claims.sub);
    let own = ap
        .issue_to(
            "aauth:self@ap.example",
            &ap.public_jwk(),
            &AgentGrant::new(3600),
            NOW,
        )
        .unwrap();
    assert_eq!(
        own.claims.cnf.jwk.thumbprint().unwrap(),
        ap.public_jwk().thumbprint().unwrap()
    );
    let jwks: Value = serde_json::from_slice(&ap.jwks().unwrap()).unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);

    let child = ap
        .issue_subagent_to(
            &planner.token,
            &SigningKey::from_seed([4; 32]).public_jwk(),
            "search1",
            600,
            NOW,
        )
        .unwrap();
    assert_eq!(child.claims.sub, "aauth:planner+search1@ap.example");
    assert_eq!(
        child.claims.parent_agent.as_deref(),
        Some("aauth:planner@ap.example")
    );
    assert_eq!(child.claims.ps.as_deref(), Some(PS));
    assert_eq!(
        ap.issue_subagent_to(
            &child.token,
            &SigningKey::from_seed([5; 32]).public_jwk(),
            "deeper",
            600,
            NOW,
        )
        .unwrap_err(),
        TokenError::UnsupportedAgentProfile
    );
    assert_eq!(
        ap.issue_to(
            "aauth:brief@ap.example",
            &ap.public_jwk(),
            &AgentGrant::new(300),
            NOW
        )
        .unwrap_err(),
        TokenError::InvalidTokenLifetime,
        "a token inside the refresh margin when issued"
    );
}

#[test]
fn the_client_refuses_a_token_for_another_key() {
    let service = service();
    let keys = keys(&service);
    let mut client = BootstrapClient::new(SigningKey::from_seed([2; 32]), AP).unwrap();
    let enroll = client
        .enrollment_request(&format!("{AP}/enroll"), &json!({}), NOW)
        .unwrap();
    service.handle(&enroll, NOW);
    let first = client
        .refresh_request(&format!("{AP}/refresh"), None, &json!({}), NOW)
        .unwrap();
    let second = client
        .refresh_request(&format!("{AP}/refresh"), None, &json!({}), NOW)
        .unwrap();
    let answer = service.handle(second.request(), NOW).into_response();
    assert!(matches!(
        client.complete_refresh(first, &answer, &keys, NOW),
        Err(BootstrapError::UnexpectedToken)
    ));
}
