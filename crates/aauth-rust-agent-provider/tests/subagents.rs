use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{
    AgentClaims, AgentProviderKeys, AgentToken, Confirmation, TokenError, verify_subagent,
};
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::json;

fn fixture() -> (AgentProvider, AgentClaims, AgentClaims) {
    let ap =
        AgentProvider::new("https://ap.example", "ap", SigningKey::from_seed([1; 32])).unwrap();
    let parent = AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:parent@ap.example".into(),
        jti: "parent".into(),
        iat: 1000,
        exp: 2000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        ps: Some("https://ps.example".into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    };
    let mut child = parent.clone();
    child.sub = "aauth:parent+worker@ap.example".into();
    child.jti = "child".into();
    child.parent_agent = Some(parent.sub.clone());
    child.cnf.jwk = SigningKey::from_seed([3; 32]).public_jwk();
    child.ps = None;
    (ap, parent, child)
}
fn signed(claims: &AgentClaims, seed: u8) -> String {
    Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap"}),
        &serde_json::to_vec(claims).unwrap(),
        &SigningKey::from_seed([seed; 32]),
    )
    .unwrap()
}

#[test]
fn issues_child_after_authenticating_parent_with_configured_ap_key() {
    let (ap, parent, mut child) = fixture();
    let parent_compact = ap.issue(&parent).unwrap();
    child.exp = parent.exp + 1000;
    let compact = ap.issue_subagent(&child, &parent_compact, 1000).unwrap();
    let keys = AgentProviderKeys::from_documents(
        &parent.iss,
        &ap.metadata().unwrap(),
        &ap.jwks().unwrap(),
    )
    .unwrap();
    let parent = AgentToken::parse(&parent_compact)
        .unwrap()
        .verify(&keys, 1000)
        .unwrap();
    assert_eq!(
        verify_subagent(&compact, &parent, &keys, 1000)
            .unwrap()
            .claims()
            .sub,
        child.sub
    );
    assert_eq!(
        ap.issue(&child).unwrap_err(),
        TokenError::UnsupportedAgentProfile
    );
}

#[test]
fn refuses_forged_expired_not_yet_valid_and_foreign_parents() {
    let (ap, mut parent, child) = fixture();
    assert!(
        ap.issue_subagent(&child, &signed(&parent, 9), 1000)
            .is_err()
    );
    parent.exp = 1000;
    assert_eq!(
        ap.issue_subagent(&child, &signed(&parent, 1), 1000)
            .unwrap_err(),
        TokenError::ExpiredJwt
    );
    parent.exp = 2000;
    parent.nbf = Some(1001);
    assert!(
        ap.issue_subagent(&child, &signed(&parent, 1), 1000)
            .is_err()
    );
    parent.nbf = None;
    parent.iss = "https://other.example".into();
    parent.sub = "aauth:parent@other.example".into();
    assert!(
        ap.issue_subagent(&child, &signed(&parent, 1), 1000)
            .is_err()
    );
}

#[test]
fn refuses_child_parent_wrong_binding_naming_and_same_key() {
    let (ap, mut parent, child) = fixture();
    parent.parent_agent = Some("aauth:grandparent@ap.example".into());
    assert!(
        ap.issue_subagent(&child, &signed(&parent, 1), 1000)
            .is_err()
    );
    parent.parent_agent = None;
    let compact = ap.issue(&parent).unwrap();
    let mut wrong = child.clone();
    wrong.parent_agent = None;
    assert!(ap.issue_subagent(&wrong, &compact, 1000).is_err());
    wrong = child.clone();
    wrong.parent_agent = Some("aauth:other@ap.example".into());
    assert!(ap.issue_subagent(&wrong, &compact, 1000).is_err());
    wrong = child.clone();
    wrong.cnf = parent.cnf.clone();
    assert!(ap.issue_subagent(&wrong, &compact, 1000).is_err());
    wrong = child;
    wrong.sub = "aauth:other+worker@ap.example".into();
    assert!(ap.issue_subagent(&wrong, &compact, 1000).is_err());
}

#[test]
fn issuance_retains_lifetime_limits_and_top_level_profile() {
    let (ap, parent, mut child) = fixture();
    let compact = ap.issue(&parent).unwrap();
    for expiry in [1000, 1000 + 86401, 1_000_000_000_000] {
        child.exp = expiry;
        assert_eq!(
            ap.issue_subagent(&child, &compact, 1000).unwrap_err(),
            TokenError::InvalidTokenLifetime
        );
    }
    let mut named_like_child = parent;
    named_like_child.sub = "aauth:parent+worker@ap.example".into();
    assert_eq!(
        ap.issue(&named_like_child).unwrap_err(),
        TokenError::UnsupportedAgentProfile
    );
}
