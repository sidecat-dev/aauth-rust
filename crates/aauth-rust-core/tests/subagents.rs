use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, AgentToken, Confirmation, TokenError, verify_subagent,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use serde_json::json;

struct Keys;
impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        if !["https://ap.example", "https://other.example"].contains(&issuer)
            || dwk != "aauth-agent.json"
            || kid != "ap"
        {
            return Err(TokenError::UnknownKey);
        }
        Ok(SigningKey::from_seed([1; 32]).public_jwk())
    }
}
fn claims() -> (AgentClaims, AgentClaims) {
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
    (parent, child)
}
fn mint(claims: &AgentClaims) -> String {
    Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap"}),
        &serde_json::to_vec(claims).unwrap(),
        &SigningKey::from_seed([1; 32]),
    )
    .unwrap()
}

#[test]
fn verifies_authoritative_parent_and_preserves_exact_child_bytes() {
    let (parent, mut child) = claims();
    let parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    // AP token lifetimes are independent, as are optional PS fields.
    child.exp = 2500;
    child.ps = Some("https://different-ps.example".into());
    let compact = mint(&child);
    let admitted = verify_subagent(&compact, &parent, &Keys, 1000).unwrap();
    assert_eq!(admitted.compact(), compact);
    assert_eq!(
        admitted.claims().parent_agent.as_deref(),
        Some(parent.claims().sub.as_str())
    );
}

#[test]
fn parent_claim_is_required_and_never_inferred_from_plus_naming() {
    let (parent, mut child) = claims();
    let parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    for marker in [None, Some("aauth:somebody@ap.example".into())] {
        child.parent_agent = marker;
        assert_eq!(
            verify_subagent(&mint(&child), &parent, &Keys, 1000).unwrap_err(),
            TokenError::InvalidJwt
        );
    }
}

#[test]
fn rejects_foreign_ap_even_when_both_signatures_and_parent_marker_are_valid() {
    let (parent, mut child) = claims();
    let parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    child.iss = "https://other.example".into();
    child.sub = "aauth:parent+worker@other.example".into();
    assert_eq!(
        verify_subagent(&mint(&child), &parent, &Keys, 1000).unwrap_err(),
        TokenError::InvalidJwt
    );
}

#[test]
fn rejects_child_as_parent_and_malformed_child_naming() {
    let (mut parent, mut child) = claims();
    parent.parent_agent = Some("aauth:grandparent@ap.example".into());
    let delegated_parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(
        verify_subagent(&mint(&child), &delegated_parent, &Keys, 1000).unwrap_err(),
        TokenError::InvalidJwt
    );
    parent.parent_agent = None;
    let parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    for subject in [
        "aauth:other+worker@ap.example",
        "aauth:parent+@ap.example",
        "aauth:parent@ap.example",
        "aauth:parent+worker+leaf@ap.example",
    ] {
        child.sub = subject.into();
        assert_eq!(
            verify_subagent(&mint(&child), &parent, &Keys, 1000).unwrap_err(),
            TokenError::InvalidJwt,
            "{subject}"
        );
    }
}

#[test]
fn distinct_child_proof_key_is_required() {
    let (parent, mut child) = claims();
    child.cnf = parent.cnf.clone();
    let parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(
        verify_subagent(&mint(&child), &parent, &Keys, 1000).unwrap_err(),
        TokenError::InvalidJwt
    );
}

#[test]
fn verifies_actual_child_signature_and_not_before() {
    let (parent, mut child) = claims();
    let parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    let forged = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap"}),
        &serde_json::to_vec(&child).unwrap(),
        &SigningKey::from_seed([9; 32]),
    )
    .unwrap();
    assert!(verify_subagent(&forged, &parent, &Keys, 1000).is_err());
    child.nbf = Some(1001);
    assert_eq!(
        verify_subagent(&mint(&child), &parent, &Keys, 1000).unwrap_err(),
        TokenError::InvalidJwt
    );
}

#[test]
fn expiry_remains_distinguishable_and_verified_parent_cannot_be_reused_after_expiry() {
    let (mut parent, mut child) = claims();
    child.exp = 1500;
    let verified_parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(
        verify_subagent(&mint(&child), &verified_parent, &Keys, 1500).unwrap_err(),
        TokenError::ExpiredJwt
    );
    parent.exp = 1400;
    let verified_parent = AgentToken::parse(&mint(&parent))
        .unwrap()
        .verify(&Keys, 1000)
        .unwrap();
    assert_eq!(
        verify_subagent(&mint(&child), &verified_parent, &Keys, 1400).unwrap_err(),
        TokenError::ExpiredJwt
    );
}
