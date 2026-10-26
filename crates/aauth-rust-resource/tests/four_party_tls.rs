#[path = "../examples/four_party/mod.rs"]
mod journey;

#[test]
fn real_tls_four_party_handoff_verifies_proofs_grants_and_one_post_effect() {
    // Core overview four-party, ps-to-as-token-request, auth-token-delivery,
    // auth-token-verification; Signature-Key jwks-uri-scheme and covered-components.
    let t = journey::run().unwrap();
    assert_eq!(t.unsigned_status, 401);
    assert_eq!(t.challenge_status, 401);
    assert_eq!(t.authorized_status, 200);
    assert_eq!(t.tampered_status, 401);
    assert_eq!(t.denied_status, 403);
    assert_eq!(t.bad_delivery_status, 502);
    assert_eq!(t.untrusted_ps_status, 401);
    assert_eq!(t.denied_error, "access_denied");
    assert_eq!(t.bad_delivery_error, "as_unreachable");
    assert_eq!(t.untrusted_ps_error, "invalid_key");
    assert_eq!(t.forwarded_tokens.len(), 3);
    for actual in &t.forwarded_tokens {
        assert_eq!(
            actual.agent_token.as_bytes(),
            t.original_tokens.agent_token.as_bytes()
        );
        assert_eq!(
            actual.presented_token.as_bytes(),
            t.original_tokens.presented_token.as_bytes()
        );
        assert_eq!(
            actual.resource_token.as_bytes(),
            t.original_tokens.resource_token.as_bytes()
        );
    }
    assert_eq!(t.effect_count, 1);
    assert_eq!(t.auth_issuer, "https://as.example");
    assert_eq!(t.auth_document, "aauth-access.json");
    assert_eq!(t.subject, "orders-pairwise-person");
    assert!(t.auth_expiry > t.challenge_expiry);
    assert!(t.ps_proof_verified);
    assert!(t.as_token_retained);
    assert!(t.untrusted_tls_refused);
}

#[test]
fn real_tls_deferred_payment_approval_grant_and_one_post_effect() {
    let t = journey::run_deferred().unwrap();
    let d = t.deferred.as_ref().unwrap();
    assert_eq!(d.access_statuses, [402, 202, 200]);
    assert_eq!(d.agent_statuses, [202, 202, 202, 200, 410]);
    assert!(d.stable_ps_location);
    assert!(d.as_state_consumed);
    assert_eq!(d.as_calls_after_waiting_agent_poll, 1);
    assert_eq!(t.effect_count, 1);
    assert_eq!(t.authorized_status, 200);
    assert_eq!(t.tampered_status, 401);
    assert!(t.ps_proof_verified && t.as_token_retained && t.untrusted_tls_refused);
    assert_eq!(t.denied_error, "access_denied");
    assert_eq!(t.bad_delivery_error, "as_unreachable");
    assert_eq!(t.auth_issuer, "https://as.example");
    assert_eq!(t.auth_document, "aauth-access.json");
    for actual in &t.forwarded_tokens {
        assert_eq!(actual.agent_token, t.original_tokens.agent_token);
        assert_eq!(actual.presented_token, t.original_tokens.presented_token);
        assert_eq!(actual.resource_token, t.original_tokens.resource_token);
    }
}
