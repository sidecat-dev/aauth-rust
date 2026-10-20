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
    assert_eq!(t.effect_count, 1);
    assert_eq!(t.auth_issuer, "https://as.example");
    assert_eq!(t.auth_document, "aauth-access.json");
    assert_eq!(t.subject, "orders-pairwise-person");
    assert!(t.auth_expiry > t.challenge_expiry);
    assert!(t.ps_proof_verified);
    assert!(t.as_token_retained);
    assert!(t.untrusted_tls_refused);
}
