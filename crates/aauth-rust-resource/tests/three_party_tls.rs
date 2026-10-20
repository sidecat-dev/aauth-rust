#[path = "../examples/three_party/mod.rs"]
mod journey;

#[test]
fn tls_person_authorization_and_chaining_change_application_state_once() {
    let transcript = journey::run().unwrap();
    assert_eq!(transcript.unsigned_status, 401);
    assert_eq!(transcript.person_challenge_status, 401);
    assert_eq!(transcript.tampered_status, 401);
    assert_eq!(transcript.authorized_status, 200);
    assert_eq!(transcript.order_count, 1);
    assert_eq!(transcript.inventory_count, 1);
    assert_ne!(transcript.upstream_subject, transcript.downstream_subject);
    assert!(transcript.downstream_expiry <= transcript.upstream_expiry);
    assert!(!transcript.intermediary_has_binding);
    assert!(transcript.untrusted_tls_refused);
}

#[test]
fn replaying_identical_authorized_post_runs_a_second_complete_chain_without_host_idempotency() {
    let transcript = journey::run_replayed().unwrap();
    assert_eq!(transcript.authorized_status, 200);
    assert_eq!(transcript.tampered_status, 401);
    assert_eq!(transcript.order_count, 2);
    assert_eq!(transcript.inventory_count, 2);
    assert!(!transcript.intermediary_has_binding);
}
