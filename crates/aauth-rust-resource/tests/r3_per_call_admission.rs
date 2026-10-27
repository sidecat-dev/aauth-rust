#[path = "../examples/r3_per_call/mod.rs"]
mod journey;

#[test]
fn held_completion_applies_policy_to_original_delete_and_denial_preserves_claim() {
    let t = journey::run_admission_case(journey::AdmissionCase::HeldPolicy).unwrap();
    eprintln!("held policy: status={} effects={} consumed={}",
        t.held_policy_denied_status, t.held_policy_effect_delta, t.held_policy_claim_consumed);
    assert_eq!(t.held_policy_denied_status, 403);
    assert_eq!(t.held_policy_effect_delta, 0);
    assert!(!t.held_policy_claim_consumed);
    // The same held proposal still completes once after the original request is allowed.
    assert_eq!(t.held_completion_status, 200);
    assert_eq!(t.held_replay_status, 200);
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
}

#[test]
fn signed_revocation_completed_during_policy_blocks_new_claim_and_effect() {
    let t = journey::run_admission_case(journey::AdmissionCase::Revocation).unwrap();
    eprintln!("revocation: revoke={} completion={} error={} effects={} consumed={}",
        t.revocation_status, t.revoked_completion_status, t.revoked_completion_error,
        t.revocation_effect_delta, t.revocation_claim_consumed);
    assert_eq!(t.revocation_status, 200);
    assert_eq!(t.revoked_completion_status, 401);
    assert_eq!(t.revoked_completion_error, "error=revoked_jwt");
    assert_eq!(t.revocation_effect_delta, 0);
    assert!(!t.revocation_claim_consumed);
    // Previously admitted requests remain the two original effects.
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
}

#[test]
fn signed_revocation_during_bound_claim_suppresses_release_without_rollback_or_redispatch() {
    let t = journey::run_admission_case(journey::AdmissionCase::ClaimRevocation).unwrap();
    eprintln!("claim revocation: revoke={} completion={} error={} effects={} consumed={} retry={} unchanged={} result={}",
        t.revocation_status, t.revoked_completion_status, t.revoked_completion_error,
        t.revocation_effect_delta, t.revocation_claim_consumed, t.revocation_retry_status,
        t.revocation_claim_unchanged, t.revocation_result_retained);
    assert_eq!(t.revocation_status, 200);
    assert_eq!(t.revoked_completion_status, 401);
    assert_eq!(t.revoked_completion_error, "error=revoked_jwt");
    assert_eq!(t.revocation_effect_delta, 0);
    assert!(t.revocation_claim_consumed);
    assert_eq!(t.revocation_retry_status, 401);
    assert!(t.revocation_claim_unchanged);
    assert!(!t.revocation_result_retained);
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
}
