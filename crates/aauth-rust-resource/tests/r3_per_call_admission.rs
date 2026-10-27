#[path = "../examples/r3_per_call/mod.rs"]
mod journey;

#[test]
fn held_completion_applies_policy_to_original_delete_and_denial_preserves_claim() {
    let t = journey::run_admission_case(journey::AdmissionCase::HeldPolicy).unwrap();
    eprintln!(
        "held policy: status={} effects={} consumed={}",
        t.held_policy_denied_status, t.held_policy_effect_delta, t.held_policy_claim_consumed
    );
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
    eprintln!(
        "revocation: revoke={} completion={} error={} effects={} consumed={}",
        t.revocation_status,
        t.revoked_completion_status,
        t.revoked_completion_error,
        t.revocation_effect_delta,
        t.revocation_claim_consumed
    );
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
    eprintln!(
        "claim revocation: revoke={} completion={} error={} effects={} consumed={} retry={} unchanged={} result={}",
        t.revocation_status,
        t.revoked_completion_status,
        t.revoked_completion_error,
        t.revocation_effect_delta,
        t.revocation_claim_consumed,
        t.revocation_retry_status,
        t.revocation_claim_unchanged,
        t.revocation_result_retained
    );
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

#[test]
fn release_gated_query_is_release_consent_released_once_and_replayed_without_recompute() {
    let t = journey::run_admission_case(journey::AdmissionCase::Release).unwrap();
    eprintln!("release: {t:?}");
    // The query ran at the challenge and its result was proposed for release.
    assert_eq!(t.release_held_status, 202);
    assert_eq!(t.release_runs_at_challenge, 1);
    assert_eq!(
        t.release_result_seen,
        r#"{"contains":["national_id"],"records":1}"#
    );
    // Execution consent decided the deletes; release consent decided both queries.
    assert_eq!(
        t.consents,
        ["execution", "execution", "execution", "release", "release"]
    );
    // Denial at the PS, and the class token at that pending URL, release nothing.
    assert_eq!(t.release_denied_ps_status, 403);
    assert_eq!(t.declined_pending_status, 403);
    // The r-1 approval neither completes the r-2 proposal nor a re-sent call.
    assert_eq!(t.release_mismatch_status, 403);
    assert_eq!(t.release_at_route_status, 403);
    // Released once; the same token gets identical bytes; nothing recomputes.
    assert_eq!(t.release_status, 200);
    assert!(t.release_body.contains("national_id"), "{}", t.release_body);
    assert_eq!(t.release_replay_status, 200);
    assert!(t.release_replay_matches);
    assert_eq!(t.release_runs_after_completion, 0);
    assert!(t.release_claim_consumed);
    assert_eq!(t.query_runs, 2);
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
}

#[test]
fn signed_revocation_completed_during_policy_blocks_release_claim_and_recompute() {
    let t = journey::run_admission_case(journey::AdmissionCase::ReleaseRevocation).unwrap();
    eprintln!("release revocation: {t:?}");
    assert_eq!(t.revocation_status, 200);
    assert_eq!(t.revoked_completion_status, 401);
    assert_eq!(t.revoked_completion_error, "error=revoked_jwt");
    assert_eq!(t.revocation_effect_delta, 0);
    assert!(!t.revocation_claim_consumed);
    assert_eq!(t.query_runs, 1);
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
}

#[test]
fn signed_revocation_during_bound_release_claim_retains_and_releases_nothing() {
    let t = journey::run_admission_case(journey::AdmissionCase::ReleaseClaimRevocation).unwrap();
    eprintln!("release claim revocation: {t:?}");
    assert_eq!(t.revocation_status, 200);
    assert_eq!(t.revoked_completion_status, 401);
    assert_eq!(t.revoked_completion_error, "error=revoked_jwt");
    assert_eq!(t.revocation_effect_delta, 0);
    // Consumed and never released: the retry is refused and the claim is unchanged.
    assert!(t.revocation_claim_consumed);
    assert_eq!(t.revocation_retry_status, 401);
    assert!(t.revocation_claim_unchanged);
    assert!(!t.revocation_result_retained);
    assert_eq!(t.query_runs, 1);
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
}
