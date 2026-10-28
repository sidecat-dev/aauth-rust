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

#[test]
fn approval_expiry_replaces_presented_token_once_and_refuses_expired_approvals() {
    let t = journey::run_admission_case(journey::AdmissionCase::ApprovalExpiry).unwrap();
    eprintln!("approval expiry: {t:?}");
    // 401 execution approval: class token expiry during PS consent records the approval
    // and answers expired_presented_token without issuing a token.
    assert_eq!(t.expired_presented_status, 400);
    assert_eq!(t.expired_presented_error, "expired_presented_token");
    assert_eq!(t.substituted_replacement_ps_status, 403);
    // Resubmission with a refreshed class token applies the recorded approval once
    // without calling consent again.
    assert_eq!(t.replacement_approval_status, 200);
    assert_eq!(t.replacement_consents_delta, 0);
    assert_eq!(t.replacement_retry_status, 200);
    assert_eq!(t.replacement_replay_status, 200);
    assert!(t.replacement_replay_matches);
    assert!(t.consumed_approval_reprompted);
    assert_eq!(t.expired_per_call_status, 401);
    assert_eq!(t.expired_per_call_error, "error=expired_jwt");

    // 202 release approval: class token expiry during release consent answers
    // expired_presented_token; the original pending URL is not pollable; the
    // re-requested call applies the recorded release approval once without recomputing
    // on completion or replay.
    assert_eq!(t.release_expired_presented_status, 400);
    assert_eq!(t.release_expired_presented_error, "expired_presented_token");
    assert_eq!(t.release_old_pending_expired_class_status, 401);
    assert_eq!(t.release_old_pending_refreshed_class_status, 403);
    assert_eq!(t.release_replacement_approval_status, 200);
    assert_eq!(t.release_replacement_consents_delta, 0);
    assert_eq!(t.release_old_pending_with_replacement_status, 403);
    assert_eq!(t.release_replacement_status, 200);
    assert_eq!(t.release_replacement_replay_status, 200);
    assert!(t.release_replacement_replay_matches);
    assert_eq!(t.release_runs_after_completion, 0);
    assert_eq!(t.release_expired_token_status, 401);
    assert_eq!(t.release_expired_token_error, "error=expired_jwt");
    assert!(t.expired_recorded_approval_reprompted);
    // Release retry custody: the re-requested call is answered from the held
    // response. Nothing runs at the replacement challenge, and the released
    // bytes are the original challenge's computation.
    assert_eq!(t.release_runs_at_replacement_challenge, 0);
    assert_eq!(t.release_runs_since_original_challenge, 0);
    assert!(t.release_replacement_body_matches_original);
    // The class token at the replacement pending URL releases nothing.
    assert_eq!(t.release_poll_before_approval_status, 403);
    // Changed parameters are a fresh challenge, refused by release consent.
    assert_eq!(t.release_changed_params_runs_delta, 1);
    assert_eq!(t.release_changed_params_ps_status, 403);
    // A held response outlives an expired recorded approval, which re-prompts.
    assert_eq!(t.release_expired_approval_reuse_runs_delta, 0);
    // Past the held response's horizon: a fresh challenge and consent again.
    assert_eq!(t.release_expired_held_runs_delta, 1);
    assert!(t.release_expired_held_reprompted);
    // Two original deletes plus one replacement delete.
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#, r#""r-1""#]);
}

#[test]
fn live_same_token_call_does_not_retire_the_in_flight_challenge() {
    let t = journey::run_admission_case(journey::AdmissionCase::ReleaseSupersede).unwrap();
    eprintln!("live duplicate: {t:?}");
    // The second identical call under the live class token computes again.
    assert_eq!(t.release_supersede_status, 202);
    assert_eq!(t.release_supersede_runs_delta, 1);
    // The first challenge is still releasable and is the original computation.
    assert_eq!(t.release_superseded_poll_status, 200);
    assert_eq!(t.release_superseded_runs_delta, 0);
    assert_eq!(t.release_successor_status, 200);
    assert!(t.release_successor_body_matches_original);
    assert_eq!(t.query_runs, 2);
    assert_eq!(
        t.consents,
        ["execution", "execution", "execution", "release"]
    );
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
}

#[test]
fn completion_after_held_result_horizon_is_refused_while_the_token_is_live() {
    let t = journey::run_admission_case(journey::AdmissionCase::ReleaseHorizon).unwrap();
    eprintln!("horizon: {t:?}");
    assert_eq!(t.release_horizon_status, 403);
    assert_ne!(t.release_horizon_error, "error=expired_jwt");
    assert_eq!(t.release_horizon_runs_delta, 0);
}

#[test]
fn fresh_bytes_can_be_released_under_a_still_live_recorded_approval() {
    let t = journey::run_admission_case(journey::AdmissionCase::ReleaseFreshConsent).unwrap();
    eprintln!("fresh under prior consent: {t:?}");
    // Unresolved: after `release_until`, the resource recomputes, and the PS
    // still applies the earlier release approval because the proposal
    // descriptor did not change.
    assert_eq!(t.release_fresh_runs_delta, 1);
    assert_eq!(t.release_fresh_consents_delta, 0);
    assert!(t.release_fresh_body_is_new);
}
