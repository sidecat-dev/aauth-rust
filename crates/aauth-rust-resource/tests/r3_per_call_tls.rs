#[path = "../examples/r3_per_call/mod.rs"]
mod journey;

#[test]
fn per_call_delete_runs_once_per_approval_across_retry_replay_recomposition_and_hold() {
    let t = journey::run().unwrap();
    // Class grant: read served directly; delete left per call.
    assert_eq!(t.read_status, 200);
    assert_eq!(t.reads, 1);
    // 401 path: proposal challenge, one-operation approval, single use.
    assert_eq!(t.challenge_status, 401);
    assert_eq!(t.proposal_operation, r#"{"tool":"records.delete"}"#);
    assert_eq!(t.substituted_parameters_status, 403);
    assert_eq!(t.wrong_holder_status, 401);
    assert_eq!(t.retry_status, 200);
    assert_eq!(t.replay_status, 200);
    assert!(t.replay_matches_first);
    // Retained result survives recomposition from the same files; nothing runs again.
    assert_eq!(t.replay_after_restart_status, 200);
    // Parameter-sensitive consent refuses another record; no token, no effect.
    assert_eq!(t.denied_parameters_ps_status, 403);
    // 202 path: held invocation completes once at its pending URL.
    assert_eq!(t.held_status, 202);
    assert!(t.held_location_at_signed_origin);
    assert_eq!(t.foreign_token_at_pending_status, 403);
    assert_eq!(t.held_completion_status, 200);
    assert_eq!(t.held_replay_status, 200);
    // Exactly two deletions: one per approved per-call token.
    assert_eq!(t.deletes, [r#""r-1""#, r#""r-1""#]);
    // Class grant plus two per-call approvals reached the audit log.
    assert_eq!(t.audit_records, 3);
}
