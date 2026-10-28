mod r3_per_call_interop;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let t = r3_per_call_interop::run()?;
    println!(
        "go->rust: person={} read={} 401={} expiry-err={} reused-approval={} substituted={} ps-denied={} retry={} replay={} replay-matches={}",
        t.go_to_rust_person_token_issued,
        t.go_to_rust_class_read_status,
        t.go_to_rust_401_challenge_status,
        t.go_to_rust_approval_expiry_error,
        t.go_to_rust_approval_replacement_reused_without_reprompt,
        t.go_to_rust_substituted_parameters_status,
        t.go_to_rust_ps_denied_other_record_status,
        t.go_to_rust_401_retry_status,
        t.go_to_rust_401_replay_status,
        t.go_to_rust_401_replay_matches_first,
    );
    println!(
        "go->rust 202: held={} foreign={} poll={} replay={} | release: held={} poll={} replay={} query-runs={}",
        t.go_to_rust_202_held_status,
        t.go_to_rust_202_foreign_token_status,
        t.go_to_rust_202_poll_status,
        t.go_to_rust_202_replay_status,
        t.go_to_rust_release_held_status,
        t.go_to_rust_release_poll_status,
        t.go_to_rust_release_replay_status,
        t.go_to_rust_query_runs,
    );
    println!(
        "rust<->go: person={} class-exchange={} ps-fetched={} ps-issuances={} read={} ungranted-delete={} proposal-exchange={} proposal-err={} | effects: reads={} deletes={:?} rust-ps-audit={}",
        t.rust_to_go_person_status,
        t.rust_to_go_class_exchange_status,
        t.rust_to_go_ps_fetched_document,
        t.rust_to_go_ps_issuance_records,
        t.rust_to_go_class_read_status,
        t.rust_to_go_ungranted_delete_status,
        t.rust_to_go_proposal_exchange_status,
        t.rust_to_go_proposal_exchange_error,
        t.reads,
        t.deletes,
        t.rust_ps_audit_records,
    );
    Ok(())
}
