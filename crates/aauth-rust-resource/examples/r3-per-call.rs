mod r3_per_call;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let t = r3_per_call::run()?;
    println!(
        "class: read={} | 401: challenge={} proposal-op={} substituted={} wrong-holder={} retry={} replay={} replay-matches={}",
        t.read_status,
        t.challenge_status,
        t.proposal_operation,
        t.substituted_parameters_status,
        t.wrong_holder_status,
        t.retry_status,
        t.replay_status,
        t.replay_matches_first
    );
    println!(
        "recomposed: replay={} ps-denied-other-record={} | 202: held={} location-at-origin={} foreign-token={} completion={} replay={}",
        t.replay_after_restart_status,
        t.denied_parameters_ps_status,
        t.held_status,
        t.held_location_at_signed_origin,
        t.foreign_token_at_pending_status,
        t.held_completion_status,
        t.held_replay_status
    );
    println!(
        "effects: reads={} deletes={:?} audit-records={}",
        t.reads, t.deletes, t.audit_records
    );
    Ok(())
}
