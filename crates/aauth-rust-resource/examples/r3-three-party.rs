mod r3_three_party;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let t = r3_three_party::run()?;
    println!(
        "authorization_endpoint={} r3_uri-at-signed-origin={} documents-served={} granted={:?}",
        t.authorization_endpoint, t.r3_uri_at_signed_origin, t.documents_served, t.granted
    );
    println!(
        "authorized={} receipts={} receipt-matches-signed-body={} audit-records={}",
        t.authorized_status, t.receipts, t.receipt_matches_signed_body, t.audit_records
    );
    println!(
        "refused: not-granted={} tampered={} wrong-holder={} agent-fetch={} unsigned-fetch={} substituted-reference={}",
        t.not_granted_status,
        t.tampered_status,
        t.wrong_holder_status,
        t.agent_fetch_status,
        t.unsigned_fetch_status,
        t.substituted_reference_refused
    );
    println!(
        "refused: unknown-operation={} widened-grant={} fetch-egress={} resource-store={} ps-audit={} untrusted-TLS={}",
        t.unknown_operation_status,
        t.widened_grant_status,
        t.fetch_refused_status,
        t.resource_store_failure_status,
        t.audit_failure_status,
        t.untrusted_tls_refused
    );
    Ok(())
}
