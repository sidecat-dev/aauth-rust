mod three_party;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = three_party::run()?;
    println!(
        "unsigned={} person-challenge={} tampered={} authorized={}",
        result.unsigned_status,
        result.person_challenge_status,
        result.tampered_status,
        result.authorized_status
    );
    println!(
        "orders={} inventory={} directed-subjects-differ={} downstream-within-upstream={} intermediary-binding={} untrusted-TLS-refused={}",
        result.order_count,
        result.inventory_count,
        result.upstream_subject != result.downstream_subject,
        result.downstream_expiry <= result.upstream_expiry,
        result.intermediary_has_binding,
        result.untrusted_tls_refused
    );
    Ok(())
}
