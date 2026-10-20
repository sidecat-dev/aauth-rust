mod four_party;
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let t = four_party::run()?;
    assert_eq!(
        (t.unsigned_status, t.challenge_status, t.authorized_status),
        (401, 401, 200)
    );
    assert_eq!(
        (
            t.tampered_status,
            t.denied_status,
            t.bad_delivery_status,
            t.untrusted_ps_status
        ),
        (401, 403, 502, 401)
    );
    assert_eq!(t.effect_count, 1);
    assert_eq!(
        (
            t.auth_issuer.as_str(),
            t.auth_document.as_str(),
            t.subject.as_str()
        ),
        (
            "https://as.example",
            "aauth-access.json",
            "orders-pairwise-person"
        )
    );
    assert!(
        t.auth_expiry > t.challenge_expiry
            && t.ps_proof_verified
            && t.as_token_retained
            && t.untrusted_tls_refused
    );
    println!(
        "four-party TLS: Person challenge, PS service proof, AS grant, verified PS delivery, one POST effect; tamper/denial/unverifiable grant/foreign PS/untrusted TLS refused"
    );
    Ok(())
}
