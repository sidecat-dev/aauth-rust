mod four_party;
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deferred = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("--deferred") => true,
        Some(_) => return Err("usage: four-party [--deferred]".into()),
    };
    let t = if deferred {
        four_party::run_deferred()?
    } else {
        four_party::run()?
    };
    if let Some(d) = &t.deferred {
        assert_eq!(d.access_statuses, [402, 202, 200]);
        assert_eq!(d.agent_statuses, [202, 202, 202, 200, 410]);
        assert!(d.stable_ps_location && d.as_state_consumed);
        assert_eq!(d.as_calls_after_waiting_agent_poll, 1);
        println!(
            "deferred TLS: AS402 -> approval202 -> verified grant200; PS202 -> one terminal200 -> gone410; host confirms example settlement"
        );
    }
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
    assert_eq!(t.denied_error, "access_denied");
    assert_eq!(t.bad_delivery_error, "as_unreachable");
    assert_eq!(t.untrusted_ps_error, "invalid_key");
    assert_eq!(t.forwarded_tokens.len(), 3);
    for actual in &t.forwarded_tokens {
        assert_eq!(
            actual.agent_token.as_bytes(),
            t.original_tokens.agent_token.as_bytes()
        );
        assert_eq!(
            actual.presented_token.as_bytes(),
            t.original_tokens.presented_token.as_bytes()
        );
        assert_eq!(
            actual.resource_token.as_bytes(),
            t.original_tokens.resource_token.as_bytes()
        );
    }
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
