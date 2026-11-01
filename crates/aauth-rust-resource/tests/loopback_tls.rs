#[path = "../examples/support/mod.rs"]
mod journey;

#[test]
fn direct_agent_identity_over_verified_loopback_tls() {
    let observations = journey::run().unwrap();
    let actual: Vec<_> = observations
        .iter()
        .map(|o| (o.scenario, o.status, o.detail.as_str()))
        .collect();
    assert_eq!(
        actual,
        vec![
            ("ap-metadata", 200, "issuer and jwks_uri"),
            ("ap-jwks", 200, "Ed25519 issuer key"),
            ("resource-metadata", 200, "issuer https://resource.example"),
            ("unsigned", 401, "requirement=agent-token"),
            ("valid-identity", 200, "aauth:Agent@ap.example"),
            ("hwk-proof", 200, "pseudonymous proof verified"),
            ("hwk-identity", 401, "error=unsupported_scheme"),
            ("tampered-signature", 401, "error=invalid_signature"),
            ("expired-token", 401, "error=expired_jwt"),
            ("uncovered-key", 401, "error=invalid_input"),
            ("future-created", 401, "error=clock_skew"),
            ("future-iat", 401, "error=clock_skew"),
            ("wrong-confirmation-key", 401, "error=invalid_signature"),
            ("policy-denial", 403, "no signature diagnostics"),
            ("untrusted-tls", 0, "certificate refused"),
        ]
    );
}
