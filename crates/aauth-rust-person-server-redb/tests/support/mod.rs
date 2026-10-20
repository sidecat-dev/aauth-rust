use aauth_rust_person_server::{AgentIdentity, TokenKind, TokenRecord, TokenReference, TokenTie};

pub fn record(jti: &str) -> TokenRecord {
    let agent = AgentIdentity {
        issuer: "https://ap.example".into(),
        subject: "aauth:Agent@ap.example".into(),
    };
    TokenRecord {
        person_server: None,
        token: TokenTie {
            reference: TokenReference {
                issuer: "https://ps.example".into(),
                jti: jti.into(),
            },
            compact_sha256: "exact-compact-digest".into(),
        },
        kind: TokenKind::Person,
        resource: "https://resource.example".into(),
        subject: "directed-person".into(),
        person_id: "internal-person".into(),
        tenant: Some("tenant".into()),
        agent: agent.clone(),
        principal: agent,
        agent_token_jti: "agent-token".into(),
        agent_jkt: "thumbprint".into(),
        issued_at: 1000,
        expires_at: 1300,
        retain_until: 5260,
        presented: None,
        upstream: None,
    }
}
