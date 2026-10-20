//! Executable storage contract for host-supplied Person Server stores.
//! Each invocation uses fresh disposable stores; never run on production state.
use crate::{AgentIdentity, Store, StoreError, TokenKind, TokenRecord, TokenReference, TokenTie};
use std::sync::Arc;
mod federation;
mod issuance;
mod persistence;
mod subagents;
mod validation;
pub use persistence::check_persistence_contract;

fn record(jti: &str, person: &str) -> TokenRecord {
    TokenRecord {
        parent_agent: None,
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
        person_id: person.into(),
        tenant: Some("tenant-1".into()),
        agent: AgentIdentity {
            issuer: "https://ap.example".into(),
            subject: "aauth:Agent@ap.example".into(),
        },
        principal: AgentIdentity {
            issuer: "https://ap.example".into(),
            subject: "aauth:Agent@ap.example".into(),
        },
        agent_token_jti: "agent-token-1".into(),
        agent_jkt: "agent-thumbprint".into(),
        issued_at: 1000,
        expires_at: 1300,
        retain_until: 5260,
        presented: None,
        upstream: None,
    }
}

/// Check namespacing, round-trip, exact replay, conflicting commits, binding
/// revocation, directed identity consistency, fully populated Auth lineage,
/// malformed identity/parent refusal without state changes, and concurrent
/// first-claim / same-token retry atomicity.
/// `factory` must return a fresh empty store every time; no cleanup is performed.
///
/// # Errors
/// Returns an explanation when a store violates the contract or is unavailable.
pub fn check_store_contract<S: Store + 'static>(factory: impl Fn() -> S) -> Result<(), String> {
    subagents::check_subagents(factory())?;
    federation::check_federation(factory())?;
    let store = factory();
    let original = record("person-1", "internal-person");
    store
        .commit(original.clone(), true)
        .map_err(|e| format!("first commit: {e}"))?;
    if store
        .token(&original.token.reference)
        .map_err(|e| e.to_string())?
        != Some(original.clone())
    {
        return Err("record did not round-trip every field".into());
    }
    store
        .commit(original.clone(), true)
        .map_err(|e| format!("identical commit: {e}"))?;
    let mutations: &[fn(&mut TokenRecord)] = &[
        |r| r.token.compact_sha256 = "replacement".into(),
        |r| r.kind = TokenKind::Auth,
        |r| r.resource = "https://other.example".into(),
        |r| r.subject = "replacement".into(),
        |r| r.person_id = "replacement".into(),
        |r| r.tenant = None,
        |r| r.agent.subject = "aauth:Other@ap.example".into(),
        |r| r.principal.subject = "aauth:Other@ap.example".into(),
        |r| r.agent_token_jti = "replacement".into(),
        |r| r.agent_jkt = "replacement".into(),
        |r| r.issued_at += 1,
        |r| r.expires_at += 1,
        |r| r.retain_until += 1,
        |r| r.presented = Some(r.token.clone()),
        |r| r.upstream = Some(r.token.clone()),
    ];
    for mutate in mutations {
        let mut conflicting = original.clone();
        mutate(&mut conflicting);
        if store.commit(conflicting, false) != Err(StoreError::Conflict) {
            return Err("conflicting token commit was not refused".into());
        }
    }
    if store
        .token(&original.token.reference)
        .map_err(|e| e.to_string())?
        != Some(original.clone())
    {
        return Err("refused commit changed original".into());
    }
    let mut other_issuer = original.clone();
    other_issuer.token.reference.issuer = "https://other-ps.example".into();
    store
        .commit(other_issuer, true)
        .map_err(|e| format!("issuer namespace: {e}"))?;
    let mut other_person = record("person-2", "different-person");
    other_person.subject = "different-directed-person".into();
    if store.commit(other_person, true) != Err(StoreError::Conflict) {
        return Err("Agent was claimed by another person".into());
    }
    let mut changed_subject = record("person-3", "internal-person");
    changed_subject.subject = "different-directed-person".into();
    if store.commit(changed_subject, true) != Err(StoreError::Conflict) {
        return Err("directed identity changed for the same person/Resource".into());
    }
    let mut collision = record("person-4", "another-person");
    collision.agent.subject = "aauth:Other@ap.example".into();
    collision.principal = collision.agent.clone();
    let collision_agent = collision.principal.clone();
    if store.commit(collision, true) != Err(StoreError::Conflict) {
        return Err("different people received the same directed identity".into());
    }
    if store
        .binding("https://ps.example", &collision_agent)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("refused directed identity collision created a binding".into());
    }
    let mut renewed = record("renewed-tenant", "internal-person");
    renewed.tenant = Some("tenant-2".into());
    store
        .commit(renewed, true)
        .map_err(|e| format!("tenant is not part of the person's identifier: {e}"))?;
    store
        .revoke_binding(&original.token.reference.issuer, &original.principal)
        .map_err(|e| e.to_string())?;
    if store.commit(record("person-5", "internal-person"), true) != Err(StoreError::RevokedBinding)
    {
        return Err("token request reclaimed a revoked binding".into());
    }

    let concurrent = Arc::new(factory());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let attempts: Vec<_> = (0..8)
        .map(|i| {
            let store = concurrent.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut candidate = record(&format!("competing-{i}"), &format!("person-{i}"));
                candidate.subject = format!("directed-{i}");
                barrier.wait();
                let result = store.commit(candidate.clone(), true);
                (candidate, result)
            })
        })
        .collect();
    let results: Vec<_> = attempts
        .into_iter()
        .map(|t| {
            t.join()
                .map_err(|_| "concurrent store call panicked".to_owned())
        })
        .collect::<Result<_, _>>()?;
    if results.iter().filter(|r| r.1.is_ok()).count() != 1
        || results
            .iter()
            .any(|r| r.1.is_err() && r.1 != Err(StoreError::Conflict))
    {
        return Err("concurrent Agent claims were not atomic".into());
    }
    for (candidate, result) in &results {
        let expected = result.is_ok().then(|| candidate.clone());
        if concurrent
            .token(&candidate.token.reference)
            .map_err(|e| e.to_string())?
            != expected
        {
            return Err("concurrent losing Agent claim left an issuance".into());
        }
        if result.is_ok()
            && concurrent
                .binding(&candidate.token.reference.issuer, &candidate.principal)
                .map_err(|e| e.to_string())?
                .is_none_or(|b| b.person_id != candidate.person_id || b.revoked)
        {
            return Err("concurrent binding does not identify the winning person".into());
        }
    }
    let empty = factory();
    let mut invalid = record("invalid", "person");
    invalid.expires_at = invalid.issued_at;
    if empty.commit(invalid.clone(), true) != Err(StoreError::InvalidRecord)
        || empty
            .binding(&invalid.token.reference.issuer, &invalid.agent)
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err("invalid issuance created state".into());
    }
    let mut auth = record("auth", "person");
    auth.kind = TokenKind::Auth;
    auth.presented = Some(record("parent", "person").token);
    if empty.commit(auth, false) != Err(StoreError::MissingBinding) {
        return Err("authorization created a missing person binding".into());
    }
    issuance::check_complete_auth_records(factory())?;
    issuance::check_concurrent_token_commit(factory())?;
    persistence::check_refusal_atomicity(&factory(), "logical")?;
    validation::check_invalid_records(factory)?;
    Ok(())
}
