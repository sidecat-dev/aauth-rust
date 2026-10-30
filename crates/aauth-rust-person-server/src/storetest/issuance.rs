use super::{
    AgentIdentity, Store, StoreError, TokenKind, TokenRecord, TokenReference, TokenTie, record,
};
use crate::R3IssuanceAudit;
use std::sync::Arc;

pub(super) fn auth_record(jti: &str, parent: &TokenRecord) -> TokenRecord {
    let mut auth = parent.clone();
    auth.token.reference.jti = jti.into();
    auth.token.compact_sha256 = "auth-compact-digest".into();
    auth.kind = TokenKind::Auth;
    auth.agent = AgentIdentity {
        issuer: "https://intermediary.example".into(),
        subject: "aauth:Intermediary@intermediary.example".into(),
    };
    auth.agent_token_jti = "intermediary-agent-token".into();
    auth.agent_jkt = "intermediary-key-thumbprint".into();
    auth.presented = Some(parent.token.clone());
    auth.upstream = Some(TokenTie {
        reference: TokenReference {
            issuer: "https://ps.example".into(),
            jti: "upstream-token".into(),
        },
        compact_sha256: "upstream-exact-digest".into(),
    });
    auth
}

type Mutation = (&'static str, fn(&mut TokenRecord));

pub(super) fn check_complete_auth_records(store: impl Store) -> Result<(), String> {
    let parent = record("person-full", "internal-person");
    let auth = auth_record("auth-full", &parent);
    if store
        .token(&auth.token.reference)
        .map_err(|e| e.to_string())?
        .is_some()
        || store
            .binding(&parent.token.reference.issuer, &parent.principal)
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err("factory did not return an empty store".into());
    }
    store
        .commit(parent.clone(), true)
        .map_err(|e| e.to_string())?;
    store
        .commit(auth.clone(), false)
        .map_err(|e| e.to_string())?;
    if store
        .token(&auth.token.reference)
        .map_err(|e| e.to_string())?
        != Some(auth.clone())
    {
        return Err("complete Auth issuance did not round-trip every field".into());
    }
    store
        .commit(auth.clone(), false)
        .map_err(|e| format!("Auth identical retry: {e}"))?;
    let mutations: &[Mutation] = &[
        ("PS namespace", |r| {
            r.person_server = Some("https://other-ps.example".into())
        }),
        ("compact digest", |r| r.token.compact_sha256.push('x')),
        ("kind", |r| r.kind = TokenKind::Person),
        ("resource", |r| r.resource = "https://other.example".into()),
        ("subject", |r| r.subject.push('x')),
        ("person", |r| r.person_id.push('x')),
        ("tenant", |r| r.tenant = Some("other-tenant".into())),
        ("Agent issuer", |r| {
            r.agent.issuer = "https://other.example".into()
        }),
        ("Agent subject", |r| r.agent.subject.push('x')),
        ("principal issuer", |r| {
            r.principal.issuer = "https://other.example".into()
        }),
        ("principal subject", |r| r.principal.subject.push('x')),
        ("Agent token JTI", |r| r.agent_token_jti.push('x')),
        ("Agent thumbprint", |r| r.agent_jkt.push('x')),
        ("issued at", |r| r.issued_at += 1),
        ("expires at", |r| r.expires_at += 1),
        ("invalid conflicting expiry", |r| r.expires_at = r.issued_at),
        ("retain until", |r| r.retain_until += 1),
        ("presented absent", |r| r.presented = None),
        ("presented issuer", |r| {
            r.presented.as_mut().unwrap().reference.issuer = "https://other.example".into()
        }),
        ("presented JTI", |r| {
            r.presented.as_mut().unwrap().reference.jti.push('x')
        }),
        ("presented digest", |r| {
            r.presented.as_mut().unwrap().compact_sha256.push('x')
        }),
        ("upstream absent", |r| r.upstream = None),
        ("upstream issuer", |r| {
            r.upstream.as_mut().unwrap().reference.issuer = "https://other.example".into()
        }),
        ("upstream JTI", |r| {
            r.upstream.as_mut().unwrap().reference.jti.push('x')
        }),
        ("upstream digest", |r| {
            r.upstream.as_mut().unwrap().compact_sha256.push('x')
        }),
    ];
    for (name, mutate) in mutations {
        let mut conflicting = auth.clone();
        mutate(&mut conflicting);
        if store.commit(conflicting, false) != Err(StoreError::Conflict) {
            return Err(format!("changed Auth {name} was not refused"));
        }
        if store
            .token(&auth.token.reference)
            .map_err(|e| e.to_string())?
            != Some(auth.clone())
        {
            return Err(format!("refused Auth {name} changed retained state"));
        }
    }
    store
        .commit(auth.clone(), false)
        .map_err(|e| format!("Auth retry after conflicts: {e}"))?;
    let mut snapshot = store
        .token(&auth.token.reference)
        .map_err(|e| e.to_string())?
        .ok_or("Auth disappeared")?;
    snapshot.upstream.as_mut().unwrap().compact_sha256.push('x');
    snapshot.agent.subject.push('x');
    if store
        .token(&auth.token.reference)
        .map_err(|e| e.to_string())?
        != Some(auth.clone())
    {
        return Err("mutating an owned Auth snapshot changed retained state".into());
    }
    let mut other_parent = parent.clone();
    other_parent.token.reference.issuer = "https://other-ps.example".into();
    store
        .commit(other_parent.clone(), true)
        .map_err(|e| e.to_string())?;
    let other_auth = auth_record(&auth.token.reference.jti, &other_parent);
    store
        .commit(other_auth.clone(), false)
        .map_err(|e| format!("Auth issuer namespace: {e}"))?;
    if store
        .token(&other_auth.token.reference)
        .map_err(|e| e.to_string())?
        != Some(other_auth)
        || store
            .token(&auth.token.reference)
            .map_err(|e| e.to_string())?
            != Some(auth)
    {
        return Err("same Auth JTI collided across issuers".into());
    }
    Ok(())
}

pub(super) fn check_concurrent_token_commit<S: Store + 'static>(store: S) -> Result<(), String> {
    let parent = record("race-parent", "internal-person");
    store
        .commit(parent.clone(), true)
        .map_err(|e| e.to_string())?;
    let left = auth_record("auth-race", &parent);
    let mut right = left.clone();
    right.resource = "https://other-resource.example".into();
    let shared = Arc::new(store);
    let barrier = Arc::new(std::sync::Barrier::new(32));
    let attempts: Vec<_> = (0..32)
        .map(|i| {
            let store = shared.clone();
            let barrier = barrier.clone();
            let candidate = if i % 2 == 0 {
                left.clone()
            } else {
                right.clone()
            };
            std::thread::spawn(move || {
                barrier.wait();
                let result = store.commit(candidate.clone(), false);
                (candidate, result)
            })
        })
        .collect();
    let mut results = Vec::new();
    for attempt in attempts {
        results.push(
            attempt
                .join()
                .map_err(|_| "concurrent token commit panicked")?,
        );
    }
    let winner = shared
        .token(&left.token.reference)
        .map_err(|e| e.to_string())?
        .ok_or("concurrent token winner missing")?;
    if winner != left && winner != right {
        return Err("concurrent token winner differs from both candidates".into());
    }
    for (candidate, result) in results {
        let expected = if candidate == winner {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        };
        if result != expected {
            return Err(
                "concurrent identical winner retry / conflicting loser did not linearize".into(),
            );
        }
    }
    Ok(())
}

/// An R3 audit entry commits in the same write as its issuance: it round-trips
/// with the record, an entry inconsistent with the issuance leaves neither,
/// and the retained issuance cannot be replaced with or without another entry.
pub(super) fn check_r3_audit(store: impl Store) -> Result<(), String> {
    let parent = record("person-r3", "internal-person");
    store
        .commit(parent.clone(), true)
        .map_err(|e| format!("R3 parent Person: {e}"))?;
    let mut auth = parent.clone();
    auth.token.reference.jti = "auth-r3".into();
    auth.token.compact_sha256 = "r3-auth-compact-digest".into();
    auth.kind = TokenKind::Auth;
    auth.presented = Some(parent.token.clone());
    auth.r3 = Some(R3IssuanceAudit {
        r3_uri: "https://resource.example/r3/class".into(),
        r3_s256: aauth_rust_r3::digest(b"class document"),
        vocabulary: "urn:aauth:vocabulary:mcp".into(),
        person_server: auth.token.reference.issuer.clone(),
        subject: auth.subject.clone(),
        account: Some(String::new()),
        presented_jti: parent.token.reference.jti.clone(),
        agent_jkt: auth.agent_jkt.clone(),
        agent: auth.agent.subject.clone(),
        parent_agent: None,
    });
    let inconsistent: &[Mutation] = &[
        ("subject", |r| r.r3.as_mut().unwrap().subject.push('x')),
        ("Agent", |r| r.r3.as_mut().unwrap().agent.push('x')),
        ("Agent thumbprint", |r| {
            r.r3.as_mut().unwrap().agent_jkt.push('x')
        }),
        ("Person Server", |r| {
            r.r3.as_mut().unwrap().person_server = "https://other-ps.example".into()
        }),
        ("digest", |r| {
            r.r3.as_mut().unwrap().r3_s256 = "not-a-digest".into()
        }),
        ("kind", |r| {
            r.kind = TokenKind::Person;
            r.presented = None;
        }),
    ];
    for (name, mutate) in inconsistent {
        let mut refused = auth.clone();
        mutate(&mut refused);
        if store.commit(refused, false) != Err(StoreError::InvalidRecord) {
            return Err(format!(
                "R3 audit entry with another {name} was not refused"
            ));
        }
        if store
            .token(&auth.token.reference)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err(format!("refused R3 audit entry ({name}) left an issuance"));
        }
    }
    store
        .commit(auth.clone(), false)
        .map_err(|e| format!("R3 Auth issuance: {e}"))?;
    let retained = store
        .token(&auth.token.reference)
        .map_err(|e| e.to_string())?;
    if retained != Some(auth.clone()) {
        return Err("R3 audit entry did not round-trip with its issuance".into());
    }
    let changed: &[Mutation] = &[
        ("absent", |r| r.r3 = None),
        ("digest", |r| {
            r.r3.as_mut().unwrap().r3_s256 = aauth_rust_r3::digest(b"other document")
        }),
        ("account", |r| r.r3.as_mut().unwrap().account = None),
    ];
    for (name, mutate) in changed {
        let mut conflicting = auth.clone();
        mutate(&mut conflicting);
        if store.commit(conflicting, false) != Err(StoreError::Conflict) {
            return Err(format!("changed R3 audit entry ({name}) was not refused"));
        }
    }
    if store
        .token(&auth.token.reference)
        .map_err(|e| e.to_string())?
        != Some(auth)
    {
        return Err("refused R3 audit change altered the retained entry".into());
    }
    Ok(())
}
