use super::*;

pub(super) fn check_federation(store: impl Store) -> Result<(), String> {
    let person = record("person-fed", "person");
    store
        .commit(person.clone(), true)
        .map_err(|e| e.to_string())?;
    let mut auth = person.clone();
    auth.kind = TokenKind::Auth;
    auth.token.reference.issuer = "https://as.example".into();
    auth.token.reference.jti = "as-auth".into();
    auth.token.compact_sha256 = "as-digest".into();
    auth.person_server = Some("https://ps.example".into());
    auth.presented = Some(person.token.clone());
    store
        .commit(auth.clone(), false)
        .map_err(|e| format!("AS Auth with PS binding: {e}"))?;
    store
        .commit(auth.clone(), false)
        .map_err(|e| format!("exact AS Auth retry: {e}"))?;
    if store
        .token(&auth.token.reference)
        .map_err(|e| e.to_string())?
        != Some(auth.clone())
    {
        return Err("AS issuer/PS namespace did not round-trip".into());
    }
    if store
        .binding("https://as.example", &person.principal)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("AS token invented an AS person binding".into());
    }
    let mut conflicting = auth.clone();
    conflicting.person_server = Some("https://other-ps.example".into());
    if store.commit(conflicting, false) != Err(StoreError::Conflict) {
        return Err("PS namespace rewrite was not a conflict".into());
    }
    for mode in 0..3 {
        let mut invalid = auth.clone();
        invalid.token.reference.jti = format!("invalid-{mode}");
        match mode {
            0 => invalid.person_server = Some("https://other-ps.example".into()),
            1 => invalid.presented.as_mut().unwrap().compact_sha256.push('x'),
            _ => invalid.subject.push('x'),
        }
        if store.commit(invalid.clone(), false).is_ok()
            || store
                .token(&invalid.token.reference)
                .map_err(|e| e.to_string())?
                .is_some()
        {
            return Err(format!("invalid federated ancestry accepted: {mode}"));
        }
    }
    let mut step = auth.clone();
    step.token.reference.jti = "as-step".into();
    step.presented = Some(auth.token.clone());
    store
        .commit(step, false)
        .map_err(|e| format!("AS Auth step-up: {e}"))?;
    store
        .revoke_binding("https://ps.example", &person.principal)
        .map_err(|e| e.to_string())?;
    let mut after = auth;
    after.token.reference.jti = "after-revoke".into();
    if store.commit(after, false) != Err(StoreError::RevokedBinding) {
        return Err("AS Auth bypassed revoked PS binding".into());
    }
    Ok(())
}
