use super::{AgentIdentity, Store, StoreError, TokenRecord, issuance::auth_record, record};

fn assert_retained(store: &impl Store, expected: &TokenRecord) -> Result<(), String> {
    if store
        .token(&expected.token.reference)
        .map_err(|e| e.to_string())?
        != Some(expected.clone())
    {
        return Err("reopened store lost or changed a complete issuance".into());
    }
    Ok(())
}

/// Check retained Person/Auth records, issuer namespaces, atomic refusal and
/// sticky binding revocation across two actual close/reopen cycles.
///
/// `factory` must create a fresh disposable store. `reopen` consumes its sole
/// live handle and must close it before reopening the same backend. The callback
/// owns backend-specific paths and errors; returning the original live object
/// does not test persistence. Run [`super::check_store_contract`] separately.
/// This contract does not simulate process death, power loss or storage failure.
///
/// # Errors
/// Returns an explanation if reopening fails or retained state changes.
pub fn check_persistence_contract<S: Store>(
    factory: impl Fn() -> S,
    reopen: impl Fn(S) -> Result<S, String>,
) -> Result<(), String> {
    let store = factory();
    let parent = record("retained-person", "internal-person");
    let auth = auth_record("retained-auth", &parent);
    store
        .commit(parent.clone(), true)
        .map_err(|e| e.to_string())?;
    store
        .commit(auth.clone(), false)
        .map_err(|e| e.to_string())?;
    let child = super::subagents::child_record("persisted-child");
    store
        .commit(child.clone(), true)
        .map_err(|e| e.to_string())?;
    let mut other_parent = parent.clone();
    other_parent.token.reference.issuer = "https://other-ps.example".into();
    let other_auth = auth_record("retained-auth", &other_parent);
    store
        .commit(other_parent.clone(), true)
        .map_err(|e| e.to_string())?;
    store
        .commit(other_auth.clone(), false)
        .map_err(|e| e.to_string())?;
    let mut federated = parent.clone();
    federated.kind = crate::TokenKind::Auth;
    federated.token.reference.issuer = "https://as.example".into();
    federated.token.reference.jti = "federated-auth".into();
    federated.person_server = Some(parent.token.reference.issuer.clone());
    federated.presented = Some(parent.token.clone());
    store
        .commit(federated.clone(), false)
        .map_err(|e| format!("federated commit: {e}"))?;
    check_refusal_atomicity(&store, "before-reopen")?;
    let mut changed = auth.clone();
    changed.upstream.as_mut().unwrap().compact_sha256.push('x');
    if store.commit(changed, false) != Err(StoreError::Conflict) {
        return Err("changed retained Auth accepted before reopening".into());
    }
    let store = reopen(store).map_err(|e| format!("first reopen: {e}"))?;
    for expected in [
        &parent,
        &auth,
        &other_parent,
        &other_auth,
        &federated,
        &child,
    ] {
        assert_retained(&store, expected)?;
    }
    let binding = store
        .binding(&parent.token.reference.issuer, &parent.principal)
        .map_err(|e| e.to_string())?
        .ok_or("reopened store lost binding")?;
    if binding.person_id != parent.person_id || binding.revoked {
        return Err("reopened store changed the original active binding".into());
    }
    check_refusal_atomicity(&store, "after-reopen")?;
    store
        .revoke_binding(&parent.token.reference.issuer, &parent.principal)
        .map_err(|e| e.to_string())?;
    let store = reopen(store).map_err(|e| format!("second reopen: {e}"))?;
    if !store
        .binding(&parent.token.reference.issuer, &parent.principal)
        .map_err(|e| e.to_string())?
        .is_some_and(|b| b.revoked && b.person_id == parent.person_id)
    {
        return Err("reopened store lost binding revocation".into());
    }
    // An exact retention retry is not a fresh credential release. It must not
    // silently reclaim the revoked binding or change the stored issuance.
    store
        .commit(auth.clone(), false)
        .map_err(|e| format!("exact retry after revocation: {e}"))?;
    let mut new_auth = auth.clone();
    new_auth.token.reference.jti = "after-revocation".into();
    if store.commit(new_auth.clone(), false) != Err(StoreError::RevokedBinding)
        || store
            .token(&new_auth.token.reference)
            .map_err(|e| e.to_string())?
            .is_some()
        || !store
            .binding(&parent.token.reference.issuer, &parent.principal)
            .map_err(|e| e.to_string())?
            .is_some_and(|b| b.revoked)
    {
        return Err("reopened revoked binding allowed a new issuance or was reclaimed".into());
    }
    let mut independent = other_auth.clone();
    independent.token.reference.jti = "unrelated-issuer-after-revocation".into();
    store
        .commit(independent, false)
        .map_err(|e| format!("revocation escaped issuer namespace: {e}"))?;
    for expected in [
        &parent,
        &auth,
        &other_parent,
        &other_auth,
        &federated,
        &child,
    ] {
        assert_retained(&store, expected)?;
    }
    Ok(())
}

pub(super) fn check_refusal_atomicity(store: &impl Store, prefix: &str) -> Result<(), String> {
    let mut original = record(&format!("{prefix}-original"), &format!("{prefix}-person"));
    original.subject = format!("{prefix}-subject");
    original.agent.subject = format!("aauth:{prefix}@ap.example");
    original.principal = original.agent.clone();
    store
        .commit(original.clone(), true)
        .map_err(|e| e.to_string())?;
    let issuer = &original.token.reference.issuer;

    let mut collision = original.clone();
    collision.token.reference.jti = format!("{prefix}-collision");
    collision.person_id.push_str("-other");
    collision.agent = AgentIdentity {
        issuer: original.agent.issuer.clone(),
        subject: format!("aauth:{prefix}-other@ap.example"),
    };
    collision.principal = collision.agent.clone();
    if store.commit(collision.clone(), true) != Err(StoreError::Conflict)
        || store
            .binding(issuer, &collision.principal)
            .map_err(|e| e.to_string())?
            .is_some()
        || store
            .token(&collision.token.reference)
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err("refused subject collision leaked binding or token state".into());
    }
    // This correction is valid only if the refused commit did not populate the
    // other person's directed-identity index with the original person's subject.
    collision.subject.push_str("-other");
    store
        .commit(collision, true)
        .map_err(|e| format!("refusal polluted directed index: {e}"))?;

    let mut changed = original.clone();
    changed.token.reference.jti = format!("{prefix}-changed-subject");
    changed.subject.push_str("-changed");
    if store.commit(changed.clone(), true) != Err(StoreError::Conflict)
        || store
            .token(&changed.token.reference)
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err("refused directed identity change leaked token state".into());
    }
    let mut retry = original.clone();
    retry.token.reference.jti = format!("{prefix}-valid-retry");
    store
        .commit(retry, true)
        .map_err(|e| format!("refusal changed original directed identity: {e}"))?;
    // The failed subject must still be available for a different person; this
    // catches pollution of the reverse Resource/subject -> person index.
    changed.token.reference.jti = format!("{prefix}-reuse-refused-subject");
    changed.person_id.push_str("-third");
    changed.agent.subject = format!("aauth:{prefix}-third@ap.example");
    changed.principal = changed.agent.clone();
    store
        .commit(changed, true)
        .map_err(|e| format!("refusal polluted subject index: {e}"))?;

    let mut rebound = original.clone();
    rebound.token.reference.jti = format!("{prefix}-rebind");
    rebound.person_id.push_str("-replacement");
    rebound.subject.push_str("-replacement");
    if store.commit(rebound.clone(), true) != Err(StoreError::Conflict)
        || store
            .token(&rebound.token.reference)
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err("refused rebind created issuance state".into());
    }
    let binding = store
        .binding(issuer, &original.principal)
        .map_err(|e| e.to_string())?
        .ok_or("binding disappeared after refused rebind")?;
    if binding.person_id != original.person_id || binding.revoked {
        return Err("refused rebind changed original person".into());
    }
    assert_retained(store, &original)
}
