use super::*;

pub(super) fn child_record(jti: &str) -> TokenRecord {
    let mut child = record(jti, "internal-person");
    child.parent_agent = Some(child.principal.clone());
    child.agent.subject = "aauth:Agent+worker@ap.example".into();
    child.agent_token_jti = "child-token".into();
    child.agent_jkt = "child-proof-key".into();
    child
}

pub(super) fn check_subagents(store: impl Store) -> Result<(), String> {
    let child = child_record("child-person");
    store
        .commit(child.clone(), true)
        .map_err(|e| format!("first child Person: {e}"))?;
    if store
        .token(&child.token.reference)
        .map_err(|e| e.to_string())?
        != Some(child.clone())
    {
        return Err("child issuance lost its authoritative parent or exact holder".into());
    }
    if store
        .binding(child.binding_issuer(), &child.agent)
        .map_err(|e| e.to_string())?
        .is_some()
        || store
            .binding(child.binding_issuer(), &child.principal)
            .map_err(|e| e.to_string())?
            .is_none_or(|binding| binding.revoked || binding.person_id != child.person_id)
    {
        return Err("child issuance did not establish only the parent binding".into());
    }
    for mode in 0..4 {
        let mut invalid = child.clone();
        invalid.token.reference.jti = format!("invalid-child-{mode}");
        match mode {
            0 => invalid.parent_agent = None,
            1 => invalid.parent_agent = Some(invalid.agent.clone()),
            2 => invalid.parent_agent.as_mut().unwrap().subject = "aauth:Other@ap.example".into(),
            _ => invalid.upstream = Some(child.token.clone()),
        }
        if store.commit(invalid.clone(), true) != Err(StoreError::InvalidRecord)
            || store
                .token(&invalid.token.reference)
                .map_err(|e| e.to_string())?
                .is_some()
        {
            return Err(format!(
                "malformed child parent/chain case {mode} changed state"
            ));
        }
    }
    let mut auth = child.clone();
    auth.kind = TokenKind::Auth;
    auth.token.reference.jti = "child-auth".into();
    auth.token.compact_sha256 = "exact-child-auth".into();
    auth.presented = Some(child.token.clone());
    store
        .commit(auth.clone(), false)
        .map_err(|e| e.to_string())?;
    let mut federated = auth.clone();
    federated.token.reference.issuer = "https://as.example".into();
    federated.token.reference.jti = "child-as-auth".into();
    federated.person_server = Some(child.binding_issuer().into());
    store
        .commit(federated.clone(), false)
        .map_err(|e| e.to_string())?;
    for expected in [&child, &auth, &federated] {
        if store
            .token(&expected.token.reference)
            .map_err(|e| e.to_string())?
            != Some(expected.clone())
        {
            return Err("child Person/Auth receipt did not preserve parent and holder".into());
        }
        let mut changed = expected.clone();
        changed.parent_agent = None;
        if store.commit(changed, false) != Err(StoreError::Conflict) {
            return Err("same-token retry changed a retained child parent".into());
        }
    }
    store
        .revoke_binding(child.binding_issuer(), &child.principal)
        .map_err(|e| e.to_string())?;
    for mut new in [child.clone(), auth, federated] {
        let establish = new.kind == TokenKind::Person;
        new.token.reference.jti.push_str("-after-revocation");
        if store.commit(new.clone(), establish) != Err(StoreError::RevokedBinding)
            || store
                .token(&new.token.reference)
                .map_err(|e| e.to_string())?
                .is_some()
        {
            return Err("child issuance bypassed revoked parent binding".into());
        }
    }
    Ok(())
}
