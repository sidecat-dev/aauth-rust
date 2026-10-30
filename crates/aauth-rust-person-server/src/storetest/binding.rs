use super::{Store, StoreError, TokenKind, record};
use crate::Binding;

/// A replacement binding exists only after revocation, is one generation
/// later, and never revives a credential issued under an earlier binding.
pub(super) fn check_binding_replacement(store: impl Store) -> Result<(), String> {
    let first = record("bound-person", "first-person");
    let issuer = first.token.reference.issuer.clone();
    let agent = first.principal.clone();
    store
        .commit(first.clone(), true)
        .map_err(|e| format!("first binding: {e}"))?;
    if store.replace_binding(&issuer, &agent, "second-person") != Err(StoreError::Conflict) {
        return Err("an active binding was replaced without revocation".into());
    }
    let mut stranger = agent.clone();
    stranger.subject = "aauth:Stranger@ap.example".into();
    if store.replace_binding(&issuer, &stranger, "second-person") != Err(StoreError::MissingBinding)
    {
        return Err("a missing binding was replaced".into());
    }
    store
        .revoke_binding(&issuer, &agent)
        .map_err(|e| e.to_string())?;
    if store.replace_binding(&issuer, &agent, "") != Err(StoreError::InvalidRecord) {
        return Err("a binding was replaced for an empty person".into());
    }
    let replaced = store
        .replace_binding(&issuer, &agent, "second-person")
        .map_err(|e| format!("replacement: {e}"))?;
    let expected = Binding {
        person_id: "second-person".into(),
        revoked: false,
        generation: 1,
    };
    if replaced != expected
        || store.binding(&issuer, &agent).map_err(|e| e.to_string())? != Some(expected)
    {
        return Err("replacement is not an active binding one generation later".into());
    }

    let mut stale = record("stale-auth", "first-person");
    stale.kind = TokenKind::Auth;
    stale.presented = Some(first.token.clone());
    if store.commit(stale, false) != Err(StoreError::RevokedBinding) {
        return Err("a credential of the revoked binding was admitted".into());
    }
    let mut current = record("second-person-token", "second-person");
    current.subject = "second-directed-person".into();
    current.binding_generation = 1;
    store
        .commit(current.clone(), true)
        .map_err(|e| format!("issuance under the replacement: {e}"))?;
    let mut other = record("first-person-again", "first-person");
    other.binding_generation = 1;
    if store.commit(other, true) != Err(StoreError::Conflict) {
        return Err("another person claimed the replaced binding".into());
    }

    // Binding the first person again is a third binding. Their credentials
    // from the first one stay revoked.
    store
        .revoke_binding(&issuer, &agent)
        .map_err(|e| e.to_string())?;
    let again = store
        .replace_binding(&issuer, &agent, "first-person")
        .map_err(|e| format!("second replacement: {e}"))?;
    if again.generation != 2 || again.revoked {
        return Err("second replacement is not generation 2".into());
    }
    let mut revived = record("revived-auth", "first-person");
    revived.kind = TokenKind::Auth;
    revived.presented = Some(first.token.clone());
    if store.commit(revived, false) != Err(StoreError::RevokedBinding) {
        return Err("a replacement revived a credential of an earlier binding".into());
    }
    if store
        .token(&first.token.reference)
        .map_err(|e| e.to_string())?
        != Some(first)
    {
        return Err("replacement changed a retained record".into());
    }
    Ok(())
}
