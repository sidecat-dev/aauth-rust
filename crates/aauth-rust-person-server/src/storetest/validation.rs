use super::{Store, StoreError, TokenKind, TokenRecord, record};

pub(super) fn check_invalid_records<S: Store>(factory: impl Fn() -> S) -> Result<(), String> {
    let mutations: &[fn(&mut TokenRecord)] = &[
        |r| {
            r.agent.issuer.clear();
            r.principal = r.agent.clone();
        },
        |r| {
            r.agent.subject.clear();
            r.principal = r.agent.clone();
        },
        |r| r.agent.issuer.clear(),
        |r| r.agent.subject.clear(),
        |r| r.principal.issuer.clear(),
        |r| r.principal.subject.clear(),
        |r| r.presented = Some(r.token.clone()),
        |r| {
            r.kind = TokenKind::Auth;
            r.presented = None;
        },
        |r| {
            let mut tie = r.token.clone();
            tie.reference.issuer.clear();
            r.upstream = Some(tie);
        },
        |r| {
            let mut tie = r.token.clone();
            tie.reference.jti.clear();
            r.upstream = Some(tie);
        },
        |r| {
            let mut tie = r.token.clone();
            tie.compact_sha256.clear();
            r.upstream = Some(tie);
        },
        |r| {
            r.kind = TokenKind::Auth;
            let mut tie = r.token.clone();
            tie.reference.issuer.clear();
            r.presented = Some(tie);
        },
        |r| {
            r.kind = TokenKind::Auth;
            let mut tie = r.token.clone();
            tie.reference.jti.clear();
            r.presented = Some(tie);
        },
        |r| {
            r.kind = TokenKind::Auth;
            let mut tie = r.token.clone();
            tie.compact_sha256.clear();
            r.presented = Some(tie);
        },
    ];
    for (case, mutate) in mutations.iter().enumerate() {
        let store = factory();
        let original = record("invalid-shape", "internal-person");
        let mut invalid = original.clone();
        mutate(&mut invalid);
        let establish = invalid.kind == TokenKind::Person;
        if store.commit(invalid.clone(), establish) != Err(StoreError::InvalidRecord) {
            return Err(format!(
                "malformed identity/lineage case {case} was not InvalidRecord"
            ));
        }
        if store
            .token(&invalid.token.reference)
            .map_err(|e| e.to_string())?
            .is_some()
            || store
                .binding(&invalid.token.reference.issuer, &invalid.principal)
                .map_err(|e| e.to_string())?
                .is_some()
        {
            return Err(format!("malformed case {case} created a token or binding"));
        }
        // Either private index would make one of these subsequent valid
        // issuances conflict. Use the same person with a different subject,
        // then a different person with the refused subject.
        let mut corrected = original.clone();
        corrected.subject.push_str("-corrected");
        store
            .commit(corrected, true)
            .map_err(|e| format!("malformed case {case} leaked a directed index: {e}"))?;
        let mut other = original;
        other.token.reference.jti.push_str("-other");
        other.person_id.push_str("-other");
        other.agent.subject = "aauth:Other@ap.example".into();
        other.principal = other.agent.clone();
        store
            .commit(other, true)
            .map_err(|e| format!("malformed case {case} leaked a subject index: {e}"))?;
    }
    Ok(())
}
