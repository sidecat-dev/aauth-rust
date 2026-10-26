use crate::error::Error;
use crate::hints::{AccessMode, OperationHints};

#[test]
fn hints_access_mode_wire_spellings_are_exact() {
    for mode in [
        AccessMode::AgentToken,
        AccessMode::PersonToken,
        AccessMode::SessionToken,
        AccessMode::AuthToken,
        AccessMode::PerCall,
    ] {
        assert_eq!(AccessMode::parse(mode.as_str()).ok(), Some(mode));
    }
    for text in ["", "unknown", "Auth-Token", "per_call", " auth-token"] {
        assert!(AccessMode::parse(text).is_err(), "accepted {text:?}");
    }
}

#[test]
fn hints_keep_sparse_presence_and_refuse_a_session_annotation() -> Result<(), Error> {
    let hints = OperationHints::new(Some(AccessMode::PersonToken), Some(false))?;
    assert_eq!(hints.access_mode(), Some(AccessMode::PersonToken));
    assert_eq!(hints.budget(), Some(false));
    let absent = OperationHints::new(None, None)?;
    assert_eq!(absent.access_mode(), None);
    assert_eq!(absent.budget(), None);
    assert!(OperationHints::new(Some(AccessMode::SessionToken), None).is_err());
    Ok(())
}

#[test]
fn hints_plan_expected_credential_without_granting_it() -> Result<(), Error> {
    use AccessMode::{AgentToken, AuthToken, PerCall, PersonToken, SessionToken};
    let cases = [
        (
            "resource default",
            PersonToken,
            None,
            None,
            PersonToken,
            false,
            false,
        ),
        (
            "explicit replacement",
            AuthToken,
            Some(PersonToken),
            None,
            PersonToken,
            false,
            false,
        ),
        (
            "per call",
            AgentToken,
            Some(PerCall),
            None,
            PerCall,
            false,
            false,
        ),
        (
            "budget implies auth",
            AgentToken,
            None,
            Some(true),
            AuthToken,
            true,
            false,
        ),
        (
            "budget replaces session default",
            SessionToken,
            None,
            Some(true),
            AuthToken,
            true,
            false,
        ),
        (
            "contradictory publication",
            AuthToken,
            Some(AgentToken),
            Some(true),
            AuthToken,
            true,
            true,
        ),
        (
            "per-call budget",
            AuthToken,
            Some(PerCall),
            Some(true),
            PerCall,
            true,
            false,
        ),
        (
            "per-call default budget",
            PerCall,
            None,
            Some(true),
            PerCall,
            true,
            false,
        ),
        (
            "explicit false budget",
            AgentToken,
            None,
            Some(false),
            AgentToken,
            false,
            false,
        ),
    ];
    for (name, default, mode, budget, want_mode, want_budget, want_conflict) in cases {
        let plan = OperationHints::new(mode, budget)?.plan(default);
        assert_eq!(plan.access_mode(), want_mode, "{name}");
        assert_eq!(plan.budget_required(), want_budget, "{name}");
        assert_eq!(plan.publisher_conflict(), want_conflict, "{name}");
    }
    Ok(())
}

#[test]
fn hints_separate_publisher_validation_from_agent_fallback() -> Result<(), Error> {
    for mode in [AccessMode::AgentToken, AccessMode::PersonToken] {
        let hints = OperationHints::new(Some(mode), Some(true))?;
        assert!(hints.validate_for_publication().is_err(), "{mode}");
        let plan = hints.plan(AccessMode::AgentToken);
        assert_eq!(plan.access_mode(), AccessMode::AuthToken);
        assert!(plan.publisher_conflict());
    }
    for (mode, budget) in [
        (Some(AccessMode::PerCall), Some(true)),
        (Some(AccessMode::AuthToken), Some(true)),
        (Some(AccessMode::PersonToken), Some(false)),
        (None, Some(true)),
        (None, None),
    ] {
        OperationHints::new(mode, budget)?.validate_for_publication()?;
    }
    Ok(())
}
