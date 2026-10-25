use aauth_rust_agent::{InteractionCompletion, PermissionDecision};

#[test]
fn resource_pending_url_remains_the_completion_signal() {
    let mut watch = InteractionCompletion::new("https://resource.example/pending/job");
    assert_eq!(watch.poll_target(), "https://resource.example/pending/job");
    watch.note_person_server_resolved();
    assert!(watch.person_server_resolved());
    assert!(!watch.is_complete());
    assert_eq!(watch.poll_target(), "https://resource.example/pending/job");
    watch.note_resource_resolved();
    assert!(watch.is_complete());
}

#[test]
fn denied_permission_is_not_proceedable() {
    let denied = PermissionDecision::parse(br#"{"permission":"denied","reason":"no"}"#).unwrap();
    assert!(!denied.may_proceed());
    let granted = PermissionDecision::parse(br#"{"permission":"granted"}"#).unwrap();
    assert!(granted.may_proceed());
}
