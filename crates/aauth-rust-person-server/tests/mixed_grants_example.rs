#[path = "../examples/mixed_grants/mod.rs"]
mod mixed;

#[test]
fn one_person_server_origin_serves_verified_direct_and_federated_grants() {
    let flow = mixed::run().unwrap();
    assert_eq!(flow.direct_issuer, "https://ps.example");
    assert_eq!(flow.federated_issuer, "https://as.example");
    assert_eq!(flow.direct_subject, flow.federated_subject);
    assert!(flow.shared_discovery_key);
    assert!(flow.shared_binding_and_retention);
    assert_eq!(flow.tampered_routing_status, 400);
    assert_eq!(flow.unknown_audience_status, 400);
    assert_eq!(
        flow.access_calls, 1,
        "routing hints alone must never authorize an AS call"
    );
}
