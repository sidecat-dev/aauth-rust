mod mixed_grants;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flow = mixed_grants::run()?;
    assert_eq!(flow.direct_subject, flow.federated_subject);
    assert!(flow.shared_discovery_key && flow.shared_binding_and_retention);
    assert_eq!(
        (
            flow.tampered_routing_status,
            flow.unknown_audience_status,
            flow.access_calls
        ),
        (400, 400, 1)
    );
    println!(
        "one PS origin: shared key/store/IDs, PS-issued {} and AS-issued {} grants for the same person; routing hints cannot authorize",
        flow.direct_issuer, flow.federated_issuer
    );
    Ok(())
}
