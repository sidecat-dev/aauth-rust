#[path = "../examples/r3_three_party/mod.rs"]
mod journey;

#[test]
fn tls_class_r3_agent_ps_resource_writes_one_receipt_for_a_narrower_grant() {
    let t = journey::run().unwrap();
    // Differing-origin metadata: identity at records.example, endpoints at the signed origin.
    assert_eq!(
        t.authorization_endpoint,
        "https://api.records.example/authorize"
    );
    assert!(t.r3_uri_at_signed_origin);
    // The PS fetched the literal document for the grant, the widened attempt and
    // the audit-failure attempt; closed egress fetched nothing.
    assert_eq!(t.documents_served, 3);
    // Requested read and export; host consent granted only read.
    assert_eq!(t.granted, [r#"{"tool":"records.read"}"#]);
    assert_eq!(t.authorized_status, 200);
    assert!(t.receipt_matches_signed_body);
    assert_eq!(t.receipts, 1);
    // Only the successful issuance reached the audit log.
    assert_eq!(t.audit_records, 1);

    assert_eq!(t.not_granted_status, 403);
    assert_eq!(t.tampered_status, 401);
    assert_eq!(t.wrong_holder_status, 401);
    assert_eq!(t.agent_fetch_status, 401);
    assert_eq!(t.unsigned_fetch_status, 401);
    assert!(t.substituted_reference_refused);
    assert_eq!(t.unknown_operation_status, 400);
    assert_eq!(t.widened_grant_status, 500);
    assert_eq!(t.fetch_refused_status, 500);
    assert_eq!(t.resource_store_failure_status, 500);
    assert_eq!(t.audit_failure_status, 500);
    assert!(t.untrusted_tls_refused);
}
