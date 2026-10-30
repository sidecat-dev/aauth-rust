use aauth_rust_person_server::{
    AgentIdentity, Binding, MemoryStore, Store, StoreError, TokenKind, TokenRecord, TokenReference,
    storetest,
};

#[test]
fn memory_store_passes_the_public_atomic_binding_and_issuance_contract() {
    storetest::check_store_contract(MemoryStore::default).unwrap();
}

#[test]
fn child_person_retains_authoritative_parent_and_establishes_only_parent_binding() {
    let mut value = serde_json::to_value(record()).unwrap();
    value["kind"] = serde_json::json!("Person");
    value["presented"] = serde_json::Value::Null;
    value["upstream"] = serde_json::Value::Null;
    value["parent_agent"] = value["principal"].clone();
    value["agent"]["subject"] = serde_json::json!("aauth:Agent+worker@ap.example");
    let child: TokenRecord = serde_json::from_value(value).unwrap();
    let store = MemoryStore::default();
    assert_eq!(store.commit(child.clone(), true), Ok(()));
    let retained = store.token(&child.token.reference).unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&retained).unwrap()["parent_agent"]["subject"],
        "aauth:Agent@ap.example"
    );
    assert!(
        store
            .binding("https://ps.example", &child.agent)
            .unwrap()
            .is_none()
    );
    store
        .revoke_binding("https://ps.example", &child.principal)
        .unwrap();
    let mut another = child;
    another.token.reference.jti = "another-child-credential".into();
    assert_eq!(store.commit(another, true), Err(StoreError::RevokedBinding));
}

#[test]
fn tenant_is_not_part_of_the_directed_person_identifier() {
    let mut value = serde_json::to_value(record()).unwrap();
    value["kind"] = serde_json::json!("Person");
    value["presented"] = serde_json::Value::Null;
    value["upstream"] = serde_json::Value::Null;
    value["parent_agent"] = value["principal"].clone();
    value["agent"]["subject"] = serde_json::json!("aauth:Agent+worker@ap.example");
    value["tenant"] = serde_json::json!("team");
    let first: TokenRecord = serde_json::from_value(value.clone()).unwrap();
    let store = MemoryStore::default();
    assert_eq!(store.commit(first, true), Ok(()));

    value["token"]["reference"]["jti"] = serde_json::json!("same-person-other-tenant");
    value["tenant"] = serde_json::json!("other-team");
    let same_person: TokenRecord = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(store.commit(same_person, true), Ok(()));

    value["token"]["reference"]["jti"] = serde_json::json!("other-subject");
    value["subject"] = serde_json::json!("other-directed-person");
    value["tenant"] = serde_json::json!("third-team");
    let other_subject: TokenRecord = serde_json::from_value(value).unwrap();
    assert_eq!(store.commit(other_subject, true), Err(StoreError::Conflict));
}

// A host adapter can accidentally omit fields from its Auth-row serializer even
// when Person records round-trip correctly. The public contract must catch it.
#[derive(Default)]
struct DropsAuthLineage(MemoryStore);
impl Store for DropsAuthLineage {
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        self.0.binding(issuer, agent)
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        self.0.token(reference).map(|record| {
            record.map(|mut record| {
                if record.kind == TokenKind::Auth {
                    record.upstream = None;
                }
                record
            })
        })
    }
    fn commit(&self, record: TokenRecord, establish: bool) -> Result<(), StoreError> {
        self.0.commit(record, establish)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        self.0.revoke_binding(issuer, agent)
    }
}

#[test]
fn public_contract_detects_an_adapter_that_drops_auth_lineage() {
    assert!(storetest::check_store_contract(DropsAuthLineage::default).is_err());
}

#[test]
fn persistence_contract_detects_state_lost_when_the_store_is_reopened() {
    assert!(
        storetest::check_persistence_contract(MemoryStore::default, |_| {
            Ok(MemoryStore::default())
        })
        .is_err()
    );
}

fn record() -> TokenRecord {
    use aauth_rust_person_server::TokenTie;
    let agent = AgentIdentity {
        issuer: "https://ap.example".into(),
        subject: "aauth:Agent@ap.example".into(),
    };
    let tie = TokenTie {
        reference: TokenReference {
            issuer: "https://ps.example".into(),
            jti: "token-1".into(),
        },
        compact_sha256: "digest".into(),
    };
    TokenRecord {
        parent_agent: None,
        person_server: None,
        token: tie.clone(),
        kind: TokenKind::Auth,
        resource: "https://resource.example".into(),
        subject: "directed-person".into(),
        person_id: "internal-person".into(),
        tenant: Some("tenant".into()),
        agent: agent.clone(),
        principal: agent,
        binding_generation: 0,
        agent_token_jti: "agent-token".into(),
        agent_jkt: "thumbprint".into(),
        issued_at: 1000,
        expires_at: 1300,
        retain_until: 5260,
        presented: Some(tie.clone()),
        upstream: Some(tie),
        r3: None,
    }
}

#[test]
fn store_adapters_share_complete_record_serialization_and_shape_validation() {
    let valid = record();
    assert_eq!(valid.validate_for_commit(false), Ok(()));
    assert_eq!(
        valid.validate_for_commit(true),
        Err(StoreError::InvalidRecord)
    );
    let round_trip: TokenRecord =
        serde_json::from_slice(&serde_json::to_vec(&valid).unwrap()).unwrap();
    assert_eq!(round_trip, valid);
    for change in [
        (|r: &mut TokenRecord| r.token.reference.jti.clear()) as fn(&mut TokenRecord),
        |r| r.token.compact_sha256.clear(),
        |r| r.person_id.clear(),
        |r| r.subject.clear(),
        |r| r.agent_jkt.clear(),
        |r| r.agent_token_jti.clear(),
        |r| r.issued_at = -1,
        |r| r.expires_at = r.issued_at,
        |r| r.retain_until = r.expires_at - 1,
        |r| r.resource = "http://resource.example".into(),
        |r| r.token.reference.issuer = "http://ps.example".into(),
        |r| r.agent.issuer.clear(),
        |r| r.agent.subject.clear(),
        |r| r.principal.issuer.clear(),
        |r| r.principal.subject.clear(),
        |r| r.agent.issuer = "http://ap.example".into(),
        |r| r.agent.subject = "not-an-agent".into(),
        |r| r.principal.issuer = "http://ap.example".into(),
        |r| r.principal.subject = "not-an-agent".into(),
        |r| r.presented.as_mut().unwrap().reference.issuer.clear(),
        |r| r.presented.as_mut().unwrap().reference.jti.clear(),
        |r| r.presented.as_mut().unwrap().compact_sha256.clear(),
        |r| r.upstream.as_mut().unwrap().reference.issuer.clear(),
        |r| r.upstream.as_mut().unwrap().reference.jti.clear(),
        |r| r.upstream.as_mut().unwrap().compact_sha256.clear(),
        |r| r.kind = TokenKind::Person,
        |r| r.presented = None,
    ] {
        let mut invalid = valid.clone();
        change(&mut invalid);
        assert_eq!(
            invalid.validate_for_commit(false),
            Err(StoreError::InvalidRecord)
        );
        assert_eq!(
            MemoryStore::default().commit(invalid, false),
            Err(StoreError::InvalidRecord)
        );
    }
}

#[derive(Default)]
struct DropsChildParent(MemoryStore);
impl Store for DropsChildParent {
    fn binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<Option<Binding>, StoreError> {
        self.0.binding(issuer, agent)
    }
    fn token(&self, reference: &TokenReference) -> Result<Option<TokenRecord>, StoreError> {
        self.0.token(reference).map(|record| {
            record.map(|mut r| {
                r.parent_agent = None;
                r
            })
        })
    }
    fn commit(&self, record: TokenRecord, establish: bool) -> Result<(), StoreError> {
        self.0.commit(record, establish)
    }
    fn revoke_binding(&self, issuer: &str, agent: &AgentIdentity) -> Result<(), StoreError> {
        self.0.revoke_binding(issuer, agent)
    }
}
#[test]
fn public_contract_detects_lost_parent_identity_on_child_records() {
    assert!(storetest::check_store_contract(DropsChildParent::default).is_err());
}
