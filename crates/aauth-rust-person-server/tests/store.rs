use aauth_rust_person_server::{
    AgentIdentity, Binding, MemoryStore, Store, StoreError, TokenKind, TokenRecord, TokenReference,
    storetest,
};

#[test]
fn memory_store_passes_the_public_atomic_binding_and_issuance_contract() {
    storetest::check_store_contract(MemoryStore::default).unwrap();
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
        token: tie.clone(),
        kind: TokenKind::Auth,
        resource: "https://resource.example".into(),
        subject: "directed-person".into(),
        person_id: "internal-person".into(),
        tenant: Some("tenant".into()),
        agent: agent.clone(),
        principal: agent,
        agent_token_jti: "agent-token".into(),
        agent_jkt: "thumbprint".into(),
        issued_at: 1000,
        expires_at: 1300,
        retain_until: 5260,
        presented: Some(tie.clone()),
        upstream: Some(tie),
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
