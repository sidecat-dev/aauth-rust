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
