use aauth_rust_person_server::{MemoryStore, storetest};

#[test]
fn memory_store_passes_the_public_atomic_binding_and_issuance_contract() {
    storetest::check_store_contract(MemoryStore::default).unwrap();
}
