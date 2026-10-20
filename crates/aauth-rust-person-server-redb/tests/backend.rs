mod support;
use aauth_rust_person_server::{Store, StoreError, storetest};
use aauth_rust_person_server_redb::RedbStore;
use std::cell::RefCell;
use support::record;

#[derive(Default)]
struct Databases(RefCell<Vec<tempfile::TempDir>>);
impl Databases {
    fn fresh(&self) -> RedbStore {
        let directory = tempfile::tempdir().unwrap();
        let store = RedbStore::open(directory.path().join("person.redb")).unwrap();
        self.0.borrow_mut().push(directory);
        store
    }
}

#[test]
fn durable_adapter_passes_the_shared_logical_contract() {
    let databases = Databases::default();
    storetest::check_store_contract(|| databases.fresh()).unwrap();
}

#[test]
fn durable_adapter_passes_the_consuming_reopen_contract() {
    let databases = Databases::default();
    storetest::check_persistence_contract(
        || databases.fresh(),
        |store| {
            let path = store.path().to_owned();
            drop(store);
            RedbStore::open(path).map_err(|e| e.to_string())
        },
    )
    .unwrap();
}

#[test]
fn clones_share_commits_and_the_last_close_releases_the_file_lock() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let store = RedbStore::open(&path).unwrap();
    assert_eq!(store.path(), path);
    let clone = store.clone();
    let expected = record("shared");
    store.commit(expected.clone(), true).unwrap();
    assert_eq!(
        clone.token(&expected.token.reference).unwrap(),
        Some(expected.clone())
    );
    drop(store);
    assert_eq!(
        RedbStore::open(&path).err().unwrap().code(),
        "store_unavailable"
    );
    drop(clone);
    let reopened = RedbStore::open(&path).unwrap();
    assert_eq!(
        reopened.token(&expected.token.reference).unwrap(),
        Some(expected.clone())
    );
    reopened
        .revoke_binding(&expected.token.reference.issuer, &expected.principal)
        .unwrap();
    reopened.commit(expected.clone(), true).unwrap();
    assert!(
        reopened
            .binding(&expected.token.reference.issuer, &expected.principal)
            .unwrap()
            .unwrap()
            .revoked
    );
    let mut replacement = expected;
    replacement.token.reference.jti = "fresh-after-revocation".into();
    assert_eq!(
        reopened.commit(replacement, true),
        Err(StoreError::RevokedBinding)
    );
}

#[test]
fn local_open_errors_are_typed_and_do_not_overwrite_existing_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("not-a-database");
    std::fs::write(&path, b"not a redb database").unwrap();
    assert_eq!(
        RedbStore::open(&path).err().unwrap().code(),
        "store_unavailable"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"not a redb database");
    assert_eq!(
        RedbStore::open(directory.path().join("missing/parent/db"))
            .err()
            .unwrap()
            .code(),
        "store_unavailable"
    );
}

#[test]
fn unrecognized_database_identity_or_schema_is_refused_without_adopting_it() {
    use redb::{Database, ReadableDatabase, TableDefinition};
    let directory = tempfile::tempdir().unwrap();
    for (name, version) in [("unrelated", None), ("future", Some(999))] {
        let path = directory.path().join(name);
        let database = Database::create(&path).unwrap();
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction
                .open_table(TableDefinition::<&str, u64>::new("unrelated"))
                .unwrap();
            table.insert("untouched", 42).unwrap();
            if let Some(version) = version {
                let mut meta = transaction
                    .open_table(TableDefinition::<&str, u64>::new("aauth_ps_metadata"))
                    .unwrap();
                meta.insert("schema_version", version).unwrap();
            }
        }
        transaction.commit().unwrap();
        drop(database);
        assert_eq!(
            RedbStore::open(&path).err().unwrap().code(),
            "unsupported_store_schema"
        );
        let database = Database::open(&path).unwrap();
        let read = database.begin_read().unwrap();
        let table = read
            .open_table(TableDefinition::<&str, u64>::new("unrelated"))
            .unwrap();
        assert_eq!(table.get_owned("untouched").unwrap().unwrap().value(), 42);
    }
}

#[test]
fn future_version_of_an_otherwise_complete_schema_is_refused() {
    use redb::{Database, ReadableDatabase, TableDefinition};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let store = RedbStore::open(&path).unwrap();
    let expected = record("old-schema-record");
    store.commit(expected, true).unwrap();
    drop(store);
    let database = Database::open(&path).unwrap();
    let transaction = database.begin_write().unwrap();
    transaction
        .open_table(TableDefinition::<&str, u64>::new("aauth_ps_metadata"))
        .unwrap()
        .insert("schema_version", 999)
        .unwrap();
    transaction.commit().unwrap();
    drop(database);
    assert_eq!(
        RedbStore::open(&path).err().unwrap().code(),
        "unsupported_store_schema"
    );
    let database = Database::open(&path).unwrap();
    let transaction = database.begin_read().unwrap();
    let meta = transaction
        .open_table(TableDefinition::<&str, u64>::new("aauth_ps_metadata"))
        .unwrap();
    assert_eq!(
        meta.get_owned("schema_version").unwrap().unwrap().value(),
        999
    );
}
