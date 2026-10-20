#![cfg(unix)]

mod support;
use aauth_rust_person_server::{Store, StoreError, storetest};
use aauth_rust_person_server_redb::{MAX_RECORD_BYTES, RedbStore};
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

#[test]
fn unreadable_or_miskeyed_rows_are_unavailable_instead_of_missing_identity() {
    use redb::{Database, TableDefinition};
    let directory = tempfile::tempdir().unwrap();
    for case in [
        "malformed-token",
        "miskeyed-token",
        "malformed-binding",
        "empty-identity",
        "person-with-presented",
        "empty-upstream-tie",
        "oversized-record",
    ] {
        let path = directory.path().join(case);
        let expected = record("retained");
        let store = RedbStore::open(&path).unwrap();
        store.commit(expected.clone(), true).unwrap();
        drop(store);
        let database = Database::open(&path).unwrap();
        let transaction = database.begin_write().unwrap();
        if case == "malformed-binding" {
            let key = serde_json::to_string(&(
                &expected.token.reference.issuer,
                &expected.principal.issuer,
                &expected.principal.subject,
            ))
            .unwrap();
            transaction
                .open_table(TableDefinition::<&str, &[u8]>::new("aauth_ps_bindings"))
                .unwrap()
                .insert(key.as_str(), b"{}".as_slice())
                .unwrap();
        } else {
            let key = serde_json::to_string(&(
                &expected.token.reference.issuer,
                &expected.token.reference.jti,
            ))
            .unwrap();
            let bytes = if case == "miskeyed-token" {
                let mut different = expected.clone();
                different.token.reference.jti.push_str("-other");
                serde_json::to_vec(&different).unwrap()
            } else if case == "empty-identity" {
                let mut invalid = expected.clone();
                invalid.agent.issuer.clear();
                invalid.agent.subject.clear();
                invalid.principal = invalid.agent.clone();
                serde_json::to_vec(&invalid).unwrap()
            } else if case == "person-with-presented" {
                let mut invalid = expected.clone();
                invalid.presented = Some(invalid.token.clone());
                serde_json::to_vec(&invalid).unwrap()
            } else if case == "empty-upstream-tie" {
                let mut invalid = expected.clone();
                let mut tie = invalid.token.clone();
                tie.compact_sha256.clear();
                invalid.upstream = Some(tie);
                serde_json::to_vec(&invalid).unwrap()
            } else if case == "oversized-record" {
                let mut invalid = expected.clone();
                invalid.subject = "x".repeat(1024 * 1024);
                serde_json::to_vec(&invalid).unwrap()
            } else {
                b"{}".to_vec()
            };
            transaction
                .open_table(TableDefinition::<&str, &[u8]>::new("aauth_ps_tokens"))
                .unwrap()
                .insert(key.as_str(), bytes.as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        drop(database);
        let reopened = RedbStore::open(&path).unwrap();
        if case == "malformed-binding" {
            assert_eq!(
                reopened.binding(&expected.token.reference.issuer, &expected.principal),
                Err(StoreError::Unavailable)
            );
        } else {
            assert!(
                matches!(
                    reopened.token(&expected.token.reference),
                    Err(StoreError::Unavailable)
                ),
                "malformed case {case} did not return Unavailable"
            );
            assert_eq!(
                reopened
                    .binding(&expected.token.reference.issuer, &expected.principal)
                    .unwrap()
                    .unwrap()
                    .person_id,
                expected.person_id
            );
        }
    }
}

#[test]
fn empty_binding_identity_is_unavailable_for_read_commit_and_revoke() {
    use aauth_rust_person_server::Binding;
    use redb::{Database, TableDefinition};
    let directory = tempfile::tempdir().unwrap();
    for revoked in [false, true] {
        let path = directory
            .path()
            .join(format!("empty-binding-{revoked}.redb"));
        let original = record("retained");
        let store = RedbStore::open(&path).unwrap();
        store.commit(original.clone(), true).unwrap();
        drop(store);
        let database = Database::open(&path).unwrap();
        let transaction = database.begin_write().unwrap();
        let key = serde_json::to_string(&(
            &original.token.reference.issuer,
            &original.principal.issuer,
            &original.principal.subject,
        ))
        .unwrap();
        let bytes = serde_json::to_vec(&Binding {
            person_id: String::new(),
            revoked,
        })
        .unwrap();
        transaction
            .open_table(TableDefinition::<&str, &[u8]>::new("aauth_ps_bindings"))
            .unwrap()
            .insert(key.as_str(), bytes.as_slice())
            .unwrap();
        transaction.commit().unwrap();
        drop(database);
        let store = RedbStore::open(path).unwrap();
        let issuer = &original.token.reference.issuer;
        assert_eq!(
            store.binding(issuer, &original.principal),
            Err(StoreError::Unavailable)
        );
        let candidate = record("new-issuance");
        assert_eq!(
            store.commit(candidate.clone(), true),
            Err(StoreError::Unavailable)
        );
        assert_eq!(store.token(&candidate.token.reference).unwrap(), None);
        assert_eq!(
            store.revoke_binding(issuer, &original.principal),
            Err(StoreError::Unavailable)
        );
        assert_eq!(
            store.token(&original.token.reference).unwrap(),
            Some(original)
        );
    }
}

#[test]
fn oversized_records_are_invalid_without_leaking_any_table_state() {
    use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.redb");
    let store = RedbStore::open(&path).unwrap();
    let mut oversized = record("oversized");
    oversized.subject = "x".repeat(64 * 1024 * 1024);
    assert_eq!(
        store.commit(oversized, true),
        Err(StoreError::InvalidRecord)
    );
    drop(store);
    let database = Database::open(&path).unwrap();
    let read = database.begin_read().unwrap();
    for table in ["aauth_ps_tokens", "aauth_ps_bindings"] {
        assert!(
            read.open_table(TableDefinition::<&str, &[u8]>::new(table))
                .unwrap()
                .is_empty()
                .unwrap()
        );
    }
    for table in ["aauth_ps_directed", "aauth_ps_subjects"] {
        assert!(
            read.open_table(TableDefinition::<&str, &str>::new(table))
                .unwrap()
                .is_empty()
                .unwrap()
        );
    }
    drop(read);
    drop(database);
    let store = RedbStore::open(path).unwrap();
    let valid = record("oversized");
    store.commit(valid.clone(), true).unwrap();
    assert_eq!(store.token(&valid.token.reference).unwrap(), Some(valid));
}

#[test]
fn one_mib_encoded_record_is_accepted_but_one_more_byte_is_invalid() {
    const LIMIT: usize = MAX_RECORD_BYTES;
    let directory = tempfile::tempdir().unwrap();
    let store = RedbStore::open(directory.path().join("boundary.redb")).unwrap();
    let mut boundary = record("boundary");
    let overhead = serde_json::to_vec(&boundary).unwrap().len() - boundary.subject.len();
    boundary.subject = "x".repeat(LIMIT - overhead);
    assert_eq!(serde_json::to_vec(&boundary).unwrap().len(), LIMIT);
    store.commit(boundary.clone(), true).unwrap();
    store.commit(boundary.clone(), true).unwrap();
    assert_eq!(
        store.token(&boundary.token.reference).unwrap(),
        Some(boundary.clone())
    );
    let mut too_large = boundary.clone();
    too_large.subject.push('x');
    assert_eq!(
        store.commit(too_large.clone(), true),
        Err(StoreError::Conflict)
    );
    too_large.token.reference.jti = "new-jti!".into(); // same byte length
    assert_eq!(serde_json::to_vec(&too_large).unwrap().len(), LIMIT + 1);
    assert_eq!(
        store.commit(too_large.clone(), true),
        Err(StoreError::InvalidRecord)
    );
    assert_eq!(store.token(&too_large.token.reference).unwrap(), None);
    assert_eq!(
        store.token(&boundary.token.reference).unwrap(),
        Some(boundary)
    );
}
