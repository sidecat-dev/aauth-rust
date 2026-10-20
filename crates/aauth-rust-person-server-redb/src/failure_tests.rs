use super::*;
use redb::{BackendError, StorageBackend, backends::FileBackend};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    ops::Bound,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
};
#[path = "../tests/support/mod.rs"]
mod support;
use support::record;

#[derive(Debug)]
struct FailOneWrite {
    file: FileBackend,
    fail: Arc<AtomicBool>,
}
impl StorageBackend for FailOneWrite {
    fn len(&self) -> io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.file.read(offset, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected native backend write failure"));
        }
        self.file.write(offset, bytes)
    }
    fn close(&self) -> io::Result<()> {
        self.file.close()
    }
    fn try_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> {
        self.file.try_lock_range(start, end)
    }
    fn try_lock_shared_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> Result<bool, BackendError> {
        self.file.try_lock_shared_range(start, end)
    }
    fn lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        self.file.lock_range(start, end)
    }
    fn lock_shared_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        self.file.lock_shared_range(start, end)
    }
    fn unlock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        self.file.unlock_range(start, end)
    }
    fn query_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> {
        self.file.query_lock_range(start, end)
    }
}

fn child_record() -> TokenRecord {
    let mut candidate = record("child-token");
    candidate.agent.subject = "aauth:Child@ap.example".into();
    candidate.principal = candidate.agent.clone();
    candidate.person_id = "child-internal-person".into();
    candidate.subject = "child-directed-person".into();
    candidate
}
fn absent_without_index_leaks(store: &RedbStore, candidate: &TokenRecord) {
    assert_eq!(store.token(&candidate.token.reference).unwrap(), None);
    assert_eq!(
        store
            .binding(&candidate.token.reference.issuer, &candidate.principal)
            .unwrap(),
        None
    );
    let mut corrected = candidate.clone();
    corrected.subject.push_str("-corrected");
    store.commit(corrected, true).unwrap();
    let mut other = candidate.clone();
    other.token.reference.jti.push_str("-other");
    other.person_id.push_str("-other");
    other.agent.subject = "aauth:Another@ap.example".into();
    other.principal = other.agent.clone();
    store.commit(other, true).unwrap();
}

#[test]
fn backend_write_error_is_unavailable_and_recovery_preserves_the_prior_transaction() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let fail = Arc::new(AtomicBool::new(false));
    let database = Database::builder()
        .create_with_backend(FailOneWrite {
            file: FileBackend::new(file).unwrap(),
            fail: fail.clone(),
        })
        .unwrap();
    let store = RedbStore::from_database(database, path.clone()).unwrap();
    let prior = record("committed-before-failure");
    store.commit(prior.clone(), true).unwrap();
    let candidate = child_record();
    fail.store(true, Ordering::SeqCst);
    assert_eq!(
        store.commit(candidate.clone(), true),
        Err(StoreError::Unavailable)
    );
    assert!(
        !fail.load(Ordering::SeqCst),
        "the real backend did not encounter the injected write failure"
    );
    drop(store);
    let recovered = RedbStore::open(&path).unwrap();
    assert_eq!(
        recovered.token(&prior.token.reference).unwrap(),
        Some(prior)
    );
    absent_without_index_leaks(&recovered, &candidate);
}

#[test]
#[ignore = "subprocess entry; parents supply a disposable database and mode"]
fn unclean_worker() {
    let path = std::env::var_os("AAUTH_REDB_CHILD_PATH").expect("worker path");
    let mode = std::env::var("AAUTH_REDB_CHILD_MODE").expect("worker mode");
    let store = RedbStore::open(path).unwrap();
    if mode == "commit" {
        store.commit(child_record(), true).unwrap();
        println!("COMMITTED");
    } else {
        let mut transaction = store.database.begin_write().unwrap();
        transaction.set_durability(Durability::Immediate).unwrap();
        assert!(stage_issuance(&transaction, &child_record(), true).unwrap());
        println!("STAGED");
        io::stdout().flush().unwrap();
        // Keep the live transaction and database; this bypasses all Rust Drop.
        std::process::exit(0);
    }
    io::stdout().flush().unwrap();
    std::process::exit(0);
}

fn run_unclean_child(mode: &str) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("person.redb");
    let prior = record("before-process-exit");
    let store = RedbStore::open(&path).unwrap();
    store.commit(prior.clone(), true).unwrap();
    drop(store);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "failure_tests::unclean_worker",
            "--nocapture",
        ])
        .env("AAUTH_REDB_CHILD_PATH", &path)
        .env("AAUTH_REDB_CHILD_MODE", mode)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let acknowledgement = if mode == "commit" {
        "COMMITTED"
    } else {
        "STAGED"
    };
    assert!(String::from_utf8_lossy(&output.stdout).contains(acknowledgement));
    let recovered = RedbStore::open(&path).unwrap();
    assert_eq!(
        recovered.token(&prior.token.reference).unwrap(),
        Some(prior)
    );
    let candidate = child_record();
    if mode == "commit" {
        assert_eq!(
            recovered.token(&candidate.token.reference).unwrap(),
            Some(candidate.clone())
        );
        assert_eq!(
            recovered
                .binding(&candidate.token.reference.issuer, &candidate.principal)
                .unwrap()
                .unwrap()
                .person_id,
            candidate.person_id
        );
    } else {
        absent_without_index_leaks(&recovered, &candidate);
    }
}
#[test]
fn acknowledged_commit_survives_exit_without_dropping_database_handles() {
    run_unclean_child("commit");
}
#[test]
fn staged_transaction_is_invisible_after_exit_without_drop_or_commit() {
    run_unclean_child("abort");
}
