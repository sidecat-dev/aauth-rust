//! Public directory document store: process exit and an interrupted write.
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aauth_rust_r3::{Reference, digest};
use aauth_rust_resource::{
    DirectoryDocumentStore, R3DocumentRecord, R3DocumentStore, R3StoreError,
};

const URI: &str = "https://records.example/r3/c.bound";

fn directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "aauth-doc-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|stamp| stamp.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn document(subject: &str) -> R3DocumentRecord {
    R3DocumentRecord {
        reference: Reference::new(URI, digest(URI.as_bytes())).unwrap(),
        exact_json: b"{\"class\":true}".to_vec(),
        person_server: "https://ps.example".into(),
        auth_token_issuer: "https://ps.example".into(),
        auth_token_issuer_document: "aauth-person.json".into(),
        resource_token_jti: "rt-1".into(),
        resource_token: "token".into(),
        presented_jti: "ps-1".into(),
        subject: subject.into(),
        agent_jkt: "jkt".into(),
        tenant: None,
        account: None,
        scope: None,
        issued_at: 1_000,
        expires_at: 2_000,
        mission_s256: None,
    }
}

fn record_path(root: &std::path::Path) -> PathBuf {
    root.join(format!("c-{}.json", digest(URI.as_bytes())))
}

#[test]
#[ignore = "subprocess entry; the parent supplies AAUTH_DOC_DIR"]
fn reopen_document_after_process_exit_worker() {
    let root = PathBuf::from(std::env::var_os("AAUTH_DOC_DIR").expect("document directory"));
    let store = DirectoryDocumentStore::open(&root).unwrap();
    let loaded = store.load(URI).unwrap().expect("committed document");
    assert_eq!(loaded.subject, "kept");
    assert_eq!(loaded.exact_json, b"{\"class\":true}");
    println!("WROTE {}", std::process::id());
}

#[test]
fn reopen_after_process_exit_loads_the_same_document() {
    let root = directory("exit");
    let store = DirectoryDocumentStore::open(&root).unwrap();
    store.commit(&document("kept")).unwrap();
    drop(store);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "reopen_document_after_process_exit_worker",
            "--nocapture",
        ])
        .env("AAUTH_DOC_DIR", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let written = String::from_utf8_lossy(&output.stdout);
    let child_pid: u32 = written
        .lines()
        .find_map(|line| line.strip_prefix("WROTE "))
        .and_then(|pid| pid.trim().parse().ok())
        .expect("child pid");
    assert_ne!(child_pid, std::process::id());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn exact_repeat_is_accepted_and_a_different_record_conflicts() {
    let root = directory("repeat");
    let store = DirectoryDocumentStore::open(&root).unwrap();
    let original = document("kept");
    store.commit(&original).unwrap();
    store.commit(&original).unwrap();
    let mut changed = original.clone();
    changed.subject = "other".into();
    assert!(matches!(
        store.commit(&changed).unwrap_err(),
        R3StoreError::Conflict
    ));
    let loaded = store.load(URI).unwrap().expect("original document");
    assert_eq!(loaded.subject, "kept");
    assert!(
        store
            .load("https://records.example/r3/c.missing")
            .unwrap()
            .is_none()
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn interrupted_document_write_is_not_adopted() {
    let root = directory("interrupt");
    let store = DirectoryDocumentStore::open(&root).unwrap();
    let path = record_path(&root);
    store.interrupt_next_write();
    assert!(matches!(
        store.commit(&document("kept")).unwrap_err(),
        R3StoreError::Unavailable(_)
    ));
    assert!(!path.exists());
    store.commit(&document("kept")).unwrap();
    assert_eq!(store.load(URI).unwrap().expect("retry").subject, "kept");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn torn_document_is_unavailable() {
    let root = directory("torn");
    let store = DirectoryDocumentStore::open(&root).unwrap();
    store.commit(&document("kept")).unwrap();
    let path = record_path(&root);
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..1]).unwrap();
    assert!(matches!(
        store.load(URI).unwrap_err(),
        R3StoreError::Unavailable(_)
    ));
    let _ = fs::remove_dir_all(root);
}
