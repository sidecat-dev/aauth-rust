//! Public directory call store: process exit and an interrupted write.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aauth_rust_r3::{Reference, digest};
use aauth_rust_resource::{
    DirectoryCallStore, R3CallResult, R3CallStore, R3CallToken, R3Claim, R3ProposalRecord,
    R3StoreError,
};

const URI: &str = "https://records.example/r3/p.bound";

fn directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "aauth-call-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn proposal(uri: &str) -> R3ProposalRecord {
    let class = "https://records.example/r3/c.1";
    R3ProposalRecord {
        reference: Reference::new(uri, digest(uri.as_bytes())).unwrap(),
        exact_json: b"{}".to_vec(),
        person_server: "https://ps.example".into(),
        auth_token_issuer: "https://ps.example".into(),
        resource_token_jti: "rt-1".into(),
        resource_token: "token".into(),
        class_reference: Reference::new(class, digest(b"class")).unwrap(),
        presented_jti: "ps-1".into(),
        subject: "subject".into(),
        agent_jkt: "jkt".into(),
        tenant: None,
        account: None,
        scope: None,
        issued_at: 1_000,
        expires_at: 2_000,
        held: None,
        released: None,
        release_until: None,
        supersedes: None,
    }
}

fn token() -> R3CallToken {
    R3CallToken {
        compact_sha256: "sha-1".into(),
        jti: "auth-1".into(),
        retain_until: 100,
    }
}

fn ran() -> R3CallResult {
    R3CallResult {
        status: 200,
        content_type: Some("text/plain".into()),
        body: b"ran".to_vec(),
    }
}

fn claim_path(root: &Path, uri: &str) -> PathBuf {
    root.join(format!("claim-{}.json", digest(uri.as_bytes())))
}

fn execute(store: &DirectoryCallStore, uri: &str) -> String {
    match store.claim(uri, &token(), 10).unwrap() {
        R3Claim::Execute { fence } => fence,
        other => panic!("expected the first claim to execute, got {other:?}"),
    }
}

#[test]
#[ignore = "subprocess entry; the parent supplies AAUTH_CALL_DIR"]
fn reopen_after_process_exit_worker() {
    let root = PathBuf::from(std::env::var_os("AAUTH_CALL_DIR").expect("call directory"));
    let store = DirectoryCallStore::open(&root).unwrap();
    let record = proposal(URI);
    store.commit(&record).unwrap();
    let _fence = execute(&store, record.reference.uri());
    println!("WROTE {}", std::process::id());
}

#[test]
fn reopen_after_process_exit_does_not_execute_again() {
    let root = directory("exit");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "reopen_after_process_exit_worker",
            "--nocapture",
        ])
        .env("AAUTH_CALL_DIR", &root)
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
    let store = DirectoryCallStore::open(&root).unwrap();
    let loaded = store.load(URI).unwrap().expect("committed proposal");
    assert_eq!(loaded.reference.uri(), URI);
    assert!(matches!(
        store.claim(URI, &token(), 10).unwrap(),
        R3Claim::Unfinished
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn interrupted_claim_write_is_not_adopted() {
    let root = directory("claim");
    let store = DirectoryCallStore::open(&root).unwrap();
    let record = proposal(URI);
    store.commit(&record).unwrap();
    let path = claim_path(&root, URI);
    store.interrupt_next_write();
    assert!(matches!(
        store.claim(URI, &token(), 10).unwrap_err(),
        R3StoreError::Unavailable(_)
    ));
    assert!(!path.is_file());
    assert!(path.with_extension("tmp").is_file());
    let fence = execute(&store, URI);
    assert!(!fence.is_empty());
    assert!(path.is_file());
    assert!(matches!(
        store.claim(URI, &token(), 10).unwrap(),
        R3Claim::Unfinished
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn interrupted_retain_keeps_the_unfinished_claim() {
    let root = directory("retain");
    let store = DirectoryCallStore::open(&root).unwrap();
    let record = proposal(URI);
    store.commit(&record).unwrap();
    let fence = execute(&store, URI);
    let path = claim_path(&root, URI);
    let bound = fs::read(&path).unwrap();
    store.interrupt_next_write();
    assert!(matches!(
        store.retain(URI, &fence, &ran()).unwrap_err(),
        R3StoreError::Unavailable(_)
    ));
    assert_eq!(fs::read(&path).unwrap(), bound);
    assert!(!path.with_extension("prev").is_file());
    assert!(path.with_extension("tmp").is_file());
    assert!(matches!(
        store.claim(URI, &token(), 10).unwrap(),
        R3Claim::Unfinished
    ));
    let stored = store.retain(URI, &fence, &ran()).unwrap();
    assert_eq!(stored.body, b"ran");
    match store.claim(URI, &token(), 10).unwrap() {
        R3Claim::Replay(result) => assert_eq!(result.body, b"ran"),
        other => panic!("expected the retained result, got {other:?}"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn torn_claim_keeps_the_bound_claim() {
    let root = directory("torn");
    let store = DirectoryCallStore::open(&root).unwrap();
    let record = proposal(URI);
    store.commit(&record).unwrap();
    let fence = execute(&store, URI);
    store.retain(URI, &fence, &ran()).unwrap();
    let path = claim_path(&root, URI);
    assert!(path.with_extension("prev").is_file());
    fs::write(&path, b"{").unwrap();
    drop(store);
    let store = DirectoryCallStore::open(&root).unwrap();
    assert!(matches!(
        store.claim(URI, &token(), 10).unwrap(),
        R3Claim::Unfinished
    ));
    let _ = fs::remove_dir_all(root);
}
