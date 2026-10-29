//! Directory ledger: process exit and an interrupted write.
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aauth_rust_budgets::{Budget, ChargeError, Error, Ledger, Refusal, TokenAccount};

const ISS: &str = "https://as.example";

fn account(jti: &str, amount: i64) -> TokenAccount {
    TokenAccount {
        jti: jti.into(),
        grant: Budget::new(amount, "USD", 6).unwrap(),
        ps: "https://ps.example".into(),
        sub: "ada".into(),
        aud: "https://resource.example".into(),
        iss: ISS.into(),
        jkt: format!("jkt-{jti}"),
        tenant: None,
        mission: None,
    }
}

fn directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "aauth-budget-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
#[ignore = "subprocess entry; the parent supplies AAUTH_BUDGET_DIR"]
fn reopen_after_process_exit_worker() {
    let root = PathBuf::from(std::env::var_os("AAUTH_BUDGET_DIR").expect("budget directory"));
    let mut ledger = Ledger::open_directory(&root).unwrap();
    ledger.open(account("grant", 100)).unwrap();
    let hold = ledger.reserve(ISS, "grant", 100).unwrap();
    ledger.commit(&hold, 100, 50).unwrap();
    println!("WROTE {}", std::process::id());
}

#[test]
fn reopen_after_process_exit_keeps_the_spent_grant() {
    let root = directory("exit");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "reopen_after_process_exit_worker",
            "--nocapture",
        ])
        .env("AAUTH_BUDGET_DIR", &root)
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
    let mut ledger = Ledger::open_directory(&root).unwrap();
    assert_eq!(ledger.outstanding(ISS, "grant"), Some((100, 0)));
    assert_eq!(
        ledger.person_total(
            "https://ps.example",
            "ada",
            "https://resource.example",
            "USD"
        ),
        100
    );
    assert!(matches!(
        ledger.reserve(ISS, "grant", 1),
        Err(ChargeError::Refused(Refusal::Exhausted {
            remaining: 0,
            ..
        }))
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn interrupted_write_keeps_the_last_complete_grant() {
    let root = directory("tear");
    let mut ledger = Ledger::open_directory(&root).unwrap();
    ledger.open(account("grant", 100)).unwrap();
    let hold = ledger.reserve(ISS, "grant", 40).unwrap();
    ledger.commit(&hold, 40, 10).unwrap();
    ledger.interrupt_next_write();
    assert!(matches!(
        ledger.reserve(ISS, "grant", 10),
        Err(ChargeError::Protocol(Error::Unavailable))
    ));
    assert_eq!(ledger.outstanding(ISS, "grant"), Some((40, 0)));
    assert!(root.join("ledger.json.tmp").is_file());
    drop(ledger);
    let mut ledger = Ledger::open_directory(&root).unwrap();
    assert_eq!(ledger.outstanding(ISS, "grant"), Some((40, 0)));
    let hold = ledger.reserve(ISS, "grant", 10).unwrap();
    ledger.commit(&hold, 10, 11).unwrap();
    assert_eq!(ledger.outstanding(ISS, "grant"), Some((50, 0)));
    drop(ledger);
    fs::write(root.join("ledger.json"), b"{").unwrap();
    let mut ledger = Ledger::open_directory(&root).unwrap();
    assert_eq!(ledger.outstanding(ISS, "grant"), Some((40, 10)));
    assert!(matches!(
        ledger.reserve(ISS, "grant", 60),
        Err(ChargeError::Refused(Refusal::Insufficient {
            remaining: 50,
            ..
        }))
    ));
    let _ = fs::remove_dir_all(root);
}
