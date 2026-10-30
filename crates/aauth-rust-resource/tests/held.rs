use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use aauth_rust_resource::{HeldInvocations, HeldPoll};
use http::{Response, StatusCode};

fn shipped() -> Response<Vec<u8>> {
    let mut response = Response::new(b"shipped".to_vec());
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    response
}

fn poll(
    held: &HeldInvocations,
    pending_id: &str,
    jti: &str,
    exp: i64,
    now: i64,
    calls: &Arc<AtomicUsize>,
) -> HeldPoll {
    let calls = calls.clone();
    held.poll(pending_id, jti, exp, now, move || {
        calls.fetch_add(1, Ordering::SeqCst);
        shipped()
    })
}

// Core Pending URL Security: pending URLs are unguessable. The ledger draws
// each id from the operating system's secure random source; the host builds
// the URL from it and supplies no id of its own.
#[test]
fn opened_pending_ids_are_drawn_at_random() {
    let held = HeldInvocations::new();
    let ids: Vec<String> = (0..64).map(|_| held.open()).collect();
    for id in &ids {
        assert_eq!(id.len(), 22, "{id}");
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "{id}"
        );
    }
    let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len());
    // Another ledger draws its own ids, unrelated to these.
    let other = HeldInvocations::new().open();
    assert!(!ids.contains(&other));
    // An id the ledger did not draw names no invocation.
    let calls = Arc::new(AtomicUsize::new(0));
    let HeldPoll::Unknown = poll(&held, "job", "auth-1", 2000, 1000, &calls) else {
        panic!("a host-chosen id was accepted");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn repeated_auth_token_replays_the_held_result() {
    let held = HeldInvocations::new();
    let job = held.open();
    let calls = Arc::new(AtomicUsize::new(0));

    let HeldPoll::Executed(first) = poll(&held, &job, "auth-1", 2000, 1000, &calls) else {
        panic!("first poll did not execute");
    };
    assert_eq!(first.body(), b"shipped");
    assert_eq!(first.status(), 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::Replayed(mut again) = poll(&held, &job, "auth-1", 2000, 2000, &calls) else {
        panic!("poll at exp did not replay");
    };
    assert_eq!(again.body(), b"shipped");
    assert_eq!(again.headers()["content-type"], "text/plain");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    *again.body_mut() = b"changed".to_vec();

    let HeldPoll::Replayed(intact) = poll(&held, &job, "auth-1", 1, 1500, &calls) else {
        panic!("stored result changed");
    };
    assert_eq!(intact.body(), b"shipped");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::Expired = poll(&held, &job, "auth-1", 2000, 2001, &calls) else {
        panic!("result was returned after exp");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::DifferentToken = poll(&held, &job, "auth-2", 2000, 1500, &calls) else {
        panic!("a different token executed or received the result");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::Unknown = poll(&held, "missing", "auth-3", 2000, 1000, &calls) else {
        panic!("unknown pending id executed");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let other = held.open();
    let HeldPoll::DifferentToken = poll(&held, &other, "auth-1", 2000, 1000, &calls) else {
        panic!("the same jti executed a second pending invocation");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_poll_during_execution_does_not_run_again() {
    let held = Arc::new(HeldInvocations::new());
    let job = held.open();
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let held_run = Arc::clone(&held);
    let job_run = job.clone();
    let calls_run = Arc::clone(&calls);
    let entered_run = Arc::clone(&entered);
    let release_run = Arc::clone(&release);
    let worker = thread::spawn(move || {
        held_run.poll(&job_run, "auth-1", 2000, 1000, move || {
            calls_run.fetch_add(1, Ordering::SeqCst);
            entered_run.wait();
            release_run.wait();
            shipped()
        })
    });
    entered.wait();
    let during = {
        let calls = Arc::clone(&calls);
        held.poll(&job, "auth-1", 2000, 1500, move || {
            calls.fetch_add(1, Ordering::SeqCst);
            shipped()
        })
    };
    release.wait();
    match during {
        HeldPoll::Unfinished => {}
        HeldPoll::Executed(_) => panic!("second poll executed"),
        HeldPoll::Replayed(_) => panic!("second poll replayed an unfinished claim"),
        HeldPoll::Unknown => panic!("second poll missed the pending id"),
        HeldPoll::DifferentToken => panic!("second poll was treated as a different token"),
        HeldPoll::Expired => panic!("second poll expired the live claim"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let HeldPoll::Executed(done) = worker.join().expect("first poll") else {
        panic!("first poll did not finish");
    };
    assert_eq!(done.body(), b"shipped");
    let calls_replay = Arc::clone(&calls);
    let HeldPoll::Replayed(again) = held.poll(&job, "auth-1", 2000, 1600, move || {
        calls_replay.fetch_add(1, Ordering::SeqCst);
        shipped()
    }) else {
        panic!("finished poll did not replay");
    };
    assert_eq!(again.body(), b"shipped");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
