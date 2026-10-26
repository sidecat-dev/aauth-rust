use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
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

#[test]
fn repeated_auth_token_replays_the_held_result() {
    let held = HeldInvocations::new();
    assert!(held.open("").is_err());
    held.open("job").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));

    let HeldPoll::Executed(first) = poll(&held, "job", "auth-1", 2000, 1000, &calls) else {
        panic!("first poll did not execute");
    };
    assert_eq!(first.body(), b"shipped");
    assert_eq!(first.status(), 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::Replayed(mut again) = poll(&held, "job", "auth-1", 2000, 2000, &calls) else {
        panic!("poll at exp did not replay");
    };
    assert_eq!(again.body(), b"shipped");
    assert_eq!(again.headers()["content-type"], "text/plain");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    *again.body_mut() = b"changed".to_vec();

    let HeldPoll::Replayed(intact) = poll(&held, "job", "auth-1", 1, 1500, &calls) else {
        panic!("stored result changed");
    };
    assert_eq!(intact.body(), b"shipped");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::Expired = poll(&held, "job", "auth-1", 2000, 2001, &calls) else {
        panic!("result was returned after exp");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::DifferentToken = poll(&held, "job", "auth-2", 2000, 1500, &calls) else {
        panic!("a different token executed or received the result");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let HeldPoll::Unknown = poll(&held, "missing", "auth-3", 2000, 1000, &calls) else {
        panic!("unknown pending id executed");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    held.open("other").unwrap();
    let HeldPoll::DifferentToken = poll(&held, "other", "auth-1", 2000, 1000, &calls) else {
        panic!("the same jti executed a second pending invocation");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
