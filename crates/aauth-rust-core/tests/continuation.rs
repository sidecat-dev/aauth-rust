use aauth_rust_core::continuation::{
    ContinuationStore, MemoryContinuations, PendingResponse, Requirement, StoreError,
};
use http::Response;
use serde_json::json;
use std::sync::Arc;

fn response(status: u16, requirement: &str, body: serde_json::Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("location", "/token/pending/opaque")
        .header("retry-after", "5")
        .header("cache-control", "no-store")
        .header("content-type", "application/json")
        .header("aauth-requirement", requirement)
        .body(body.to_string().into_bytes())
        .unwrap()
}
#[test]
fn pending_requirements_preserve_host_inputs() {
    for (field, body, expected) in [
        (
            "requirement=claims",
            json!({"status":"pending","required_claims":["email","tenant"]}),
            Requirement::Claims(vec!["email".into(), "tenant".into()]),
        ),
        (
            "requirement=clarification",
            json!({"status":"pending","clarification":"Why write?","timeout":120,"options":["yes","no"]}),
            Requirement::Clarification {
                question: "Why write?".into(),
                timeout: Some(120),
                options: vec!["yes".into(), "no".into()],
            },
        ),
        (
            "requirement=interaction; url=\"https://as.example/consent\"; code=\"abc\"",
            json!({"status":"interacting"}),
            Requirement::Interaction {
                url: "https://as.example/consent".into(),
                code: "abc".into(),
            },
        ),
        (
            "requirement=approval",
            json!({"status":"future-status"}),
            Requirement::Approval,
        ),
    ] {
        let pending =
            PendingResponse::parse("https://as.example/token", &response(202, field, body))
                .unwrap();
        assert_eq!(pending.location, "https://as.example/token/pending/opaque");
        assert_eq!(pending.retry_after, 5);
        assert_eq!(pending.requirement, expected);
        let again =
            PendingResponse::parse("https://as.example/token", &pending.response().unwrap())
                .unwrap();
        assert_eq!(pending, again);
    }
}
#[test]
fn payment_preserves_details_without_becoming_an_agent_instruction() {
    let mut r = response(402, "requirement=approval", json!({"bill":"invoice-1"}));
    r.headers_mut().remove("aauth-requirement");
    r.headers_mut().insert(
        "www-authenticate",
        "Payment id=\"invoice-1\", method=\"example\""
            .parse()
            .unwrap(),
    );
    let p = PendingResponse::parse("https://as.example/token", &r).unwrap();
    assert!(matches!(p.requirement, Requirement::Payment { .. }));
    assert_eq!(p.response().unwrap().status(), 402);
    assert_eq!(
        p.response().unwrap().headers()["www-authenticate"],
        "Payment id=\"invoice-1\", method=\"example\""
    );
    assert_eq!(p.response().unwrap().body(), r.body());
}
#[test]
fn pending_urls_and_framing_fail_closed() {
    for location in [
        "https://evil.example/p",
        "//evil.example/p",
        "http://as.example/p",
        "https://user@as.example/p",
        "/p#fragment",
        "/p?secret=1",
        "/../token",
        "/p%2fsecret",
        "relative",
    ] {
        let mut r = response(202, "requirement=approval", json!({"status":"pending"}));
        r.headers_mut()
            .insert("location", location.parse().unwrap());
        assert!(
            PendingResponse::parse("https://as.example/token", &r).is_err(),
            "{location}"
        );
    }
    for header in ["location", "retry-after", "cache-control", "content-type"] {
        let mut r = response(202, "requirement=approval", json!({"status":"pending"}));
        r.headers_mut().remove(header);
        assert!(
            PendingResponse::parse("https://as.example/token", &r).is_err(),
            "{header}"
        );
    }
}
#[test]
fn malformed_requirements_cannot_be_acknowledged_as_pending() {
    for (field, body) in [
        (
            "requirement=claims",
            json!({"status":"pending","required_claims":[]}),
        ),
        (
            "requirement=claims",
            json!({"status":"pending","required_claims":[1]}),
        ),
        ("requirement=clarification", json!({"status":"pending"})),
        (
            "requirement=interaction; url=\"http://as.example/u\"; code=\"c\"",
            json!({"status":"pending"}),
        ),
        (
            "requirement=approval",
            json!({"auth_token":"should-not-be-here","status":"pending"}),
        ),
        ("requirement=unknown", json!({"status":"pending"})),
    ] {
        assert!(
            PendingResponse::parse("https://as.example/token", &response(202, field, body))
                .is_err(),
            "{field}"
        );
    }
}
#[test]
fn continuation_store_cas_serializes_delivery_and_releases_capacity() {
    let store = Arc::new(MemoryContinuations::new(1));
    store.insert("one", json!({"state":"waiting"})).unwrap();
    assert_eq!(store.insert("two", json!({})), Err(StoreError::Capacity));
    let before = store.load("one").unwrap().unwrap();
    let other = store.clone();
    assert!(
        other
            .replace("one", before.revision, Some(json!({"state":"ready"})))
            .unwrap()
    );
    assert!(!store.replace("one", before.revision, None).unwrap());
    let ready = store.load("one").unwrap().unwrap();
    assert_eq!(ready.value["state"], "ready");
    assert!(store.replace("one", ready.revision, None).unwrap());
    assert!(store.load("one").unwrap().is_none());
    store.insert("two", json!({})).unwrap();
}
#[test]
fn only_one_concurrent_consumer_can_claim_a_continuation() {
    let store = Arc::new(MemoryContinuations::new(2));
    store.insert("one", json!({"state":"ready"})).unwrap();
    let revision = store.load("one").unwrap().unwrap().revision;
    let consumers: Vec<_> = (0..12)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || store.replace("one", revision, None).unwrap())
        })
        .collect();
    assert_eq!(
        consumers
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn claims_must_never_request_subject_from_the_ps() {
    let r = response(
        202,
        "requirement=claims",
        json!({"status":"pending","required_claims":["sub"]}),
    );
    assert!(PendingResponse::parse("https://as.example/token", &r).is_err());
}
#[test]
fn store_revisions_prevent_delete_reinsert_aba_and_bound_record_size() {
    let store = MemoryContinuations::new(1);
    store.insert("same", json!({"v":1})).unwrap();
    let first = store.load("same").unwrap().unwrap();
    assert!(store.replace("same", first.revision, None).unwrap());
    store.insert("same", json!({"v":2})).unwrap();
    assert!(!store.replace("same", first.revision, None).unwrap());
    let second = store.load("same").unwrap().unwrap();
    assert_eq!(
        store.replace(
            "same",
            second.revision,
            Some(json!({"data":"x".repeat(1_048_576)}))
        ),
        Err(StoreError::Capacity)
    );
    assert_eq!(store.load("same").unwrap().unwrap().value, json!({"v":2}));
}
