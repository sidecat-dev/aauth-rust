//! Directory event store: accepted events and use counts survive a reopen
//! and a process exit, and an interrupted or torn write is refused.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::events::{
    DirectoryEventStore, EventInbox, EventStore, EventStoreError, SubscribeRequest, Subscription,
};
use aauth_rust_core::events::{EventClaims, body_s256, generate_identifier, mint_event_token};
use aauth_rust_core::{AgentClaims, Confirmation, TrustedIssuerKeys};
use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};

const AGENT: &str = "aauth:k7q3p9n2@ap.example";
const RESOURCE: &str = "https://resource.example";
/// Surrounding and inner whitespace a normalizing store would lose.
const PAYLOAD: &[u8] =
    b"\n{ \"event_type\" : \"slot.available\",\n  \"slot_time\":\"2026-07-15T10:00:00Z\" }\n";

type Inbox = EventInbox<TrustedIssuerKeys, DirectoryEventStore>;

fn directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "aauth-events-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}
fn provider() -> AgentProvider {
    AgentProvider::new("https://ap.example", "ap-1", SigningKey::from_seed([1; 32]))
        .unwrap()
        .with_event_endpoint("https://ap.example/events")
        .unwrap()
}
fn agent_token(ap: &AgentProvider) -> String {
    ap.issue(&AgentClaims {
        iss: "https://ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: AGENT.into(),
        jti: "agent-1".into(),
        iat: 1000,
        exp: 5000,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([2; 32]).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })
    .unwrap()
}
fn resource_keys() -> TrustedIssuerKeys {
    let jwks = json!({"keys":[{"kid":"resource-1",
        "kty":"OKP","crv":"Ed25519","alg":"Ed25519",
        "x":SigningKey::from_seed([5; 32]).public_jwk().x}]});
    TrustedIssuerKeys::from_documents(
        RESOURCE,
        "aauth-resource.json",
        br#"{"issuer":"https://resource.example","jwks_uri":"https://resource.example/jwks.json"}"#,
        jwks.to_string().as_bytes(),
    )
    .unwrap()
}
fn inbox(root: &Path) -> Inbox {
    EventInbox::new(
        &provider(),
        resource_keys(),
        DirectoryEventStore::open(root).unwrap(),
    )
    .unwrap()
}
fn subscribe(inbox: &Inbox, max_uses: Option<u64>) -> Subscription {
    let ap = provider();
    ap.issue_subscribe_token(
        inbox.store(),
        &SubscribeRequest {
            agent_token: &agent_token(&ap),
            resource: RESOURCE,
            expires_at: 2000,
            max_uses,
            subscription_expires_at: None,
        },
        1000,
    )
    .unwrap()
    .subscription
}
/// A fresh event token for `eid` that binds `PAYLOAD`.
fn event(eid: &str) -> String {
    mint_event_token(
        &SigningKey::from_seed([5; 32]),
        "resource-1",
        &EventClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: AGENT.into(),
            eid: eid.into(),
            jti: generate_identifier(),
            iat: 1000,
            exp: 1300,
            body_s256: Some(body_s256(PAYLOAD)),
            extra: Default::default(),
        },
    )
    .unwrap()
}
fn delivery(token: &str, now: i64) -> Request<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri("https://ap.example/events")
        .header("content-type", "application/json")
        .body(PAYLOAD.to_vec())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([5; 32]),
        KeyMaterial::SelfJwt { jwt: token.into() },
        now,
    )
    .unwrap();
    request
}
fn deliver(inbox: &Inbox, token: &str, now: i64) -> Response<Vec<u8>> {
    inbox.receive(&delivery(token, now), now).into_response()
}
fn remaining(response: &Response<Vec<u8>>) -> u64 {
    assert_eq!(response.status(), 202);
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    body["remaining_uses"].as_u64().unwrap()
}
fn files(root: &Path, prefix: &str) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix) && !name.ends_with(".tmp"))
        })
        .collect()
}

#[test]
fn accepted_events_and_the_use_count_survive_a_fresh_reopen() {
    let root = directory("reopen");
    let first_inbox = inbox(&root);
    let subscription = subscribe(&first_inbox, Some(3));
    let first = event(&subscription.eid);
    let second = event(&subscription.eid);
    assert_eq!(remaining(&deliver(&first_inbox, &first, 1000)), 2);
    assert_eq!(remaining(&deliver(&first_inbox, &second, 1001)), 1);
    drop(first_inbox);

    let reopened = inbox(&root);
    assert_eq!(
        reopened.store().subscription(&subscription.eid).unwrap(),
        Some((subscription.clone(), 2))
    );
    let pending = reopened.store().pending(AGENT).unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].event_token, first);
    assert_eq!(pending[1].event_token, second);
    for event in &pending {
        assert_eq!(event.body, PAYLOAD);
        assert_eq!(event.content_type.as_deref(), Some("application/json"));
        assert_eq!(event.eid, subscription.eid);
    }
    // A retry is still recognized and spends no use; the count goes on from 2.
    assert_eq!(remaining(&deliver(&reopened, &first, 1010)), 1);
    assert_eq!(
        remaining(&deliver(&reopened, &event(&subscription.eid), 1011)),
        0
    );
    let response = deliver(&reopened, &event(&subscription.eid), 1012);
    assert_eq!(response.status(), 404);
    reopened
        .store()
        .acknowledge(AGENT, RESOURCE, &pending[0].jti)
        .unwrap();
    drop(reopened);

    let store = DirectoryEventStore::open(&root).unwrap();
    assert_eq!(store.subscription(&subscription.eid).unwrap().unwrap().1, 3);
    let pending = store.pending(AGENT).unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].event_token, second);
    let _ = fs::remove_dir_all(root);
}

#[test]
#[ignore = "subprocess entry; the parent supplies AAUTH_EVENT_DIR"]
fn accept_then_exit_worker() {
    let root = PathBuf::from(std::env::var_os("AAUTH_EVENT_DIR").expect("event directory"));
    let inbox = inbox(&root);
    let subscription = subscribe(&inbox, Some(2));
    println!("EID {}", subscription.eid);
    for now in [1000, 1001] {
        let token = event(&subscription.eid);
        let response = deliver(&inbox, &token, now);
        println!("ACCEPTED {} {token}", response.status().as_u16());
    }
}

#[test]
fn a_process_exit_keeps_accepted_events_and_their_use_count() {
    let root = directory("exit");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "accept_then_exit_worker",
            "--nocapture",
        ])
        .env("AAUTH_EVENT_DIR", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let eid = stdout
        .lines()
        .find_map(|line| line.strip_prefix("EID "))
        .expect("child eid")
        .trim()
        .to_owned();
    let tokens: Vec<String> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ACCEPTED 202 "))
        .map(|token| token.trim().to_owned())
        .collect();
    assert_eq!(tokens.len(), 2, "the child had two events accepted");

    let inbox = inbox(&root);
    assert_eq!(inbox.store().subscription(&eid).unwrap().unwrap().1, 2);
    let pending = inbox.store().pending(AGENT).unwrap();
    let delivered: Vec<&str> = pending
        .iter()
        .map(|event| event.event_token.as_str())
        .collect();
    assert_eq!(delivered, tokens);
    assert!(pending.iter().all(|event| event.body == PAYLOAD));
    // max_uses was 2: the count read back refuses a third event.
    assert_eq!(deliver(&inbox, &event(&eid), 1010).status(), 404);
    assert_eq!(remaining(&deliver(&inbox, &tokens[0], 1011)), 0);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn an_interrupted_commit_is_refused_and_the_event_is_not_counted() {
    let root = directory("interrupt");
    let first_inbox = inbox(&root);
    let subscription = subscribe(&first_inbox, Some(1));
    let token = event(&subscription.eid);
    first_inbox.store().interrupt_next_write();
    let response = deliver(&first_inbox, &token, 1000);
    assert_eq!(response.status(), 503);
    // The event file was written but no subscription lists it.
    assert_eq!(files(&root, "e-").len(), 1);
    assert_eq!(
        first_inbox
            .store()
            .subscription(&subscription.eid)
            .unwrap()
            .unwrap()
            .1,
        0
    );
    assert!(first_inbox.store().pending(AGENT).unwrap().is_empty());
    drop(first_inbox);

    let reopened = inbox(&root);
    assert_eq!(
        reopened
            .store()
            .subscription(&subscription.eid)
            .unwrap()
            .unwrap()
            .1,
        0
    );
    assert!(reopened.store().pending(AGENT).unwrap().is_empty());
    // The Resource's retry is accepted once, as a new event.
    assert_eq!(remaining(&deliver(&reopened, &token, 1005)), 0);
    let pending = reopened.store().pending(AGENT).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_token, token);
    assert_eq!(pending[0].body, PAYLOAD);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_torn_subscription_file_is_refused_not_guessed() {
    let root = directory("torn");
    let first_inbox = inbox(&root);
    let subscription = subscribe(&first_inbox, Some(1));
    assert_eq!(
        remaining(&deliver(&first_inbox, &event(&subscription.eid), 1000)),
        0
    );
    drop(first_inbox);
    let state = files(&root, "s-");
    assert_eq!(state.len(), 1);
    fs::write(&state[0], b"{").unwrap();

    let reopened = inbox(&root);
    assert_eq!(
        reopened
            .store()
            .subscription(&subscription.eid)
            .unwrap_err(),
        EventStoreError::Unavailable
    );
    assert_eq!(
        reopened.store().pending(AGENT).unwrap_err(),
        EventStoreError::Unavailable
    );
    let response = deliver(&reopened, &event(&subscription.eid), 1005);
    assert_eq!(response.status(), 503);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_subscription_is_created_once_across_reopens() {
    let root = directory("create");
    let first_inbox = inbox(&root);
    let subscription = subscribe(&first_inbox, None);
    assert_eq!(
        first_inbox.store().create(&subscription).unwrap_err(),
        EventStoreError::Conflict
    );
    drop(first_inbox);
    let store = DirectoryEventStore::open(&root).unwrap();
    assert_eq!(
        store.subscription(&subscription.eid).unwrap(),
        Some((subscription.clone(), 0))
    );
    assert_eq!(
        store.create(&subscription).unwrap_err(),
        EventStoreError::Conflict
    );
    let _ = fs::remove_dir_all(root);
}
