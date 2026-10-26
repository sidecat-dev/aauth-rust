use super::subagents as kids;
use super::*;
use aauth_rust_core::continuation::{
    ContinuationStore, MemoryContinuations, PendingResponse, Snapshot,
};
use aauth_rust_person_server::{DeferredConfig, FederationInput};

// The resolver has already returned when this host storage read crosses expiry.
// Each test isolates a different final release path, rather than the shared
// resolver's own fresh-clock check.
#[test]
fn person_release_fences_child_expiry_during_final_binding_read() {
    let f = Fixture::new();
    let child = kids::child_token(|c| c.exp = 1005);
    f.store
        .delay_binding_after_commit
        .store(1005, Ordering::SeqCst);
    let response = kids::person(&f, &f.server(2000), &agent(false), &child);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 1005);
    assert_eq!(response.status(), 400, "{}", output(&response));
    assert_eq!(output(&response)["error"], "expired_subagent_token");
    assert!(output(&response).get("person_token").is_none());
}

fn auth_release(federated: bool) -> (Fixture, Response<Vec<u8>>) {
    let f = Fixture::new();
    let parent = agent(false);
    // The presented Person remains valid after the renewed, same-identity
    // child's earlier expiry, so it cannot mask the child-specific refusal.
    let person = compact(
        &kids::person(&f, &f.server(2000), &parent, kids::child().token()),
        "person_token",
    );
    let child = Agent::new(
        SigningKey::from_seed([11; 32]),
        kids::child_token(|c| c.exp = 1005),
    )
    .unwrap();
    let challenge = resource(&child, &person, "read", |r| {
        if federated {
            r.aud = "https://as.example".into();
        }
    });
    let mut server = f.server(2000);
    if federated {
        server = server.with_federation(deferred::NativeTransport::new(&f, 2, 0));
    }
    f.store
        .delay_binding_after_commit
        .store(1005, Ordering::SeqCst);
    let response = kids::exchange(&f, &server, &parent, child.token(), &challenge, &person);
    (f, response)
}

#[test]
fn local_auth_release_fences_child_expiry_during_final_binding_read() {
    let (f, response) = auth_release(false);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 1005);
    assert_eq!(response.status(), 400, "{}", output(&response));
    assert_eq!(output(&response)["error"], "expired_subagent_token");
    assert!(output(&response).get("auth_token").is_none());
}

#[test]
fn federated_auth_release_fences_child_expiry_during_final_binding_read() {
    let (f, response) = auth_release(true);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 1005);
    assert_eq!(response.status(), 400, "{}", output(&response));
    assert_eq!(output(&response)["error"], "expired_subagent_token");
    assert!(output(&response).get("auth_token").is_none());
}

struct DelayFinalBinding {
    inner: MemoryContinuations,
    delayed_binding: Arc<Mutex<Option<(usize, i64)>>>,
}
impl ContinuationStore for DelayFinalBinding {
    fn insert(
        &self,
        id: &str,
        value: Value,
    ) -> Result<(), aauth_rust_core::continuation::StoreError> {
        self.inner.insert(id, value)
    }
    fn load(
        &self,
        id: &str,
    ) -> Result<Option<Snapshot>, aauth_rust_core::continuation::StoreError> {
        self.inner.load(id)
    }
    fn replace(
        &self,
        id: &str,
        revision: u64,
        value: Option<Value>,
    ) -> Result<bool, aauth_rust_core::continuation::StoreError> {
        let delivering = value.is_none()
            && self
                .inner
                .load(id)?
                .is_some_and(|s| s.value["state"] == "delivering");
        let changed = self.inner.replace(id, revision, value)?;
        if changed && delivering {
            // Repreparation reads the binding once; the following final host
            // read is the last I/O before the cached-time release fence.
            *self.delayed_binding.lock().unwrap() = Some((2, 1005));
        }
        Ok(changed)
    }
}

#[test]
fn deferred_release_fences_pending_expiry_during_final_binding_read() {
    let f = Fixture::new();
    let parent = agent(false);
    let child = kids::child();
    let transport = deferred::NativeTransport::new(&f, 1, 0);
    let mut cfg = DeferredConfig::new(DelayFinalBinding {
        inner: MemoryContinuations::new(16),
        delayed_binding: f.store.delayed_binding.clone(),
    });
    // All signed credentials outlive this lease, isolating its final guard.
    cfg.lifetime = 5;
    cfg.retry_after = 0;
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(cfg)
        .unwrap();
    let person = compact(
        &kids::person(&f, &server, &parent, child.token()),
        "person_token",
    );
    let challenge = resource(&child, &person, "read", |r| {
        r.aud = "https://as.example".into()
    });
    let response = kids::exchange(&f, &server, &parent, child.token(), &challenge, &person);
    assert_eq!(response.status(), 202, "{}", output(&response));
    let pending = PendingResponse::parse(&format!("{PS}/token"), &response).unwrap();
    transport.stage.store(2, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&pending.location, FederationInput::Poll)
            .unwrap()
            .status(),
        200
    );
    let response = deferred::poll(&server, &parent, &pending.location, "GET", None, 1000);
    assert_eq!(f.host.now.load(Ordering::SeqCst), 1005);
    assert_eq!(response.status(), 408, "{}", output(&response));
    assert_eq!(output(&response)["error"], "expired");
    assert!(output(&response).get("auth_token").is_none());
    assert_eq!(
        deferred::poll(&server, &parent, &pending.location, "GET", None, 1005).status(),
        410
    );
}
