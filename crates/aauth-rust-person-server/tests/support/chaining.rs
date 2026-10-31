//! Call chaining through the four-party path: the PS passes `upstream_token`
//! to the AS, retains the AS's Auth token with the same upstream tie, and
//! relays a deferred AS answer to the intermediary.
use super::deferred::{NativeTransport, poll};
use super::*;
use aauth_rust_core::capabilities::{Capabilities, Capability};
use aauth_rust_core::continuation::{MemoryContinuations, PendingResponse, Requirement};
use aauth_rust_core::interaction::ChainedInteraction;
use aauth_rust_person_server::{
    DeferredConfig, FederationFailure, FederationFailureReason, FederationInput,
};

const AS: &str = "https://as.example";

/// An in-process AS that grants `read` for up to an hour. It records each
/// PS-to-AS body and how often its policy saw a verified upstream token.
#[derive(Clone, Default)]
struct ChainedAs {
    bodies: Arc<Mutex<Vec<Value>>>,
    chained: Arc<AtomicUsize>,
    ids: Arc<AtomicUsize>,
}
impl aauth_rust_person_server::Federation for ChainedAs {
    fn endpoint(&self, issuer: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        assert_eq!(issuer, AS);
        Ok(format!("{AS}/token"))
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        self.bodies
            .lock()
            .unwrap()
            .push(serde_json::from_slice(request.body()).unwrap());
        let chained = self.chained.clone();
        let id = self.ids.fetch_add(1, Ordering::SeqCst);
        let server = aauth_rust_access_server::AccessServer::new(
            aauth_rust_access_server::Config::new(AS, "as-key", SigningKey::from_seed([7; 32])),
            Keys,
            move |request: &aauth_rust_access_server::AuthorizationRequest| {
                if request.upstream.is_some() {
                    chained.fetch_add(1, Ordering::SeqCst);
                }
                Ok(aauth_rust_access_server::Decision {
                    scopes: vec!["read".into()],
                    lifetime: 3600,
                })
            },
            || 1000,
            move || format!("as-auth-{id}"),
        )
        .unwrap();
        Ok(server.handle(request))
    }
}

/// What the calling Agent presented to the Orders intermediary.
#[derive(Clone, Copy, Debug)]
enum Served {
    Person,
    /// Issued three-party, by a direct PS value on the same store.
    PersonServerAuth,
    AccessServerAuth,
}
fn served(f: &Fixture, federated: &Server, kind: Served) -> String {
    let caller = agent(false);
    let person = compact(&f.person(federated, &caller, ORDERS, None), "person_token");
    match kind {
        Served::Person => person,
        Served::PersonServerAuth => {
            let challenge = resource(&caller, &person, "orders.read", |_| {});
            compact(
                &f.exchange(&f.server(2000), &caller, &challenge, &person, None),
                "auth_token",
            )
        }
        Served::AccessServerAuth => {
            let challenge = resource(&caller, &person, "read", |r| r.aud = AS.into());
            compact(
                &f.exchange(federated, &caller, &challenge, &person, None),
                "auth_token",
            )
        }
    }
}

#[test]
fn four_party_chain_passes_each_kind_of_upstream_token_to_the_access_server() {
    for kind in [
        Served::Person,
        Served::PersonServerAuth,
        Served::AccessServerAuth,
    ] {
        let f = Fixture::new();
        let access = ChainedAs::default();
        let server = f.server(2000).with_federation(access.clone());
        let upstream = served(&f, &server, kind);
        let intermediary = agent(true);
        let person = compact(
            &f.person(&server, &intermediary, INVENTORY, Some(&upstream)),
            "person_token",
        );
        let challenge = resource(&intermediary, &person, "read", |r| r.aud = AS.into());
        let dispatched = access.bodies.lock().unwrap().len();
        // The Person token was issued with this upstream token, so omitting it
        // is refused before the AS is contacted.
        let omitted = f.exchange(&server, &intermediary, &challenge, &person, None);
        assert_eq!(
            output(&omitted)["error"],
            "invalid_upstream_token",
            "{kind:?}"
        );
        assert_eq!(access.bodies.lock().unwrap().len(), dispatched);

        let auth = compact(
            &f.exchange(&server, &intermediary, &challenge, &person, Some(&upstream)),
            "auth_token",
        );
        let sent = access.bodies.lock().unwrap().last().unwrap().clone();
        assert_eq!(sent["upstream_token"], upstream.as_str(), "{kind:?}");
        assert_eq!(sent["agent_token"], intermediary.token());
        assert_eq!(sent["presented_token"], person.as_str());
        assert_eq!(access.chained.load(Ordering::SeqCst), 1, "{kind:?}");
        let claims = AuthToken::parse(&auth)
            .unwrap()
            .verify(&Keys, 1000)
            .unwrap()
            .claims()
            .clone();
        assert_eq!(
            (
                claims.iss.as_str(),
                claims.aud.as_str(),
                claims.sub.as_str()
            ),
            (AS, INVENTORY, "inventory-person")
        );
        assert!(claims.exp <= expiry(&upstream), "{kind:?}");
        let receipt = f.store.token(&reference(&auth)).unwrap().unwrap();
        assert_eq!(receipt.person_server.as_deref(), Some(PS));
        assert_eq!(
            receipt.presented.as_ref().map(|tie| &tie.reference),
            Some(&reference(&person))
        );
        assert_eq!(
            receipt.upstream.as_ref().map(|tie| &tie.reference),
            Some(&reference(&upstream)),
            "{kind:?}"
        );
        assert_eq!(receipt.principal.subject, "aauth:Caller@ap.example");
        assert_eq!(receipt.agent.subject, "aauth:Orders@orders.example");

        // A step-up presents the AS's Auth token with the same upstream token.
        let step = resource(&intermediary, &auth, "read", |r| r.aud = AS.into());
        let stepped = compact(
            &f.exchange(&server, &intermediary, &step, &auth, Some(&upstream)),
            "auth_token",
        );
        let stepped = f.store.token(&reference(&stepped)).unwrap().unwrap();
        assert_eq!(stepped.presented, Some(receipt.token.clone()));
        assert_eq!(stepped.upstream, receipt.upstream);
        assert_eq!(access.chained.load(Ordering::SeqCst), 2);
        // bind_upstream, then consent_upstream for each exchange.
        assert_eq!(f.host.chain_calls.load(Ordering::SeqCst), 3);
    }
}

/// Consents to direct federation and to a downstream identity, but leaves
/// `consent_upstream` at its default.
struct NoFederatedDelegation(Host);
impl Policy for NoFederatedDelegation {
    fn bind_person(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.0.bind_person(request)
    }
    fn authorize(&self, request: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        self.0.authorize(request)
    }
    fn consent(&self, request: &AuthorizationRequest) -> Result<(), PolicyError> {
        self.0.consent(request)
    }
    fn bind_upstream(&self, request: &PersonRequest) -> Result<Person, PolicyError> {
        self.0.bind_upstream(request)
    }
}

#[test]
fn consent_to_federation_is_not_consent_to_federated_delegation() {
    let f = Fixture::new();
    let access = ChainedAs::default();
    let now = f.host.now.clone();
    let ids = f.ids.clone();
    let server: Server = PersonServer::new(
        Config::new(PS, "ps-key", SigningKey::from_seed([3; 32])),
        Keys,
        f.store.clone(),
        Box::new(NoFederatedDelegation(f.host.clone())) as BoxedPolicy,
        Box::new(move || now.load(Ordering::SeqCst)) as BoxedClock,
        Box::new(move || format!("token-{}", ids.fetch_add(1, Ordering::SeqCst))) as BoxedTokenIds,
    )
    .unwrap()
    .with_federation(access.clone());
    let upstream = served(&f, &server, Served::Person);
    let intermediary = agent(true);
    let person = compact(
        &f.person(&server, &intermediary, INVENTORY, Some(&upstream)),
        "person_token",
    );
    let challenge = resource(&intermediary, &person, "read", |r| r.aud = AS.into());
    let refused = f.exchange(&server, &intermediary, &challenge, &person, Some(&upstream));
    assert_eq!(refused.status(), 403);
    assert_eq!(output(&refused)["error"], "access_denied");
    assert_eq!(
        refused
            .extensions()
            .get::<FederationFailure>()
            .unwrap()
            .reason,
        FederationFailureReason::ConsentRefused(PolicyError::Denied)
    );
    assert!(access.bodies.lock().unwrap().is_empty());
}

#[test]
fn a_deferred_chained_request_relays_the_as_interaction_to_the_intermediary() {
    for revoke in [false, true] {
        let f = Fixture::new();
        let transport = NativeTransport::new(&f, 6, 0);
        let mut config = DeferredConfig::new(Arc::new(MemoryContinuations::new(16)));
        config.retry_after = 0;
        let server = f
            .server(2000)
            .with_revocation()
            .with_federation(transport.clone())
            .with_deferred(config)
            .unwrap();
        let caller = agent(false);
        let upstream = compact(&f.person(&server, &caller, ORDERS, None), "person_token");
        let intermediary = agent(true);
        let person = compact(
            &f.person(&server, &intermediary, INVENTORY, Some(&upstream)),
            "person_token",
        );
        let challenge = resource(&intermediary, &person, "read", |r| r.aud = AS.into());
        let first = f.exchange(&server, &intermediary, &challenge, &person, Some(&upstream));
        assert_eq!(
            first.status(),
            202,
            "{}",
            String::from_utf8_lossy(first.body())
        );
        assert_eq!(
            transport.original.lock().unwrap()[0]["upstream_token"],
            upstream.as_str()
        );
        let pending = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        let Requirement::Interaction { url, code } = &pending.requirement else {
            panic!("the AS interaction is relayed: {:?}", pending.requirement);
        };
        assert_eq!(url, "https://as.example/consent");
        // Interaction Chaining: Orders raises it to its own caller with its
        // own code and pending URL.
        let raised = ChainedInteraction::open(
            &pending,
            &Capabilities::none().with(Capability::Interaction),
            "https://orders.example/api",
            "/pending",
            "https://orders.example/interaction",
            "caller-thumbprint",
            1300,
        )
        .unwrap();
        assert_eq!(raised.downstream(), (url.as_str(), code.as_str()));
        assert!(
            raised
                .location()
                .starts_with("https://orders.example/pending/")
        );
        // The intermediary that started it polls, though its Agent token
        // names no PS; the calling Agent cannot.
        assert_eq!(
            poll(&server, &intermediary, &pending.location, "GET", None, 1000).status(),
            202
        );
        assert_eq!(
            poll(&server, &caller, &pending.location, "GET", None, 1000).status(),
            403
        );
        if revoke {
            server.revoke_person_token(&reference(&upstream).jti);
            let ended = poll(&server, &intermediary, &pending.location, "GET", None, 1000);
            assert_eq!(ended.status(), 400);
            assert_eq!(output(&ended)["error"], "revoked_upstream_token");
            assert_eq!(
                poll(&server, &intermediary, &pending.location, "GET", None, 1000).status(),
                410
            );
            continue;
        }
        transport.stage.store(2, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&pending.location, FederationInput::Poll)
                .unwrap()
                .status(),
            200
        );
        let auth = compact(
            &poll(&server, &intermediary, &pending.location, "GET", None, 1000),
            "auth_token",
        );
        let receipt = f.store.token(&reference(&auth)).unwrap().unwrap();
        assert_eq!(
            receipt.upstream.map(|tie| tie.reference),
            Some(reference(&upstream))
        );
    }
}
