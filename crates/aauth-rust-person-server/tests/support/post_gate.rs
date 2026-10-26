use super::*;
const AS: &str = "https://as.example";
fn retry(response: &Response<Vec<u8>>) -> u64 {
    response.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}
fn approval(interval: u64) -> Response<Vec<u8>> {
    PendingResponse::new(
        &format!("{AS}/token"),
        "/token/pending/scripted",
        interval,
        Requirement::Approval,
    )
    .unwrap()
    .response()
    .unwrap()
}
#[test]
fn wrong_authenticated_poller_is_distinct_and_does_not_consume_custody() {
    let f = Fixture::new();
    let server = f
        .server(2000)
        .with_federation(NativeTransport::new(&f, 1, 0))
        .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
        .unwrap();
    let holder = agent(false);
    let (_, _, first) = initial(&f, &server, &holder);
    let pending = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
    let foreign = poll(&server, &agent(true), &pending.location, "GET", None, 1000);
    assert_eq!(foreign.status(), 403);
    assert_eq!(output(&foreign)["error"], "wrong_poller");
    assert_eq!(
        poll(&server, &holder, &pending.location, "GET", None, 1000).status(),
        202
    );
    assert_eq!(
        poll(&server, &holder, &pending.location, "DELETE", None, 1000).status(),
        200
    );
    let gone = poll(&server, &holder, &pending.location, "GET", None, 1000);
    assert_eq!(gone.status(), 410);
    assert_eq!(output(&gone)["error"], "gone");
    assert_eq!(
        server.federation_pending(&pending.location).unwrap_err(),
        aauth_rust_person_server::AdvanceError::Gone
    );
}
#[test]
fn agent_retry_after_tracks_as_schedule_and_refusal_backoff() {
    let f = Fixture::new();
    let transport = ScriptedTransport::new(vec![
        approval(10),
        Response::builder().status(429).body(Vec::new()).unwrap(),
        Response::builder()
            .status(503)
            .header("retry-after", "30")
            .body(Vec::new())
            .unwrap(),
        approval(20),
    ]);
    let mut cfg = config(Arc::new(MemoryContinuations::new(16)));
    cfg.lifetime = 300;
    cfg.retry_after = 2;
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(cfg)
        .unwrap();
    let holder = agent(false);
    let (_, _, first) = initial(&f, &server, &holder);
    assert_eq!(retry(&first), 10);
    let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
    f.host.now.store(1003, Ordering::SeqCst);
    let early = poll(&server, &holder, &p.location, "GET", None, 1003);
    assert_eq!(early.status(), 429);
    assert_eq!(retry(&early), 7);
    assert_eq!(
        server.federation_pending(&p.location).unwrap().retry_after,
        7
    );
    f.host.now.store(1010, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap()
            .status(),
        429
    );
    let after_429 = poll(&server, &holder, &p.location, "GET", None, 1010);
    assert_eq!(after_429.status(), 202);
    assert_eq!(retry(&after_429), 15);
    f.host.now.store(1025, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap()
            .status(),
        503
    );
    let after_503 = poll(&server, &holder, &p.location, "GET", None, 1025);
    assert_eq!(after_503.status(), 202);
    assert_eq!(retry(&after_503), 30);
    f.host.now.store(1055, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap()
            .status(),
        202
    );
    let next = poll(&server, &holder, &p.location, "GET", None, 1055);
    assert_eq!(next.status(), 202);
    assert_eq!(retry(&next), 20);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 4);
    f.host.now.store(1300, Ordering::SeqCst);
    assert_eq!(
        server.federation_pending(&p.location).unwrap_err(),
        aauth_rust_person_server::AdvanceError::Expired
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 4);
}
#[test]
fn invalid_as_retry_after_is_a_bad_answer_and_http_date_is_supported() {
    for (status, header) in [
        (429, "3601"),
        (503, "3601"),
        (503, "garbage"),
        (429, "garbage"),
        (503, "Thu, 01 Jan 1970 01:16:41 GMT"),
    ] {
        let f = Fixture::new();
        let transport = ScriptedTransport::new(vec![
            approval(0),
            Response::builder()
                .status(status)
                .header("retry-after", header)
                .body(Vec::new())
                .unwrap(),
        ]);
        let server = f
            .server(2000)
            .with_federation(transport)
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (_, _, first) = initial(&f, &server, &holder);
        let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        let response = server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap();
        assert_eq!(response.status(), 502, "{status}:{header}");
        assert_eq!(output(&response)["error"], "as_unreachable");
        assert!(matches!(
            response
                .extensions()
                .get::<aauth_rust_person_server::FederationFailure>()
                .unwrap()
                .reason,
            aauth_rust_person_server::FederationFailureReason::MalformedResponse(_)
        ));
        assert_eq!(
            poll(&server, &holder, &p.location, "GET", None, 1000).status(),
            502
        );
        assert_eq!(
            poll(&server, &holder, &p.location, "GET", None, 1000).status(),
            410
        );
    }
    let f = Fixture::new();
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1020);
    let transport = ScriptedTransport::new(vec![
        approval(0),
        Response::builder()
            .status(503)
            .header("retry-after", httpdate::fmt_http_date(at))
            .body(Vec::new())
            .unwrap(),
        approval(5),
    ]);
    let server = f
        .server(2000)
        .with_federation(transport.clone())
        .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
        .unwrap();
    let holder = agent(false);
    let (_, _, first) = initial(&f, &server, &holder);
    let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
    assert_eq!(
        server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        retry(&poll(&server, &holder, &p.location, "GET", None, 1000)),
        20
    );
    f.host.now.store(1019, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap_err(),
        aauth_rust_person_server::AdvanceError::NotReady
    );
    f.host.now.store(1020, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap()
            .status(),
        202
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 3);
}
#[derive(Clone)]
struct Replay {
    native: NativeTransport,
    replay: Arc<AtomicBool>,
    body: Arc<Mutex<Vec<u8>>>,
}
impl aauth_rust_person_server::Federation for Replay {
    fn endpoint(&self, i: &str) -> Result<String, aauth_rust_person_server::FederationError> {
        aauth_rust_person_server::Federation::endpoint(&self.native, i)
    }
    fn send(
        &self,
        r: &Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, aauth_rust_person_server::FederationError> {
        if self.replay.load(Ordering::SeqCst) && r.uri().path().starts_with("/token/pending/") {
            return Ok(Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(self.body.lock().unwrap().clone())
                .unwrap());
        }
        let response = aauth_rust_person_server::Federation::send(&self.native, r)?;
        if response.status() == 200 && r.method() != "DELETE" {
            *self.body.lock().unwrap() = response.body().clone();
        }
        Ok(response)
    }
}
#[test]
fn cross_exchange_grant_reuse_is_bounded_by_the_exact_presented_parent() {
    for same_presented in [false, true] {
        let f = Fixture::new();
        let native = NativeTransport::new(&f, 1, 0);
        let replay = Replay {
            native: native.clone(),
            replay: Arc::new(AtomicBool::new(false)),
            body: Arc::new(Mutex::new(Vec::new())),
        };
        let server = f
            .server(2000)
            .with_federation(replay.clone())
            .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
            .unwrap();
        let holder = agent(false);
        let (person_a, challenge_a, first) = initial(&f, &server, &holder);
        let a = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
        native.stage.store(2, Ordering::SeqCst);
        assert_eq!(
            server
                .advance_federation(&a.location, FederationInput::Poll)
                .unwrap()
                .status(),
            200
        );
        let token_a = compact(
            &poll(&server, &holder, &a.location, "GET", None, 1000),
            "auth_token",
        );
        let person_b = if same_presented {
            person_a.clone()
        } else {
            compact(&f.person(&server, &holder, ORDERS, None), "person_token")
        };
        assert_eq!(person_a == person_b, same_presented);
        let challenge_b = resource(&holder, &person_b, "read", |r| {
            r.aud = AS.into();
            r.jti = "another-resource-challenge".into();
        });
        assert_ne!(challenge_a, challenge_b);
        native.stage.store(1, Ordering::SeqCst);
        let second = f.exchange(&server, &holder, &challenge_b, &person_b, None);
        let b = PendingResponse::parse(&format!("{PS}/token"), &second).unwrap();
        assert_ne!(a.location, b.location);
        replay.replay.store(true, Ordering::SeqCst);
        let host = server
            .advance_federation(&b.location, FederationInput::Poll)
            .unwrap();
        assert_eq!(host.status(), if same_presented { 200 } else { 502 });
        assert_eq!(
            server.federation_pending(&b.location).unwrap_err(),
            aauth_rust_person_server::AdvanceError::NotReady
        );
        if !same_presented {
            assert_eq!(output(&host)["error"], "as_unreachable");
            let d = host
                .extensions()
                .get::<aauth_rust_person_server::FederationFailure>()
                .unwrap();
            assert_eq!(d.status, Some(http::StatusCode::OK));
            assert_eq!(
                d.reason,
                aauth_rust_person_server::FederationFailureReason::InvalidGrant
            );
        }
        let delivered = poll(&server, &holder, &b.location, "GET", None, 1000);
        assert_eq!(delivered.status(), host.status());
        if same_presented {
            assert_eq!(compact(&delivered, "auth_token"), token_a);
        } else {
            assert!(output(&delivered).get("auth_token").is_none());
        }
        assert_eq!(
            poll(&server, &holder, &b.location, "GET", None, 1000).status(),
            410
        );
    }
}
#[test]
fn a_captured_signed_poll_can_take_one_delivery_inside_its_proof_window() {
    let f = Fixture::new();
    let native = NativeTransport::new(&f, 1, 0);
    let server = f
        .server(2000)
        .with_federation(native.clone())
        .with_deferred(config(Arc::new(MemoryContinuations::new(16))))
        .unwrap();
    let holder = agent(false);
    let (_, _, first) = initial(&f, &server, &holder);
    let p = PendingResponse::parse(&format!("{PS}/token"), &first).unwrap();
    let mut captured = Request::builder()
        .uri(&p.location)
        .body(Vec::new())
        .unwrap();
    holder.sign(&mut captured, 1000).unwrap();
    assert_eq!(server.handle(&captured).status(), 202);
    f.host.now.store(1005, Ordering::SeqCst);
    native.stage.store(2, Ordering::SeqCst);
    assert_eq!(
        server
            .advance_federation(&p.location, FederationInput::Poll)
            .unwrap()
            .status(),
        200
    );
    let replay = server.handle(&captured);
    assert_eq!(replay.status(), 200);
    let token = AuthToken::parse(&compact(&replay, "auth_token"))
        .unwrap()
        .verify(&Keys, 1005)
        .unwrap();
    assert_eq!(
        token.claims().cnf.jwk.thumbprint().unwrap(),
        holder.public_jwk().thumbprint().unwrap()
    );
    assert_eq!(
        poll(&server, &holder, &p.location, "GET", None, 1005).status(),
        410
    );
    assert_eq!(server.handle(&captured).status(), 410);
}
