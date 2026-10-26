use aauth_rust_agent::{Agent, PollError, PollSession};
use aauth_rust_core::continuation::{PendingResponse, Requirement};
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest};
use http::Response;
use serde_json::json;
fn agent() -> Agent {
    let key = SigningKey::from_seed([2; 32]);
    let token=Jws::sign(&json!({"typ":"aa-agent+jwt","alg":"Ed25519","kid":"ap"}),json!({"iss":"https://ap.example","dwk":"aauth-agent.json","sub":"aauth:Caller@ap.example","jti":"agent","iat":1000,"exp":5000,"ps":"https://ps.example","cnf":{"jwk":key.public_jwk()}}).to_string().as_bytes(),&SigningKey::from_seed([1;32])).unwrap();
    Agent::new(key, token).unwrap()
}
fn pending(requirement: Requirement) -> Response<Vec<u8>> {
    PendingResponse::new(
        "https://ps.example/token",
        "/pending/opaque",
        5,
        requirement,
    )
    .unwrap()
    .response()
    .unwrap()
}
#[test]
fn polls_use_signed_get_without_replaying_the_original_body() {
    let a = agent();
    let session = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Approval),
        1000,
        1100,
    )
    .unwrap();
    assert!(matches!(
        session.request(&a, 1004),
        Err(PollError::TooEarly { at: 1005 })
    ));
    let request = session.request(&a, 1005).unwrap();
    assert_eq!(request.method(), "GET");
    assert_eq!(request.uri(), "https://ps.example/pending/opaque");
    assert!(request.body().is_empty());
    let proof = PreparedRequest::prepare(&request, "sig", 1005, 60).unwrap();
    assert!(matches!(proof.key(), KeyMaterial::Jwt(token) if token == a.token()));
    proof.verify(&a.public_jwk()).unwrap();
}
#[test]
fn backoff_updates_deadline_and_terminal_delivery_stops_the_session() {
    let a = agent();
    let mut session = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Approval),
        1000,
        1100,
    )
    .unwrap();
    assert!(
        session
            .accept(
                Response::builder().status(429).body(Vec::new()).unwrap(),
                1005
            )
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        session.request(&a, 1014),
        Err(PollError::TooEarly { at: 1015 })
    ));
    let terminal = Response::builder()
        .status(200)
        .body(b"actual response".to_vec())
        .unwrap();
    assert_eq!(
        session.accept(terminal, 1015).unwrap().unwrap().body(),
        b"actual response"
    );
    assert!(matches!(
        session.request(&a, 1015),
        Err(PollError::Finished)
    ));
    assert!(
        session
            .accept(pending(Requirement::Approval), 1016)
            .is_err()
    );
}

#[test]
fn accept_returns_terminal_bytes_without_verifying_a_token() {
    let mut session = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Approval),
        1000,
        1100,
    )
    .unwrap();
    let body = br#"{"auth_token":"not-a-jwt"}"#;
    let terminal = Response::builder().status(200).body(body.to_vec()).unwrap();
    let got = session.accept(terminal, 1005).unwrap().unwrap();
    assert_eq!(got.body(), body);
    assert!(matches!(
        session.request(&agent(), 1005),
        Err(PollError::Finished)
    ));
    assert!(
        session
            .accept(pending(Requirement::Approval), 1016)
            .is_err()
    );
}
#[test]
fn changed_pending_location_and_expired_sessions_refuse_before_signing() {
    let a = agent();
    let mut session = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Approval),
        1000,
        1010,
    )
    .unwrap();
    let mut changed = pending(Requirement::Approval);
    changed
        .headers_mut()
        .insert("location", "/pending/other".parse().unwrap());
    assert!(session.accept(changed, 1005).is_err());
    assert!(session.request(&a, 1010).is_err());
    let session = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Approval),
        1000,
        1010,
    )
    .unwrap();
    assert!(matches!(session.request(&a, 1010), Err(PollError::Expired)));
}
#[test]
fn clarification_answers_and_cancellation_sign_exact_actions() {
    let a = agent();
    let mut session = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Clarification {
            question: "Why?".into(),
            timeout: Some(60),
            options: vec![],
        }),
        1000,
        1100,
    )
    .unwrap();
    let request = session
        .answer(&a, "To book the requested meeting", 1001)
        .unwrap();
    assert_eq!(request.method(), "POST");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(request.body()).unwrap(),
        json!({"action":"clarification_response","clarification_response":"To book the requested meeting"})
    );
    PreparedRequest::prepare(&request, "sig", 1001, 60)
        .unwrap()
        .verify(&a.public_jwk())
        .unwrap();
    assert_eq!(session.cancel(&a, 1001).unwrap().method(), "DELETE");
    let mut approval = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Approval),
        1000,
        1100,
    )
    .unwrap();
    assert!(approval.answer(&a, "wrong requirement", 1001).is_err());
}

#[test]
fn clarification_timeout_refuses_late_answers_and_polls() {
    let a = agent();
    let response = pending(Requirement::Clarification {
        question: "Why?".into(),
        timeout: Some(2),
        options: vec![],
    });
    let mut session = PollSession::new("https://ps.example/token", &response, 1000, 1100).unwrap();
    assert!(session.answer(&a, "on time", 1001).is_ok());
    assert!(matches!(
        session.answer(&a, "late", 1002),
        Err(PollError::Expired)
    ));
    assert!(matches!(session.request(&a, 1005), Err(PollError::Expired)));
}

#[test]
fn answered_question_timeout_does_not_shorten_later_approval() {
    let a = agent();
    let response = pending(Requirement::Clarification {
        question: "Why?".into(),
        timeout: Some(2),
        options: vec![],
    });
    let mut session = PollSession::new("https://ps.example/token", &response, 1000, 1100).unwrap();
    session.answer(&a, "answer", 1001).unwrap();
    assert!(
        session
            .accept(pending(Requirement::Approval), 1001)
            .unwrap()
            .is_none()
    );
    assert!(session.request(&a, 1006).is_ok());
}

#[test]
fn unchanged_clarification_poll_does_not_slide_the_question_deadline() {
    let a = agent();
    let question = || {
        pending(Requirement::Clarification {
            question: "Why?".into(),
            timeout: Some(10),
            options: vec![],
        })
    };
    let mut session =
        PollSession::new("https://ps.example/token", &question(), 1000, 1100).unwrap();
    session.request(&a, 1005).unwrap();
    session.accept(question(), 1005).unwrap();
    assert!(matches!(
        session.answer(&a, "late", 1010),
        Err(PollError::Expired)
    ));
    assert!(matches!(session.request(&a, 1010), Err(PollError::Expired)));
}

#[test]
fn an_answer_can_start_a_new_round_with_identical_question_text() {
    let a = agent();
    let question = || {
        pending(Requirement::Clarification {
            question: "Why?".into(),
            timeout: Some(10),
            options: vec![],
        })
    };
    let mut session =
        PollSession::new("https://ps.example/token", &question(), 1000, 1100).unwrap();
    session.answer(&a, "first answer", 1005).unwrap();
    session.accept(question(), 1005).unwrap();
    assert!(session.request(&a, 1010).is_ok());
    assert!(session.answer(&a, "second answer", 1014).is_ok());
    assert!(matches!(session.request(&a, 1015), Err(PollError::Expired)));
}

#[test]
fn on_time_answer_accepts_a_delayed_response_within_the_session_lifetime() {
    let a = agent();
    let question = || {
        pending(Requirement::Clarification {
            question: "Why?".into(),
            timeout: Some(10),
            options: vec![],
        })
    };
    for status in [200, 202, 403, 408] {
        let mut session =
            PollSession::new("https://ps.example/token", &question(), 1000, 1100).unwrap();
        session.answer(&a, "on time", 1009).unwrap();
        let terminal = status != 202;
        let response = if terminal {
            Response::builder()
                .status(status)
                .body(b"actual response".to_vec())
                .unwrap()
        } else {
            pending(Requirement::Approval)
        };
        let result = session.accept(response, 1011).unwrap();
        assert_eq!(result.is_some(), terminal);
        if !terminal {
            assert!(session.request(&a, 1016).is_ok());
        }
    }
    let mut session =
        PollSession::new("https://ps.example/token", &question(), 1000, 1100).unwrap();
    session.answer(&a, "on time", 1009).unwrap();
    assert!(matches!(
        session.accept(pending(Requirement::Approval), 1100),
        Err(PollError::Expired)
    ));
}

#[test]
fn a_429_preserves_the_servers_longer_retry_after_minimum() {
    let a = agent();
    let mut session = PollSession::new(
        "https://ps.example/token",
        &pending(Requirement::Approval),
        1000,
        1100,
    )
    .unwrap();
    session
        .accept(
            Response::builder()
                .status(429)
                .header("retry-after", "30")
                .body(Vec::new())
                .unwrap(),
            1005,
        )
        .unwrap();
    assert!(matches!(
        session.request(&a, 1034),
        Err(PollError::TooEarly { at: 1035 })
    ));
    assert!(session.request(&a, 1035).is_ok());
}

#[test]
fn a_held_invocation_is_polled_with_the_auth_token() {
    let a = agent();
    let resource_token = "eyJhbGciOiJFZDI1NTE5In0.e30.c2ln";
    let held = PendingResponse::new(
        "https://resource.example/records",
        "/pending/opaque",
        5,
        Requirement::AuthToken {
            resource_token: resource_token.into(),
        },
    )
    .unwrap()
    .response()
    .unwrap();
    let session = PollSession::new("https://resource.example/records", &held, 1000, 1100).unwrap();
    let auth = aauth_rust_core::mint_auth_token(
        &SigningKey::from_seed([3; 32]),
        "ps-1",
        &aauth_rust_core::AuthClaims {
            iss: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            aud: "https://resource.example".into(),
            sub: "directed-person".into(),
            jti: "auth-1".into(),
            iat: 1000,
            exp: 2000,
            ps: "https://ps.example".into(),
            cnf: aauth_rust_core::Confirmation {
                jwk: a.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: Some("read".into()),
            account: None,
            extra: Default::default(),
        },
    )
    .unwrap();
    let presenting = a.with_token(auth).unwrap();
    let request = session.request(&presenting, 1005).unwrap();
    let proof = PreparedRequest::prepare(&request, "sig", 1005, 60).unwrap();
    assert!(matches!(proof.key(), KeyMaterial::Jwt(token) if token == presenting.token()));
    proof.verify(&presenting.public_jwk()).unwrap();
    assert_ne!(presenting.token(), a.token());
}
