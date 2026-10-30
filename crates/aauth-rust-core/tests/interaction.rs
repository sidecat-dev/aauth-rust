use aauth_rust_core::continuation::{PendingResponse, Requirement};
use aauth_rust_core::interaction::{
    CallbackError, CallbackReceipt, ChainedInteraction, InteractionOutcome, completion_redirect,
    parse_interaction_query, person_server_redirect, receive_callback,
};

const RESOURCE: &str = "https://resource.example/consent";
const CALLBACK: &str = "https://ps.example/interaction/return";
const CODE: &str = "C0DE8X42";

fn location(response: &http::Response<Vec<u8>>) -> String {
    response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

#[test]
fn resource_callback_redirects_and_an_error_does_not_complete() {
    for url in [
        "http://resource.example/consent",
        "https://resource.example/consent?next=1",
        "https://resource.example/consent#part",
        "https://user:pw@resource.example/consent",
    ] {
        assert!(
            person_server_redirect(url, CODE, CALLBACK, true).is_err(),
            "{url}"
        );
    }
    assert!(person_server_redirect(RESOURCE, CODE, CALLBACK, false).is_err());
    assert!(person_server_redirect(RESOURCE, "short", CALLBACK, true).is_err());

    let from_ps = person_server_redirect(RESOURCE, CODE, CALLBACK, true).unwrap();
    assert_eq!(from_ps.status(), 302);
    let query = location(&from_ps)
        .strip_prefix(&format!("{RESOURCE}?"))
        .unwrap()
        .to_owned();
    let parsed = parse_interaction_query(&query).unwrap();
    assert_eq!(parsed.code, CODE);
    assert_eq!(parsed.callback.as_deref(), Some(CALLBACK));

    let from_agent = format!("callback={}&code={CODE}", CALLBACK.replace(':', "%3A"));
    let parsed = parse_interaction_query(&from_agent).unwrap();
    assert_eq!(parsed.code, CODE);
    assert_eq!(parsed.callback.as_deref(), Some(CALLBACK));
    assert!(parse_interaction_query("code=C0DE8X42&from=agent").is_err());

    let completed = completion_redirect(CALLBACK, InteractionOutcome::Completed).unwrap();
    assert_eq!(completed.status(), 302);
    assert_eq!(location(&completed), CALLBACK);
    assert!(!location(&completed).contains("error"));

    for error in [
        CallbackError::AccessDenied,
        CallbackError::UserAbandoned,
        CallbackError::ServerError,
        CallbackError::TemporarilyUnavailable,
        CallbackError::InteractionExpired,
    ] {
        let response = completion_redirect(CALLBACK, InteractionOutcome::Failed(error)).unwrap();
        assert_eq!(response.status(), 302);
        assert_eq!(
            location(&response),
            format!("{CALLBACK}?error={}", error_name(error))
        );
        let expected = match error {
            CallbackError::AccessDenied => "denied",
            CallbackError::UserAbandoned => "abandoned",
            CallbackError::InteractionExpired => "expired",
            CallbackError::ServerError | CallbackError::TemporarilyUnavailable => "server_error",
        };
        assert!(matches!(
            receive_callback(Some(location(&response).split_once('?').unwrap().1)),
            CallbackReceipt::Abandoned { polling_error } if polling_error == expected
        ));
    }

    assert!(matches!(receive_callback(None), CallbackReceipt::Continue));
    assert!(matches!(
        receive_callback(Some("")),
        CallbackReceipt::Continue
    ));
    assert!(matches!(
        receive_callback(Some("error=not_a_callback_error")),
        CallbackReceipt::Abandoned {
            polling_error: "server_error"
        }
    ));
}

#[test]
fn chained_interaction_draws_the_resources_own_code_and_pending_url() {
    let downstream = PendingResponse::new(
        "https://down.example/token",
        "/pending/down",
        5,
        Requirement::Interaction {
            url: "https://down.example/consent".into(),
            code: "DNST1234".into(),
        },
    )
    .unwrap();
    let approval = PendingResponse::new(
        "https://down.example/token",
        "/pending/other",
        5,
        Requirement::Approval,
    )
    .unwrap();
    assert!(
        ChainedInteraction::open(
            &approval,
            "https://resource.example/api",
            "/pending",
            "https://resource.example/interact",
            "thumb-owner",
            2000,
        )
        .is_err()
    );
    let mut chain = ChainedInteraction::open(
        &downstream,
        "https://resource.example/api",
        "/pending",
        "https://resource.example/interact",
        "thumb-owner",
        2000,
    )
    .unwrap();
    assert_eq!(
        chain.downstream(),
        ("https://down.example/consent", "DNST1234")
    );
    let own_code = chain.code().to_owned();
    let own_location = chain.location().to_owned();
    let id = own_location
        .strip_prefix("https://resource.example/pending/")
        .expect("pending URL under the given path");
    assert_eq!(id.len(), 22);
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(own_code.len(), 9);
    assert_eq!(own_code.as_bytes()[4], b'-');
    let other = ChainedInteraction::open(
        &downstream,
        "https://resource.example/api",
        "/pending",
        "https://resource.example/interact",
        "thumb-owner",
        2000,
    )
    .unwrap();
    assert_ne!(other.code(), own_code);
    assert_ne!(other.location(), own_location);
    let stranger = chain.poll("thumb-other", 1000).unwrap();
    assert_eq!(stranger.status(), 404);
    assert!(stranger.body().is_empty());
    let propagated = chain.poll("thumb-owner", 1000).unwrap();
    assert_eq!(propagated.status(), 202);
    let pending = PendingResponse::parse("https://resource.example/api", &propagated).unwrap();
    assert_eq!(pending.location, own_location);
    match pending.requirement {
        Requirement::Interaction { url, code } => {
            assert_eq!(url, "https://resource.example/interact");
            assert_eq!(code, own_code);
            assert_ne!(code, "DNST1234");
        }
        other => panic!("expected interaction, got {other:?}"),
    }
    chain
        .complete(Some("text/plain"), b"shipped".to_vec())
        .unwrap();
    assert!(
        chain
            .complete(Some("text/plain"), b"again".to_vec())
            .is_err()
    );
    let hidden = chain.poll("thumb-other", 2000).unwrap();
    assert_eq!(hidden.status(), 404);
    assert!(hidden.body().is_empty());
    let result = chain.poll("thumb-owner", 2000).unwrap();
    assert_eq!(result.status(), 200);
    assert_eq!(result.body(), b"shipped");
    assert_eq!(
        result
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain"
    );
    let again = chain.poll("thumb-owner", 2000).unwrap();
    assert_eq!(again.status(), 410);
    assert!(again.body().is_empty());
    let mut expired = ChainedInteraction::open(
        &downstream,
        "https://resource.example/api",
        "/pending",
        "https://resource.example/interact",
        "thumb-owner",
        1500,
    )
    .unwrap();
    expired
        .complete(Some("text/plain"), b"late".to_vec())
        .unwrap();
    let late = expired.poll("thumb-owner", 1501).unwrap();
    assert_eq!(late.status(), 410);
    assert!(late.body().is_empty());
}

fn error_name(error: CallbackError) -> &'static str {
    match error {
        CallbackError::AccessDenied => "access_denied",
        CallbackError::UserAbandoned => "user_abandoned",
        CallbackError::ServerError => "server_error",
        CallbackError::TemporarilyUnavailable => "temporarily_unavailable",
        CallbackError::InteractionExpired => "interaction_expired",
    }
}
