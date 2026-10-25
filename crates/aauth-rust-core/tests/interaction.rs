use aauth_rust_core::interaction::{
    CallbackError, CallbackReceipt, InteractionOutcome, completion_redirect,
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

fn error_name(error: CallbackError) -> &'static str {
    match error {
        CallbackError::AccessDenied => "access_denied",
        CallbackError::UserAbandoned => "user_abandoned",
        CallbackError::ServerError => "server_error",
        CallbackError::TemporarilyUnavailable => "temporarily_unavailable",
        CallbackError::InteractionExpired => "interaction_expired",
    }
}
