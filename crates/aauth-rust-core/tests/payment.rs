use aauth_rust_core::continuation::{
    PaymentChallenge, PaymentChallengeError, PendingResponse, Requirement,
};
use serde_json::json;

fn payment(authenticate: &str) -> PendingResponse {
    PendingResponse {
        location: "https://as.example/pending/bill".into(),
        retry_after: 5,
        requirement: Requirement::Payment {
            authenticate: authenticate.into(),
        },
        body: json!({}),
    }
}

#[test]
fn payment_accessor_extracts_token_and_quoted_parameters() {
    for authenticate in [
        "Payment id=invoice-1, method=example, amount=10.50, currency=USD",
        "Payment id=\"invoice-1\", method=\"example\", amount=\"10.50\", currency=\"USD\"",
        "pAyMeNt ID = invoice-1, MeThOd=example, AMOUNT =\"10.50\", CuRrEnCy=USD",
    ] {
        assert_eq!(
            payment(authenticate).payment_challenge().unwrap(),
            Some(PaymentChallenge {
                id: "invoice-1".into(),
                method: Some("example".into()),
                amount: Some("10.50".into()),
                currency: Some("USD".into()),
            }),
            "{authenticate}",
        );
    }
}

#[test]
fn payment_accessor_decodes_quoted_commas_quotes_and_backslashes() {
    let authenticate = r#"Payment id="invoice,\"one\\two", method="https://pay.example/\"method", amount="10,50", currency="U\SD""#;
    assert_eq!(
        payment(authenticate).payment_challenge().unwrap(),
        Some(PaymentChallenge {
            id: "invoice,\"one\\two".into(),
            method: Some("https://pay.example/\"method".into()),
            amount: Some("10,50".into()),
            currency: Some("USD".into()),
        }),
    );
}

#[test]
fn payment_accessor_ignores_unknown_parameters_without_inventing_optional_values() {
    assert_eq!(
        payment("Payment realm=checkout, id=bill-1, future=\"a,b\", empty=\"\"")
            .payment_challenge()
            .unwrap(),
        Some(PaymentChallenge {
            id: "bill-1".into(),
            method: None,
            amount: None,
            currency: None,
        }),
    );
}

#[test]
fn payment_accessor_selects_one_unambiguous_challenge_from_other_schemes() {
    for authenticate in [
        "Basic realm=elsewhere, Payment id=bill-1, amount=3, Bearer realm=elsewhere",
        "Negotiate YWJjZA==, Payment id=bill-1, amount=3, Basic",
        "Payment id=bill-1, amount=3, Negotiate YWJjZA==",
        "Basic, Payment id=bill-1, amount=3",
        "\tBasic\t, Payment id=bill-1, amount=3\t",
        "Payment id=bill-1, amount=3, Basic\t",
    ] {
        let bill = payment(authenticate).payment_challenge().unwrap().unwrap();
        assert_eq!(bill.id, "bill-1", "{authenticate}");
        assert_eq!(bill.amount.as_deref(), Some("3"), "{authenticate}");
        assert_eq!(bill.method, None, "{authenticate}");
    }
}

#[test]
fn payment_accessor_returns_none_for_nonpayment_requirements() {
    for requirement in [
        Requirement::Waiting,
        Requirement::Approval,
        Requirement::Claims(vec!["email".into()]),
    ] {
        let mut pending = payment("Payment id=unused");
        pending.requirement = requirement;
        assert_eq!(pending.payment_challenge().unwrap(), None);
    }
}

#[test]
fn payment_accessor_preserves_original_authenticate_when_rendered_and_reparsed() {
    let authenticate = r#"pAyMeNt ID = "invoice,\"one\\two", future = "a,b", Method=example"#;
    let pending = payment(authenticate);
    let original = pending.clone();
    assert_eq!(
        pending.payment_challenge().unwrap().unwrap().id,
        "invoice,\"one\\two"
    );
    assert_eq!(pending, original);
    let wire = pending.response().unwrap();
    assert_eq!(wire.headers()["www-authenticate"], authenticate);
    let parsed = PendingResponse::parse("https://as.example/token", &wire).unwrap();
    assert_eq!(
        parsed.payment_challenge().unwrap(),
        pending.payment_challenge().unwrap()
    );
    assert_eq!(parsed.requirement, original.requirement);
}

#[test]
fn payment_accessor_rejects_missing_empty_or_duplicate_ids_and_parameters() {
    for authenticate in [
        "Payment",
        "Payment method=example",
        "Payment id=\"\"",
        "Payment id=one, id=one",
        "Payment id=one, ID=two",
        "Payment id=one, method=a, METHOD=b",
        "Payment id=one, future=a, FUTURE=b",
        "Basic id=some-other-scheme",
    ] {
        assert!(
            payment(authenticate).payment_challenge().is_err(),
            "{authenticate}"
        );
    }
}

#[test]
fn payment_accessor_rejects_ambiguous_multiple_payment_challenges() {
    for authenticate in [
        "Payment id=one, Payment id=two",
        "Payment id=one, pAyMeNt id=one",
        "Payment id=one, Basic realm=other, Payment id=two",
    ] {
        assert!(
            payment(authenticate).payment_challenge().is_err(),
            "{authenticate}"
        );
    }
}

#[test]
fn payment_accessor_rejects_malformed_authentication_grammar() {
    for authenticate in [
        "",
        "Payment id=",
        "Payment id=\"unterminated",
        "Payment id=\"dangling\\",
        "Payment id=one two",
        "Payment id=one; method=example",
        "Payment id=\"one\"junk",
        "Payment id=one, =value",
        "Payment id=one, future=",
        "Payment id=one, Basic realm=\"unterminated",
        "Payment id=one, Basic realm=a, REALM=b",
        "Payment id=one, Negotiate abc=def=",
        "Payment id=one\r\nInjected: true",
        "Payment id=\"one\u{7f}two\"",
        "Payment id=\"one\\\ntwo\"",
        "Payment YWJjZA==",
        "Payment\tid=one",
        "Payment id=one, id=two,",
        "Payment id=one, Payment",
    ] {
        assert!(
            payment(authenticate).payment_challenge().is_err(),
            "{authenticate:?}"
        );
    }
}

#[test]
fn payment_accessor_bounds_mutated_public_headers_and_errors_do_not_expose_them() {
    let authenticate = format!("Payment id=\"{}\"", "x".repeat(65536));
    let error: PaymentChallengeError = payment(&authenticate).payment_challenge().unwrap_err();
    let error: &dyn std::error::Error = &error;
    let display = error.to_string();
    assert!(!display.contains(&authenticate));
    assert!(!display.is_empty());
    assert_eq!(
        display,
        payment("Payment id=\"secret-bill\", ID=other")
            .payment_challenge()
            .unwrap_err()
            .to_string(),
    );
}
