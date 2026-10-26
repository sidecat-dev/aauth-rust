//! Executable budgets rules. Role tests cover issuance and HTTP; these cover the
//! objects, the cap, and the usage arithmetic those roles call.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;

use aauth_rust_budgets::{
    AllocationBook, Budget, BudgetHeader, Caller, ChargeError, ConsumptionRecord, Error,
    IssuerPolicy, KeyRole, Ledger, MAX_AMOUNT, Refusal, RevocationSettlement, TokenAccount,
    UnitDeclaration, act_on_header, answer_usage, assume_lost_cost, balance_after, check_declared,
    consent_figure, header_is_fresh, human_amount, issue_auth_budget, metered_access_mode,
    narrow_to, offer_budget, parse_budget, parse_declarations, parse_header, parse_max_cost,
    parse_resource_claims, parse_usage_query, plan_from_grant, read_granted, recover_omitted_cost,
    response_complete_without_trailer, sanitize_markdown, sender_field, sign_usage_response,
    spend_plan, trailer_field, usage_signature_covers, validate_endpoint_url, validate_narrowing,
    verify_delivered, verify_usage_signature, withhold_budget_header,
};
use aauth_rust_jose::SigningKey;
use serde_json::json;

fn usd(amount: i64) -> Budget {
    Budget::new(amount, "USD", 6).unwrap()
}

fn units() -> Vec<UnitDeclaration> {
    vec![UnitDeclaration::with_max("USD", 6, 10_000_000, "dollars <b>bold</b>").unwrap()]
}

const ISS: &str = "https://as.example";

fn account(jti: &str, amount: i64, sub: &str) -> TokenAccount {
    TokenAccount {
        jti: jti.into(),
        grant: usd(amount),
        ps: "https://ps.example".into(),
        sub: sub.into(),
        aud: "https://resource.example".into(),
        iss: "https://as.example".into(),
        jkt: format!("jkt-{jti}"),
        tenant: None,
        mission: None,
    }
}

#[test]
fn budget_object_requires_three_integer_members_inside_fifteen_digits() {
    let value = json!({"amount": 5, "unit": "USD", "decimals": 6});
    assert_eq!(parse_budget(&value).unwrap(), usd(5));
    assert!(matches!(
        parse_budget(&json!({"amount": 1.0, "unit": "USD", "decimals": 6})),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        parse_budget(&json!({"amount": -1, "unit": "USD", "decimals": 6})),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        parse_budget(&json!({"amount": 1_000_000_000_000_000_i64, "unit": "USD", "decimals": 6})),
        Err(Error::Range)
    ));
    assert!(matches!(
        parse_budget(&json!({"amount": 1, "decimals": 6})),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        parse_budget(&json!({"unit": "USD", "decimals": 6})),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        parse_budget(&json!({"amount": 1, "unit": "USD"})),
        Err(Error::Malformed)
    ));
    assert!(parse_budget(&json!({"amount": 1, "unit": "USD", "decimals": -1})).is_err());
    assert_eq!(usd(1).amount(), 1);
    assert!(Budget::new(MAX_AMOUNT, "USD", 0).is_ok());
    assert!(Budget::new(MAX_AMOUNT + 1, "USD", 0).is_err());
}

#[test]
fn narrowing_keeps_the_resource_unit_and_never_raises_the_amount() {
    let offer = usd(100);
    assert!(validate_narrowing(&offer, &usd(100)).is_ok());
    assert!(validate_narrowing(&offer, &usd(101)).is_err());
    assert!(matches!(
        validate_narrowing(&offer, &Budget::new(50, "EUR", 6).unwrap()),
        Err(Error::Denomination)
    ));
    assert!(matches!(
        validate_narrowing(&offer, &Budget::new(50, "USD", 2).unwrap()),
        Err(Error::Denomination)
    ));
    let narrowed = narrow_to(&offer, Some(40)).unwrap();
    assert_eq!(
        (narrowed.amount(), narrowed.unit(), narrowed.decimals()),
        (40, "USD", 6)
    );
    assert_eq!(narrow_to(&offer, Some(500)).unwrap().amount(), 100);
    assert_eq!(narrow_to(&offer, None).unwrap().amount(), 100);
}

#[test]
fn resource_offer_narrows_a_high_request_and_rejects_a_scale_change() {
    let declared = units();
    let high = usd(50_000_000);
    assert_eq!(
        offer_budget(&declared, Some(&high), 1).unwrap().amount(),
        10_000_000
    );
    assert!(matches!(
        offer_budget(&declared, Some(&Budget::new(1, "EUR", 6).unwrap()), 1),
        Err(Error::UndeclaredUnit)
    ));
    assert!(matches!(
        offer_budget(&declared, Some(&Budget::new(1, "USD", 2).unwrap()), 1),
        Err(Error::DecimalsMismatch)
    ));
    assert_eq!(
        offer_budget(&declared, None, 5_000_000).unwrap().amount(),
        5_000_000
    );
    assert_eq!(
        offer_budget(&declared, None, 20_000_000).unwrap().amount(),
        10_000_000
    );
    assert!(matches!(
        parse_declarations(&json!([
            {"unit": "USD", "decimals": 6},
            {"unit": "USD", "decimals": 6}
        ])),
        Err(Error::Malformed)
    ));
    assert!(metered_access_mode("auth-token").is_ok());
    assert!(matches!(
        metered_access_mode("session"),
        Err(Error::AccessMode)
    ));
    assert!(validate_endpoint_url("https://resource.example/usage").is_ok());
    assert!(validate_endpoint_url("https://resource.example/usage?x=1").is_err());
    assert!(validate_endpoint_url("http://resource.example/usage").is_err());
}

#[test]
fn consumption_requires_budget_and_the_presented_jti() {
    let mut extra = BTreeMap::new();
    extra.insert(
        "budget_consumed".into(),
        json!({"jti": "auth-1", "consumed": 4}),
    );
    assert!(parse_resource_claims(&extra, "auth-1").is_err());
    extra.insert("budget".into(), usd(10).to_value());
    let parsed = parse_resource_claims(&extra, "auth-1").unwrap();
    assert_eq!(parsed.consumed.unwrap().consumed(), 4);
    extra.insert(
        "budget_consumed".into(),
        json!({"jti": "other", "consumed": 4}),
    );
    assert!(parse_resource_claims(&extra, "auth-1").is_err());
    extra.insert("budget_consumed".into(), json!({"consumed": 4}));
    assert!(parse_resource_claims(&extra, "auth-1").is_err());
    extra.insert("budget_consumed".into(), json!({"jti": "auth-1"}));
    assert!(parse_resource_claims(&extra, "auth-1").is_err());
    let mut missing = BTreeMap::new();
    missing.insert("budget".into(), json!({"unit": "USD"}));
    assert!(parse_resource_claims(&missing, "auth-1").is_err());
}

#[test]
fn consent_keeps_the_amount_out_of_the_sanitized_description() {
    let figure = consent_figure(
        &usd(5_000_000),
        "pay <script>javascript:alert(1)</script> [x](data:text/html,hi)",
    );
    assert_eq!(figure.amount, "$5.00");
    assert!(!figure.description.contains('<'));
    assert!(!figure.description.contains("javascript:"));
    assert!(!figure.description.contains("data:"));
    assert_ne!(figure.amount, figure.description);
    assert_eq!(human_amount(&usd(5_000_000)), "$5.00");
    assert_eq!(
        human_amount(&Budget::new(1500, "kWh", 3).unwrap()),
        "1.500 kWh"
    );
    let cleaned = sanitize_markdown("a <b>b</b> c");
    assert_eq!(cleaned, "a b c");
    let kept = sanitize_markdown("see [docs](https://example.test/a)");
    assert!(kept.contains("https://example.test/a"), "{kept}");
    for sample in [
        "JavaScript:alert(1)",
        "javajavascript:script:alert(1)",
        "java&#115;cript:alert(1)",
        "&#106;avascript:alert(1)",
        "JaVaScRiPt&#58;alert(1)",
        "data:text/html,hi",
        "vbscript:msg",
    ] {
        let stripped = sanitize_markdown(sample).to_ascii_lowercase();
        assert!(!stripped.contains("javascript:"), "{sample} -> {stripped}");
        assert!(!stripped.contains("data:"), "{sample} -> {stripped}");
        assert!(!stripped.contains("vbscript:"), "{sample} -> {stripped}");
    }
}

#[test]
fn header_ignores_unknown_members_and_refuses_a_stale_or_foreign_unit() {
    let grant = usd(100);
    let field = sender_field(&BudgetHeader::final_cost(40, 10, "USD", 6).unwrap(), true).unwrap();
    assert!(field.starts_with("remaining=40"));
    assert!(field.contains("cost=10"));
    assert!(!field.contains("reserved="));
    let with_extra = format!("{field}, future=1");
    let parsed = parse_header(&with_extra, Some(&grant), Some(0)).unwrap();
    assert!(parsed.actionable);
    assert_eq!(act_on_header(&parsed), Some(40));
    assert!(
        !parse_header(&field, Some(&grant), Some(1))
            .unwrap()
            .actionable
    );
    assert!(header_is_fresh(Some(0)));
    assert!(!header_is_fresh(Some(2)));
    let foreign = sender_field(&BudgetHeader::final_cost(40, 10, "EUR", 6).unwrap(), true).unwrap();
    assert!(
        !parse_header(&foreign, Some(&grant), None)
            .unwrap()
            .actionable
    );
    assert!(act_on_header(&parse_header(&foreign, Some(&grant), None).unwrap()).is_none());
    assert!(BudgetHeader::final_cost(1, 1, "USD", 6).is_ok());
    assert!(BudgetHeader::build_pair_rejected());
    assert!(parse_max_cost("1000").is_ok());
    assert!(parse_max_cost("1000;x=1").is_err());
}

#[test]
fn trailer_carries_only_cost_and_a_served_request_names_cost_or_reserved() {
    let header = BudgetHeader::reserved_hold(10, 4, "USD", 6).unwrap();
    let field = sender_field(&header, true).unwrap();
    assert!(field.contains("reserved=4"));
    assert!(!field.contains("cost="));
    let trailer = trailer_field(&header, 3).unwrap();
    assert_eq!(trailer.name, "aauth-budget");
    assert_eq!(trailer.field, "cost=3");
    assert!(trailer_field(&BudgetHeader::final_cost(1, 1, "USD", 6).unwrap(), 1).is_err());
    let refusal = BudgetHeader::refusal(0, None, "USD", 6).unwrap();
    assert!(sender_field(&refusal, true).is_err());
    assert!(sender_field(&refusal, false).is_ok());
    assert_eq!(balance_after(1_568_800, 431_200, 221_200), 1_778_800);
    assert_eq!(recover_omitted_cost(100, 40, 70), 70);
    assert_eq!(assume_lost_cost(Some(40), 100), 40);
    assert_eq!(assume_lost_cost(None, 100), 100);
    assert!(!withhold_budget_header(false));
    assert!(!withhold_budget_header(true));
    let mut extra = BTreeMap::new();
    extra.insert("budget".into(), usd(9).to_value());
    let granted = read_granted(&extra).unwrap().unwrap();
    assert_eq!(spend_plan(&granted, Some(&usd(100))), 9);
    assert_ne!(spend_plan(&granted, Some(&usd(100))), 100);
    assert_eq!(plan_from_grant(&extra, Some(&usd(100))).unwrap(), Some(9));
    assert_eq!(trailer.listed, "AAuth-Budget");
    assert!(response_complete_without_trailer(None));
    assert!(response_complete_without_trailer(Some("cost=3")));
}

#[test]
fn issuer_copies_unit_and_will_not_exceed_the_offer_or_invent_a_budget() {
    let offer = usd(100);
    let policy = IssuerPolicy::capped(40, units());
    let parameter = usd(80);
    let issued = issue_auth_budget(Some(&offer), Some(&parameter), &policy)
        .unwrap()
        .unwrap();
    assert_eq!(
        (issued.amount(), issued.unit(), issued.decimals()),
        (40, "USD", 6)
    );
    assert!(
        issue_auth_budget(Some(&offer), None, &policy)
            .unwrap()
            .is_none()
    );
    assert!(issue_auth_budget(None, None, &policy).unwrap().is_none());
    assert!(issue_auth_budget(None, Some(&parameter), &policy).is_err());
    assert!(issue_auth_budget(Some(&offer), Some(&usd(101)), &policy).is_err());
    assert!(matches!(
        issue_auth_budget(
            Some(&offer),
            Some(&Budget::new(10, "USD", 2).unwrap()),
            &policy
        ),
        Err(Error::DecimalsMismatch)
    ));
    assert!(verify_delivered(Some(&usd(40)), Some(&usd(40))).is_ok());
    assert!(verify_delivered(Some(&usd(40)), Some(&usd(41))).is_err());
    assert!(verify_delivered(None, Some(&usd(1))).is_err());
    assert!(verify_delivered(Some(&usd(1)), None).is_err());
    assert!(verify_delivered(None, None).is_ok());
    assert!(check_declared(&Budget::new(1, "USD", 2).unwrap(), &units()).is_err());
    assert!(check_declared(&usd(1), &[]).is_ok());
}

#[test]
fn unreported_allocation_counts_as_fully_consumed_until_a_figure_replaces_it() {
    let mut book = AllocationBook::new();
    book.insert("a", 100, 500);
    book.insert("a", 999, 900);
    assert_eq!(book.accounted(), 100);
    book.apply_record(&ConsumptionRecord::new("a", 30).unwrap())
        .unwrap();
    book.apply_record(&ConsumptionRecord::new("a", 30).unwrap())
        .unwrap();
    assert_eq!(book.accounted(), 30);
    book.insert("b", 50, 200);
    assert_eq!(book.free(1_000, 30, 100), 1_000 - 30 - 100 - 50);
    book.note_revocation("b", RevocationSettlement::Recorded(80));
    assert_eq!(book.free(1_000, 30, 100), 1_000 - 30 - 100);
    book.insert("c", 7, 150);
    book.note_revocation("c", RevocationSettlement::Unsupported);
    assert_eq!(book.free(1_000, 30, 100), 1_000 - 30 - 100 - 7);
    assert_eq!(book.free(1_000, 30, 150), 1_000 - 30 - 100);
    book.insert("d", 9, 180);
    book.note_revocation("d", RevocationSettlement::Unavailable);
    assert_eq!(book.free(1_000, 30, 150), 1_000 - 30 - 100 - 9);
    assert_eq!(book.free(1_000, 30, 180), 1_000 - 30 - 100);
    assert_eq!(book.free_owned(1_000, 30, 100, "ada"), 1_000 - 30);
    book.insert_owned("e", 40, 200, "ada");
    book.insert_owned("f", 10, 200, "bob");
    assert_eq!(book.free_owned(1_000, 30, 100, "ada"), 1_000 - 30 - 40);
    assert_eq!(book.free_owned(1_000, 30, 100, "bob"), 1_000 - 30 - 10);
}

#[test]
fn cap_is_per_token_and_a_refusal_does_not_draw_down() {
    let mut ledger = Ledger::new();
    ledger.open(account("t", 100, "ada")).unwrap();
    let hold = ledger.reserve(ISS, "t", 40).unwrap();
    assert!(matches!(
        ledger.reserve(ISS, "t", 70),
        Err(ChargeError::Refused(Refusal::Insufficient {
            remaining: 60,
            ..
        }))
    ));
    assert_eq!(ledger.committed(ISS, "t"), Some(0));
    assert_eq!(ledger.outstanding(ISS, "t"), Some((0, 40)));
    let header = ledger.commit(&hold, 15, 1_000).unwrap();
    assert!(header.contains("cost=15"));
    assert!(header.contains("remaining=85"));
    assert_eq!(ledger.committed(ISS, "t"), Some(15));
    assert_eq!(
        ledger.person_total(
            "https://ps.example",
            "ada",
            "https://resource.example",
            "USD"
        ),
        15
    );
    ledger.open(account("other", 1_000, "ada")).unwrap();
    assert!(ledger.reserve(ISS, "other", 1_000).is_ok());
    ledger.open(account("full", 10, "ada")).unwrap();
    assert!(matches!(
        ledger.reserve(ISS, "full", 11),
        Err(ChargeError::Refused(Refusal::Insufficient { .. }))
    ));
    let hold = ledger.reserve(ISS, "full", 10).unwrap();
    ledger.commit(&hold, 10, 2).unwrap();
    assert!(matches!(
        ledger.reserve(ISS, "full", 1),
        Err(ChargeError::Refused(Refusal::Exhausted {
            remaining: 0,
            ..
        }))
    ));
}

#[test]
fn failed_call_records_what_it_metered_and_a_replay_does_not_meter_again() {
    let mut ledger = Ledger::new();
    ledger.open(account("t", 100, "ada")).unwrap();
    let hold = ledger.reserve(ISS, "t", 50).unwrap();
    ledger.commit(&hold, 0, 10).unwrap();
    assert_eq!(ledger.committed(ISS, "t"), Some(0));
    assert_eq!(
        ledger.person_total(
            "https://ps.example",
            "ada",
            "https://resource.example",
            "USD"
        ),
        0
    );
    let hold = ledger.reserve(ISS, "t", 50).unwrap();
    ledger.commit(&hold, 12, 11).unwrap();
    assert_eq!(ledger.committed(ISS, "t"), Some(12));
    assert_eq!(
        ledger.person_total(
            "https://ps.example",
            "ada",
            "https://resource.example",
            "USD"
        ),
        12
    );
    let stream = ledger.reserve(ISS, "t", 20).unwrap();
    let preview = ledger.stream_header(&stream).unwrap();
    assert!(preview.contains("reserved=20"));
    assert!(!preview.contains("cost="));
    ledger.commit(&stream, 5, 12).unwrap();
    let before = ledger.held_refusal(ISS, "t", None).unwrap();
    assert_eq!(ledger.committed(ISS, "t"), Some(17));
    assert!(before.contains("remaining="));
    let first = ledger
        .complete_held("pending", ISS, "t", 10, 4, 13)
        .unwrap();
    assert!(first.contains("cost=4"));
    let committed = ledger.committed(ISS, "t").unwrap();
    let again = ledger
        .complete_held("pending", ISS, "t", 10, 4, 14)
        .unwrap();
    assert!(again.contains("cost=4"));
    assert_eq!(ledger.committed(ISS, "t"), Some(committed));
    assert!(
        ledger
            .complete_held("other", ISS, "t", 1_000, 1, 15)
            .is_err()
    );
    assert_eq!(ledger.committed(ISS, "t"), Some(committed));
}

#[test]
fn concurrent_reserves_cannot_both_spend_the_last_unit() {
    let ledger = Arc::new(Mutex::new(Ledger::new()));
    ledger
        .lock()
        .unwrap()
        .open(account("t", 10, "ada"))
        .unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let ledger = Arc::clone(&ledger);
        handles.push(thread::spawn(move || {
            let mut guard = ledger.lock().unwrap();
            guard.reserve(ISS, "t", 4).is_ok()
        }));
    }
    let mut wins = 0;
    for handle in handles {
        if handle.join().unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 2);
    let state = ledger.lock().unwrap();
    let (committed, reserved) = state.outstanding(ISS, "t").unwrap();
    assert_eq!(committed + reserved, 8);
    assert!(committed + reserved <= 10);
}

#[test]
fn usage_counters_follow_utc_calendars_and_omit_unknown_keys() {
    let mut ledger = Ledger::new();
    let mut ada = account("day", 100, "ada");
    ada.jkt = "known".into();
    ledger.open(ada).unwrap();
    let hold = ledger.reserve(ISS, "day", 1).unwrap();
    ledger.commit(&hold, 1, 1_792_886_400 + 3_600).unwrap();
    let mut week = account("week", 100, "ada");
    week.jkt = "known".into();
    ledger.open(week).unwrap();
    let hold = ledger.reserve(ISS, "week", 2).unwrap();
    ledger.commit(&hold, 2, 1_792_368_000).unwrap();
    let mut month = account("month", 100, "ada");
    month.jkt = "old".into();
    ledger.open(month).unwrap();
    let hold = ledger.reserve(ISS, "month", 4).unwrap();
    ledger.commit(&hold, 4, 1_792_281_600).unwrap();
    let mut year = account("year", 100, "bea");
    year.jkt = "old".into();
    ledger.open(year).unwrap();
    let hold = ledger.reserve(ISS, "year", 8).unwrap();
    ledger.commit(&hold, 8, 1_754_611_200).unwrap();
    let mut quiet_key = account("quiet", 10, "ada");
    quiet_key.jkt = "zero".into();
    ledger.open(quiet_key).unwrap();
    let mut retained = ledger.clone();
    ledger.prune_keys(1_792_886_400 + 7_200, 86_400);
    retained.prune_keys(1_792_886_400 + 7_200, 86_400 * 40);
    let caller = Caller {
        id: "https://as.example".into(),
        role: KeyRole::AccessServer,
        ps: Some("https://ps.example".into()),
    };
    let query = parse_usage_query(
        &json!({"sub": "ada", "ps": "https://ps.example", "jkts": ["known", "missing", "old", "zero"]}),
        KeyRole::AccessServer,
    )
    .unwrap();
    let body = answer_usage(&ledger, &caller, &query, 1_792_886_400 + 7_200, &usd(0));
    let usage = body.usage.unwrap();
    assert_eq!(usage.all_time, 7);
    assert_eq!(usage.day, Some(1));
    assert_eq!(usage.week, Some(3));
    assert_eq!(usage.month, Some(7));
    assert_eq!(usage.year, Some(7));
    let keys = body.jkts.unwrap();
    assert_eq!(keys.get("known"), Some(&3));
    assert_eq!(keys.get("zero"), Some(&0));
    assert!(!keys.contains_key("missing"));
    assert!(!keys.contains_key("old"));
    let kept = answer_usage(&retained, &caller, &query, 1_792_886_400 + 7_200, &usd(0))
        .jkts
        .unwrap();
    assert!(kept.contains_key("old"));
    assert_eq!(ledger.as_of(1_792_886_400 + 9_000), 1_792_886_400 + 9_000);
    let _parked = ledger.reserve(ISS, "day", 1).unwrap();
    assert_eq!(ledger.as_of(1_792_886_400 + 9_000), 1_792_886_400 + 3_600);
    let quiet = parse_usage_query(
        &json!({"sub": "nobody", "ps": "https://ps.example"}),
        KeyRole::AccessServer,
    )
    .unwrap();
    assert!(
        answer_usage(&ledger, &caller, &quiet, 1_792_886_400, &usd(0))
            .usage
            .is_none()
    );
    assert!(
        parse_usage_query(&json!({"sub": "ada", "tenant": "t"}), KeyRole::PersonServer).is_err()
    );
    assert!(parse_usage_query(&json!({"sub": "ada"}), KeyRole::AccessServer).is_err());
    assert!(parse_usage_query(&json!({}), KeyRole::PersonServer).is_err());
    assert!(
        parse_usage_query(
            &json!({"ps": "https://ps.example", "sub": "ada"}),
            KeyRole::PersonServer
        )
        .is_err()
    );
    let both = parse_usage_query(
        &json!({"sub": "ada", "ps": "https://ps.example", "jkts": ["known"]}),
        KeyRole::AccessServer,
    )
    .unwrap();
    assert_eq!(both.sub.as_deref(), Some("ada"));
    assert_eq!(both.jkts.unwrap(), vec!["known".to_owned()]);
}

#[test]
fn signed_usage_covers_the_response_components_and_an_unsigned_body_still_parses() {
    let key = SigningKey::from_seed([9; 32]);
    let body = br#"{"as_of":1,"aud":"https://ps.example","unit":"USD","decimals":6}"#;
    let signed = sign_usage_response(
        &key,
        "https://resource.example",
        "resource",
        "resource.example",
        "/usage",
        body,
        1000,
    )
    .unwrap();
    assert!(usage_signature_covers(&signed.signature_input));
    assert!(signed.signature_key.contains("dwk=\"aauth-resource.json\""));
    assert!(
        signed
            .signature_key
            .contains("id=\"https://resource.example\"")
    );
    verify_usage_signature(
        &signed,
        &key.public_jwk(),
        "resource.example",
        "/usage",
        1000,
    )
    .unwrap();
    assert!(
        verify_usage_signature(&signed, &key.public_jwk(), "other.example", "/usage", 1000)
            .is_err()
    );
    let unsigned = parse_usage_query(&json!({"jkts": ["abc"]}), KeyRole::PersonServer).unwrap();
    assert_eq!(unsigned.jkts.unwrap(), vec!["abc".to_owned()]);
}

trait PairProbe {
    fn build_pair_rejected() -> bool;
}
impl PairProbe for BudgetHeader {
    fn build_pair_rejected() -> bool {
        BudgetHeader::final_cost(1, 1, "USD", 6).is_ok()
            && matches!(
                sender_field(&BudgetHeader::refusal(1, None, "USD", 6).unwrap(), true),
                Err(Error::Malformed)
            )
            && BudgetHeader::final_cost(1, 1, "", 6).is_err()
    }
}

#[test]
fn the_same_jti_from_two_issuers_keeps_separate_grants() {
    let mut ledger = Ledger::new();
    let other = "https://other.example";
    let mut foreign = account("same", 80, "ada");
    foreign.iss = other.into();
    ledger.open(account("same", 100, "ada")).unwrap();
    ledger.open(foreign).unwrap();
    let hold = ledger.reserve(ISS, "same", 40).unwrap();
    ledger.commit(&hold, 40, 1).unwrap();
    let hold = ledger.reserve(other, "same", 70).unwrap();
    ledger.commit(&hold, 70, 1).unwrap();
    assert_eq!(ledger.committed(ISS, "same"), Some(40));
    assert_eq!(ledger.committed(other, "same"), Some(70));
    assert_eq!(ledger.outstanding(ISS, "same"), Some((40, 0)));
    assert_eq!(ledger.outstanding(other, "same"), Some((70, 0)));
    assert!(matches!(
        ledger.open(account("same", 50, "ada")),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        ledger.open(account("same", 100, "bob")),
        Err(Error::Malformed)
    ));
}

#[test]
fn concurrent_commits_add_once_per_winner_and_a_different_audience_stays_at_zero() {
    let ledger = Arc::new(Mutex::new(Ledger::new()));
    ledger
        .lock()
        .unwrap()
        .open(account("race", 10, "ada"))
        .unwrap();
    let mut other = account("elsewhere", 10, "ada");
    other.aud = "https://other.example".into();
    ledger.lock().unwrap().open(other).unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let ledger = Arc::clone(&ledger);
        handles.push(thread::spawn(move || {
            let mut guard = ledger.lock().unwrap();
            let Ok(hold) = guard.reserve(ISS, "race", 1) else {
                return false;
            };
            guard.commit(&hold, 1, 1).is_ok()
        }));
    }
    let mut wins = 0;
    for handle in handles {
        if handle.join().unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 8);
    let state = ledger.lock().unwrap();
    assert_eq!(
        state.person_total(
            "https://ps.example",
            "ada",
            "https://resource.example",
            "USD"
        ),
        wins
    );
    assert_eq!(
        state.person_total("https://ps.example", "ada", "https://other.example", "USD"),
        0
    );
}
