use aauth_rust_core::continuation::{
    ContinuationStore, MemoryContinuations, PendingResponse, Requirement, StoreError,
    canonical_interaction_code, generate_interaction_code, generate_pending_id,
    is_emitted_interaction_code,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::Response;
use serde_json::json;
use std::collections::BTreeSet;
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
            "requirement=interaction; url=\"https://as.example/consent\"; code=\"C0DE8X42\"",
            json!({"status":"interacting"}),
            Requirement::Interaction {
                url: "https://as.example/consent".into(),
                code: "C0DE8X42".into(),
            },
        ),
        (
            "requirement=approval",
            json!({"status":"future-status"}),
            Requirement::Approval,
        ),
        (
            "requirement=auth-token; resource-token=\"eyJhbGciOiJFZDI1NTE5In0.e30.c2ln\"",
            json!({"status":"pending"}),
            Requirement::AuthToken {
                resource_token: "eyJhbGciOiJFZDI1NTE5In0.e30.c2ln".into(),
            },
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
    assert!(
        PendingResponse::parse(
            "https://as.example/token",
            &response(202, "requirement=auth-token", json!({"status":"pending"}))
        )
        .is_err()
    );
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
    for header in ["location", "cache-control", "content-type"] {
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

#[test]
fn minimal_payment_challenge_only_requires_location_and_payment_details() {
    let r = Response::builder()
        .status(402)
        .header("location", "/pending/bill")
        .header(
            "www-authenticate",
            "Payment id=\"invoice-1\", method=\"example\"",
        )
        .body(Vec::new())
        .unwrap();
    let pending = PendingResponse::parse("https://as.example/token", &r).unwrap();
    assert_eq!(pending.retry_after, 5);
    assert_eq!(pending.location, "https://as.example/pending/bill");
}
#[test]
fn absent_retry_after_uses_the_protocol_default() {
    let mut r = response(202, "requirement=approval", json!({"status":"pending"}));
    r.headers_mut().remove("retry-after");
    assert_eq!(
        PendingResponse::parse("https://as.example/token", &r)
            .unwrap()
            .retry_after,
        5
    );
}

#[test]
fn interaction_urls_reject_queries_and_fragments_when_parsed() {
    for url in [
        "https://as.example/consent?secret=1",
        "https://as.example/consent?",
        "https://as.example/consent#fragment",
    ] {
        let field = format!("requirement=interaction; url=\"{url}\"; code=\"C0DE8X42\"");
        assert!(
            PendingResponse::parse(
                "https://as.example/token",
                &response(202, &field, json!({"status":"pending"})),
            )
            .is_err(),
            "{url}"
        );
    }
}

#[test]
fn interaction_urls_reject_queries_and_fragments_when_constructed() {
    for url in [
        "https://as.example/consent?secret=1",
        "https://as.example/consent?",
        "https://as.example/consent#fragment",
    ] {
        assert!(
            PendingResponse::new(
                "https://as.example/token",
                "/pending/interaction",
                5,
                Requirement::Interaction {
                    url: url.into(),
                    code: "C0DE8X42".into(),
                },
            )
            .is_err(),
            "{url}"
        );
    }
}

#[test]
fn interaction_codes_require_eight_crockford_symbols_when_parsed_and_constructed() {
    for code in [
        "",
        "C0DE8X4",
        "C0DE-8X4",
        "--------",
        "C0DE8X4I",
        "C0DE8X4L",
        "C0DE8X4O",
        "C0DE8X4U",
        "C0DE8X4u",
        "C0DE8X4_",
        "C0DE 8X42",
        "C0DE8X42=",
    ] {
        let requirement = Requirement::Interaction {
            url: "https://as.example/consent".into(),
            code: code.into(),
        };
        let field =
            format!("requirement=interaction; url=\"https://as.example/consent\"; code=\"{code}\"");
        assert!(
            PendingResponse::parse(
                "https://as.example/token",
                &response(202, &field, json!({"status":"pending"})),
            )
            .is_err(),
            "parsed {code}"
        );
        assert!(
            PendingResponse::new(
                "https://as.example/token",
                "/pending/interaction",
                5,
                requirement,
            )
            .is_err(),
            "constructed {code}"
        );
    }
}

#[test]
fn interaction_codes_are_emitted_in_upper_case_and_parsed_in_any_case() {
    for code in ["c0de8x42", "C0de-8x42"] {
        assert!(!is_emitted_interaction_code(code), "{code}");
        let requirement = Requirement::Interaction {
            url: "https://as.example/consent".into(),
            code: code.into(),
        };
        assert!(
            PendingResponse::new(
                "https://as.example/token",
                "/pending/interaction",
                5,
                requirement.clone(),
            )
            .is_err(),
            "constructed {code}"
        );
        let field =
            format!("requirement=interaction; url=\"https://as.example/consent\"; code=\"{code}\"");
        assert_eq!(
            PendingResponse::parse(
                "https://as.example/token",
                &response(202, &field, json!({"status":"pending"})),
            )
            .unwrap()
            .requirement,
            requirement,
        );
    }
    for code in ["C0DE8X42", "C0DE-8X42", "0123456789ABCDEFGHJKMNPQRSTVWXYZ"] {
        let requirement = Requirement::Interaction {
            url: "https://as.example/consent".into(),
            code: code.into(),
        };
        let pending = PendingResponse::new(
            "https://as.example/token",
            "/pending/interaction",
            5,
            requirement.clone(),
        )
        .unwrap();
        assert_eq!(pending.requirement, requirement);
        assert_eq!(
            PendingResponse::parse("https://as.example/token", &pending.response().unwrap())
                .unwrap()
                .requirement,
            requirement,
        );
    }
}

#[test]
fn canonical_interaction_code_strips_hyphens_and_folds_aliases() {
    let folded = canonical_interaction_code("ai-b2-c3d4").unwrap();
    assert_eq!(folded, "A1B2C3D4");
    assert_eq!(
        canonical_interaction_code("ALB2C3D4").as_deref(),
        Some("A1B2C3D4")
    );
    assert_eq!(
        canonical_interaction_code("ao-b2-c3d4").as_deref(),
        Some("A0B2C3D4")
    );
    assert!(canonical_interaction_code("short").is_none());
    assert!(canonical_interaction_code("C0DE8X4U").is_none());
}

#[test]
fn generated_interaction_codes_carry_forty_random_bits() {
    const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut seen = BTreeSet::new();
    let mut symbols = vec![BTreeSet::new(); 8];
    for _ in 0..2048 {
        let code = generate_interaction_code();
        assert_eq!(code.len(), 9, "{code}");
        assert_eq!(code.as_bytes()[4], b'-', "{code}");
        assert!(is_emitted_interaction_code(&code), "{code}");
        let canonical = canonical_interaction_code(&code).unwrap();
        assert_eq!(canonical.len(), 8);
        assert_eq!(canonical, code.replace('-', ""));
        for (position, symbol) in canonical.chars().enumerate() {
            assert!(ALPHABET.contains(symbol), "{code}");
            symbols[position].insert(symbol);
        }
        assert!(seen.insert(canonical), "a 40-bit code repeated: {code}");
    }
    // Each of the eight symbols takes all 32 values, so all 40 bits vary.
    assert!(symbols.iter().all(|position| position.len() == 32));
    let pending = PendingResponse::new(
        "https://resource.example/api",
        "/pending/job",
        5,
        Requirement::Interaction {
            url: "https://resource.example/consent".into(),
            code: generate_interaction_code(),
        },
    )
    .unwrap();
    pending.response().unwrap();
}

#[test]
fn generated_pending_ids_carry_128_random_bits() {
    let mut seen = BTreeSet::new();
    let mut ones = [0_u32; 128];
    let draws = 2048;
    for _ in 0..draws {
        let id = generate_pending_id();
        assert_eq!(id.len(), 22, "{id}");
        let bytes = URL_SAFE_NO_PAD.decode(&id).unwrap();
        assert_eq!(bytes.len(), 16);
        for (bit, count) in ones.iter_mut().enumerate() {
            *count += u32::from((bytes[bit / 8] >> (bit % 8)) & 1);
        }
        let location = format!("/token/pending/{id}");
        let pending = PendingResponse::new(
            "https://as.example/token",
            &location,
            5,
            Requirement::Approval,
        )
        .unwrap();
        assert_eq!(
            pending.location,
            format!("https://as.example/token/pending/{id}")
        );
        assert!(seen.insert(id), "a 128-bit pending id repeated");
    }
    // Every bit position is set in some identifiers and clear in others.
    assert!(ones.iter().all(|count| (1..draws).contains(count)));
}
