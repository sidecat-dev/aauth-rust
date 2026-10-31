//! Code checks for the R3 token wrappers, ported from Go
//! `token_r3_external_test.go`. These exercise the library API only.

use std::collections::BTreeMap;
use std::sync::Mutex;

use aauth_rust_budgets::{Budget, ConsumptionRecord};
use aauth_rust_core::{
    AgentKeyResolver, AuthClaims, Confirmation, ResourceClaims, ResourceToken, TokenError,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey, strict_json};
use serde_json::{Map, Value, json};

use crate::jsonvalue::{Json, parse_json};
use crate::{
    AnnotationEncoding, Authorization, Codec, Error, GrantedOperations, IssuanceError,
    IssuanceRecord, IssuanceStore, McpCodec, Operation, OperationAccess, Parameter, Parameters,
    Proposal, ProposalOptions, R3TokenError, Reference, Registry, Vocabulary, VocabularyUri,
    digest, mint_auth_token, mint_budget_auth_token, mint_budget_per_call_auth_token,
    mint_budget_proposal_resource_token, mint_budget_resource_token, mint_direct_auth_token,
    mint_per_call_auth_token, mint_proposal_resource_token, mint_resource_token, standard_registry,
    verify_auth_token_claims, verify_budget_auth_token, verify_budget_per_call_auth_token,
    verify_budget_resource_token, verify_direct_auth_token, verify_per_call_auth_token,
    verify_resource_token,
};

type Checked = Result<(), Box<dyn std::error::Error>>;

const NOW: i64 = 1_788_120_000;
const RESOURCE: &str = "https://resource.example";
const ACCESS: &str = "https://access.example";
const PERSON: &str = "https://person.example";
const RESOURCE_KID: &str = "resource-key";
const ACCESS_KID: &str = "access-key";
const DOCUMENT_URI: &str = "https://resource.example/r3/class-one";
const MCP: &str = "urn:aauth:vocabulary:mcp";
const CLASS: &[u8] = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"},{"tool":"records.delete"}]}"#;
const READ: &str =
    r#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}"#;
const DELETE: &str =
    r#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"}]}"#;

struct Keys(Vec<(&'static str, &'static str, &'static str, Jwk)>);

impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        self.0
            .iter()
            .find(|(i, d, k, _)| *i == issuer && *d == dwk && *k == kid)
            .map(|(.., jwk)| jwk.clone())
            .ok_or(TokenError::UnknownKey)
    }
}

struct Fixture {
    registry: Registry,
    resource_key: SigningKey,
    access_key: SigningKey,
    request_key: SigningKey,
    keys: Keys,
}

fn fixture() -> Fixture {
    let resource_key = SigningKey::from_seed([1; 32]);
    let access_key = SigningKey::from_seed([2; 32]);
    let request_key = SigningKey::from_seed([3; 32]);
    let keys = Keys(vec![
        (
            RESOURCE,
            "aauth-resource.json",
            RESOURCE_KID,
            resource_key.public_jwk(),
        ),
        (
            ACCESS,
            "aauth-access.json",
            ACCESS_KID,
            access_key.public_jwk(),
        ),
    ]);
    Fixture {
        registry: standard_registry().expect("standard registry"),
        resource_key,
        access_key,
        request_key,
        keys,
    }
}

fn resource_claims() -> ResourceClaims {
    ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: ACCESS.into(),
        sub: "person-1".into(),
        jti: "resource-token-1".into(),
        iat: NOW,
        exp: NOW + 300,
        ps: PERSON.into(),
        presented_jti: "person-token-1".into(),
        agent_jkt: digest(b"agent-key"),
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: None,
        account: None,
        login_hint: None,
        extra: BTreeMap::new(),
    }
}

fn auth_claims(request_key: &SigningKey) -> AuthClaims {
    AuthClaims {
        iss: ACCESS.into(),
        dwk: "aauth-access.json".into(),
        aud: RESOURCE.into(),
        sub: "person-1".into(),
        jti: "auth-token-1".into(),
        iat: NOW,
        exp: NOW + 3600,
        ps: PERSON.into(),
        cnf: Confirmation {
            jwk: request_key.public_jwk(),
        },
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: None,
        account: None,
        extra: BTreeMap::new(),
    }
}

fn payload(compact: &str) -> Map<String, Value> {
    let jws = Jws::parse(compact).expect("compact");
    match strict_json(jws.payload()).expect("payload") {
        Value::Object(members) => members,
        _ => panic!("payload is not an object"),
    }
}

fn sign(key: &SigningKey, kid: &str, typ: &str, members: &Value) -> String {
    let body = serde_json::to_vec(members).expect("payload");
    Jws::sign(
        &json!({"alg": "Ed25519", "typ": typ, "kid": kid}),
        &body,
        key,
    )
    .expect("sign")
}

fn with(base: &Value, members: &[(&str, Value)]) -> Value {
    let mut value = base.clone();
    for (name, member) in members {
        value[*name] = member.clone();
    }
    value
}

fn claim(text: &str) -> Value {
    serde_json::from_str(text).expect("claim JSON")
}

fn tool(name: &str) -> Operation {
    let vocabulary = McpCodec::vocabulary().expect("mcp");
    Operation::new(&vocabulary, format!(r#"{{"tool":"{name}"}}"#).as_bytes()).expect("tool")
}

fn granted(names: &[&str]) -> GrantedOperations {
    let vocabulary = McpCodec::vocabulary().expect("mcp");
    let operations: Vec<_> = names.iter().map(|name| tool(name)).collect();
    GrantedOperations::new(&vocabulary, &operations).expect("granted")
}

fn reference(uri: &str, exact: &[u8]) -> Reference {
    Reference::new(uri, digest(exact)).expect("reference")
}

#[test]
fn token_resource_round_trip_is_scope_optional_and_consumes_r3_members() -> Checked {
    let f = fixture();
    let mut claims = resource_claims();
    claims
        .extra
        .insert("r3_future".into(), json!({"retained": true}));
    let (compact, minted) = mint_resource_token(
        &f.registry,
        &f.resource_key,
        RESOURCE_KID,
        &claims,
        DOCUMENT_URI,
        CLASS,
    )?;
    assert_eq!(minted, reference(DOCUMENT_URI, CLASS));
    assert!(!payload(&compact).contains_key("scope"));

    let verified = verify_resource_token(&compact, &f.keys, NOW)?;
    assert_eq!(verified.reference(), &minted);
    assert_eq!(verified.compact(), compact);
    assert!(!verified.claims().extra.contains_key("r3_uri"));
    assert!(!verified.claims().extra.contains_key("r3_s256"));
    assert_eq!(
        verified.claims().extra.get("r3_future"),
        Some(&json!({"retained": true}))
    );
    let document = f
        .registry
        .parse_referenced_document(verified.reference(), CLASS)?;
    crate::validate_document_account(&document, verified.claims().account.as_deref())?;

    // Rust Core keeps unknown members in `extra` and confers no authority from
    // them; Go Core's plain verifier refuses them instead. Only the R3
    // wrappers interpret these members.
    let core = ResourceToken::parse(&compact)?.verify(&f.keys, NOW)?;
    assert!(core.claims().extra.contains_key("r3_uri"));

    assert!(verify_resource_token(&compact, &f.keys, NOW + 300).is_err());
    Ok(())
}

#[test]
fn token_resource_verification_refuses_partial_mixed_and_variant_members() -> Checked {
    let f = fixture();
    let base = serde_json::to_value(resource_claims())?;
    let uri = json!("https://resource.example/r3/one");
    let s256 = json!(digest(b"exact document bytes"));
    let cases: Vec<(&str, Vec<(&str, Value)>)> = vec![
        ("missing digest", vec![("r3_uri", uri.clone())]),
        ("missing URI", vec![("r3_s256", s256.clone())]),
        (
            "http URI",
            vec![
                ("r3_uri", json!("http://resource.example/r3/one")),
                ("r3_s256", s256.clone()),
            ],
        ),
        (
            "short digest",
            vec![("r3_uri", uri.clone()), ("r3_s256", json!("short"))],
        ),
        (
            "numeric URI",
            vec![("r3_uri", json!(7)), ("r3_s256", s256.clone())],
        ),
        (
            "present empty scope",
            vec![
                ("r3_uri", uri.clone()),
                ("r3_s256", s256.clone()),
                ("scope", json!("")),
            ],
        ),
        (
            "grant belongs in an auth token",
            vec![
                ("r3_uri", uri.clone()),
                ("r3_s256", s256.clone()),
                ("r3_granted", claim(READ)),
            ],
        ),
        (
            "per call in a resource token",
            vec![
                ("r3_uri", uri.clone()),
                ("r3_s256", s256.clone()),
                ("r3_per_call", claim(READ)),
            ],
        ),
        (
            "mixed Budget",
            vec![
                ("r3_uri", uri.clone()),
                ("r3_s256", s256.clone()),
                ("budget", json!({"amount": 1, "unit": "USD", "decimals": 2})),
            ],
        ),
        (
            "Budget case variant",
            vec![
                ("r3_uri", uri.clone()),
                ("r3_s256", s256.clone()),
                ("Budget", json!({"amount": 1})),
            ],
        ),
        (
            "long-s fold of budget_consumed",
            vec![
                ("r3_uri", uri.clone()),
                ("r3_s256", s256.clone()),
                ("budget_con\u{17f}umed", json!({})),
            ],
        ),
        (
            "removed r3_conditional",
            vec![
                ("r3_uri", uri.clone()),
                ("r3_s256", s256.clone()),
                ("r3_conditional", json!({})),
            ],
        ),
        (
            "URI case variant",
            vec![
                ("r3_uri", uri.clone()),
                ("R3_URI", uri.clone()),
                ("r3_s256", s256.clone()),
            ],
        ),
    ];
    for (name, members) in cases {
        let compact = sign(
            &f.resource_key,
            RESOURCE_KID,
            "aa-resource+jwt",
            &with(&base, &members),
        );
        assert!(
            verify_resource_token(&compact, &f.keys, NOW).is_err(),
            "accepted {name}"
        );
    }
    let mixed = sign(
        &f.resource_key,
        RESOURCE_KID,
        "aa-resource+jwt",
        &with(
            &base,
            &[
                ("r3_uri", uri),
                ("r3_s256", s256),
                ("budget", json!({"amount": 1})),
            ],
        ),
    );
    match verify_resource_token(&mixed, &f.keys, NOW) {
        Err(R3TokenError::UnsupportedClaim { claim, .. }) => assert_eq!(claim, "budget"),
        other => panic!("mixed Budget token: {other:?}"),
    }
    Ok(())
}

#[test]
fn token_minters_refuse_unproven_mismatched_or_colliding_inputs() -> Checked {
    let f = fixture();
    let document = f.registry.parse_document(CLASS)?;
    let grant = f.registry.parse_grant(READ.as_bytes(), &document)?;
    let class = reference(DOCUMENT_URI, CLASS);
    let base = auth_claims(&f.request_key);

    let scopeless = mint_direct_auth_token(
        &f.registry,
        &f.access_key,
        ACCESS_KID,
        &base,
        &class,
        CLASS,
        &grant,
    )?;
    let members = payload(&scopeless);
    assert!(!members.contains_key("scope"));
    assert!(!members.contains_key("r3_per_call"));

    let mint = |claims: &AuthClaims, reference: &Reference, exact: &[u8], grant: &crate::Grant| {
        mint_direct_auth_token(
            &f.registry,
            &f.access_key,
            ACCESS_KID,
            claims,
            reference,
            exact,
            grant,
        )
    };
    assert!(mint(&base, &Reference::default(), CLASS, &grant).is_err());
    assert!(mint(&base, &class, CLASS, &crate::Grant::default()).is_err());
    let other_bytes =
        br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"other"}]}"#;
    assert!(mint(&base, &class, other_bytes, &grant).is_err());
    let other = reference("https://resource.example/r3/other", other_bytes);
    assert!(mint(&base, &other, other_bytes, &grant).is_err());
    for name in [
        "r3_uri",
        "R3_S256",
        "r3_\u{17f}256",
        "r3_granted",
        "r3_per_call",
        "budget",
        "budget_consumed",
        "r3_conditional",
    ] {
        let mut claims = base.clone();
        claims.extra.insert(name.into(), json!(true));
        assert!(
            mint(&claims, &class, CLASS, &grant).is_err(),
            "auth accepted {name}"
        );
        let mut resource = resource_claims();
        resource.extra.insert(name.into(), json!(true));
        assert!(
            mint_resource_token(
                &f.registry,
                &f.resource_key,
                RESOURCE_KID,
                &resource,
                DOCUMENT_URI,
                CLASS
            )
            .is_err(),
            "resource accepted {name}"
        );
    }
    let resource = resource_claims();
    for (uri, exact) in [
        ("", CLASS),
        ("https://resource.example/r3/one#part", CLASS),
        (DOCUMENT_URI, b"{}".as_slice()),
    ] {
        assert!(
            mint_resource_token(
                &f.registry,
                &f.resource_key,
                RESOURCE_KID,
                &resource,
                uri,
                exact
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn token_minters_bind_the_document_account_exactly() -> Checked {
    let f = fixture();
    let work = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}],"account":"work"}"#;
    let document = f.registry.parse_document(work)?;
    let grant = f.registry.parse_grant(READ.as_bytes(), &document)?;
    let pinned = reference(DOCUMENT_URI, work);
    for (account, accepted) in [
        (Some("work"), true),
        (None, false),
        (Some("other"), false),
        (Some(""), false),
    ] {
        let mut resource = resource_claims();
        resource.account = account.map(str::to_owned);
        let minted = mint_resource_token(
            &f.registry,
            &f.resource_key,
            RESOURCE_KID,
            &resource,
            DOCUMENT_URI,
            work,
        );
        assert_eq!(minted.is_ok(), accepted, "resource account {account:?}");
        let mut auth = auth_claims(&f.request_key);
        auth.account = account.map(str::to_owned);
        let minted = mint_direct_auth_token(
            &f.registry,
            &f.access_key,
            ACCESS_KID,
            &auth,
            &pinned,
            work,
            &grant,
        );
        assert_eq!(minted.is_ok(), accepted, "auth account {account:?}");
    }
    let mut empty = resource_claims();
    empty.account = Some(String::new());
    assert!(
        mint_resource_token(
            &f.registry,
            &f.resource_key,
            RESOURCE_KID,
            &empty,
            DOCUMENT_URI,
            CLASS
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn token_class_authorization_splits_direct_and_per_call_operations() -> Checked {
    let f = fixture();
    let document = f.registry.parse_document(CLASS)?;
    let class = reference(DOCUMENT_URI, CLASS);
    let authorization = Authorization::new(
        &granted(&["records.read"]),
        &granted(&["records.delete"]),
        &document,
    )?;
    let compact = mint_auth_token(
        &f.registry,
        &f.access_key,
        ACCESS_KID,
        &auth_claims(&f.request_key),
        &class,
        CLASS,
        &authorization,
    )?;
    let members = payload(&compact);
    assert_eq!(members.get("r3_granted"), Some(&claim(READ)));
    assert_eq!(members.get("r3_per_call"), Some(&claim(DELETE)));

    let verified = verify_auth_token_claims(&f.registry, &compact, &f.keys, NOW)?;
    assert_eq!(verified.reference(), &class);
    assert!(verified.operations().per_call_claim_present());
    let operations = verified.operations();
    assert_eq!(
        operations.access_for(&tool("records.read"))?,
        OperationAccess::Granted
    );
    assert_eq!(
        operations.access_for(&tool("records.delete"))?,
        OperationAccess::PerCall
    );
    assert_eq!(
        operations.access_for(&tool("records.export"))?,
        OperationAccess::Denied
    );
    for name in ["r3_uri", "r3_s256", "r3_granted", "r3_per_call"] {
        assert!(!verified.claims().extra.contains_key(name), "{name}");
    }
    let proven = verified.prove_against_document(&f.registry, &class, CLASS)?;
    assert!(proven.is_proven());
    let moved = reference("https://resource.example/r3/class-two", CLASS);
    assert!(
        verified
            .prove_against_document(&f.registry, &moved, CLASS)
            .is_err()
    );
    assert!(verify_direct_auth_token(&f.registry, &compact, &f.keys, NOW).is_err());

    assert!(
        Authorization::new(
            &granted(&["records.read"]),
            &granted(&["records.read"]),
            &document
        )
        .is_err()
    );
    let direct_only = Authorization::new(&granted(&["records.read"]), &granted(&[]), &document)?;
    let direct = mint_auth_token(
        &f.registry,
        &f.access_key,
        ACCESS_KID,
        &auth_claims(&f.request_key),
        &class,
        CLASS,
        &direct_only,
    )?;
    assert!(!payload(&direct).contains_key("r3_per_call"));
    let verified = verify_direct_auth_token(&f.registry, &direct, &f.keys, NOW)?;
    assert!(!verified.operations().per_call_claim_present());
    Ok(())
}

#[test]
fn token_per_call_binds_the_exact_proposal() -> Checked {
    let f = fixture();
    let parameters = Parameters::new([("id".to_owned(), Parameter::inline(br#""record-7""#)?)])?;
    let proposal = Proposal::new(
        &tool("records.delete"),
        &parameters,
        ProposalOptions {
            account: Some("work"),
            result: None,
            display: None,
        },
    )?;
    let exact = serde_json::to_vec(&proposal)?;
    let proposal_uri = "https://resource.example/r3/proposal-one";
    let mut resource = resource_claims();
    resource.account = Some("work".into());
    let (resource_compact, pinned) = mint_proposal_resource_token(
        &f.registry,
        &f.resource_key,
        RESOURCE_KID,
        &resource,
        proposal_uri,
        &exact,
    )?;
    assert_eq!(
        verify_resource_token(&resource_compact, &f.keys, NOW)?.reference(),
        &pinned
    );
    let members = payload(&resource_compact);
    for forbidden in ["r3_granted", "r3_per_call", "parameters"] {
        assert!(!members.contains_key(forbidden), "{forbidden}");
    }

    let mut claims = auth_claims(&f.request_key);
    claims.account = Some("work".into());
    let compact = mint_per_call_auth_token(
        &f.registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &pinned,
        &exact,
    )?;
    let members = payload(&compact);
    assert_eq!(members.get("r3_granted"), Some(&claim(DELETE)));
    assert!(!members.contains_key("r3_per_call"));
    let (verified, operation) =
        verify_per_call_auth_token(&f.registry, &compact, &f.keys, NOW, &pinned, &exact)?;
    assert!(operation.equal(&tool("records.delete"))?);
    assert_eq!(verified.reference(), &pinned);
    let general = verify_auth_token_claims(&f.registry, &compact, &f.keys, NOW)?;
    assert!(!general.operations().per_call_claim_present());

    let base = with(
        &serde_json::to_value(&claims)?,
        &[
            ("r3_uri", json!(pinned.uri())),
            ("r3_s256", json!(pinned.digest())),
            ("r3_granted", claim(DELETE)),
        ],
    );
    let other = reference("https://resource.example/r3/proposal-other", &exact);
    for (name, members) in [
        (
            "different operation",
            with(&base, &[("r3_granted", claim(READ))]),
        ),
        (
            "different account",
            with(&base, &[("account", json!("other"))]),
        ),
        ("missing account", {
            let mut value = base.clone();
            value.as_object_mut().expect("object").remove("account");
            value
        }),
        (
            "different reference",
            with(&base, &[("r3_uri", json!(other.uri()))]),
        ),
        (
            "two operations",
            with(
                &base,
                &[(
                    "r3_granted",
                    claim(
                        r#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"},{"tool":"records.read"}]}"#,
                    ),
                )],
            ),
        ),
        (
            "carries r3_per_call",
            with(
                &base,
                &[(
                    "r3_per_call",
                    claim(r#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}"#),
                )],
            ),
        ),
    ] {
        let manual = sign(&f.access_key, ACCESS_KID, "aa-auth+jwt", &members);
        assert!(
            verify_per_call_auth_token(&f.registry, &manual, &f.keys, NOW, &pinned, &exact)
                .is_err(),
            "accepted {name}"
        );
    }

    let mut changed = exact.clone();
    changed.push(b'\n');
    f.registry.parse_proposal(&changed)?;
    assert!(
        mint_per_call_auth_token(
            &f.registry,
            &f.access_key,
            ACCESS_KID,
            &claims,
            &pinned,
            &changed
        )
        .is_err()
    );
    let mut wrong_account = claims.clone();
    wrong_account.account = Some("other".into());
    assert!(
        mint_per_call_auth_token(
            &f.registry,
            &f.access_key,
            ACCESS_KID,
            &wrong_account,
            &pinned,
            &exact
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn token_auth_claims_refuse_partial_mixed_and_malformed_shapes() -> Checked {
    let f = fixture();
    let base = serde_json::to_value(auth_claims(&f.request_key))?;
    let uri = json!("https://resource.example/r3/class");
    let s256 = json!(digest(b"document"));
    let complete = with(
        &base,
        &[
            ("r3_uri", uri.clone()),
            ("r3_s256", s256.clone()),
            ("r3_granted", claim(READ)),
        ],
    );
    let strip = |name: &str| {
        let mut value = complete.clone();
        value.as_object_mut().expect("object").remove(name);
        value
    };
    let direct_refusals = [
        ("missing URI", strip("r3_uri")),
        ("missing digest", strip("r3_s256")),
        ("missing grant", strip("r3_granted")),
        (
            "present empty scope",
            with(&complete, &[("scope", json!(""))]),
        ),
        (
            "mixed Budget",
            with(&complete, &[("budget", json!({"amount": 1}))]),
        ),
        (
            "Budget case variant",
            with(&complete, &[("Budget", json!({"amount": 1}))]),
        ),
        (
            "grant case variant",
            with(&complete, &[("R3_GRANTED", claim(READ))]),
        ),
        (
            "grant not an envelope",
            with(&complete, &[("r3_granted", json!(true))]),
        ),
        (
            "per call present",
            with(&complete, &[("r3_per_call", claim(DELETE))]),
        ),
        (
            "removed r3_conditional",
            with(&complete, &[("r3_conditional", json!({}))]),
        ),
    ];
    for (name, members) in direct_refusals {
        let compact = sign(&f.access_key, ACCESS_KID, "aa-auth+jwt", &members);
        assert!(
            verify_direct_auth_token(&f.registry, &compact, &f.keys, NOW).is_err(),
            "direct accepted {name}"
        );
    }

    let per_call_refusals = [
        ("overlap", "r3_per_call", claim(READ)),
        (
            "wrong vocabulary",
            "r3_per_call",
            claim(r#"{"vocabulary":"urn:example:other","operations":[{"tool":"records.delete"}]}"#),
        ),
        (
            "missing operations",
            "r3_per_call",
            claim(r#"{"vocabulary":"urn:aauth:vocabulary:mcp"}"#),
        ),
        (
            "duplicate tool",
            "r3_per_call",
            claim(
                r#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"},{"tool":"records.delete"}]}"#,
            ),
        ),
        ("non-object", "r3_per_call", json!(true)),
        ("case variant", "R3_Per_Call", claim(DELETE)),
    ];
    for (name, member, value) in per_call_refusals {
        let compact = sign(
            &f.access_key,
            ACCESS_KID,
            "aa-auth+jwt",
            &with(&complete, &[(member, value)]),
        );
        assert!(
            verify_auth_token_claims(&f.registry, &compact, &f.keys, NOW).is_err(),
            "claims accepted {name}"
        );
    }

    let empty_grant = with(
        &complete,
        &[
            (
                "r3_granted",
                claim(r#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}"#),
            ),
            ("r3_future", json!({"retained": true})),
        ],
    );
    let compact = sign(&f.access_key, ACCESS_KID, "aa-auth+jwt", &empty_grant);
    let verified = verify_direct_auth_token(&f.registry, &compact, &f.keys, NOW)?;
    assert!(verified.claims().scope.is_none());
    assert!(
        verified
            .operations()
            .granted_operations()
            .operations()?
            .is_empty()
    );
    assert_eq!(
        verified.claims().extra.get("r3_future"),
        Some(&json!({"retained": true}))
    );
    let unregistered = sign(
        &f.access_key,
        ACCESS_KID,
        "aa-auth+jwt",
        &with(
            &complete,
            &[(
                "r3_granted",
                claim(r#"{"vocabulary":"urn:example:other","operations":[]}"#),
            )],
        ),
    );
    assert!(verify_auth_token_claims(&f.registry, &unregistered, &f.keys, NOW).is_err());
    assert_eq!(MCP, McpCodec::URI);
    Ok(())
}

#[test]
fn token_budget_profile_carries_both_companions_together() -> Checked {
    let f = fixture();
    let document = f.registry.parse_document(CLASS)?;
    let grant = f.registry.parse_grant(READ.as_bytes(), &document)?;
    let offer = Budget::new(500, "USD", 2)?;
    let record = ConsumptionRecord::new("person-token-1", 120)?;
    let resource = resource_claims();
    let (resource_compact, class) = mint_budget_resource_token(
        &f.registry,
        &f.resource_key,
        RESOURCE_KID,
        &resource,
        DOCUMENT_URI,
        CLASS,
        &offer,
        Some(&record),
    )?;
    let (verified, got_offer, got_record) =
        verify_budget_resource_token(&resource_compact, &f.keys, NOW)?;
    assert_eq!(verified.reference(), &class);
    assert_eq!(got_offer, offer);
    assert_eq!(got_record, Some(record));
    for name in ["r3_uri", "r3_s256", "budget", "budget_consumed"] {
        assert!(!verified.claims().extra.contains_key(name), "{name}");
    }
    assert!(verify_resource_token(&resource_compact, &f.keys, NOW).is_err());
    let foreign = ConsumptionRecord::new("another-token", 1)?;
    assert!(
        mint_budget_resource_token(
            &f.registry,
            &f.resource_key,
            RESOURCE_KID,
            &resource,
            DOCUMENT_URI,
            CLASS,
            &offer,
            Some(&foreign),
        )
        .is_err()
    );

    let claims = auth_claims(&f.request_key);
    let budget = Budget::new(300, "USD", 2)?;
    let compact = mint_budget_auth_token(
        &f.registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &class,
        CLASS,
        &grant,
        &budget,
    )?;
    let (verified, got_budget) = verify_budget_auth_token(&f.registry, &compact, &f.keys, NOW)?;
    assert_eq!(got_budget, budget);
    assert!(
        verified
            .operations()
            .granted_operations()
            .equal(&granted(&["records.read"]))?
    );
    assert!(!verified.operations().per_call_claim_present());
    assert!(!verified.claims().extra.contains_key("budget"));
    verified.prove_against_document(&f.registry, &class, CLASS)?;
    assert!(verify_direct_auth_token(&f.registry, &compact, &f.keys, NOW).is_err());

    let unrepresentable = Budget::new(1, "d\u{f6}llar", 2)?;
    assert!(
        mint_budget_auth_token(
            &f.registry,
            &f.access_key,
            ACCESS_KID,
            &claims,
            &class,
            CLASS,
            &grant,
            &unrepresentable,
        )
        .is_err()
    );
    let base = payload(&compact);
    for (name, value) in [
        ("r3_per_call", claim(DELETE)),
        ("budget_consumed", json!({"jti": "x", "consumed": 1})),
        ("Budget", json!({"amount": 1})),
    ] {
        let mut members = base.clone();
        members.insert(name.into(), value);
        let manual = sign(
            &f.access_key,
            ACCESS_KID,
            "aa-auth+jwt",
            &Value::Object(members),
        );
        assert!(
            verify_budget_auth_token(&f.registry, &manual, &f.keys, NOW).is_err(),
            "accepted {name}"
        );
    }
    Ok(())
}

#[test]
fn token_budget_profile_carries_a_per_call_grant() -> Checked {
    let f = fixture();
    let document = f.registry.parse_document(CLASS)?;
    let read = f.registry.parse_grant(READ.as_bytes(), &document)?;
    let operation = read.granted_operations().operations()?.remove(0);
    let proposal = Proposal::new(
        &operation,
        &Parameters::new(std::iter::empty())?,
        ProposalOptions::default(),
    )?;
    let exact = serde_json::to_vec(&proposal)?;
    let offer = Budget::new(40, "USD", 2)?;
    let (resource_compact, pinned) = mint_budget_proposal_resource_token(
        &f.registry,
        &f.resource_key,
        RESOURCE_KID,
        &resource_claims(),
        "https://resource.example/r3/proposal-one",
        &exact,
        &offer,
    )?;
    let (verified, got_offer, consumed) =
        verify_budget_resource_token(&resource_compact, &f.keys, NOW)?;
    assert_eq!(verified.reference(), &pinned);
    assert_eq!((got_offer, consumed), (offer.clone(), None));
    assert!(verify_resource_token(&resource_compact, &f.keys, NOW).is_err());

    let claims = auth_claims(&f.request_key);
    let compact = mint_budget_per_call_auth_token(
        &f.registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &pinned,
        &exact,
        &offer,
    )?;
    let (token, granted, grant) =
        verify_budget_per_call_auth_token(&f.registry, &compact, &f.keys, NOW, &pinned, &exact)?;
    assert_eq!(grant, offer);
    assert!(granted.equal(&operation)?);
    assert!(!token.claims().extra.contains_key("budget"));
    // The plain per-call profile refuses the budget; the budget profile
    // refuses another proposal and a grant without a budget.
    assert!(
        verify_per_call_auth_token(&f.registry, &compact, &f.keys, NOW, &pinned, &exact).is_err()
    );
    let other = Reference::new("https://resource.example/r3/proposal-two", digest(&exact))?;
    assert!(
        verify_budget_per_call_auth_token(&f.registry, &compact, &f.keys, NOW, &other, &exact)
            .is_err()
    );
    let plain = mint_per_call_auth_token(
        &f.registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &pinned,
        &exact,
    )?;
    assert!(
        verify_budget_per_call_auth_token(&f.registry, &plain, &f.keys, NOW, &pinned, &exact)
            .is_err()
    );
    Ok(())
}

/// Example store honoring the [`IssuanceStore`] contract.
#[derive(Default)]
struct MemoryIssuance(Mutex<BTreeMap<(String, String), IssuanceRecord>>);

impl IssuanceStore for MemoryIssuance {
    fn commit(&self, record: &IssuanceRecord) -> Result<(), IssuanceError> {
        let mut records = self
            .0
            .lock()
            .map_err(|_| IssuanceError::Store("issuance lock poisoned".into()))?;
        let key = (
            record.auth_token_issuer.clone(),
            record.auth_token_jti.clone(),
        );
        match records.get(&key) {
            Some(existing) if existing == record => Ok(()),
            Some(_) => Err(IssuanceError::Conflict),
            None => {
                records.insert(key, record.clone());
                Ok(())
            }
        }
    }
}

#[test]
fn token_issuance_record_is_built_from_verified_tokens() -> Checked {
    let f = fixture();
    let (resource_compact, _) = mint_resource_token(
        &f.registry,
        &f.resource_key,
        RESOURCE_KID,
        &resource_claims(),
        DOCUMENT_URI,
        CLASS,
    )?;
    let resource = verify_resource_token(&resource_compact, &f.keys, NOW)?;
    let document = f
        .registry
        .parse_referenced_document(resource.reference(), CLASS)?;
    let rc = resource.claims();
    let record = IssuanceRecord {
        auth_token_issuer: ACCESS.into(),
        auth_token_jti: "auth-token-1".into(),
        resource: rc.iss.clone(),
        r3_reference: resource.reference().clone(),
        vocabulary: document.operation_set().vocabulary().clone(),
        issued_at: NOW,
        person_server: rc.ps.clone(),
        subject: rc.sub.clone(),
        account: rc.account.clone(),
        presented_jti: rc.presented_jti.clone(),
        agent_jkt: rc.agent_jkt.clone(),
        agent: "aauth:agent@agents.example".into(),
        parent_agent: None,
    };
    let store = MemoryIssuance::default();
    store.commit(&record)?;
    store.commit(&record.clone())?;
    let mut changed = record.clone();
    changed.account = Some(String::new());
    assert!(matches!(
        store.commit(&changed),
        Err(IssuanceError::Conflict)
    ));
    Ok(())
}

const NUMERIC: &str = "https://example.test/vocabulary/numeric";

/// A custom vocabulary whose operation identity is the exact numeric literal of
/// `level`: `1.0000000000000001`, `1.0`, and `1` are three different operations.
struct NumericCodec;

fn numeric_level(raw: &[u8]) -> Result<String, Error> {
    let Json::Object(members) = parse_json(raw)? else {
        return Err(Error::new("numeric operation must be an object"));
    };
    match members.as_slice() {
        [(name, Json::Number(literal))] if name == "level" => Ok(literal.clone()),
        _ => Err(Error::new(
            "numeric operation must be {\"level\": <number>}",
        )),
    }
}

impl Codec for NumericCodec {
    type Set = Vec<String>;

    fn uri(&self) -> VocabularyUri {
        VocabularyUri::parse(NUMERIC).expect("numeric vocabulary URI")
    }

    fn annotation_encoding(&self) -> AnnotationEncoding {
        AnnotationEncoding::UNAVAILABLE
    }

    fn validate_discovery_endpoint(&self, _endpoint: &str) -> Result<(), Error> {
        Ok(())
    }

    fn parse_set(&self, raw: &[Vec<u8>]) -> Result<Self::Set, Error> {
        let mut levels: Vec<String> = Vec::with_capacity(raw.len());
        for value in raw {
            let level = numeric_level(value)?;
            if levels.contains(&level) {
                return Err(Error::new(format!("repeated level {level}")));
            }
            levels.push(level);
        }
        Ok(levels)
    }

    fn marshal_set(&self, set: &Self::Set) -> Result<Vec<Vec<u8>>, Error> {
        Ok(set
            .iter()
            .map(|level| format!(r#"{{"level":{level}}}"#).into_bytes())
            .collect())
    }

    fn union_sets<'a>(
        &self,
        sets: impl IntoIterator<Item = &'a Self::Set>,
    ) -> Result<Self::Set, Error>
    where
        Self::Set: 'a,
    {
        let mut union: Vec<String> = Vec::new();
        for set in sets {
            for level in set {
                if !union.contains(level) {
                    union.push(level.clone());
                }
            }
        }
        Ok(union)
    }

    fn sets_equal(&self, left: &Self::Set, right: &Self::Set) -> bool {
        left.len() == right.len() && self.is_subset(left, right)
    }

    fn is_subset(&self, subset: &Self::Set, superset: &Self::Set) -> bool {
        subset.iter().all(|level| superset.contains(level))
    }

    fn is_disjoint(&self, left: &Self::Set, right: &Self::Set) -> bool {
        !left.iter().any(|level| right.contains(level))
    }
}

fn numeric_envelope(operations: &[&str]) -> String {
    format!(
        r#"{{"vocabulary":"{NUMERIC}","operations":[{}]}}"#,
        operations.join(",")
    )
}

/// Every mint path signs operation claims through Core's `serde_json::Value`
/// claim map. A literal that map would respell must be refused before signing;
/// the earlier mint signed `1.0` for a grant proven as `1.0000000000000001`.
#[test]
fn token_mints_refuse_operation_claims_core_would_respell() -> Checked {
    let f = fixture();
    let registry = Registry::new(&[Vocabulary::new(NumericCodec)?])?;
    let vocabulary = registry
        .vocabulary(&VocabularyUri::parse(NUMERIC)?)
        .expect("numeric registration");
    let lossy = r#"{"level":1.0000000000000001}"#;
    let exact = r#"{"level":1.5}"#;
    let other = r#"{"level":2}"#;
    let class_bytes = numeric_envelope(&[lossy, exact, other]);
    let class_bytes = class_bytes.as_bytes();
    let document = registry.parse_document(class_bytes)?;
    let class = reference(DOCUMENT_URI, class_bytes);
    let claims = auth_claims(&f.request_key);
    let granted_set = |operations: &[&str]| {
        registry.parse_granted_operations(numeric_envelope(operations).as_bytes())
    };
    let respelled = serde_json::to_string(&serde_json::from_str::<Value>("1.0000000000000001")?)?
        != "1.0000000000000001";
    let budget = Budget::new(300, "USD", 2)?;

    let lossy_grant = registry.parse_grant(numeric_envelope(&[lossy]).as_bytes(), &document)?;
    let lossy_proposal = serde_json::to_vec(&Proposal::new(
        &Operation::new(&vocabulary, lossy.as_bytes())?,
        &Parameters::new(Vec::<(String, Parameter)>::new())?,
        ProposalOptions::default(),
    )?)?;
    let lossy_pinned = reference(
        "https://resource.example/r3/proposal-lossy",
        &lossy_proposal,
    );
    let attempts = [
        (
            "class r3_granted",
            mint_auth_token(
                &registry,
                &f.access_key,
                ACCESS_KID,
                &claims,
                &class,
                class_bytes,
                &Authorization::new(&granted_set(&[lossy])?, &granted_set(&[other])?, &document)?,
            ),
        ),
        (
            "class r3_per_call",
            mint_auth_token(
                &registry,
                &f.access_key,
                ACCESS_KID,
                &claims,
                &class,
                class_bytes,
                &Authorization::new(&granted_set(&[exact])?, &granted_set(&[lossy])?, &document)?,
            ),
        ),
        (
            "direct",
            mint_direct_auth_token(
                &registry,
                &f.access_key,
                ACCESS_KID,
                &claims,
                &class,
                class_bytes,
                &lossy_grant,
            ),
        ),
        (
            "per-call",
            mint_per_call_auth_token(
                &registry,
                &f.access_key,
                ACCESS_KID,
                &claims,
                &lossy_pinned,
                &lossy_proposal,
            ),
        ),
        (
            "Budget",
            mint_budget_auth_token(
                &registry,
                &f.access_key,
                ACCESS_KID,
                &claims,
                &class,
                class_bytes,
                &lossy_grant,
                &budget,
            ),
        ),
    ];
    for (name, minted) in attempts {
        match minted {
            Err(err) => {
                assert!(respelled, "{name}: refused a literal Value keeps: {err}");
                assert!(
                    err.to_string().contains("cannot be signed exactly"),
                    "{name}: {err}"
                );
            }
            Ok(compact) => {
                assert!(!respelled, "{name}: signed a respelled operation claim");
                let signed = Jws::parse(&compact)?;
                assert!(
                    String::from_utf8_lossy(signed.payload()).contains("1.0000000000000001"),
                    "{name}: signed payload lost the proven literal"
                );
            }
        }
    }

    // Literals the claim map keeps exactly still mint and verify on every path.
    let compact = mint_auth_token(
        &registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &class,
        class_bytes,
        &Authorization::new(&granted_set(&[exact])?, &granted_set(&[other])?, &document)?,
    )?;
    let verified = verify_auth_token_claims(&registry, &compact, &f.keys, NOW)?;
    let operations = verified.operations();
    let level = |raw: &str| Operation::new(&vocabulary, raw.as_bytes());
    assert_eq!(
        operations.access_for(&level(exact)?)?,
        OperationAccess::Granted
    );
    assert_eq!(
        operations.access_for(&level(other)?)?,
        OperationAccess::PerCall
    );
    assert_eq!(
        operations.access_for(&level(lossy)?)?,
        OperationAccess::Denied
    );

    let exact_grant = registry.parse_grant(numeric_envelope(&[exact]).as_bytes(), &document)?;
    let direct = mint_direct_auth_token(
        &registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &class,
        class_bytes,
        &exact_grant,
    )?;
    let verified = verify_direct_auth_token(&registry, &direct, &f.keys, NOW)?;
    assert!(
        verified
            .operations()
            .granted_operations()
            .equal(&exact_grant.granted_operations())?
    );

    let proposal = serde_json::to_vec(&Proposal::new(
        &level(other)?,
        &Parameters::new(Vec::<(String, Parameter)>::new())?,
        ProposalOptions::default(),
    )?)?;
    let pinned = reference("https://resource.example/r3/proposal-two", &proposal);
    let per_call = mint_per_call_auth_token(
        &registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &pinned,
        &proposal,
    )?;
    let (_, operation) =
        verify_per_call_auth_token(&registry, &per_call, &f.keys, NOW, &pinned, &proposal)?;
    assert!(operation.equal(&level(other)?)?);

    let budgeted = mint_budget_auth_token(
        &registry,
        &f.access_key,
        ACCESS_KID,
        &claims,
        &class,
        class_bytes,
        &exact_grant,
        &budget,
    )?;
    let (verified, _) = verify_budget_auth_token(&registry, &budgeted, &f.keys, NOW)?;
    assert!(
        verified
            .operations()
            .granted_operations()
            .equal(&exact_grant.granted_operations())?
    );

    // Verification reads the signed bytes, so an exactly signed literal keeps
    // its identity even though Core's own `Value` copy rounds it.
    let core = serde_json::to_string(&claims)?;
    let raw_payload = format!(
        r#"{},"r3_uri":"{}","r3_s256":"{}","r3_granted":{}}}"#,
        &core[..core.len() - 1],
        class.uri(),
        class.digest(),
        numeric_envelope(&[lossy]),
    );
    let manual = Jws::sign(
        &json!({"alg": "Ed25519", "typ": "aa-auth+jwt", "kid": ACCESS_KID}),
        raw_payload.as_bytes(),
        &f.access_key,
    )?;
    let verified = verify_auth_token_claims(&registry, &manual, &f.keys, NOW)?;
    let operations = verified.operations();
    assert_eq!(
        operations.access_for(&level(lossy)?)?,
        OperationAccess::Granted
    );
    assert_eq!(
        operations.access_for(&level(r#"{"level":1.0}"#)?)?,
        OperationAccess::Denied
    );
    Ok(())
}
