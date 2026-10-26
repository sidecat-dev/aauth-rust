use aauth_rust_agent::{Requirement, RequirementError};
use http::{HeaderMap, HeaderValue};

fn parse(value: &str) -> Result<Requirement, RequirementError> {
    Requirement::parse(&HeaderValue::from_str(value).unwrap())
}

#[test]
fn dictionary_parsing_extracts_supported_requirements_and_ignores_extensions() {
    assert_eq!(
        parse("requirement=agent-token").unwrap(),
        Requirement::AgentToken
    );
    assert_eq!(
        parse("other=?1, requirement=person-token;future=42").unwrap(),
        Requirement::PersonToken
    );
    assert_eq!(
        parse("other=(1 2), requirement=auth-token;future=?1;resource-token=\"header.payload.signature\"").unwrap(),
        Requirement::AuthToken { resource_token: "header.payload.signature".into() }
    );
    // Extraction preserves SF string decoding; only the verifier authenticates a JWT.
    assert_eq!(
        parse(r#"requirement=auth-token;resource-token="a\"b\\c""#).unwrap(),
        Requirement::AuthToken {
            resource_token: "a\"b\\c".into()
        }
    );
}

#[test]
fn missing_or_mistyped_requirement_is_refused() {
    for value in [
        "",
        "other=agent-token",
        "requirement=\"agent-token\"",
        "requirement=(agent-token)",
        "requirement=?1",
        "requirement=agent-token garbage",
    ] {
        assert!(
            matches!(parse(value), Err(RequirementError::Malformed)),
            "{value}"
        );
    }
    assert!(matches!(
        Requirement::parse(&HeaderValue::from_bytes(&[255]).unwrap()),
        Err(RequirementError::Malformed)
    ));
}

#[test]
fn auth_challenge_needs_a_nonempty_string_parameter_on_the_member() {
    for value in [
        "requirement=auth-token",
        "requirement=auth-token;resource-token",
        "requirement=auth-token;resource-token=jwt",
        "requirement=auth-token;resource-token=\"\"",
        "requirement=auth-token, resource-token=\"wrong-member\"",
    ] {
        assert!(
            matches!(parse(value), Err(RequirementError::InvalidResourceToken)),
            "{value}"
        );
    }
}

#[test]
fn budget_reason_is_an_ignored_parameter_and_unknown_requirements_stay_unsatisfiable() {
    assert_eq!(
        parse(
            "requirement=auth-token;resource-token=\"header.payload.signature\";reason=budget-exhausted"
        ),
        Ok(Requirement::AuthToken {
            resource_token: "header.payload.signature".into()
        })
    );
    assert_eq!(
        parse(
            "requirement=auth-token;resource-token=\"header.payload.signature\";reason=insufficient-budget"
        ),
        Ok(Requirement::AuthToken {
            resource_token: "header.payload.signature".into()
        })
    );
    assert!(matches!(
        parse("requirement=budget-exhausted"),
        Err(RequirementError::Unsupported(_))
    ));
}

#[test]
fn unsupported_requirements_are_explicit_errors_never_success() {
    for value in [
        "interaction",
        "approval",
        "clarification",
        "claims",
        "future-requirement",
    ] {
        assert_eq!(
            parse(&format!("requirement={value};unknown=\"data\"")),
            Err(RequirementError::Unsupported(value.into()))
        );
    }
}

#[test]
fn header_map_combines_dictionary_lines_and_distinguishes_absence() {
    let mut headers = HeaderMap::new();
    assert_eq!(Requirement::from_headers(&headers).unwrap(), None);
    headers.append("aauth-requirement", "other=?1".parse().unwrap());
    headers.append(
        "aauth-requirement",
        "requirement=auth-token;resource-token=\"exact.jwt.bytes\""
            .parse()
            .unwrap(),
    );
    assert_eq!(
        Requirement::from_headers(&headers).unwrap(),
        Some(Requirement::AuthToken {
            resource_token: "exact.jwt.bytes".into()
        })
    );
    headers.append(
        "aauth-requirement",
        "requirement=person-token".parse().unwrap(),
    );
    assert_eq!(
        Requirement::from_headers(&headers).unwrap(),
        Some(Requirement::PersonToken)
    );
}

#[test]
fn oversized_fields_are_refused_and_debug_omits_the_compact_credential() {
    let compact = "sensitive.jwt.credential";
    let requirement = parse(&format!(
        "requirement=auth-token;resource-token=\"{compact}\""
    ))
    .unwrap();
    assert!(!format!("{requirement:?}").contains(compact));
    assert!(matches!(
        parse(&format!(
            "requirement=auth-token;resource-token=\"{}\"",
            "a".repeat(65536)
        )),
        Err(RequirementError::Malformed)
    ));
}
