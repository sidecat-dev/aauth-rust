use aauth_rust_core::capabilities::{Capabilities, Capability};
use aauth_rust_core::continuation::Requirement;
use http::HeaderMap;

fn declared(lines: &[&str]) -> Capabilities {
    let mut headers = HeaderMap::new();
    for line in lines {
        headers.append("aauth-capabilities", line.parse().unwrap());
    }
    Capabilities::from_headers(&headers)
}

#[test]
fn an_absent_or_unreadable_field_declares_nothing() {
    for nothing in [
        declared(&[]),
        declared(&["interaction, (payment)"]),
        declared(&["interaction, \"payment\""]),
        declared(&["interaction,,"]),
        declared(&["interaction, 7"]),
    ] {
        assert!(nothing.is_empty());
        let interaction = Requirement::Interaction {
            url: "https://resource.example/consent".into(),
            code: "ABCD-EFGH".into(),
        };
        assert!(!nothing.allows(&interaction));
        assert!(!nothing.allows(&Requirement::Payment {
            authenticate: "Payment".into()
        }));
        assert!(nothing.allows(&Requirement::Approval));
        assert_eq!(nothing.header_value(), None);
    }
}

#[test]
fn unknown_values_and_parameters_are_ignored_across_field_lines() {
    let capabilities = declared(&["interaction;version=2, telepathy", "budget;x=?1"]);
    assert_eq!(
        capabilities.iter().collect::<Vec<_>>(),
        [Capability::Interaction, Capability::Budget]
    );
    assert!(!capabilities.contains(Capability::Clarification));
    assert!(capabilities.allows(&Requirement::Interaction {
        url: "https://resource.example/consent".into(),
        code: "ABCD-EFGH".into(),
    }));
    assert!(!capabilities.allows(&Requirement::Clarification {
        question: "Why?".into(),
        timeout: None,
        options: Vec::new(),
    }));
    let agent = Capabilities::none()
        .with(Capability::Clarification)
        .union(&capabilities);
    assert_eq!(
        agent.header_value().unwrap(),
        "interaction, clarification, budget"
    );
    assert_eq!(
        declared(&[agent.header_value().unwrap().to_str().unwrap()]),
        agent
    );
    let mut headers = HeaderMap::new();
    headers.insert("aauth-capabilities", "payment".parse().unwrap());
    agent.insert_into(&mut headers);
    assert_eq!(Capabilities::from_headers(&headers), agent);
    Capabilities::none().insert_into(&mut headers);
    assert!(!headers.contains_key("aauth-capabilities"));
}
