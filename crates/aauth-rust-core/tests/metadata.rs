use aauth_rust_core::{
    AgentProviderKeys, DisplayError, MetadataDisplay, TokenError, metadata_jwks_uri,
};

const ISSUER: &str = "https://ap.example";

#[test]
fn display_urls_use_https_when_set_and_when_read() {
    let display = MetadataDisplay::new()
        .with_name("Example Agents")
        .unwrap()
        .with_description("Agents for **example** work.\nSee the docs.")
        .unwrap()
        .with_logo_uri("https://ap.example/logo.png")
        .unwrap()
        .with_logo_dark_uri("https://ap.example/logo-dark.png")
        .unwrap()
        .with_documentation_uri("https://docs.ap.example/aauth#agents")
        .unwrap()
        .with_tos_uri("https://ap.example/terms?lang=en")
        .unwrap()
        .with_policy_uri("https://ap.example/privacy")
        .unwrap();
    let names: Vec<&str> = display.members().iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "name",
            "description",
            "logo_uri",
            "logo_dark_uri",
            "documentation_uri",
            "tos_uri",
            "policy_uri"
        ]
    );

    for uri in [
        "http://ap.example/logo.png",
        "//ap.example/logo.png",
        "/logo.png",
        "https://user@ap.example/logo.png",
        "https:///logo.png",
        "https://ap.example/logo .png",
        "data:image/png;base64,AAAA",
    ] {
        assert_eq!(
            MetadataDisplay::new().with_logo_uri(uri),
            Err(DisplayError("logo_uri")),
            "{uri}"
        );
    }
    assert_eq!(
        MetadataDisplay::new().with_name(" "),
        Err(DisplayError("name"))
    );
    assert_eq!(
        MetadataDisplay::new().with_name("Line\nbreak"),
        Err(DisplayError("name"))
    );

    let published = br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/jwks","name":"Example Agents","tos_uri":"https://ap.example/terms"}"#;
    let read = MetadataDisplay::from_metadata(published).unwrap();
    assert_eq!(read.name(), Some("Example Agents"));
    assert_eq!(read.tos_uri(), Some("https://ap.example/terms"));
    assert_eq!(read.logo_uri(), None);
    assert_eq!(
        MetadataDisplay::from_metadata(
            br#"{"issuer":"https://ap.example","policy_uri":"http://ap.example/privacy"}"#
        ),
        Err(DisplayError("policy_uri"))
    );
    assert_eq!(
        MetadataDisplay::from_metadata(br#"{"issuer":"https://ap.example","logo_uri":7}"#),
        Err(DisplayError("logo_uri"))
    );
}

#[test]
fn discovery_refuses_metadata_whose_display_url_is_not_https() {
    let good = br#"{"issuer":"https://ap.example","jwks_uri":"https://ap.example/jwks","logo_uri":"https://ap.example/logo.png"}"#;
    assert_eq!(
        metadata_jwks_uri(ISSUER, good).unwrap(),
        "https://ap.example/jwks"
    );
    for member in [
        "logo_uri",
        "logo_dark_uri",
        "documentation_uri",
        "tos_uri",
        "policy_uri",
    ] {
        let metadata = format!(
            r#"{{"issuer":"https://ap.example","jwks_uri":"https://ap.example/jwks","{member}":"http://ap.example/x"}}"#
        );
        assert_eq!(
            metadata_jwks_uri(ISSUER, metadata.as_bytes()).err(),
            Some(TokenError::InvalidDiscoveryMetadata),
            "{member}"
        );
        assert_eq!(
            AgentProviderKeys::from_documents(ISSUER, metadata.as_bytes(), br#"{"keys":[]}"#).err(),
            Some(TokenError::InvalidDiscoveryMetadata),
            "{member}"
        );
    }
}
