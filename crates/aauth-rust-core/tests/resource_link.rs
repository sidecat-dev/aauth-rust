use aauth_rust_core::TokenError;
use aauth_rust_core::resource_link::{
    discovery_from_headers, fetch_targets, links_from_header, links_from_html,
    metadata_matches_link,
};

const TARGET: &str = "https://api.example/.well-known/aauth-resource.json";

#[test]
fn resource_links_are_metadata_targets_and_not_requirements() {
    let header = format!(
        r#"<{TARGET}>; rel="aauth-resource", <https://evil.example/steal>; rel="aauth-resource", <https://other.example/.well-known/aauth-resource.json>; rel="other""#
    );
    let links = links_from_header(&header);
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].target, TARGET);
    assert_eq!(links[0].issuer, "https://api.example");

    let fetched = fetch_targets([
        TARGET,
        "https://api.example/.well-known/aauth-resource.json?x=1",
        "http://api.example/.well-known/aauth-resource.json",
        "https://api.example/metadata",
        "https://api.example/extra/.well-known/aauth-resource.json",
        "/.well-known/aauth-resource.json",
        "https://user:pw@api.example/.well-known/aauth-resource.json",
        "https://api.example:8443/.well-known/aauth-resource.json",
    ]);
    assert_eq!(fetched, vec![TARGET.to_owned()]);

    let html = r#"<html><head>
        <link rel="aauth-resource" href="https://api.example/.well-known/aauth-resource.json">
        <link href="https://evil.example/steal" rel="aauth-resource">
        </head></html>"#;
    let html_links = links_from_html(html);
    assert_eq!(html_links.len(), 1);
    assert_eq!(html_links[0].target, TARGET);

    metadata_matches_link(&links[0], br#"{"issuer":"https://api.example"}"#).unwrap();
    assert_eq!(
        metadata_matches_link(&links[0], br#"{"issuer":"https://other.example"}"#).unwrap_err(),
        TokenError::IssuerMismatch
    );

    let carried = discovery_from_headers(Some(&header), Some("requirement=person-token"));
    assert_eq!(carried.links, links);
    assert_eq!(
        carried.requirement.as_deref(),
        Some("requirement=person-token")
    );
    let link_only = discovery_from_headers(Some(&header), None);
    assert!(link_only.requirement.is_none());
    assert_eq!(link_only.links[0].target, TARGET);
}
