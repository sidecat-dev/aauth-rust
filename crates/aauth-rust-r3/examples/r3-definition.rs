//! Parse an authoritative R3 definition the way a Resource would before it
//! issues a resource token, using only the public API. Nothing is fetched.
//!
//! ```text
//! cargo run -p aauth-rust-r3 --example r3-definition
//! cargo run -p aauth-rust-r3 --example r3-definition -- openapi https://api.example/openapi.json openapi.json
//! cargo run -p aauth-rust-r3 --example r3-definition -- asyncapi https://api.example/asyncapi.json asyncapi.json
//! cargo run -p aauth-rust-r3 --example r3-definition -- graphql https://api.example/graphql introspection.json
//! cargo run -p aauth-rust-r3 --example r3-definition -- mcp https://api.example/mcp page-1.json page-2.json
//! ```
//!
//! MCP files are the `result` objects of successive `tools/list` responses.
//! Each later page is taken to answer a request for the prior page's
//! `nextCursor`. A refusal prints its kind and exits with status 1.

use std::error::Error;

use aauth_rust_r3::{
    AccessMode, AsyncApiCodec, AsyncApiDocumentSource, AuthoritativeSnapshot, DefinitionError,
    DefinitionRegistry, GraphQlCodec, GraphQlIntrospectionSource, McpCodec, OpenApiCodec,
    OpenApiDocumentSource, ToolsListPage, ToolsListSnapshot,
};

const USAGE: &str = "usage: r3-definition [mcp|openapi|asyncapi|graphql <endpoint> <file>...]";

const SAMPLE_ENDPOINT: &str = "https://resource.example/mcp";

const SAMPLE_PAGE: &str = r#"{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token"}},{"name":"calendar.write","inputSchema":{"type":"object","properties":{"title":{"type":"string"}},"required":["title"]},"_meta":{"aauth.dev/access-mode":"auth-token","aauth.dev/budget":true}}]}"#;

enum Source {
    Mcp(ToolsListSnapshot),
    OpenApi(OpenApiDocumentSource),
    AsyncApi(AsyncApiDocumentSource),
    GraphQl(GraphQlIntrospectionSource),
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (endpoint, source) = match args.as_slice() {
        [] => (
            SAMPLE_ENDPOINT.to_owned(),
            Source::Mcp(ToolsListSnapshot::new(vec![ToolsListPage::initial(
                SAMPLE_PAGE.as_bytes(),
            )])),
        ),
        [vocabulary, endpoint, files @ ..] if !files.is_empty() => {
            let mut bodies = Vec::with_capacity(files.len());
            for file in files {
                bodies.push(std::fs::read(file)?);
            }
            (endpoint.clone(), source(vocabulary, &bodies)?)
        }
        _ => return Err(USAGE.into()),
    };
    let snapshot = match parse(&endpoint, &source) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            eprintln!("refused {}: {err}", err.kind());
            std::process::exit(1);
        }
    };
    // The Resource allowlists the parsers it trusts for its advertised vocabularies.
    let registry = DefinitionRegistry::new(&[
        McpCodec::definition_registration()?,
        OpenApiCodec::definition_registration()?,
        AsyncApiCodec::definition_registration()?,
        GraphQlCodec::definition_registration()?,
    ])?;
    registry.validate(&snapshot)?;
    report(&snapshot)
}

fn source(vocabulary: &str, bodies: &[Vec<u8>]) -> Result<Source, Box<dyn Error>> {
    let single = || match bodies {
        [body] => Ok(body.as_slice()),
        _ => Err(format!("{vocabulary} takes exactly one file")),
    };
    Ok(match vocabulary {
        "mcp" => Source::Mcp(mcp_pages(bodies)?),
        "openapi" => Source::OpenApi(OpenApiDocumentSource::new(single()?)),
        "asyncapi" => Source::AsyncApi(AsyncApiDocumentSource::new(single()?)),
        "graphql" => Source::GraphQl(GraphQlIntrospectionSource::new(single()?)),
        _ => return Err(USAGE.into()),
    })
}

fn mcp_pages(bodies: &[Vec<u8>]) -> Result<ToolsListSnapshot, Box<dyn Error>> {
    let mut pages = Vec::with_capacity(bodies.len());
    let mut cursor: Option<String> = None;
    for body in bodies {
        pages.push(match cursor.take() {
            None => ToolsListPage::initial(body),
            Some(requested) => ToolsListPage::continued(requested, body),
        });
        let result: serde_json::Value = serde_json::from_slice(body)?;
        cursor = result
            .get("nextCursor")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
    }
    Ok(ToolsListSnapshot::new(pages))
}

fn parse(endpoint: &str, source: &Source) -> Result<AuthoritativeSnapshot, DefinitionError> {
    match source {
        Source::Mcp(pages) => McpCodec::parse_definition(endpoint, pages),
        Source::OpenApi(document) => OpenApiCodec::parse_definition(endpoint, document),
        Source::AsyncApi(document) => AsyncApiCodec::parse_definition(endpoint, document),
        Source::GraphQl(response) => GraphQlCodec::parse_definition(endpoint, response),
    }
}

fn report(snapshot: &AuthoritativeSnapshot) -> Result<(), Box<dyn Error>> {
    let receipt = snapshot.receipt();
    println!("vocabulary {}", snapshot.vocabulary());
    println!("endpoint   {}", receipt.discovery_endpoint());
    println!("encoding   {}", receipt.encoding());
    println!(
        "receipt    {} over {} bytes",
        receipt.digest(),
        receipt.byte_length()
    );
    let operations = snapshot.operations();
    for operation in operations.operations()? {
        let json = String::from_utf8(operation.json()?)?;
        match snapshot.hints_for(&operation)? {
            Some(hints) => {
                // A plan is advisory; the runtime AAuth-Requirement stays authoritative.
                let planned = hints.plan(AccessMode::AuthToken);
                println!(
                    "operation  {json} hints access_mode={} budget={} plan={} budget_required={}",
                    hints.access_mode().map_or("-", |mode| mode.as_str()),
                    hints
                        .budget()
                        .map_or_else(|| "-".to_owned(), |budget| budget.to_string()),
                    planned.access_mode(),
                    planned.budget_required()
                );
            }
            None => println!("operation  {json} (no published hints)"),
        }
    }
    // Every derived operation is, by construction, defined by the source.
    snapshot.validate_defined(&operations)?;
    Ok(())
}
