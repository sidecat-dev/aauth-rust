# aauth-rust-r3

Rich Resource Requests (R3) for AAuth: describe what an API offers as named
operations, such as MCP tools or OpenAPI operations, so a person approves
specific operations instead of broad scopes, and the API admits only calls to
operations that were granted. The Resource, Person Server and Access Server
crates use it when you turn R3 on; use it directly to turn your API's own
definition into operations and check calls against a grant.

Rust needs the system linker to build: on Ubuntu or Debian,
`sudo apt-get install build-essential`; on macOS, the Xcode command line
tools; on Windows, the MSVC build tools. Then, in a project made with
`cargo new`:

```sh
cargo add aauth-rust-r3@0.1.0-alpha.29
```

```rust
use aauth_rust_r3::{GrantedOperations, McpCodec, Operation, ToolsListPage, ToolsListSnapshot};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The `result` of your MCP server's tools/list response.
    let tools = br#"{"tools":[
        {"name":"calendar.read","inputSchema":{"type":"object"}},
        {"name":"calendar.write","inputSchema":{"type":"object"}}
    ]}"#;
    let pages = ToolsListSnapshot::new(vec![ToolsListPage::initial(tools)]);
    let definition = McpCodec::parse_definition("https://api.example/mcp", &pages)?;
    let offered = definition.operations();
    for operation in offered.operations()? {
        println!("{}", String::from_utf8(operation.json()?)?);
    }

    // The person approved reading the calendar, and nothing else.
    let mcp = McpCodec::vocabulary()?;
    let read = Operation::new(&mcp, br#"{"tool":"calendar.read"}"#)?;
    let write = Operation::new(&mcp, br#"{"tool":"calendar.write"}"#)?;
    let granted = GrantedOperations::new(&mcp, &[read.clone()])?;
    assert!(granted.is_subset_of(&offered)?);

    // Each call is admitted only if its operation was granted.
    assert!(granted.contains(&read)?);
    assert!(!granted.contains(&write)?);
    Ok(())
}
```

```text
{"tool":"calendar.read"}
{"tool":"calendar.write"}
```

## Why use it

- **Seven vocabularies included.** Codecs for MCP, OpenAPI, AsyncAPI, GraphQL,
  gRPC, WSDL and OData, and parsers that derive operations from MCP tool
  lists, OpenAPI and AsyncAPI documents, gRPC descriptor sets, WSDL 1.1 and
  OData CSDL. You can register your own vocabulary with the `Codec` trait.
- **Set rules, not string matching.** Operations compare by the vocabulary's
  rules: subset, union, disjointness and membership. A grant that names an
  operation the API never offered is detectable before it is used.
- **Records that cannot drift.** R3 documents and per-call proposals are
  identified by the hash of their exact bytes, so what the person approved is
  what the API checks. Keep the original bytes: re-serialized JSON does not
  hash the same.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. No C dependencies, but Rust still
  needs the system linker.
- It fetches nothing. The signed artifact fetcher runs over an HTTPS
  transport your host supplies.
- GraphQL introspection is refused, because a schema alone names no
  operation. gRPC needs a descriptor set: hosted `.proto` text and live
  reflection are refused. OData metadata does not prove HTTP methods. The
  JSON Schema checks do not validate `pattern`.
- It does not decide policy or run a call: the Resource does, and the person
  decides at their Person Server.

## Specifications

Implements Rich Resource Requests (`draft-hardt-aauth-r3`), from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e).

## Links

- [API documentation](https://docs.rs/aauth-rust-r3)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::r3` in the umbrella crate, with the rest of the family
- [R3 guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/features/r3.md): turning R3 on in each role, and its limits
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT

[![Built by Sidecat](https://gitlab.com/sidecat-dev/aauth-rust/-/raw/main/assets/built-by-sidecat-240.png)](https://sidecat.dev)
