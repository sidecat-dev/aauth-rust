# aauth-rust-discovery

The HTTPS client for AAuth discovery: it fetches the metadata and keys of
the issuers your service trusts, caches them by the protocol's rules, and
delivers revocations, while refusing destinations an attacker could choose.
Every AAuth role can use it as its key resolver; it is the one crate of the
family that opens connections, and you add it only if you want it to.

Rust needs the system linker to build: on Ubuntu or Debian,
`sudo apt-get install build-essential`; on macOS, the Xcode command line
tools; on Windows, the MSVC build tools. Then, in a project made with
`cargo new`:

```sh
cargo add aauth-rust-discovery@0.1.0-alpha.28 aauth-rust-resource@0.1.0-alpha.28 aauth-rust-core@0.1.0-alpha.28 http@1
# used by the second example
cargo add aauth-rust-signature-key@0.1.0-alpha.28
```

A Resource whose keys come from discovery. The first signed request from an
agent of `ap.example` fetches that provider's metadata and JWKS over HTTPS;
later ones use the cache. In the example, `request` stands for the request
your server received.

```rust,no_run
use aauth_rust_core::VerifiedAgentToken;
use aauth_rust_discovery::{DiscoveryClient, KeyResolver};
use aauth_rust_resource::AgentIdentityResource;
use http::Request;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DiscoveryClient::new()?;
    let keys = KeyResolver::new(client).trust("https://ap.example", "aauth-agent.json");
    let api = AgentIdentityResource::for_origin(
        "https://api.example",
        keys,
        |agent: &VerifiedAgentToken, _: &Request<Vec<u8>>| agent.claims().sub.ends_with("@ap.example"),
    )?;

    // For each request your server receives, on a blocking thread.
    // Here an unsigned stand-in, which gets a 401 before anything is fetched.
    let request = Request::builder().uri("https://api.example/hello").body(Vec::new())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let response = api.authorize(&request, now).into_response();
    println!("{}", response.status());
    Ok(())
}
```

```text
401 Unauthorized
```

What it refuses, before any request leaves the process:

```rust
use aauth_rust_core::{AgentKeyResolver, TokenError};
use aauth_rust_discovery::{DiscoveryClient, DiscoveryError, KeyResolver, Refusal};
use aauth_rust_signature_key::DiscoveryFetch;

fn main() -> Result<(), DiscoveryError> {
    let client = DiscoveryClient::new()?;
    let keys = KeyResolver::new(client.clone()).trust("https://ap.example", "aauth-agent.json");

    // Discovery is not trust: an issuer you did not name is never contacted.
    let stranger = keys.key("https://elsewhere.example", "aauth-agent.json", "key-1");
    assert_eq!(stranger.unwrap_err(), TokenError::UntrustedIssuer);

    // Only https, and only public addresses.
    let plain = client.get(DiscoveryFetch::Metadata { url: "http://ap.example/.well-known/aauth-agent.json" });
    assert!(matches!(plain, Err(DiscoveryError::Refused { reason: Refusal::NotHttps, .. })));
    let local = client.get(DiscoveryFetch::Metadata { url: "https://127.0.0.1/.well-known/aauth-agent.json" });
    assert!(matches!(local, Err(DiscoveryError::Refused { reason: Refusal::RestrictedAddress(_), .. })));
    println!("refused: an untrusted issuer, plain http, a loopback address");
    Ok(())
}
```

```text
refused: an untrusted issuer, plain http, a loopback address
```

## Why use it

- **Safe egress by default.** `https` only; globally routable addresses only,
  checked after name resolution and pinned for the connection; same-host
  redirects only; bounded bodies and deadlines; no proxy taken from the
  environment. Relaxing a rule, such as admitting loopback in development, is
  an explicit builder call.
- **Trust stays explicit.** `KeyResolver` fetches only for the issuers and
  roles you name, and refreshes a key once when a signature fails under it,
  as the protocol allows.
- **Revocation delivery.** `RevocationClient` sends the revocation cascade a
  Person Server, Access Server or Resource computes from its own records.
  Install it with the role's `with_revocation_directory`.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. It uses rustls with the ring provider,
  which needs a C compiler to build.
- Every call blocks the calling thread. From an async runtime, call it on a
  blocking thread, such as `tokio::task::spawn_blocking`.
- Server certificates are checked against the platform's root store.
- It sends one HTTP/1.1 request per connection, with no connection reuse.

## Specifications

Implements discovery and key retrieval from the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`), from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
with the egress and cache rules of HTTP Signature Keys, from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6).

## Links

- [API documentation](https://docs.rs/aauth-rust-discovery)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::discovery` in the umbrella crate, with the rest of the family
- [Discovery guide](https://gitlab.com/sidecat-dev/aauth-rust/-/blob/main/docs/discovery.md): installing it in each role, and revocation delivery
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust)
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT

[![Built by Sidecat](https://gitlab.com/sidecat-dev/aauth-rust/-/raw/main/assets/built-by-sidecat-240.png)](https://sidecat.dev)
