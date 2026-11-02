# Discovery and revocation delivery

A server that verifies AAuth requests needs other servers' keys, and a server
that revokes tokens has to tell the servers holding them. The role crates do
neither: they ask your service. `aauth-rust-discovery` is the opt-in crate that
does both over HTTPS, and it is the only crate in this workspace that opens a
network connection.

Crate: `aauth-rust-discovery`. It has three parts:

- `DiscoveryClient` fetches metadata documents and key sets, and sends
  server-to-server requests, with the egress rules below.
- `KeyResolver` is an `AgentKeyResolver` for the issuers you trust. Pass it
  to any role in place of a key snapshot. It fetches `{iss}/.well-known/{dwk}`,
  checks its `issuer`, fetches its `jwks_uri`, selects the `kid`, and caches
  the key set. It also resolves the keys of clients outside AAuth that a
  Resource built `with_further_schemes` hands you: a `jwks` signer whose URL
  you trust, and a `self-jwt` signer whose issuer you trust.
- `RevocationClient` is a `RevocationDirectory`. Install it on a Person Server,
  Access Server or Resource with `with_revocation_directory`, and each
  revocation the role cascades from its own records reaches its recipient.

Every call blocks the calling thread. In an async service, call the role from
a blocking task, such as `tokio::task::spawn_blocking`.

## Smallest working code

A Person Server that finds keys by discovery and delivers its revocations.
Nothing is fetched until a request needs a key.

```rust
use aauth_rust_core::{AgentKeyResolver, TokenError};
use aauth_rust_discovery::{DiscoveryClient, DiscoveryError, KeyResolver, Refusal, RevocationClient};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    AuthorizationRequest, Config, Grant, MemoryStore, Person, PersonRequest, PersonServer, Policy,
    PolicyError,
};
use aauth_rust_signature_key::DiscoveryFetch;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct People;
impl Policy for People {
    fn bind_person(&self, _: &PersonRequest) -> Result<Person, PolicyError> {
        Err(PolicyError::Denied)
    }
    fn authorize(&self, _: &AuthorizationRequest) -> Result<Grant, PolicyError> {
        Err(PolicyError::Denied)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One client for every outbound request: the platform's root
    // certificates, public addresses only.
    let client = DiscoveryClient::new()?;
    // The issuers this server accepts, each in one role.
    let keys = Arc::new(
        KeyResolver::new(client.clone())
            .trust("https://ap.example", "aauth-agent.json")
            .trust("https://notes.example", "aauth-resource.json"),
    );
    let ids = AtomicU64::new(0);
    let ps = PersonServer::new(
        Config::new("https://ps.example", "ps-1", SigningKey::generate()),
        keys.clone(),
        MemoryStore::default(),
        People,
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs() as i64)
        },
        move || format!("ps-{}", ids.fetch_add(1, Ordering::SeqCst)),
    )?
    .with_revocation_directory(Arc::new(RevocationClient::new(client.clone())));
    let metadata: Value = serde_json::from_slice(&ps.metadata())?;
    assert_eq!(metadata["revocation_endpoint"], "https://ps.example/revoke");

    // Discovery is not trust: an issuer you did not name is refused before
    // any request is made.
    assert_eq!(
        keys.key("https://other.example", "aauth-agent.json", "key-1").unwrap_err(),
        TokenError::UntrustedIssuer
    );
    // Private addresses are refused unless you allow them.
    let private = client.get(DiscoveryFetch::Metadata {
        url: "https://10.0.0.7/.well-known/aauth-agent.json",
    });
    assert!(matches!(
        private,
        Err(DiscoveryError::Refused { reason: Refusal::RestrictedAddress(_), .. })
    ));
    Ok(())
}
```

The test `crates/aauth-rust-discovery/tests/cascade.rs` runs the whole path
over TLS on loopback: an agent obtains a person token and an Access Server's
auth token, then the Person Server revokes the person token, and the
revocation reaches the API directly and through the Access Server, each
signed by its sender and verified with keys found by discovery.

## The egress rules

`DiscoveryClient::new()` applies the HTTP Signature Keys egress admission to
every URL, before it connects:

- `https` only, on the first request and on every redirect;
- the host is resolved once, every address must be globally routable unicast
  (loopback, private, link-local, shared, documentation and multicast
  addresses are refused), and the connection goes to an admitted address;
- a redirect is followed only on the same host, at most three;
- a `jwks_uri` must be on its metadata document's host;
- a response body is at most 65536 bytes, and each fetch, redirects
  included, ends within ten seconds;
- proxy settings in the environment are not read.

TLS is rustls with the ring provider; certificates are checked against the
platform's root certificates.

## Development and tests

Relaxing a rule is a call you make, never a default. To reach servers on your
own machine, admit restricted addresses, trust your test certificate, and
resolve your test names to loopback:

```rust
use aauth_rust_discovery::DiscoveryClient;
use std::net::{Ipv4Addr, SocketAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The certificate your test server presents for ps.test, and its listener.
    let certificate = rcgen::generate_simple_self_signed(vec!["ps.test".into()])?;
    let listener = SocketAddr::from((Ipv4Addr::LOCALHOST, 8443));
    let client = DiscoveryClient::builder()
        .allow_restricted_addresses()
        .root_certificates([certificate.cert.der().to_vec()])
        .resolver(move |_host: &str, _port: u16| Ok(vec![listener]))
        .build()?;
    assert!(client.limits().allow_restricted_addresses);
    Ok(())
}
```

`builder().limits(EgressLimits { .. })` changes the size and timeout, or admits
a cross-origin `jwks_uri`. `builder().transport(..)` replaces the connection
itself, for example to go through an egress proxy; the client still admits
each URL and address and hands the transport the address to use.

## How keys are cached

`KeyResolver` follows the caching rules of HTTP Signature Keys and the AAuth
protocol:

- the key set's `Cache-Control` (`max-age`, `s-maxage`, `no-store`,
  `no-cache`), `Expires` and `Age` set how long it is used, at most 24 hours,
  five minutes when it says nothing;
- one issuer and role is fetched at most once a minute, a failed fetch
  included;
- a `kid` missing from a fresh set fetches the set again, once that minute
  has passed;
- when a signature fails under a cached key, the set is fetched again once,
  in case the issuer replaced the key under the same `kid`, within the same
  once-a-minute limit;
- when a fetch fails, a set fetched less than 24 hours ago still answers;
- at most 1024 issuers, roles and URLs are held; `with_capacity` changes that.

## Signers outside AAuth

A Resource built `with_further_schemes(&["jwks", "self-jwt"])` returns those
requests as `Decision::OtherScheme(proof)`. The same `KeyResolver` verifies
them:

- `jwks`: the URL in the request is the signer's identity. Trust it with
  `trust_jwks(url)`, or `trust_jwks_when(|url| ...)` for a rule, then call
  `proof.verify_jwks(&keys)`. The URL is fetched as presented, through the
  client's rules, and cached by URL.
- `self-jwt`: trust the issuer and role with `trust(iss, dwk)`, then call
  `keys.verify_self_jwt(&proof, now, typ)`, with the JWT `typ` your
  deployment uses.

A signer you did not trust is never fetched; its request is refused with
`invalid_key`.

## What a delivery reports

`RevocationClient` maps each answer to the outcome the role's cascade records:

| The recipient | Outcome |
| --- | --- |
| answers `200` | recorded |
| publishes no `revocation_endpoint`, or answers `unsupported_iss` | `revocation_unsupported` |
| times out, answers `5xx`, another error, or a body that is not a JSON object | `revocation_unavailable` |
| answers `202` | deferred: the role answers `202` too, and its next attempt polls the `Location` with a signed GET |
| answers `429 rate_limited` | deferred: the next attempt posts again |

`RevocationClient::deliver` returns the same outcome with its cause, for your
logs. See [Errors](errors.md) for what a caller does with each refusal.
