//! Discovery over loopback TLS: the key resolver's journey and the refusals.
mod support;

use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_core::{AgentKeyResolver, TokenError};
use aauth_rust_discovery::{DiscoveryError, KeyResolver, Refusal};
use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::DiscoveryFetch;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use support::{Net, json, status_with};

const AP: &str = "https://ap.test";

#[test]
fn key_resolver_discovers_caches_and_refetches_over_tls() {
    let (first_key, rotated_key) = (SigningKey::generate(), SigningKey::generate());
    let (first_public, rotated_public) = (first_key.public_jwk(), rotated_key.public_jwk());
    let first = AgentProvider::new(AP, "ap-1", first_key).unwrap();
    let rotated = AgentProvider::new(AP, "ap-2", rotated_key).unwrap();
    let metadata = first.metadata().unwrap();
    let jwks = Arc::new(Mutex::new(first.jwks().unwrap()));
    let mut net = Net::new(&["ap.test"]);
    let served = jwks.clone();
    net.serve("ap.test", move |request| match request.uri().path() {
        // A same-host redirect is followed.
        "/.well-known/aauth-agent.json" => status_with(307, "location", "/documents/agent.json"),
        "/documents/agent.json" => json(200, metadata.clone()),
        "/.well-known/jwks.json" => {
            let mut response = json(200, served.lock().unwrap().clone());
            let headers = response.headers_mut();
            headers.insert("cache-control", "public, max-age=300".parse().unwrap());
            headers.insert("transfer-encoding", "chunked".parse().unwrap());
            response
        }
        _ => json(404, "{}"),
    });
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let time = clock.clone();
    let keys = KeyResolver::new(net.client())
        .trust(AP, "aauth-agent.json")
        .with_clock(move || time.load(Ordering::SeqCst));

    let key = keys.key(AP, "aauth-agent.json", "ap-1").unwrap();
    assert_eq!(key.x, first_public.x);
    assert_eq!(
        net.log(),
        [
            "GET ap.test/.well-known/aauth-agent.json",
            "GET ap.test/documents/agent.json",
            "GET ap.test/.well-known/jwks.json",
        ]
    );

    // Fresh: answered from the cache.
    let fetched_at = 1_800_000_000;
    clock.store(fetched_at + 20, Ordering::SeqCst);
    keys.key(AP, "aauth-agent.json", "ap-1").unwrap();
    assert_eq!(net.log().len(), 3);

    // The issuer rotates. An unknown kid inside the minute after the last
    // fetch is not fetched for.
    *jwks.lock().unwrap() = rotated.jwks().unwrap();
    clock.store(fetched_at + 30, Ordering::SeqCst);
    assert_eq!(
        keys.key(AP, "aauth-agent.json", "ap-2").unwrap_err(),
        TokenError::UnknownKey
    );
    assert_eq!(net.log().len(), 3);
    // After it, the unknown kid refetches the set.
    clock.store(fetched_at + 61, Ordering::SeqCst);
    let key = keys.key(AP, "aauth-agent.json", "ap-2").unwrap();
    assert_eq!(key.x, rotated_public.x);
    assert_eq!(net.count("GET ap.test/.well-known/jwks.json"), 2);

    // Discovery is not trust: an issuer the host did not name is never fetched.
    let before = net.log().len();
    assert_eq!(
        keys.key("https://other.test", "aauth-agent.json", "ap-1")
            .unwrap_err(),
        TokenError::UntrustedIssuer
    );
    assert_eq!(
        keys.key(AP, "aauth-person.json", "ap-1").unwrap_err(),
        TokenError::UntrustedIssuer
    );
    assert_eq!(net.log().len(), before);
}

#[test]
fn admission_and_document_checks_refuse() {
    let provider = AgentProvider::new(AP, "ap-1", SigningKey::generate()).unwrap();
    let metadata = provider.metadata().unwrap();
    let mut net = Net::new(&["ap.test", "hop.test", "big.test", "mismatch.test"]);
    let served = metadata.clone();
    net.serve("ap.test", move |_| json(200, served.clone()));
    net.serve("hop.test", |_| {
        status_with(
            302,
            "location",
            "https://ap.test/.well-known/aauth-agent.json",
        )
    });
    net.serve("big.test", |_| json(200, vec![b' '; 70_000]));
    // Serves the AP's document, which names https://ap.test as its issuer.
    net.serve("mismatch.test", move |_| json(200, metadata.clone()));
    let client = net.client();
    let get = |url: &str| client.get(DiscoveryFetch::Metadata { url });

    let refused = get("http://ap.test/.well-known/aauth-agent.json").unwrap_err();
    assert!(
        matches!(
            refused,
            DiscoveryError::Refused {
                reason: Refusal::NotHttps,
                ..
            }
        ),
        "{refused}"
    );

    // Loopback is refused unless the client was built to admit it.
    let strict = net.strict_client();
    let refused = strict
        .get(DiscoveryFetch::Metadata {
            url: "https://ap.test/.well-known/aauth-agent.json",
        })
        .unwrap_err();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(
        matches!(refused, DiscoveryError::Refused { reason: Refusal::RestrictedAddress(address), .. } if address == loopback),
        "{refused}"
    );
    let ok = get("https://ap.test/.well-known/aauth-agent.json").unwrap();
    assert_eq!(ok.body(), provider.metadata().unwrap());

    // A redirect to another host is not followed.
    let refused = get("https://hop.test/.well-known/aauth-agent.json").unwrap_err();
    assert!(
        matches!(
            refused,
            DiscoveryError::Refused {
                reason: Refusal::CrossHostRedirect,
                ..
            }
        ),
        "{refused}"
    );

    let refused = get("https://big.test/.well-known/aauth-agent.json").unwrap_err();
    assert!(
        matches!(refused, DiscoveryError::TooLarge { limit: 65_536, .. }),
        "{refused}"
    );

    // A document served for one issuer that names another is refused, and
    // its jwks_uri is not fetched.
    let keys = KeyResolver::new(client.clone()).trust("https://mismatch.test", "aauth-agent.json");
    assert_eq!(
        keys.key("https://mismatch.test", "aauth-agent.json", "ap-1")
            .unwrap_err(),
        TokenError::IssuerMismatch
    );
    assert_eq!(
        net.log(),
        [
            "GET ap.test/.well-known/aauth-agent.json",
            "GET hop.test/.well-known/aauth-agent.json",
            "GET big.test/.well-known/aauth-agent.json",
            "GET mismatch.test/.well-known/aauth-agent.json",
        ]
    );
}
