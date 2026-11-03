# aauth-rust-signature-key

HTTP Message Signatures (RFC 9421) with the `Signature-Key` header that says
which key signed: sign a request on the client, and on the server check that
the signature covers the request you actually received. Every AAuth role
signs and checks requests with it; use it directly to sign or verify HTTP
messages under your own key scheme.

```toml
[dependencies]
aauth-rust-jose = "0.1.0-alpha.27"
aauth-rust-signature-key = "0.1.0-alpha.27"
http = "1"
```

```rust
use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::{KeyMaterial, PreparedRequest, sign_request};
use http::Request;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // The client signs a POST. The `hwk` scheme carries its public key inline.
    let key = SigningKey::generate();
    let mut request = Request::builder()
        .method("POST")
        .uri("https://api.example/notes")
        .header("content-type", "application/json")
        .body(br#"{"text":"hello"}"#.to_vec())?;
    sign_request(&mut request, &key, KeyMaterial::Hwk(key.public_jwk()), now)?;
    for name in ["signature-key", "signature-input", "signature"] {
        println!("{name}: {}", request.headers()[name].to_str()?);
    }

    // The server rebuilds the signature base from the request and checks it,
    // allowing 60 seconds of clock difference.
    let proof = PreparedRequest::prepare(&request, "sig", now, 60)?;
    let KeyMaterial::Hwk(public) = proof.key() else {
        return Err("expected an inline key".into());
    };
    proof.verify(public)?;

    // A body changed after signing no longer matches its Content-Digest.
    *request.body_mut() = br#"{"text":"changed"}"#.to_vec();
    let refused = PreparedRequest::prepare(&request, "sig", now, 60).unwrap_err();
    assert_eq!(refused.code(), "invalid_signature");
    Ok(())
}
```

```text
signature-key: sig=hwk;kty="OKP";crv="Ed25519";x="bNYmmduwhswcUPbp92hv7i0HNuEsnQnLhD67CKkMn5k";alg="Ed25519"
signature-input: sig=("@method" "@authority" "@path" "content-digest" "content-type" "signature-key");created=1793674255
signature: sig=:3LPdveTS+HB9/M5DOPbbKrx2kH7hCuqMLqRrJJzfyAoM7H1/boOkXJZeKDOWrlCEGsA+ltyoBhZQNisQ4zakCg==:
```

The key, the time and the signature differ on every run. Signing also adds
the `content-digest` header that the signature covers.

## Why use it

- **Coverage is enforced, not hoped for.** Signing always covers the method,
  authority, path, query, `Authorization`, `Content-Digest` and
  `Content-Type` when present, and verification refuses a signature that
  leaves any of them out. The digest is computed from the actual body, up to
  1 MiB.
- **Every key scheme of the draft.** `hwk`, `jwt`, `jkt-jwt`, `self-jwt`,
  `jwks`, `jwks_uri`, `x509` and `cached` are each a `KeyMaterial` variant.
  Checking a signature proves only the key; who that key belongs to is decided
  by the AAuth role or by your code.
- **Plain buffered `http` types.** It works on `http::Request<Vec<u8>>` and
  `http::Response<Vec<u8>>` with any HTTP stack. The tradeoff: streaming bodies
  must be collected first.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. Pure Rust.
- Times are Unix seconds. Your host supplies the clock.
- It never opens a connection. Fetching a `jwks_uri` or `x5u` is your
  transport's job, through the egress checks this crate provides;
  `aauth-rust-discovery` is one such transport.

## Specifications

Implements HTTP Signature Keys (`draft-hardt-httpbis-signature-key`), from the
[editor's copy of 13 September 2026](https://github.com/dickhardt/signature-key/tree/69f5ba2647be848feed043fb6d8b0790e43cd0b6),
and the HTTP signing profile of the AAuth protocol draft, from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e).

## Links

- [API documentation](https://docs.rs/aauth-rust-signature-key)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::signature_key` in the umbrella crate, with the rest of the family
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust), with a guide for each role
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
