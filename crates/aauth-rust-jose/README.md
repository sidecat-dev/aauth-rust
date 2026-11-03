# aauth-rust-jose

The keys and signatures under every AAuth role: Ed25519, ECDSA and RSA signing
keys, their public JWKs and thumbprints, and the Ed25519 and ES256 compact JWS
that AAuth tokens use. Use it directly to create, save, load or hand off the
keys your agent or server signs with.

Rust needs the system linker to build: on Ubuntu or Debian,
`sudo apt-get install build-essential`; on macOS, the Xcode command line
tools; on Windows, the MSVC build tools. Then, in a project made with
`cargo new`:

```sh
cargo add aauth-rust-jose@0.1.0-alpha.28 serde_json@1
```

```rust
use aauth_rust_jose::{Jws, SigningKey};
use serde_json::json;

fn main() -> Result<(), aauth_rust_jose::Error> {
    // A new Ed25519 key. Its public half is the JWK you publish or put in a token.
    let key = SigningKey::generate();
    let public = key.public_jwk();

    // Sign a compact JWS, then parse it and check it with the public key.
    let header = json!({"alg": "Ed25519", "typ": "JWT", "kid": "key-1"});
    let compact = Jws::sign(&header, br#"{"hello":"world"}"#, &key)?;
    let parsed = Jws::parse(&compact)?;
    parsed.verify(&public)?;
    println!("verified: {}", String::from_utf8_lossy(parsed.payload()));

    // Any other key is refused.
    let other = parsed.verify(&SigningKey::generate().public_jwk());
    println!("another key: {}", if other.is_err() { "refused" } else { "accepted" });

    // Save the key as PKCS #8 and load it again: same key, same thumbprint.
    let saved = key.export_pkcs8_der()?;
    let loaded = SigningKey::from_pkcs8_der("Ed25519", saved.as_bytes())?;
    let same = loaded.public_jwk().thumbprint()? == public.thumbprint()?;
    println!("reloaded, same thumbprint: {same}");
    Ok(())
}
```

```text
verified: {"hello":"world"}
another key: refused
reloaded, same thumbprint: true
```

## Why use it

- **Keys that live elsewhere.** `SigningKey::external` wraps a platform
  keystore, HSM, secure enclave or remote signer. The private key never enters
  this library, and every role signs with it like any other key. Such a key
  cannot be exported.
- **Only what AAuth allows.** Compact JWS signs and verifies only Ed25519 and
  ES256, the token algorithms of the protocol. `none`, `HS256`, `EdDSA`, `crit`
  and `b64` are refused at parse time. The JWK side also covers ES384, RS256
  and PS256, which HTTP signatures may use.
- **Exact bytes.** A parsed JWS keeps its original compact form and payload
  bytes, so a token you forward or hash is the one you received. It is not a
  general JOSE library: there is no JWE and no other JWS algorithm.

## Compatibility and limits

- Rust 1.99 or later, edition 2024. No C dependencies, but Rust still
  needs the system linker.
- `SigningKey::generate` uses the operating system's random number generator.
- Saving the private key is up to you. `export_pkcs8_der` returns unencrypted
  bytes, zeroed when dropped; store them where only the key's owner can read
  them.

## Specifications

Implements the key and signature profile of the AAuth protocol draft
(`draft-hardt-oauth-aauth-protocol`), from the
[AAuth drafts, editor's copy of 3 October 2026](https://github.com/dickhardt/AAuth/tree/70d67375deb0bb002af7da0711fc58f6e8926e7e),
on RFC 7515, 7517, 7518, 7638, 8032 and 8037.

## Links

- [API documentation](https://docs.rs/aauth-rust-jose)
- [aauth-rust](https://crates.io/crates/aauth-rust): this crate is also available as `aauth_rust::jose` in the umbrella crate, with the rest of the family
- [Repository](https://gitlab.com/sidecat-dev/aauth-rust), with a guide for each role
- [Issues](https://gitlab.com/sidecat-dev/aauth-rust/-/issues)
- [Changelog](https://gitlab.com/sidecat-dev/aauth-rust/-/releases)

## Status

Alpha: APIs may change before 1.0.

## License

MIT
