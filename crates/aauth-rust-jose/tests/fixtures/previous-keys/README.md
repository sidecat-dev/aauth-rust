# Previous AAuth key encodings

These test vectors come from the previous signing implementation at
`5251bc5acf77b4ab3f22832cf805255167b4f89f`. The Ed25519 and EC keys use
publicly stated test seeds. Both RSA profiles use the repository's existing
2048-bit test key. No service or account uses these keys.

To regenerate, copy `emit.rs` to
`crates/aauth-rust-jose/examples/previous_keys.rs` in that revision. From its
workspace root run `cargo run --locked --quiet -p aauth-rust-jose --example previous_keys`
and save stdout as `cases.json`. Create the examples directory first if needed.
PS256 produces a new random signature each time. Both that previous
signature and a newly produced signature must verify with the saved public JWK.
The four deterministic signature profiles must match the old bytes exactly.
