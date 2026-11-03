# aauth-rust

[AAuth](https://github.com/dickhardt/AAuth) tells an API which software agent
is calling it and on whose behalf. This crate brings every AAuth for Rust
crate into one dependency, one module per crate.

## Add it

```sh
cargo add aauth-rust
```

Every module is on by default. Each role module and `discovery` has a Cargo
feature of the same name. A service that only checks requests can keep just
the Resource:

```toml
[dependencies]
aauth-rust = { version = "0.1.0-alpha.26", default-features = false, features = ["resource"] }
```

The crates need Rust 1.99 or later.

## Modules

| Module | Role or purpose |
| --- | --- |
| `agent` | Agent: signs an agent's requests and checks the tokens it receives |
| `agent_provider` | Agent Provider: issues Agent tokens and publishes the provider's keys |
| `resource` | Resource, the API: checks requests before your handler runs |
| `person_server` | Person Server: issues tokens that name the person an agent acts for |
| `person_server_redb` | File-backed storage for a Person Server, on Unix |
| `access_server` | Access Server: decides access for an API from the API's own rules |
| `supervision_server` | Supervision Server: approves or refuses an agent's requests for the person |
| `discovery` | Fetches other servers' keys and delivers revocations over HTTPS; the only module that opens connections |
| `core`, `signature_key`, `jose` | Tokens, HTTP signatures and keys, used by the roles; always on |
| `r3`, `budgets` | Operation lists and spending caps, used by the roles; always on |

## Documentation

The [repository](https://gitlab.com/sidecat-dev/aauth-rust) has a guide for
each role and feature in its
[docs](https://gitlab.com/sidecat-dev/aauth-rust/-/tree/main/docs). This is an
alpha: APIs can change from one release to the next.

## License

MIT; see [LICENSE](LICENSE).
