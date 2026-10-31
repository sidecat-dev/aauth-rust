# AAuth for Rust: documentation

Start with [Get started](getting-started.md): it runs an agent calling an API
over TLS on your machine, and walks through the code. Then read
[How AAuth works](how-aauth-works.md) for the parties, the tokens and the ways
an API can decide who gets in.

## Roles

Each guide says what the role does, shows the flow, and gives the smallest
program that runs it. Every Rust sample on these pages compiles and runs as a
test.

| Guide | Crate | For |
| --- | --- | --- |
| [Agent](roles/agent.md) | `aauth-rust-agent` | an HTTP client that calls APIs for a person |
| [Agent Provider](roles/agent-provider.md) | `aauth-rust-agent-provider` | vouching for agents with Agent tokens |
| [Resource](roles/resource.md) | `aauth-rust-resource` | an API that checks who is calling |
| [Person Server](roles/person-server.md) | `aauth-rust-person-server` | knowing which person an agent acts for, and what they allow |
| [Access Server](roles/access-server.md) | `aauth-rust-access-server` | a Resource that keeps its own access policy |
| [Supervision Server](roles/supervision-server.md) | `aauth-rust-supervision-server` | deciding agents' requests in their person's place |

## Features

| Guide | Defined in |
| --- | --- |
| [Call chaining](features/call-chaining.md): an API that calls another API for the same person | core protocol |
| [Missions](features/missions.md): work the person approved, which every token is checked against | core protocol |
| [R3](features/r3.md): approving specific operations instead of scopes | `draft-hardt-aauth-r3` |
| [Budgets](features/budgets.md): capping what an agent may spend at a Resource | `draft-hardt-aauth-budgets` |
| [Events](features/events.md): notifying an agent later, through its Agent Provider | `draft-hardt-aauth-events` |
| [Supervision](features/supervision.md): what happens to each act a supervision server decides | `draft-hardt-aauth-supervision` |

## Reference

- [Errors](errors.md): every refusal, and what the caller does about it.
- [USE-IN-YOUR-SERVICE.md](../USE-IN-YOUR-SERVICE.md): the full reference for
  running each role in a service.
- [CONFORMANCE.md](../CONFORMANCE.md): what the libraries do and do not do.
- [INTERPRETATIONS.md](../INTERPRETATIONS.md): the choices made where a draft
  leaves room.
- [SPECIFICATIONS.md](../SPECIFICATIONS.md): the draft versions implemented.
- [SECURITY.md](../SECURITY.md): what your service is responsible for.

## Examples

Every example runs on your machine alone, with no account and no outside service:

```sh
cargo run --locked -p aauth-rust-resource --example getting-started
cargo run --locked -p aauth-rust-resource --example library
cargo run --locked -p aauth-rust-resource --example axum
cargo run --locked -p aauth-rust-resource --example direct-identity
cargo run --locked -p aauth-rust-resource --example three-party
cargo run --locked -p aauth-rust-resource --example four-party
cargo run --locked -p aauth-rust-resource --example four-party -- --deferred
cargo run --locked -p aauth-rust-resource --example subagent
cargo run --locked -p aauth-rust-resource --example r3-three-party
cargo run --locked -p aauth-rust-resource --example r3-per-call
cargo run --locked -p aauth-rust-r3 --example r3-definition
cargo run --locked -p aauth-rust-person-server --example mixed-grants
cargo run --locked -p aauth-rust-person-server --example supervised-agents
cargo run --locked -p aauth-rust-person-server-redb --example contracts
```

| Example | Shows |
| --- | --- |
| `getting-started` | an agent calling an API over TLS, with its Agent token |
| `library` | the same checks in one process, with no network |
| `axum` | the Resource check inside the axum web framework |
| `direct-identity` | fourteen checks of agent identity over TLS, refusals included |
| `three-party` | a Person Server's consent, and one API calling another, over TLS |
| `four-party` | an Access Server's decision over TLS; `--deferred` adds payment and approval |
| `subagent` | a parent agent getting credentials for a sub-agent |
| `r3-three-party`, `r3-per-call` | R3 operations, per-call proposals and held results |
| `r3-definition` | reading an MCP tool list as R3 operations |
| `mixed-grants` | one Person Server issuing both its own and an Access Server's Auth tokens |
| `supervised-agents` | one person, three agents, two supervision servers |
| `contracts` | the store contract tests run against the redb store |
