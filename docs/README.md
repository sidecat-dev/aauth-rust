# AAuth for Rust: documentation

Start with [Get started](getting-started.md): it runs an agent calling an API
over TLS on your machine, and walks through the code. Then read
[How AAuth works](how-aauth-works.md) for the parties, the tokens and the ways
an API can decide who gets in.

## Roles

Each guide says what the role does, shows the flow, and gives the smallest
program that runs it. That program is a test: `cargo test` compiles and runs
it.

| Guide | Crate | For |
| --- | --- | --- |
| [Agent](roles/agent.md) | `aauth-rust-agent` | an HTTP client that calls APIs for a person |
| [Agent Provider](roles/agent-provider.md) | `aauth-rust-agent-provider` | vouching for agents with Agent tokens |
| [Resource](roles/resource.md) | `aauth-rust-resource` | an API that checks who is calling |
| [Person Server](roles/person-server.md) | `aauth-rust-person-server` | knowing which person an agent acts for, and what they allow |
| [Access Server](roles/access-server.md) | `aauth-rust-access-server` | an API that decides access by its own rules |
| [Supervision Server](roles/supervision-server.md) | `aauth-rust-supervision-server` | approving or refusing an agent's requests for the person |

## Features

| Guide | What it adds | Defined in |
| --- | --- | --- |
| [Call chaining](features/call-chaining.md) | an API calling another API for the same person | core protocol |
| [Missions](features/missions.md) | a task the person approves up front; tokens issued for it are checked against it | core protocol |
| [R3](features/r3.md) | approving named operations, such as MCP tools, instead of broad scopes | `draft-hardt-aauth-r3` |
| [Budgets](features/budgets.md) | a cap on what an agent may spend at an API | `draft-hardt-aauth-budgets` |
| [Events](features/events.md) | an API notifying an agent later, through its Agent Provider | `draft-hardt-aauth-events` |
| [Supervision](features/supervision.md) | what happens to each request a supervision server decides | `draft-hardt-aauth-supervision` |

## Reference

- [Discovery and revocation delivery](discovery.md): `aauth-rust-discovery`
  fetches other servers' keys and delivers revocations over HTTPS.
- [Errors](errors.md): the refusals the servers send, and what the caller does
  about each.
- [USE-IN-YOUR-SERVICE.md](../USE-IN-YOUR-SERVICE.md): the full reference for
  running each role in a service.
- [CONFORMANCE.md](../CONFORMANCE.md): what the libraries do and do not do.
- [INTERPRETATIONS.md](../INTERPRETATIONS.md): the choices made where a draft
  leaves room.
- [SPECIFICATIONS.md](../SPECIFICATIONS.md): the draft versions implemented.
- [SECURITY.md](../SECURITY.md): what your service is responsible for.

## Examples

Every example runs on your machine alone, with no account and no outside
service. Run each from the checkout.

| Command | Shows |
| --- | --- |
| `cargo run --locked -p aauth-rust-resource --example getting-started` | an agent calling an API over TLS, with its Agent token |
| `cargo run --locked -p aauth-rust-resource --example library` | the same check in one process, with no network |
| `cargo run --locked -p aauth-rust-resource --example axum` | the Resource check inside the axum web framework |
| `cargo run --locked -p aauth-rust-resource --example direct-identity` | fourteen checks of agent identity over TLS, refusals included |
| `cargo run --locked -p aauth-rust-resource --example three-party` | a Person Server's consent, and one API calling another, over TLS |
| `cargo run --locked -p aauth-rust-resource --example four-party` | an Access Server's decision over TLS |
| `cargo run --locked -p aauth-rust-resource --example four-party -- --deferred` | the same, with payment and approval while the agent waits |
| `cargo run --locked -p aauth-rust-resource --example subagent` | a parent agent getting credentials for a sub-agent, an agent it starts to do part of its work |
| `cargo run --locked -p aauth-rust-resource --example r3-three-party` | approving named operations instead of scopes |
| `cargo run --locked -p aauth-rust-resource --example r3-per-call` | approving one call at a time, and releasing a result only after approval |
| `cargo run --locked -p aauth-rust-r3 --example r3-definition` | reading a list of MCP tools as operations |
| `cargo run --locked -p aauth-rust-person-server --example mixed-grants` | one Person Server issuing both its own and an Access Server's Auth tokens |
| `cargo run --locked -p aauth-rust-person-server --example supervised-agents` | one person, three agents, two supervision servers |
| `cargo run --locked -p aauth-rust-person-server-redb --example contracts` | the storage tests a Person Server store must pass, run against the file-backed store |
