# AAuth for Rust

`aauth-rust` implements the AAuth protocol family (agent authorization: Agent, Agent Provider, Person Server, Resource, Access Server; R3, Events, Budgets, Bootstrap; HTTP Signature Keys) as a Rust workspace, developed alongside [aauth-go](https://gitlab.com/sidecat-dev/aauth-go) against the same pinned editor sources, so that findings can be checked in both before they are raised with the editors.

Status: not yet started.

Principles: local-first testing, then remote; easy to stand up and build on; small crates with clear boundaries; conformance stated only where a test executes it.

License: MIT.
