# R3 port hand-back

Branch `wc-05-rust-r3` starts at `704effbf898e768839de82277334a716379a931e`. Commit `3c373a55d6f265844c18743268fcf5b7b9aca1c2` adds crate `aauth-rust-r3`. This batch is grammar and set algebra. No row is `pass`.

## What is in the batch

The crate registers a codec and keeps whole-set algebra on that registration. It does not fetch a definition, decide policy, execute a call, or issue a token. Documents, direct grants, per-call proposals, the seven standard vocabularies, and the resource and person-server wiring are later batches.

`VocabularyUri` accepts a non-empty trimmed absolute URI and rejects a fragment. `AnnotationEncoding` accepts `unavailable`, `mcp-meta`, `specification-extension`, `odata-metadata`, or a third-party absolute URI. Cardinality is enforced before the codec runs and again on the canonical marshal: a request or document is non-empty, a grant may be empty and keeps its vocabulary, and a proposal is exactly one operation. Normalization fails if the codec changes the operation count or the operation meaning. Two registrations of one URI are not interchangeable. `Registry` parses one strict `vocabulary` / `operations` envelope, rejects duplicate and unknown members, and dispatches only to the named registration. `Operation`, `OperationSet`, and `GrantedOperations` refuse context-free JSON. Discovery-endpoint validation is syntax only.

The tests use a named codec, the same shape as Go's `vocabulary_test.go`. They do not import a standard vocabulary.

## Rows

| id | result | test |
| --- | --- | --- |
| R3-L00156-O01-MAY | reaches, not run | `vocabulary_accepts_a_namespaced_third_party_annotation_encoding` registers `https://example.test/vocabulary/custom-annotation` and refuses an unnamespaced annotation encoding. The integration journey that publishes a private codec is not in this batch. |

These library checks are in the batch. The rows also need a later object, so they are not marked reached:

| id | what this batch checks | what is still missing |
| --- | --- | --- |
| R3-L00413-O01-REQUIRED | An empty request set is refused before the codec runs. | The authorization request object. |
| R3-L00471-O01-REQUIRED | An empty document set is refused before the codec runs. | The R3 document object. |
| R3-L00617-O01-REQUIRED | An empty grant is valid and keeps its vocabulary. | The MCP grant wire tests. |
| R3-L00643-O01-REQUIRED | An empty or multi-operation proposal is refused before the codec runs. | The proposal document. |

`vocabulary_uri_rejects_a_fragment_and_a_non_absolute_form` checks the URI grammar used by R3-L00144-O02-MUST. Metadata publication is not in this batch, so that row is not reached.

## Droplet

One run, for this batch:

```
cargo test -p aauth-rust-r3 --locked --lib vocabulary_
```

The thirteen tests under that filter are:

- `vocabulary_enforces_cardinality_before_codec_dispatch`
- `vocabulary_enforces_cardinality_after_canonical_marshal`
- `vocabulary_rejects_codec_that_drops_operations_during_normalization`
- `vocabulary_rejects_codec_that_changes_operations_during_normalization`
- `vocabulary_accepts_a_namespaced_third_party_annotation_encoding`
- `vocabulary_delegates_discovery_endpoint_validation_to_codec`
- `vocabulary_registry_drives_whole_set_algebra`
- `vocabulary_registry_fails_closed`
- `vocabulary_zero_value_operation_set_union_returns_an_error`
- `vocabulary_context_bound_operation_envelopes_refuse_context_free_unmarshal`
- `vocabulary_uri_rejects_a_fragment_and_a_non_absolute_form`
- `vocabulary_envelope_rejects_duplicate_and_unknown_members`
- `vocabulary_granted_operations_keep_owned_copies_and_set_relations`

While preparing the commit, this window ran that filter, `cargo fmt -p aauth-rust-r3`, and `cargo clippy -p aauth-rust-r3 --all-targets --locked -- -D warnings`. Those runs are not the droplet log. A `reaches, not run` row stays short of `pass` until that log exists.

## Go edges not copied

Errors are `Result`. There is no `context.Context`, no `net/http`, and no process-global registry. A bad registration returns an error. Operation order is the order the codec retains. The allowlist is a `BTreeMap` and is not wire order. `operations` returns `Result` instead of a nil slice. The envelope parser rejects duplicate object members and does not reserialize operation objects.

## Left untracked

`BRIEF.md`, `GO-R3-TABLE.md`, and `obligations-r3.json` are not in the batch commit.
