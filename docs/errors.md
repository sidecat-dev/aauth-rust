# Errors

This page lists what the servers in this library answer when they refuse, and
what the caller does about each. Terms are defined in
[How AAuth works](how-aauth-works.md).

A refusal reaches the agent in one of five ways:

| Status and header | Meaning | Where |
| --- | --- | --- |
| `401` with `Signature-Error` | The signature, or the token that carries the key, failed a check | [Signature and token errors](#signature-and-token-errors) |
| `401` with `AAuth-Requirement` | The server needs a different token | [How AAuth works](how-aauth-works.md#challenges-and-waiting) |
| `403` with no `Signature-Error` | Everything checked out, and policy said no | [Refusals by policy](#refusals-by-policy) |
| `400`, `403`, `500` or `502` with an `error` in the body | A Person Server or Access Server refused a token request | [Token endpoint errors](#token-endpoint-errors) |
| Any non-`202` status from a pending URL | A deferred request ended without success | [Polling errors](#polling-errors) |

Error bodies are `application/problem+json`, with the code in `error` and
sometimes an explanation in `detail`. For a `401`, the `Signature-Error`
header is the code to act on, not the body.

## Signature and token errors

The code is in the `error` member of the `Signature-Error` header, for example
`Signature-Error: error=invalid_input, required_input=("@method" "@authority")`.

| Code | What it means | What the caller does |
| --- | --- | --- |
| `invalid_signature` | The signature is missing, malformed or does not verify; its `created` time is more than 60 seconds old; or the request went to a different origin or path than the server is configured for. | Sign again, last, after the URL, headers and body are final. Send to the server's own origin. Check the clock. |
| `invalid_input` | The signature does not cover something the server requires; `required_input` lists all of it. | Sign again covering the listed components. `Agent::sign` covers `content-digest` and `content-type` for a body; for anything else the server's metadata lists, use `with_additional_signature_components`. |
| `invalid_request` | The body is over the 1 MiB limit. | Send a smaller body. |
| `clock_skew` | The signature's `created`, or the token's `iat`, is more than 60 seconds ahead of the server's clock. The `Date` header has the server's time. | If `created` is ahead, fix the agent's clock. If the token's `iat` is ahead, the issuer's clock is fast and its next token will be too: wait, and send the same token again. |
| `invalid_jwt` | The token is malformed, its signature fails, it is the wrong kind of token, or it is for another audience. | Get a new token from its issuer, for this server. For the wrong audience the body's `detail` says so: get a token for this Resource rather than renewing the old one. |
| `expired_jwt` | The token has expired. | Get a new one: renew the Agent token, or get a new Person or Auth token. |
| `revoked_jwt` | The token was withdrawn by its issuer. | Do not send it again. Start again from a Person token. |
| `invalid_key` | The key could not be parsed, or the token's issuer is not one the server trusts, or the issuer's metadata cannot be used. | Do not retry with the same issuer. The server does not accept your Agent Provider (or Person Server); that is a setup question between the parties. |
| `unknown_key` | The issuer is trusted, but the keys the server holds for it have no key with this ID. | Retry later, once the server has refreshed the issuer's keys. |
| `unsupported_scheme` | The key was presented in a way, or [scheme](how-aauth-works.md#signed-requests), the server does not accept. `Accept-Signature-Scheme` lists the schemes it does. | AAuth agents present their token under the `jwt` scheme, which `Agent::sign` does. |
| `unsupported_algorithm` | The signing algorithm is not accepted. `Accept-Signature-Alg` lists those that are: `Ed25519, ES256` from every server in this library. | Sign with an Ed25519 or ES256 key. AAuth tokens and agent keys in this library are Ed25519 or ES256; an ES384, RS256 or PS256 key cannot hold or sign one. |
| `cache_miss` | The client sent a short identifier the server had issued in place of its token, and the server no longer knows it. | Send the full token again. |
| `issuer_missing`, `issuer_mismatch` | The issuer's metadata has no `issuer`, or names another one. | Nothing on the agent's side: the issuer's metadata needs fixing. |

**For a server.** When verification fails with `UnknownKey`, refresh that
issuer's keys from its configured source, at most once a minute, and verify
again once. `UntrustedIssuer` (sent as `invalid_key`) is final: never fetch
keys for an issuer you have not chosen to trust, whatever the token names.

## Refusals by policy

A `403` without `Signature-Error` means the request was authenticated and then
refused: by your Resource policy (`AgentIdentityResource` or
`PsAuthorizationResource`, body `error` `forbidden` or `access_denied`), by a
Person Server or Access Server policy (`access_denied`), or by a supervision
server (`access_denied`). Signing again will not help. Tell the person, or ask
for different access.

A `PsAuthorizationResource` also refuses with `403` an Auth token that does not
grant every scope it requires.

## Token endpoint errors

These come from `POST /person` and `POST /token` at a Person Server, and from
an Access Server's `/token`, in the body's `error` member. The `_token` codes
name the request parameter that failed.

| Code | Status | What the caller does |
| --- | --- | --- |
| `invalid_request` | 400 | Fix the request: malformed JSON, a missing or unknown member, an unsupported parameter. |
| `invalid_resource_token` | 400 | The Resource token is malformed, fails its signature, or does not match the presented token. Call the Resource again for a new one. |
| `expired_resource_token` | 400 | Call the Resource again for a new Resource token. |
| `revoked_resource_token` | 400 | The Resource withdrew it. Do not send it again; call the Resource again. |
| `invalid_presented_token` | 400 | The presented Person or Auth token is malformed, fails its signature, or is not one this Person Server issued and recorded. Get a new Person token. |
| `expired_presented_token` | 400 | Get a new Person token, then a new Resource token. |
| `revoked_presented_token` | 400 | Get a new Person token, then a new Resource token. |
| `invalid_upstream_token` | 400 | In [call chaining](features/call-chaining.md), the upstream token (the caller's token, passed on by the API that calls another API) is malformed, fails its signature, or was not presented to that API. |
| `expired_upstream_token` | 400 | The caller must authorize again at the intermediary. |
| `revoked_upstream_token` | 400 | The upstream token, the calling agent's Agent token, or its binding to the person was revoked. Do not retry with it. |
| `invalid_subagent_token`, `expired_subagent_token` | 400 | The sub-agent's token is malformed, does not name this parent, or has expired. The parent gets a new one. |
| `invalid_agent_token` | 400 | From an Access Server: the Agent token's `ps` claim is missing or names another Person Server. |
| `invalid_budget` | 400 | A [budget](features/budgets.md) in the request or token is malformed, uses an unknown unit, or is larger than the Resource offered. |
| `clock_skew` | 400 | A token sent as a parameter has an `iat` ahead of the server's clock. Wait, using the `Date` header, and send it again. |
| `access_denied` | 403 | Policy refused. Tell the person. |
| `denied` | 403 | From `/person`: the agent's binding to the person was revoked. |
| `user_unreachable` | 403 | The Person Server has no way to reach the person, and the agent did not say it can send the person to a web page: it says so by listing `interaction` in the `capabilities` member of its request. |
| `mission_terminated` | 403 | The mission has ended. Pass the response to `agent.missions().observe`; stop working under it, and propose a new mission if `termination_reason` is `expired`. |
| `server_error` | 500 | Start over later. |
| `as_unreachable` | 502 | The Person Server could not get an Auth token from the Resource's Access Server. Get a fresh Resource token and retry after a pause. |

## Polling errors

A deferred request ends when its pending URL answers anything but `202`. A
`200` carries the result; these are the other endings:

| Code | Status | What the caller does |
| --- | --- | --- |
| `denied` | 403 | The person or approver said no. Tell the person. |
| `abandoned` | 403 | The person opened the page they were sent to and did not finish. Tell the person; start a new request if they want to try again. |
| `revoked` | 403 | A token the request depended on was revoked; `detail` says which. Start again. |
| `expired` | 408 | The request timed out. You may start a new request. |
| `invalid_code` | 410 | The code the person was given with the page was already used or is not known. Start a new request for a new code. |
| `gone` | 410 | The result was already delivered, or the pending URL is unknown. Do not poll it again. |
| `slow_down` | 429 | Polling too often: wait 5 seconds longer between polls. `PollSession` does this. |
| `server_error` | 500 | Start over. |

## Local errors

The Rust error types explain in their messages what to fix, and their
`.code()` method returns the code they map to on the wire:
`TokenError::code()`, `SignatureFailure::code()` and
`aauth_rust_signature_key::Error::code()`. A few codes never go on the wire:
`invalid_configuration` is a configuration error in your service, and
`store_unavailable` and `unsupported_store_schema` come from the redb store.

`SigningFailed`, in `TokenError` and in `aauth_rust_signature_key::Error`,
means a key held by an external signer could not sign: the keystore, device
or service failed, or returned a signature that its public key does not
verify. Nothing was minted or signed. The Person Server, Access Server and
`PsAuthorizationResource` answer it with `500` `server_error`; an agent sends
nothing. Check the signer, then try again.
