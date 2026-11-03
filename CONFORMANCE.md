# Executing behavior

## How this library approaches conformance

aauth-rust does not measure itself. The
[aauth-conformance](https://gitlab.com/sidecat-dev/aauth-conformance) project
builds a launcher around this library and drives it through generic wire
scenarios, one set per role. The same scenarios run unchanged against every
implementation. Each assertion names a suite clause, and each suite clause is
anchored in a pinned draft. The project's map, `conformance-map.edn`, lists
every sentence with a requirement keyword in the pinned drafts, the suite
clauses and scenarios that reach it, and each library's result. The drafts and
their pinned commits are in [SPECIFICATIONS.md](SPECIFICATIONS.md).

## What the current run says

| Item | Value |
| --- | --- |
| Suite | map at `dbf640d`; the run used `70bf78d`, which has the same suite digest |
| Library | `920519b`, tag `v0.1.0-alpha.25` |
| Roles | 24 of 24 offered, all passed |
| Assertions | 1,601 pass, 0 fail, 0 not claimed |
| Suite clauses | 337 of 337 pass |

## What it does not say

- **A clause with no scenario is not measured.** In the map, those are the
  `:clauses` entries whose `:suite-clauses` is empty: 433 of the 1,067 keyword
  sentences at this suite commit. A linked entry means a scenario grades a
  requirement of that section, not necessarily that sentence.
- **The figures come from a launcher run.** Remote mode tests a deployed
  server with no launcher and runs 13 of the 24 roles. The Agent signer, the
  vector roles, deferred authorization, sub-agents and missions need a
  launcher. Scenarios that need launcher-only access, such as re-signing the
  server's own token, are reported as not exercised. The suite's
  [REMOTE.md](https://gitlab.com/sidecat-dev/aauth-conformance/-/blob/dbf640d/REMOTE.md)
  lists them.
- **The suite grades behavior, not readings.** Where a draft leaves room, the
  reading this library takes is in [INTERPRETATIONS.md](INTERPRETATIONS.md).
  Each feature's limits are in its guide under [docs/features](docs/features).
- **No official or certified status is claimed,** and no percentage of any
  draft.

## Reproduce the run

The suite's
[README](https://gitlab.com/sidecat-dev/aauth-conformance/-/blob/dbf640d/README.md#run-against-local-checkouts)
gives the commands and their prerequisites. From a suite checkout at the commit
above, with this repository at the library commit, run once per role:

```sh
go run ./cmd/build-adapters -role ROLE -rust-source /path/to/aauth-rust -out build/ROLE
go run ./cmd/aauth-conformance -targets build/ROLE/targets.json -report build/ROLE/report.json -markdown build/ROLE/report.md
```

`go run ./cmd/build-adapters -h` lists the 24 role names. The suite's
[CONFORMANCE-MAP.md](https://gitlab.com/sidecat-dev/aauth-conformance/-/blob/dbf640d/CONFORMANCE-MAP.md)
gives the command that builds the map from those reports.

## Updating this page

Updating this page: check
- the suite commit, and the run's suite commit if it differs;
- the library commit and tag;
- the figures: assertions, suite clauses and unmeasured keyword sentences;
- the roles line.

After a library change, rerun every role and regenerate the map first. After a
suite change, rerun against the current library commit before changing a
figure.
