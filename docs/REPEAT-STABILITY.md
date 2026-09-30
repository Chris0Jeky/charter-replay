# Repeat stability

A single recording cannot tell a deterministic hook from one whose decision
varies between invocations (time, randomness, races, network, mutable state).
`repeat` records one hook N times over the same captured corpus and reports how
each event's decision varies. It compares nothing against a baseline, so the
result is independent of any diff.

```
charter-replay repeat --hook CMD --corpus DIR --output DIR --repeats N \
    [--workspace DIR] [--fail-on CLASSES] [--runtime R] [--ask-as E] \
    [--hook-timeout S] [--hook-output-limit BYTES] [--jobs J]
```

`--repeats` is an integer from 2 to 50. It, `--fail-on`, the corpus, the hook
command and the output path are all admitted before any hook starts. `--output`
must not exist; nothing is overwritten.

## What runs

Recording *i* goes through the ordinary `record_hook` into `runs/NN/`
(`01`, `02`, ...), so each repeat is a full independent recording with fresh
per-event workspaces and its own `hook-context.json`, `decisions.jsonl`,
`outcomes.jsonl` and `measurements.json`. Repeats run one after another.

The whole output is built in a hidden `.charter-repeat-*` directory beside
`--output` and renamed into place at the end, so a crash or interrupt never
leaves a half-written directory that looks complete. The staging directory is
removed on failure. A hard kill can leave it behind; it is safe to delete. The
output parent must already exist and be on one filesystem with the staging
directory (it is created inside it).

## Comparability

Every repeat's `hook-context.v1` ID must equal repeat 1's (see
[HOOK-CONTEXT.md](HOOK-CONTEXT.md)). A repeat with a different ID is a source
failure (`repeat-context-changed`) and is left out of classification, so events
are never merged across contexts. `comparable_repeats` in `stability.json`
says how many repeats were classified. State that lives outside the descriptor,
such as a counter file, is exactly what this mode is meant to expose: it does
not change the ID.

## Classes

Per event, across the comparable repeats, the strongest difference wins:

| class | meaning |
|---|---|
| `stable` | identical effect, outcome and reason |
| `reason-varies` | same effect and outcome, different reason text |
| `outcome-varies` | same effect, different hook outcome (`deny` vs `stop`) |
| `effect-varies` | different effects |

Indeterminate is an effect, so a hook that only sometimes times out is
`effect-varies`. Reasons are compared by the SHA-256 of the recorded `reason`
string and are never written out.

## Output

- `stability.json`, schema `repeat-stability.v1`: context ID, repeat and
  comparable counts, per-class counts, the gate (`fail_on`, `status`), per-repeat
  source failures (code to count) and one row per event with its distinct
  `(effect, outcome)` variants and counts and its reason digests with counts.
  It holds no timing, path or hook output, so identical observations give
  byte-identical files.
- `stability.md`: the same summary for people, with event IDs and codes escaped
  by the same helper as the review reports. It lists at most 100 varying
  events; `stability.json` has all rows.
- `measurements.json`, schema `repeat-measurements.v1`: the per-repeat
  latency summaries. Observational only, never part of identity.

## Exit codes

| code | meaning |
|---|---|
| 0 | stable and healthy, or only classes outside `--fail-on` |
| 1 | a class named by `--fail-on` appeared (default `effect-varies`) |
| 3 | any source failure; takes precedence over 1 |
| 2 | invalid input, including an existing output |

`--fail-on` takes a comma-separated selection from `effect-varies`,
`outcome-varies` and `reason-varies`. As in `record`, a hook crash, timeout,
invalid output or start failure, a changed input or context, and a repeat that
cannot be recorded or read back are source failures. A flaky timeout is
therefore both `effect-varies` in the rows and exit 3; the per-repeat failure
counts show which.

## Limits

- Repeats run sequentially, so this measures variation under this host, timing
  and concurrency, not complete environment control.
- Agreement across N repeats is not proof of determinism.
- Reason variation can be benign, for example a timestamp in a message.
- The publication rename is not atomic against another writer creating an empty
  directory at `--output` in the same instant; a non-empty or file target is
  always refused.
