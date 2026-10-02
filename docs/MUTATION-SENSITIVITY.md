# Bounded hook mutation sensitivity

`charter-replay mutate` measures whether a corpus distinguishes an explicitly
selected hook mutation from a baseline. It executes only hook programs, with
corpus command strings passed as input. It never rewrites a hook or executes a
corpus command. Use reviewed synthetic toy hooks and public synthetic corpora.
Hooks are unsandboxed programs; the limits below constrain the controller and
supervised streams, not arbitrary files, memory or network activity by a hook.

## Run a synthetic example

From the repository root, with Python on PATH:

```sh
charter-replay mutate --plan examples/toy-guard/mutation-plan.json \
  --corpus charter_replay/corpora/charter --output reports/mutation
```

The output parent must exist; the output directory must be new. The example
compares toy v1 against toy v2 and an unchanged copy of v1. It should produce one
killed and one survived mutant, sensitivity 1/2, and exit 1. Toy v2 changes
multiple rules; this is a controlled decision difference, not an independent
assessment of policy correctness.

## Plan and admission

The strict `mutation-plan.v1` JSON contains exactly these fields:

```json
{
  "schema_version": "mutation-plan.v1",
  "baseline": ["python", "guard_v1.py"],
  "mutants": [
    {"id": "removed-rules", "hook": ["python", "guard_v2.py"]},
    {"id": "unchanged-control", "hook": ["python", "guard_v1.py"]}
  ]
}
```

Each hook is an argv array, never a shell command. Existing file arguments and
path-shaped executables resolve relative to the plan directory. Other arguments
remain literal. Bare executables resolve through PATH before recording. On
Windows an extensionless executable resolves as `.exe`, matching CreateProcess;
use a Python interpreter executable rather than a shell launcher. Directory
arguments and unresolved or unbound executable/file inputs are refused.

All plan hooks, the complete captured corpus, settings and destination are
admitted before any hook runs. Duplicate JSON keys, unexpected fields,
duplicate mutant IDs and missing scripts are errors. Each mutant ID matches
`[a-z0-9][a-z0-9._-]{0,63}`. The runtime, ask mapping, timeout and output cap
apply equally to baseline and mutants; jobs is always 1. Every event receives a
fresh workspace, including both baseline passes. No workspace template is used.

| Controller limit | Maximum |
|---|---:|
| Plan or corpus manifest | 64 KiB each |
| Events or cases file | 8 MiB each |
| File argument or executable, at admission | 8 MiB each |
| Hook input bytes across the plan, including repeated files | 32 MiB |
| Argv words / characters per word | 128 / 4096 |
| Mutants / corpus events | 32 / 1000 |
| Planned invocations, including two baseline passes | 2000 |
| Sum of planned per-invocation timeouts | 300 seconds |
| Per-invocation timeout | 10 seconds |
| Each supervised stdout/stderr stream | 1 MiB |

`--max-invocations` and `--max-timeout-seconds` can lower their respective limits.
The default timeout is 1 second; `--hook-timeout` can change it.
`--hook-output-limit` may lower the stream cap to as little as 1024 bytes.
The timeout sum is an admission budget, not a wall-clock deadline: process
startup, context hashing, workspace cleanup and publication add overhead.
Input preflight is checked before hashing; file sizes and input identities are
rechecked around recordings. This observes inputs, and is not an immutable
snapshot or protection against malicious concurrent input writers.

## Baseline sanity and accounting

The baseline must produce healthy, determinate effects on every event in two
passes, with identical effects between passes and unchanged declared input
context. A failed or indeterminate baseline is invalid; a timed-out baseline is
timeout; differing healthy effects make it unstable. Every mutant is then
reported invalid, with `executed: false` and `baseline-not-healthy`. No score is
computed. Two agreeing passes show observed stability only.

For a healthy baseline:

| Status | Meaning |
|---|---|
| killed | Healthy determinate mutant differs in effect on at least one event. |
| survived | Healthy determinate mutant matches every baseline effect. |
| invalid | Any non-timeout source failure, input/context change, unreadable recording or indeterminate effect. |
| timeout | The only source-failure category is hook timeout. |

Failures take precedence over changed effects. Mixed timeout and other failures
are invalid. Different reasons or runtime outcomes with the same determinate
effect do not kill a mutation. Sensitivity is `killed / (killed + survived)`,
with a null rate when the denominator is zero; invalid and timeout are excluded.
Survived includes equivalent mutations and mutations outside the corpus domain.
Mutation sensitivity is neither a security proof nor independent label agreement.

Exit 0 means a healthy baseline and every mutant killed. Exit 1 means at least
one survived, with no failures. Exit 2 means refused inputs before execution.
Exit 3 means baseline, mutant or publication failure, and takes precedence over
the survivor exit.

## Output and identity

The new output directory contains `mutation.json` (`mutation-sensitivity.v1`)
and `mutation.md`; the JSON completion marker is published last with the existing
no-replace publisher. Intermediate recordings are temporary and removed before
publication. An existing destination is never overwritten.

The stable report binds the exact corpus-manifest digest and the admitted
`hook-context.v1` ID for every hook. It contains counts, explicit score
denominators, fixed failure codes, mutant IDs and changed event IDs in corpus
order. It omits raw argv, commands, paths, reasons, timestamps and latency.
For identical declared inputs and observed effects/failures, report bytes are
identical. Timeout classification remains an observation under the host's
runtime conditions; this does not make timeout occurrence deterministic.

Event and mutant IDs and context digests remain present. This is a local review
artifact, not an aggregate-only privacy export. Context leaves helper imports,
executable dependencies, permissions, ambient environment values, external
state, network and time unbound. See [hook context](HOOK-CONTEXT.md) and
[hook execution](HOOK_EXECUTION.md). No runtime binary conformance or stronger
trust boundary is asserted by this evaluator.
