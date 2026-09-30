# charter-replay

Compare coding-agent command policies against a pinned replay corpus and catch decision regressions before release.

![A replay of two versions of a guard hook](docs/demo.gif)

```bash
python -m pip install .
```

```bash
charter-replay hooks   --baseline "python examples/toy-guard/guard_v1.py"   --candidate "python examples/toy-guard/guard_v2.py"   --corpus charter_replay/corpora/charter   --output reports/demo
```

> This re-evaluates recorded command events and decisions. It does not reproduce the original agent, environment, shell effects, or operating-system boundary.

## Measure a hook

`charter-replay hooks` runs two PreToolUse command hooks over a corpus and
diffs their decisions: newly blocked, newly allowed, unchanged, and newly
indeterminate (errors and timeouts), broken down by case class and family. It
exits 1 when a class named by `--fail-on` appears (default: newly allowed or
newly indeterminate). `record` runs one hook and writes a recorded decision
source that the kernel `replay` command accepts as `recorded:<path>`.

Each hook runs once per command, as the runtime runs it: shell-free argv, the
PreToolUse JSON on stdin, `cwd` inside a fresh workspace (optionally copied
from `--workspace`), and `CLAUDE_PROJECT_DIR` set to that workspace (not under `--runtime codex`). A hook
command is a JSON array or POSIX-quoted words. On Windows, `py -3` works as the
interpreter and forward slashes avoid quoting trouble.

Each recording also writes `hook-context.json`, an input-only identity for what
the hook was given (see [docs/HOOK-CONTEXT.md](docs/HOOK-CONTEXT.md)); it is a
consistency key, not execution authentication.

`charter-replay repeat` records one hook N times (2 to 50) and classifies each
event as stable or as varying in reason, outcome or effect, keyed by that context
ID; see [docs/REPEAT-STABILITY.md](docs/REPEAT-STABILITY.md).

| hook reply | outcome | replay effect |
|---|---|---|
| exit 2 (stderr is the reason) | deny | deny |
| exit 0, no output, or JSON with no decision | allow | allow |
| `permissionDecision` allow / deny | allow / deny | allow / deny |
| `permissionDecision` ask | ask | `--ask-as` (default deny) |
| legacy `decision` approve / block | allow / deny | allow / deny |
| `continue: false` | stop | deny |
| any other exit code | crash | indeterminate |
| exit 0 with unreadable output | invalid-output | indeterminate |
| no reply within `--hook-timeout` | timeout | indeterminate |
| executable cannot start | start-failed | indeterminate |

The outcome is the prefix of each recorded reason, and `outcomes.jsonl` keeps
the exit code and latency per event. The runtime itself lets a command proceed
after a crash or timeout; indeterminate keeps those visible instead. With
`--runtime codex-legacy`, `ask` becomes deny, the v0.1 floor kept so old
recordings reproduce; it is not fail-safe, because Codex fails the hook and lets
the call continue.

`--runtime codex` is the versioned `codex-pretooluse.v1` contract, modelled on
the Codex hooks documentation (not certified against a running Codex). Its payload
adds `turn_id` and a null `transcript_path`, and no `CLAUDE_PROJECT_DIR` is set.
Replies Codex documents as unsupported (`ask`, legacy `approve`, `continue:
false`, `stopReason`, `suppressOutput`), malformed or unknown-field JSON, an
`allow` (which Codex supports only with an `updatedInput` rewrite) and exit 2
without a stderr reason are `invalid-output` and indeterminate, so the runtime's
fail-open shows up as exit 3 rather than as a block. `--ask-as` has no effect
under `codex`, since `ask` is not a decision there. The context id in
`hook-context.json` differs between the two runtimes. Reply table and sources:
[docs/RUNTIME_CONTRACTS.md](docs/RUNTIME_CONTRACTS.md).

`charter-replay import` builds a private corpus from local Claude Code and
Codex transcripts. It scrubs credentials, home paths, the local user, host and
Git identity, email addresses, private hosts and repository names, and it
refuses to write inside a Git work tree unless Git ignores the target. The
output is private even after scrubbing: never commit it.

## Kernel reference

Replay v0 compares two policy-decision streams for a small, privacy-safe command corpus. It is a
deterministic comparison tool, not a live command interceptor, policy-authoring framework, safety
proof, or benchmark.

The checked-in charter has 50 inert command strings: 20 synthetic catastrophe-boundary cases, 20
synthetic non-executing near-misses, and 10 fully re-authored historical/opaque shapes. The runner
never executes those command strings. Classification comes only from validated baseline and
candidate `PolicyDecision` effects keyed by `event_id`.

## Quick start

Validate the exact-byte corpus manifest:

```text
python -m charter_replay.cli validate --corpus charter_replay/corpora/charter
```

Run the clean reference comparison:

```text
python -m charter_replay.cli replay --baseline recorded:charter_replay/fixtures/legacy-decisions.jsonl --candidate process:python,charter_replay/tests/fixtures/process_policies/reference_candidate.py --corpus charter_replay/corpora/charter/events.jsonl --output .local/replay-proof
```

The command writes `run-manifest.json`, `report.json`, and `report.md`. The Markdown report keeps a
JSON argv array as the portable reproduction source of truth and labels its additional rendering
as either POSIX `sh` or Windows PowerShell; it never claims `cmd.exe` compatibility. Arguments
outside the proved nonempty, single-line shell subset keep the structured argv but omit the shell
form. Path-bearing reproduction material remains outside deterministic `report.json`.

Exit `0` means the configured gate passed, `1` means a configured change class was present, `2`
means an input or exact-byte binding was invalid, and `3` means a policy process failed after a
reportable comparison could be formed.

Run the authoritative dependency-free test lane with:

```text
python -m unittest discover -s charter_replay/tests -v
```

After installing the owner-approved development requirements, prove Pytest compatibility with:

```text
python -m pytest -q charter_replay/tests
python -m pytest -q charter_replay/tests/unit charter_replay/tests/contract
```

## Process argument encodings

`process:executable,arg,policy-file` retains the original bare comma-separated
contract. Commas are separators; quotes and backslashes have no escaping meaning.
Use the explicit `process-json:` prefix when a value contains a comma. Its payload
is exactly one JSON array of strings, not a shell command or a path to a JSON file.
The first string identifies the executable and the final string identifies the
policy file. Intermediate strings are passed literally and in order.

Construct the reference with a JSON encoder and pass it as a single CLI argument:

```python
import json
import subprocess
import sys

candidate = "process-json:" + json.dumps(
    [sys.executable, "-B", "policies/my candidate,final.py"]
)
subprocess.run(
    [
        sys.executable, "-m", "charter_replay.cli", "replay",
        "--baseline", "recorded:charter_replay/fixtures/legacy-decisions.jsonl",
        "--candidate", candidate,
        "--corpus", "charter_replay/corpora/charter/events.jsonl",
        "--output", ".local/replay-proof",
    ],
    check=True,
)
```

Both baseline and candidate accept either process encoding. JSON must contain at
least two nonempty strings; NUL, CR/LF and unpaired Unicode surrogates are rejected
before any policy executes. Invalid JSON, nested values, numbers, trailing data
and empty entries return input-invalid exit 2 with a bounded diagnostic. JSON
whitespace and ordinary JSON string escapes are supported. There is no fallback
to comma parsing, shell expansion, CSV parsing or filename-based autodetection.

This is an additive CLI encoding, not a process identity version change. Equivalent
decoded argv values use the same existing identity, executable/policy validation,
snapshot isolation and timeout. The Markdown report's structured reproduction
retains the chosen input encoding, so rerunning it preserves comma-bearing values.
The policy still runs as an unsandboxed program; JSON encoding grants no additional
isolation or authority.

## Baseline truth

Despite its compatibility filename, `fixtures/legacy-decisions.jsonl` is a synthetic
freeze-candidate expectation for the curated charter. It was not captured by executing the private
legacy dispatcher. The owner-approved `floor-v1-final` tag now exists at
`02bd14cfe094f9b6af85b966de481ff3f45264cf`, but that immutable implementation tag does not turn
this synthetic recording into captured dispatcher output. Its sidecar policy ID and every decision
reason preserve that distinction.

The reference candidate is equally narrow: it maps the 50 reviewed fixture event IDs to expected
effects. It does not parse command text or reproduce the frozen dispatcher.

## Reproducibility and limits

Corpus and recorded-source manifests bind exact bytes with SHA-256. A run ID binds the runner
version, both policy-source identities, the corpus-manifest digest, and gate configuration. Process
startup captures every corpus file and both recorded-source files once, validates those captured
bytes, and retains the same immutable bytes for parsing and evaluation. Replacing a validated path
later therefore cannot change a result under the earlier manifest or policy identity. Process
identity v9 includes the executable's lexical invocation basename, the resolved executable target's
bytes and four-octal-digit permission mode, entry-policy bytes, the relative names, exact
regular-file bytes, and permission modes for the policy-parent root and entries, configured
timeout, fixed environment, fixed `0700` runner-owned directory modes on POSIX, and policy-parent
working-directory contract. It also binds an opaque SHA-256 digest of the selected resolved
snapshot parent without writing that absolute path to the run manifest. Process identities are
therefore conservatively host/path-sensitive when policy-visible temporary roots differ. The digest
is machine-derived data and can confirm an offline guess of a common temporary path; it avoids
plaintext disclosure but is not a secrecy boundary. Process-source run IDs are host-context
evidence, not portable cross-host correlation keys. V9 also
binds the snapshot-mtime contract: every copied file and directory has modification time
`946684800000000000` ns (2000-01-01T00:00:00Z). An
executable alias and its target have distinct identities when their invocation names differ, while
the snapshot still binds the resolved target bytes. Immediately before each process runs, the runner
copies the bound executable and complete policy-parent tree into a private temporary snapshot,
verifies that the snapshot's entry-policy bytes, executable bytes and permission mode, and complete
tree digest exactly match the identity, normalizes every snapshot mtime, verifies that fixed mtime
before and after execution, and launches the policy only from the snapshot paths. Changing only a
source mtime therefore preserves the identity and run ID and cannot change the copied mtime observed
by the policy. The resolved parent is captured once while the source is loaded and reused during
evaluation; the private root suffix is derived from the process identity. Consequently,
`cwd`, `argv[0]`, and policy-file paths exposed by a successful run remain stable for that identity,
and changing the selected parent changes the identity and run ID. A missing parent or pre-existing
identity path fails closed; a pre-existing path is neither reused nor removed. A candidate snapshot
equal to or below the resolved policy tree fails closed before creation or copy. V0 does not
serialize concurrent evaluations of the same identity, so overlapping evaluations can make one
source fail closed and should be run sequentially.
Permission differences preserved by the copy therefore
produce distinct identities and run IDs even when names, bytes, and execute bits are unchanged.
Changing or removing an original path after snapshot preparation therefore cannot change what the
process opens. A mismatch or unavailable input produces `indeterminate`; a cleanup failure is also
a source failure. Cleanup may restore write permission only inside the runner-created private
snapshot so copied read-only inputs can be removed; it never changes the original policy tree.
Corpus and run manifests require at least one event, so an empty or truncated corpus cannot
produce a vacuous pass.

The snapshot is reproducibility containment, not an operating-system sandbox. A hostile process
running as the same OS user may still be able to discover or rewrite temporary storage, and policy
behavior after process start remains outside the snapshot guarantee. Pre/post verification catches
ordinary snapshot drift but is not an atomic defence against a same-user mutate-and-restore attack.
A generic executable must be
relocatable enough to run from the snapshot; adjacent loader libraries are copied as unbound
runtime dependencies, and Python uses its host base prefix for its unbound standard library. If the
captured executable cannot start, replay fails closed instead of falling back to the original path.
External installed dependencies, files outside the policy tree, network responses, and other host
metadata remain outside the identity; access/change/birth times and filesystem object identities
are not normalized. Callers that depend on them must isolate and record that environment.

Policy standard streams are backed by temporary files, so waiting for inherited pipe EOF cannot
extend the configured timeout. On Windows an event-gated supervisor enters a
kill-on-close Job Object before it can launch the policy and contains the policy process family. On
POSIX the policy root starts in a new session and root process group; timeout and normal root
completion send `SIGKILL` only to that root process group with bounded cleanup, so descendants that
remain in it cannot outlive replay. A descendant that calls `setpgid`/`setpgrp` to create another
group in the same session, or `setsid` to create another session, leaves POSIX v0 containment and
may continue from a deleted snapshot. Process output has no byte quota. An escaped POSIX descendant
can retain its temporary-file stream handles and continue consuming disk after timeout and after
replay returns; replay no longer observes or caps that output. Callers requiring stronger
containment must isolate the process externally.

The three report artifacts are fully staged before publication. Replacing an existing report set
uses rollback: a publication error restores the prior complete set instead of leaving a new
manifest beside old results. This is an in-process failure guarantee, not an operating-system crash
transaction; callers still own durable artifact storage.

Reports describe changes between decisions. They never claim that an original command was safe,
unsafe, executed, or reproduced. The checked-in reference and test lane performs no network access
and never imports or runs the legacy dispatcher. A caller-supplied `process:` policy is an
unsandboxed program and may use the network or filesystem unless the caller isolates it.
