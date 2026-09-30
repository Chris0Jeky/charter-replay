# Hook execution and failure evidence

`hooks` validates both hook commands, both workspace arguments, the comparison
gate, the timeout and the worker count before invoking either hook. Timeout must
be finite, greater than zero and at most 86400 seconds. Jobs must be positive.
JSON argv must not contain NUL bytes. The same validated corpus capture supplies
both hook invocations and the final comparison, even if on-disk corpus files
change during invocation. The report binds the bytes the hooks actually saw,
not a second read. A caller-selected hook is still an
unsandboxed executable; corpus commands remain input data and never execute.

## Exit-code precedence

A hook's crash, timeout, invalid output or inability to start has an
indeterminate effect and is also an explicit source failure. Identical failures
on both sides are not a healthy unchanged comparison. The kernel report and
hook summary share the same error gate and source failures.

- 0: valid comparison, no configured regression and no invocation failure.
- 1: valid comparison with a configured regression and no invocation failure.
- 2: invalid input or broken exact-byte binding.
- 3: hook/source failure after usable decisions can be formed, or report output failure.

Exit 3 has two causes that stderr tells apart: `replay gate error` (or
`gate error` for `record`) means failures were recorded and the outputs were
written; `output failed` means an output could not be written or published.

`hooks` removes the previous run's derived files from `--output` (`baseline/`,
`candidate/`, `report/`, `summary.json`, `summary.md`) once both sides are
admitted and before any hook runs, so a failed rerun cannot leave earlier
results looking current. Only regular files with those exact names are
removed; a link or directory on one of those names, or a linked `report/`,
`baseline/` or `candidate/`, is refused with exit 2 before anything is
deleted.

Exit 3 takes precedence over exit 1. A hook's exit 2 is a deny decision, not a
process failure. An ask mapped to indeterminate by `--ask-as` is not itself a
process failure; it remains a configured policy mapping and can trigger exit 1.

`record` also returns 3 for invocation failures while retaining valid recorded
decisions and its diagnostic outcomes file. Replaying those decisions later
compares recorded effects only; it does not rerun the original hook or infer
process health from a reason string. Failure evidence for the immediate `hooks`
comparison comes directly from the recorder's structured observations.

The JSON report stays free of machine-local reproduction paths. The existing
kernel Markdown includes local reproduction argv, and legacy report timestamps
still require `SOURCE_DATE_EPOCH` for byte-identical reruns. Timing remains an
observation, not part of decision identity.

## Event workspace isolation

Every event receives its own fresh workspace, including a fresh copy of a
template when supplied. Serial and parallel workers preserve input order but
share no writable replay workspace. The process cwd equals the payload cwd
inside that event's workspace; `CLAUDE_PROJECT_DIR` still names its root (except
under `--runtime codex`, which sets no project-dir variable). A
resolved cwd outside that root is rejected before invocation.

The recorder reuses the kernel's read-only-aware cleanup on every event,
including error paths. A partial template copy is removed when preparation
fails. Preparation failures become recorded indeterminate source failures.
If cleanup fails after a real hook reply, that reply is retained and an explicit
`hook-workspace-cleanup-failed` source failure makes the comparison an error
and returns exit 3. Cleanup failure does not manufacture a different decision.

Copying a large template per event costs IO. This is an intentional correctness
trade-off. Templates are caller-trusted input, not immutable identity-bound
snapshots yet. An unsandboxed hook can still access shared external state such
as its home directory, the network or absolute paths; workspace isolation does
not claim to isolate the entire machine or certify hook determinism.
