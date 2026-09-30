# Changelog

## Unreleased

- **Migration: `--runtime codex` changed.** It now selects the new
  `codex-pretooluse.v1` contract, built from the current Codex hooks documentation.
  Replies Codex documents as unsupported (`ask`, legacy `approve`, `continue:
  false`, `stopReason`, `suppressOutput`), malformed replies, `allow` and exit 2
  without a reason are `invalid-output` (indeterminate) instead of a deny, and no
  `CLAUDE_PROJECT_DIR` is set. The old behaviour is `--runtime codex-legacy`
  (`codex-legacy-floor.v1`, unchanged). `hook-context.json` records the contract id, so old
  and new recordings differ; old decision files replay unchanged. To reproduce a
  recording made before this change, pass `--runtime codex-legacy`. The contract is
  a documentation-derived model, not a certification. See
  `docs/RUNTIME_CONTRACTS.md`.
- `repeat` records one hook N times (2 to 50) over the same corpus and classifies each
  event as `stable`, `reason-varies`, `outcome-varies` or `effect-varies`, keyed by the
  hook context ID. It writes `stability.json` (`repeat-stability.v1`, no timing),
  `stability.md` and `measurements.json` into a new output directory, exits 1 for a
  class named by `--fail-on` and 3 for any source failure. See
  `docs/REPEAT-STABILITY.md`.
- `record` and `hooks` write `hook-context.json`: a versioned (`hook-context.v1`),
  input-only descriptor and SHA-256 context ID covering adapter, ask mapping,
  timeout and jobs, hook executable and argv file bytes, the workspace template
  and environment names, with unbound inputs declared. A change during recording
  fails with `hook-context-changed`. `summary.json` adds `contexts`. See
  `docs/HOOK-CONTEXT.md`.

## 0.1.0 (2026-09-29)

First release.

- `charter-replay hooks` records two PreToolUse command hooks over a corpus and
  reports newly blocked, newly allowed, unchanged and indeterminate decisions,
  broken down by case class and family, with a regression exit code.
- `charter-replay record` writes one hook's decisions as a recorded source.
- `charter-replay replay` and `validate` compare recorded or process sources
  over a pinned corpus (the decision-replay kernel).
- `charter-replay import` builds a private, scrubbed corpus from local Claude
  Code and Codex transcripts.
- Corpora: `charter` (50 hand-labelled cases) and `charter-v0.2` (494 cases).
