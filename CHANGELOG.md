# Changelog

## Unreleased

- A hook working directory outside its event workspace is now a per-event
  `start-failed` outcome (a source failure, exit 3) recorded like any other start
  failure, not a whole-run input error (exit 2) that stops the recording.
- `validate_hook_context` rejects a runtime and contract id that are not a known
  pair (derived from the runtime registry, plus the historical `codex` with
  `codex-legacy-floor.v1`). A `--workspace` template that reaches the output
  through a symlink or junction is `contains-output`, and an argv word with
  whitespace is hashed whole even when it starts with `/`, so the context id of
  a hook with such a word can change.
- `hooks` re-checks each output subdirectory before every stale-file removal and
  reports several failed removals as one exit 3. `repeat` retries the final
  rename on `PermissionError` and, if it stays locked, keeps the recordings in a
  hidden `.charter-repeat-*` directory (exit 3). A stdout that cannot encode the
  summary (a Windows cp1252 pipe) no longer changes the exit code.
- **New runtime `gemini`** (`--runtime gemini`, contract `gemini-beforetool.v1`), the
  third adapter, built from the Gemini CLI hooks documentation and the upstream
  hook runner (pinned in `docs/RUNTIME_CONTRACTS.md`). The payload is a `BeforeTool`
  event for `run_shell_command`; `decision` deny/block and exit 2 deny,
  `continue: false` is `stop`, and other exits, non-JSON stdout, `tool_input`
  rewrites, `ask`, unknown fields, duplicate keys and BOM-prefixed replies are
  indeterminate. The hook gets `GEMINI_PROJECT_DIR`, `GEMINI_SESSION_ID` and
  `CLAUDE_PROJECT_DIR`. A documentation- and source-derived model, not a
  certification. The Claude, `codex` and `codex-legacy` contracts are unchanged.
  The Action's `runtime` input accepts `gemini`.
- **Migration: `--runtime codex` changed.** It now selects the new
  `codex-pretooluse.v1` contract, built from the current Codex hooks documentation.
  Replies Codex documents as unsupported (`ask`, legacy `approve`, `continue:
  false`, `stopReason`, `suppressOutput`), malformed, duplicate-key or
  BOM-prefixed replies,
  `permissionDecision: allow` (with or without `updatedInput`) and exit 2 without a
  reason are `invalid-output` (indeterminate), and no `CLAUDE_PROJECT_DIR` is set.
  Under the old floor `ask` was a deny and `allow`/`approve` were allows; a hook
  that returns an explicit allow now exits 3 on every event. The old behaviour is
  `--runtime codex-legacy` (`codex-legacy-floor.v1`, same decisions). Its
  `hook-context.json` records runtime `codex-legacy`, so its context id differs
  from a pre-change recording even though the decisions reproduce; old decision
  files replay unchanged. The contract is a documentation-derived model, not a
  certification. See `docs/RUNTIME_CONTRACTS.md`.
- Every runtime classifies JSON nested past the parser's recursion limit as
  `invalid-output` instead of aborting the whole recording.
- A least-privilege composite GitHub Action (`action.yml`) runs `charter-replay hooks`
  in the caller's job: inputs reach the CLI through `env:` only, outputs are
  `exit-code`, `gate` and `output-dir`, the job summary is bounded, and it needs no
  token permissions and uploads nothing. A self-test workflow exercises it with
  `uses: ./` on Linux, Windows and macOS. See `docs/ACTION.md`.
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
