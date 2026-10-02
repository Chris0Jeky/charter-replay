# Changelog

## Unreleased

## 0.1.1 — 2026-10-02

- The package and runner version advance together to 0.1.1. Run identities include
  the runner version, so new replay run IDs differ from 0.1.0 even with identical
  policy and corpus inputs. Existing recordings retain their original manifests.

- A separate opt-in synthetic hook I/O probe captures fixed operation phases,
  allowlisted exception classes and bounded errno/winerror without private text.
  Attempts, execution and diagnostic output are capped. It covers real overflow
  followed by injected `EMFILE`; it does not diagnose the prior macOS OS condition
  or change production execution, mutation accounting or stable report formats.
- Recognized Windows CPython virtualenv launchers now fail process-source admission
  with a path-free input error before snapshots, policy invocation or report publication.
  Use a native replay controller and native process interpreter. Accepted v9 identities
  and snapshot guarantees remain unchanged. Real Windows native/venv regression
  coverage includes copied aliases and both argv encodings; CI adds Windows Python 3.14.
- **Bounded mutation sensitivity (R05-3).** `mutate` accepts explicit toy hook
  argv in `mutation-plan.v1`, checks two healthy baseline passes, and publishes
  deterministic killed/survived/invalid/timeout accounting. Only healthy effect
  differences count as killed; failures are excluded from the explicit score
  denominator. Plan/corpus bytes, input hashing, invocations, timeout sum and
  process output are bounded before or during execution. Includes a synthetic
  example and baseline/admission/context regressions; no security-proof claim.

- Aggregate document validation now rejects inconsistent event totals and gates,
  and malformed gate entries raise a fixed `AggregateInputError` instead of a
  `TypeError`. Valid `aggregate.v1` JSON and Markdown bytes are unchanged.
- **Kernel `report.md` renders free text literally (report-rendering change).** The
  event table cells (event id, classification, baseline and candidate effect and
  reason) and the source-failure lines now go through the same `markdown_literal`
  the review renderers use: each non-alphanumeric character becomes a numeric entity
  inside `<code>`, and control characters show as escapes, so links, mentions,
  backticks, pipes and HTML in a reason or an event id no longer render as Markdown.
  Table cells therefore look different (`<code>allow&#58; ...</code>`, and a line
  break shows as an escape instead of a space). `report.json`, `run-manifest.json`
  and the run identity are unchanged: the run id derives from the runner version,
  policy and corpus digests and `fail_on`, never from `report.md`, and no fixture or
  test pinned `report.md` bytes.
- The Action gains the `hook-output-limit` input (passed as `--hook-output-limit`
  only when non-empty) and the `summary-source` output (`summary.md`, `aggregate.md`,
  `none`, or empty when the summary step did not run). The self-test asserts the
  source in both summary modes and a 1 KiB flooding-hook case.
- A hook output stream that cannot be sized after the kill is now the indeterminate
  `output-limit` outcome (reason: output could not be sized against the limit), not
  `start-failed`. The kernel `process:` path is untouched.
- **Verified aggregate-only publication (`aggregate.v1`).** `hooks` now also writes
  `aggregate.json` and `aggregate.md` into `--output`: a deterministic, counts-only
  document (gate, diff-class counts, per-side hook outcomes and source-failure codes,
  `case_class` counts) with no event id, command, reason, family name, rationale,
  path, policy id or context id. Before writing, every free-text value of the report
  and the corpus and output paths is searched for in the rendered bytes; a hit
  refuses the aggregate (exit 3, fixed message, no echo). A new
  `charter-replay aggregate --report DIR --output FILE [--markdown FILE]` rebuilds it
  from a report directory after re-validating `report.json` against
  `run-manifest.json` (hook outcomes are then `null`), and refuses an existing output.
  Both files join the stale-output list. **Migration:** an output directory now holds
  two more files, and a `hooks` run whose aggregate is refused exits 3 (the summary is
  still written). See `docs/AGGREGATE.md`.
- The Action gains `summary-mode` (`full`, the default, or `aggregate`; anything else
  exits 2 before running) and the output `aggregate-path`. `aggregate` appends
  `aggregate.md` instead of `summary.md` to the job summary and keeps the CLI's stdout
  out of the step log.
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
- **Hook output is bounded.** `record`, `hooks` and `repeat` take
  `--hook-output-limit BYTES` (default 1 MiB per stream, 1 KiB to 64 MiB). A hook
  that prints more to stdout or stderr is killed with its whole process family (the
  POSIX process group or the Windows Job Object, the timeout kill path) and recorded as the new
  outcome `output-limit`: indeterminate, a `hook-output-limit` source failure (exit
  3), with a reason that names the stream and the limit and never the output.
  Reads are bounded to the limit plus one byte. **Migration:** a hook that legitimately
  prints more than 1 MiB on one stream now records `output-limit`; raise the limit.
  `summary.json` outcome counts gain an `output-limit` key. `hook-context.v1`
  `execution` gains `output_limit_bytes`, so every recording's context ID changes;
  files written before the field still validate. Kernel `process:` sources are
  unchanged. See `docs/HOOK_EXECUTION.md`.
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
