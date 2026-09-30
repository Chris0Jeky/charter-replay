# Runtime contract research notes

Checked against official documentation on 2026-09-29. These notes are external
research, not observations from running the installed runtimes. Documentation
can change; certify an adapter against a pinned runtime revision before claiming
exact runtime fidelity.

## Claude Code

Source: <https://code.claude.com/docs/en/hooks>.
PreToolUse exchanges JSON over stdin/stdout. Its structured output identifies
the event and permission decision. Exit 2 blocks; other nonzero exits are
non-blocking errors. The existing harness maps failures to indeterminate so a
runtime's fail-open behaviour is never silently treated as safe allowance.
The extracted adapter initially preserves the v0.1 contract, including the
supported legacy fields. Input rewriting and newer decisions need distinct
capability tests and are not certified by that extraction.

## Codex

Two contracts, selected by `--runtime`:

- `codex` is `codex-pretooluse.v1`, built from the documentation below. It is a
  documentation-derived model, not a certification against a running Codex
  binary. Pin a Codex revision and run its hooks before claiming fidelity.
- `codex-legacy` is `codex-legacy-floor.v1`, the v0.1 recorder behaviour: the
  Claude grammar with `ask` mapped to deny and the Claude environment. It is kept
  byte for byte so old recordings' decisions can be reproduced (the new
  recording's context id differs, since it names runtime `codex-legacy`). It is
  not fail-safe: Codex
  does not deny on `ask`, it fails the hook and lets the call continue. The
  context id in `hook-context.json` tells the two apart. Old recorded decision
  files replay unchanged, because replay compares recorded effects only.

Sources, retrieved 2026-09-30 (the pages show no version or date):

- <https://developers.openai.com/codex/hooks> (308 redirect to the official
  hooks reference at <https://learn.chatgpt.com/docs/hooks>). Read as data.
- The open-source implementation the docs describe, `openai/codex` at
  `d8f69ea` (2026-09-30): `codex-rs/hooks/schema/generated/pre-tool-use.command.{input,output}.schema.json`,
  `codex-rs/hooks/src/engine/output_parser.rs`, `codex-rs/hooks/src/events/pre_tool_use.rs`.
  Where the prose is thin the parser is used as corroboration, and any point on
  which prose and parser could differ is classified indeterminate below.

What the contract encodes:

- **Input.** One JSON object on stdin. Fields: `session_id`, `turn_id` (a Codex
  extension), `transcript_path` (string or null), `cwd`, `hook_event_name`,
  `model`, `permission_mode`, `tool_name`, `tool_use_id`, `tool_input`. For a
  shell command `tool_name` is `Bash` and `tool_input` is `{"command": ...}`. The
  replay sends `transcript_path: null` and no `agent_id`/`agent_type` (subagent
  only).
- **Environment.** The docs name only plugin hook variables (`PLUGIN_ROOT`,
  `PLUGIN_DATA`, and their `CLAUDE_PLUGIN_*` aliases). The replay provides none
  of them and no `CLAUDE_PROJECT_DIR`; the hook gets the replay's allow-listed
  passthrough environment and runs with the session `cwd` as working directory.
- **Exit 0, no output:** success, the call continues (outcome allow). Plain
  text on stdout is ignored (allow). JSON on stdout is parsed: no decision field
  continues (allow); `systemMessage` and `additionalContext` alone are not
  decisions.
- **Exit 2 with a stderr reason** blocks (deny; the reason is the trimmed
  stderr). Exit 2 with empty stderr is a failed hook that continues, so it is
  `invalid-output`. Any other exit code fails the hook run and the call
  continues; the harness records it as `crash` (indeterminate), as for Claude.
- **Decisions.** `permissionDecision: deny` needs a non-empty reason. The older
  `{"decision": "block", "reason": ...}` is also accepted and denies. Allowing
  is documented only together with `updatedInput`, which rewrites the command.
- **Unsupported output.** The docs say `permissionDecision: "ask"`, legacy
  `decision: "approve"`, `continue: false`, `stopReason` and `suppressOutput`
  are "parsed but not supported yet", and that Codex "marks the hook run as
  failed, reports the error, and continues the tool call". Malformed JSON that
  starts with `{` or `[`, unknown fields, `hookSpecificOutput` without a
  `hookEventName`, `deny` or `block` without a reason, `updatedInput` without
  `allow`, and `allow` without `updatedInput` fail the same way in the parser.
  All of these are `invalid-output`, an indeterminate effect, with a reason
  such as `invalid-output: ask is unsupported by codex`. A recording that hits
  one exits 3 (`hook-invalid-output` source failure), so the fail-open stays
  visible instead of scoring as a block.
- **Timeout.** The documented default is 600 seconds; the replay keeps its own
  `--hook-timeout` (default 10) and records `timeout`, indeterminate.
- **`--ask-as`.** `ask` is not a Codex decision, so this contract never emits
  the `ask` outcome and `--ask-as` has no effect on a `codex` recording. The
  option is still accepted and appears in the context descriptor, so an
  otherwise identical recording with a different `--ask-as` has a different
  context id.

Reply mapping (`codex`):

| reply | outcome | effect |
|---|---|---|
| exit 0, no output; plain-text stdout; JSON with no decision | allow | allow |
| exit 2 with stderr | deny | deny |
| `permissionDecision` deny with reason; legacy `block` with reason | deny | deny |
| other exit code | crash | indeterminate |
| exit 2 with empty stderr | invalid-output | indeterminate |
| `ask`; legacy `approve`; `continue:false`; `stopReason`; `suppressOutput` | invalid-output | indeterminate |
| `allow` with `updatedInput` (a rewrite the replay cannot evaluate) | invalid-output | indeterminate |
| `allow` without `updatedInput`; `updatedInput` without `allow` | invalid-output | indeterminate |
| deny/block without a reason; reason without decision | invalid-output | indeterminate |
| malformed or unknown-field JSON; non-object JSON; other `hookEventName` | invalid-output | indeterminate |
| duplicate member names; stdout starting with a byte-order mark; JSON nested past the parser limit | invalid-output | indeterminate |
| both modern and legacy decision fields in one reply | invalid-output | indeterminate |

Ambiguities resolved toward indeterminate (never toward allow or deny):

- `allow` with `updatedInput` is documented as supported, but the command that
  then runs is not the corpus command, so no allow or deny is claimed. It is
  reported as `invalid-output` because the contract does not model rewrites; that
  name overstates a supported reply and is tracked as a limitation.
- A `hookEventName` other than `PreToolUse`: the published schema requires
  `PreToolUse`, the parser accepts any known event name. Treated as invalid.
- A reply carrying both `hookSpecificOutput` decision fields and top-level
  `decision`/`reason`: the docs do not say which wins. Treated as invalid.
- A JSON scalar or array on stdout: plain text is documented as ignored, but a
  JSON non-object is not addressed. Treated as invalid rather than as allow.
- Duplicate member names: Python keeps the last one, while a strict parser
  rejects the reply. Treated as invalid so neither order scores a decision.
- A byte-order mark before the reply (PowerShell's default encoding) is not
  addressed by the docs. Treated as invalid rather than as ignored plain text.
- Hooks configured as asynchronous cannot apply control effects; the replay
  models synchronous command hooks only.
- The tool identity for shell calls is documented as `Bash`; other shell aliases
  and non-shell tools are not modelled.

## Gemini CLI

`gemini` is `gemini-beforetool.v1`, selected by `--runtime gemini`. It is a
documentation- and source-derived model of the BeforeTool command hook, not a
certification against a running Gemini CLI binary. Pin a Gemini CLI revision and
run its hooks before claiming fidelity.

Sources, retrieved 2026-09-30 (the pages show no version or date). All fetched
text was read as data:

- <https://geminicli.com/docs/hooks/> and <https://geminicli.com/docs/hooks/reference/>
  (the same text as `docs/hooks/{index,reference,best-practices,writing-hooks}.md`
  in the repository below).
- The open-source implementation, `google-gemini/gemini-cli` at
  `38700b4b38bf387dafded6c97c3f190d084b49e9` (main, 2026-09-29; latest release
  `v0.62.0`): `packages/core/src/hooks/{types,hookRunner,hookAggregator,hookEventHandler}.ts`,
  `packages/core/src/core/coreToolHookTriggers.ts`,
  `packages/core/src/scheduler/hook-utils.ts` and
  `packages/core/src/tools/definitions/base-declarations.ts`. The prose is thin
  in places, so the runner is used to corroborate it, and any point on which the
  two differ is classified indeterminate below.

What the contract encodes:

- **Input.** One JSON object on stdin. Base fields `session_id`,
  `transcript_path` (a string), `cwd`, `hook_event_name` (`BeforeTool`) and
  `timestamp` (ISO 8601), plus `tool_name` and `tool_input`. For a shell command
  `tool_name` is `run_shell_command` and `tool_input` carries the documented
  `command` argument (the tool also takes `description`, `dir_path` and
  `is_background`; the replay sends only `command`). `mcp_context` and
  `original_request_name` are for MCP and tail calls and are not sent. The replay
  uses a fixed `timestamp` (`1970-01-01T00:00:00.000Z`) so recordings do not
  depend on the clock, and an empty `transcript_path`, which the runtime also
  sends when it has no recording. Upstream has no `model`, `turn_id` or
  `permission_mode` field.
- **Environment and cwd.** The docs list `GEMINI_PROJECT_DIR`,
  `GEMINI_PLANS_DIR`, `GEMINI_SESSION_ID`, `GEMINI_CWD` and `CLAUDE_PROJECT_DIR`
  (an alias). The replay provides `GEMINI_PROJECT_DIR` and `CLAUDE_PROJECT_DIR`
  (both the replay workspace) and `GEMINI_SESSION_ID` (`replay-session`). It does
  not provide `GEMINI_CWD` (the adapter interface has no per-event value; the
  hook still runs with the event `cwd` as working directory) or `GEMINI_PLANS_DIR`
  (a machine-specific path). Upstream sets `GEMINI_PROJECT_DIR` to the payload
  `cwd`, while the docs call it the project root; the replay follows the docs.
- **Exit 0, no output:** success (allow). Empty stdout with non-JSON stderr is
  also allow: stderr is only a log.
- **Exit 2 with a stderr reason** blocks (deny; the reason is the trimmed
  stderr). The turn continues.
- **Decisions.** `decision: "deny"` (alias `"block"`) needs a reason and denies;
  `decision: "allow"`, no decision, `systemMessage`, `suppressOutput`, and a
  `stopReason` or `reason` without a matching decision are allow.
  `continue: false` stops the whole agent loop and the tool call never runs; it is
  recorded as the `stop` outcome (a deny effect), as for Claude.
- **Failed hooks that let the call continue.** The docs say any other exit code is
  a warning and the call proceeds, and that stdout which is not JSON makes
  parsing fail, defaulting to allow with the text shown as a message. Neither is
  scored as an allow: another exit code is `crash`, and non-JSON stdout is
  `invalid-output`, both indeterminate. A recording that hits one exits 3, so a
  blocking hook spoiled by a stray `echo` stays visible.
- **Unsupported output.** `hookSpecificOutput.tool_input` merges over the model
  arguments, so the command that runs is not the corpus command: `invalid-output`
  (not modelled), unless the reply denies or stops, in which case nothing runs.
  Also `invalid-output`: `decision` `ask` or `approve`, unknown top-level or
  `hookSpecificOutput` fields (including Claude- and Codex-style
  `permissionDecision`), `hookSpecificOutput` without `hookEventName` or with one
  other than `BeforeTool`, wrong-typed members, deny or block without a reason,
  non-object JSON, malformed JSON, duplicate member names, a byte-order mark, and
  JSON nested past the parser limit.
- **Timeout.** The documented default is 60000 ms; the replay keeps its own
  `--hook-timeout` (default 10) and records `timeout`, indeterminate.
- **`--ask-as`.** `ask` is not a documented BeforeTool decision, so this contract
  never emits the `ask` outcome and `--ask-as` has no effect on a `gemini`
  recording. The option still appears in the context descriptor.

Reply mapping (`gemini`):

| reply | outcome | effect |
|---|---|---|
| exit 0, no output (stderr is a log); no decision; `decision: allow` | allow | allow |
| exit 2 with a plain-text stderr reason | deny | deny |
| `decision` deny or block with a reason (a rewrite beside it is moot) | deny | deny |
| `continue: false` (the reason falls back through `stopReason`, `reason`) | stop | deny |
| other exit code, including a JSON deny printed on a warning exit | crash | indeterminate |
| non-JSON stdout on exit 0 | invalid-output | indeterminate |
| `hookSpecificOutput.tool_input` without a deny or stop | invalid-output | indeterminate |
| `ask`; `approve`; unknown decision text; unknown fields; wrong types | invalid-output | indeterminate |
| deny/block without a reason | invalid-output | indeterminate |
| missing or other `hookEventName`; non-object or malformed JSON | invalid-output | indeterminate |
| duplicate member names; byte-order mark; JSON nested past the parser limit | invalid-output | indeterminate |
| exit 2 with empty stderr, with any stdout, or with JSON on stderr | invalid-output | indeterminate |
| exit 0, empty stdout, JSON on stderr | invalid-output | indeterminate |

Ambiguities resolved toward indeterminate (never toward allow or deny):

- Exit 2: the docs say the action is blocked with stderr as the reason. The runner
  reads stdout first (falling back to stderr), uses the exit code only for
  non-JSON text, and lets a call with no output at all continue. So exit 2 with
  empty stderr, with any stdout, or with JSON on stderr is `invalid-output`; only
  exit 2 with a plain-text stderr and empty stdout, where both agree, is a deny.
- Exit codes other than 0 and 2: the docs say the call continues. The runner
  ignores the exit code when the output is JSON (so a deny printed on exit 1 still
  blocks) and turns plain text on exit 3 or above into a deny, though its exit 1
  becomes a warning. All of them are `crash`.
- stderr: the docs say it is never parsed as JSON. The runner parses it when
  stdout is empty, so JSON on stderr with empty stdout is `invalid-output`.
- Non-JSON stdout on exit 0 is documented as allow but also as a failure. It is
  `invalid-output`, not allow. The runner also accepts a JSON string that itself
  holds JSON (double-decoded), an array, or `null`; the docs do not, so these are
  `invalid-output`.
- Duplicate member names: Node `JSON.parse` and Python both keep the last one,
  while the docs are silent. Treated as invalid so neither order scores a decision.
- A byte-order mark: the runner `trim()` strips it, so upstream would accept the
  reply; the docs are silent and a PowerShell hook emits it by default. Treated as
  invalid rather than as plain text or as JSON. On stderr the mark is stripped
  before the JSON check, as upstream does, so BOM-prefixed JSON on stderr is the
  same ambiguous case as plain JSON on stderr, never a reason or an allow.
- `decision: "ask"` and `"approve"` exist in the upstream types, and the scheduler
  turns `ask` into a user confirmation, but the reference documents only `allow`
  and `deny` (alias `block`). Treated as invalid.
- Deny without a reason: the docs call `reason` required; the runner blocks anyway
  with a placeholder reason. Treated as invalid (the docs' rule wins).
- A deny beside a `tool_input` rewrite: the runner blocks before it applies the
  rewrite, and the docs say a rewrite applies before execution. Scored as a deny.
- `continue: false` also ends the agent session, which the replay does not model;
  only the fact that this call never runs is recorded.
- `hookSpecificOutput` is required to carry `hookEventName` (the upstream output
  type requires it, the runner does not check it).
- Multiple hooks for one event are merged by the runner (any block wins); the
  replay models one synchronous command hook per event, with no `matcher`,
  `sequential` or `env` configuration. Only the shell tool is modelled.

## Certification checklist

Record runtime version/revision, source URL and fixture provenance. Cover payload
fields, process cwd, environment, tool identity, empty output, malformed output,
unsupported fields, output rewrites, timeout and process failure. Distinguish
what the runtime does from the harness's effect mapping. Never invoke a corpus
command during contract tests. Use synthetic hook programs only.
