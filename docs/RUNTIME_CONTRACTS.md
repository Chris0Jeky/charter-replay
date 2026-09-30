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

Sources: <https://geminicli.com/docs/hooks/reference/> and
<https://geminicli.com/docs/hooks/>.
BeforeTool provides a different event/tool vocabulary, including
`run_shell_command`; allow/deny/block decisions are not the Claude-specific
permissionDecision envelope. Exit 2 blocks; other failures can continue. This
makes Gemini a useful third adapter because it tests whether the interface is
actually runtime-neutral. Defer implementation until its payload, environment,
input rewrites and unsupported-output handling have dedicated contract fixtures.

## Certification checklist

Record runtime version/revision, source URL and fixture provenance. Cover payload
fields, process cwd, environment, tool identity, empty output, malformed output,
unsupported fields, output rewrites, timeout and process failure. Distinguish
what the runtime does from the harness's effect mapping. Never invoke a corpus
command during contract tests. Use synthetic hook programs only.
