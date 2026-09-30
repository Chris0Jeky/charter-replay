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

Source: <https://developers.openai.com/codex/hooks> (redirects to the official
ChatGPT Learn hooks reference).
The current documentation says unsupported PreToolUse output, including ask,
legacy approve and continue/stop-related fields, marks the hook failed and lets
the tool call continue. This contradicts the existing harness's ask-to-deny
floor. The old floor remains a compatibility behaviour during pure extraction;
it must not be described as current runtime truth. A subsequent versioned
contract should classify unsupported output as invalid-output/indeterminate,
with fixtures for both direct and legacy reply forms and explicit migration notes.

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
