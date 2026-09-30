"""`gemini-beforetool.v1`: synthetic reply fixtures and a real-process contract.

The fixtures are derived from the documented Gemini CLI BeforeTool hook grammar
and the upstream hook runner (see docs/RUNTIME_CONTRACTS.md). They model the
documentation and source, not a running Gemini CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

from charter_replay import hook_context
from charter_replay.adapters import RUNTIMES, get_adapter
from charter_replay.hooks import HookSpec, effect_for, record_hook

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "hooks" / "gemini_hook.py"
INVALID = "invalid-output"


def specific(**fields) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "BeforeTool", **fields}})


def reply(code: int, stdout: str = "", stderr: str = ""):
    return get_adapter("gemini").classify(code, stdout, stderr)


# (label, exit code, stdout, stderr, outcome, detail, harness effect)
DOCUMENTED = (
    ("exit 0, no output", 0, "", "", "allow", "exit 0, no output", "allow"),
    ("exit 0, whitespace", 0, " \n", "", "allow", "exit 0, no output", "allow"),
    (
        "exit 0, plain-text stderr only",
        0,
        "",
        "note to the operator",
        "allow",
        "exit 0, no output",
        "allow",
    ),
    ("empty JSON object", 0, "{}", "", "allow", "no decision field", "allow"),
    (
        "whitespace around JSON",
        0,
        " \n {} \n",
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    (
        "decision allow",
        0,
        '{"decision": "allow"}',
        "",
        "allow",
        "decision allow",
        "allow",
    ),
    (
        "systemMessage only",
        0,
        '{"systemMessage": "note"}',
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    (
        "suppressOutput only",
        0,
        '{"suppressOutput": true}',
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    (
        "stopReason without continue false",
        0,
        '{"stopReason": "halt"}',
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    (
        "reason without a decision",
        0,
        '{"reason": "why"}',
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    (
        "continue true",
        0,
        '{"continue": true}',
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    (
        "null members are absent",
        0,
        '{"decision": null, "reason": null, "hookSpecificOutput": null}',
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    (
        "hookSpecificOutput with only the event name",
        0,
        specific(),
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    ("exit 2 with stderr", 2, "", " no way \n", "deny", "no way", "deny"),
    (
        "decision deny",
        0,
        '{"decision": "deny", "reason": " why "}',
        "",
        "deny",
        "why",
        "deny",
    ),
    (
        "decision block alias",
        0,
        '{"decision": "block", "reason": "alias"}',
        "",
        "deny",
        "alias",
        "deny",
    ),
    (
        "deny wins over a rewrite that never runs",
        0,
        json.dumps(
            {
                "decision": "deny",
                "reason": "no",
                "hookSpecificOutput": {
                    "hookEventName": "BeforeTool",
                    "tool_input": {"command": "ls"},
                },
            }
        ),
        "",
        "deny",
        "no",
        "deny",
    ),
    (
        "continue false with stopReason",
        0,
        '{"continue": false, "stopReason": "halt", "reason": "other"}',
        "",
        "stop",
        "halt",
        "deny",
    ),
    (
        "continue false with only a reason",
        0,
        '{"continue": false, "reason": "r"}',
        "",
        "stop",
        "r",
        "deny",
    ),
    (
        "continue false with no reason",
        0,
        '{"continue": false}',
        "",
        "stop",
        "continue is false",
        "deny",
    ),
    (
        "continue false beats decision allow",
        0,
        '{"continue": false, "decision": "allow"}',
        "",
        "stop",
        "continue is false",
        "deny",
    ),
    ("other exit code", 1, "", "boom\nmore", "crash", "exit 1: boom", "indeterminate"),
    ("high exit code", 127, "", "", "crash", "exit 127", "indeterminate"),
    (
        "deny JSON on a warning exit is not a block",
        1,
        '{"decision": "deny", "reason": "r"}',
        "",
        "crash",
        "exit 1",
        "indeterminate",
    ),
    (
        "plain text on exit 3 is not a block",
        3,
        "",
        "denied?",
        "crash",
        "exit 3: denied?",
        "indeterminate",
    ),
)

# (label, exit code, stdout, stderr, detail prefix)
UNSUPPORTED = (
    ("ask", 0, '{"decision": "ask"}', "", "decision is not allow, deny or block"),
    ("approve", 0, '{"decision": "approve"}', "", "decision is not allow"),
    ("upper-case deny", 0, '{"decision": "DENY", "reason": "r"}', "", "decision is"),
    ("decision not text", 0, '{"decision": 5}', "", "decision must be a string"),
    (
        "unknown top-level field",
        0,
        '{"decision": "deny", "reason": "r", "extra": 1}',
        "",
        "unknown field 'extra'",
    ),
    (
        "claude-style permissionDecision at top level",
        0,
        '{"permissionDecision": "deny"}',
        "",
        "unknown field 'permissionDecision'",
    ),
    (
        "claude-style hookSpecificOutput",
        0,
        specific(permissionDecision="deny", permissionDecisionReason="r"),
        "",
        "unknown hookSpecificOutput field 'permissionDecision'",
    ),
    (
        "additionalContext is not a BeforeTool field",
        0,
        specific(additionalContext="ctx"),
        "",
        "unknown hookSpecificOutput field 'additionalContext'",
    ),
    (
        "missing hookEventName",
        0,
        '{"hookSpecificOutput": {"tool_input": {"command": "ls"}}}',
        "",
        "hookSpecificOutput has no hookEventName",
    ),
    (
        "other hookEventName",
        0,
        '{"hookSpecificOutput": {"hookEventName": "PreToolUse"}}',
        "",
        "hookEventName is not BeforeTool",
    ),
    (
        "hookSpecificOutput not object",
        0,
        '{"hookSpecificOutput": "deny"}',
        "",
        "hookSpecificOutput must be an object",
    ),
    (
        "rewrite alone",
        0,
        specific(tool_input={"command": "ls"}),
        "",
        "hookSpecificOutput.tool_input rewrites the command",
    ),
    (
        "rewrite with decision allow",
        0,
        json.dumps(
            {
                "decision": "allow",
                "hookSpecificOutput": {
                    "hookEventName": "BeforeTool",
                    "tool_input": {"command": "ls"},
                },
            }
        ),
        "",
        "hookSpecificOutput.tool_input rewrites the command",
    ),
    (
        "rewrite that is not an object",
        0,
        specific(tool_input="ls"),
        "",
        "hookSpecificOutput.tool_input rewrites the command",
    ),
    ("deny without reason", 0, '{"decision": "deny"}', "", "deny without a reason"),
    ("block without reason", 0, '{"decision": "block"}', "", "deny without a reason"),
    (
        "deny with blank reason",
        0,
        '{"decision": "deny", "reason": "  "}',
        "",
        "deny without a reason",
    ),
    (
        "deny with only a stopReason",
        0,
        '{"decision": "deny", "stopReason": "r"}',
        "",
        "deny without a reason",
    ),
    ("continue not boolean", 0, '{"continue": "no"}', "", "continue must be a boolean"),
    (
        "suppressOutput not boolean",
        0,
        '{"suppressOutput": 1}',
        "",
        "suppressOutput must be a boolean",
    ),
    (
        "reason not text",
        0,
        '{"decision": "deny", "reason": 5}',
        "",
        "reason must be a string",
    ),
    ("plain text on stdout", 0, "hello", "", "stdout is not JSON"),
    (
        "text before the JSON reply",
        0,
        'checking...\n{"decision": "deny", "reason": "r"}',
        "",
        "stdout is not JSON",
    ),
    ("malformed JSON object", 0, '{"decision": ', "", "stdout is not JSON"),
    ("bracket text", 0, "[warn] careful", "", "stdout is not JSON"),
    ("whitespace then malformed", 0, ' \n{"decision": ', "", "stdout is not JSON"),
    ("JSON array", 0, "[]", "", "JSON reply is not an object"),
    ("JSON number", 0, "0", "", "JSON reply is not an object"),
    ("JSON null", 0, "null", "", "JSON reply is not an object"),
    (
        "double-encoded JSON string",
        0,
        json.dumps('{"decision": "deny", "reason": "r"}'),
        "",
        "JSON reply is not an object",
    ),
    (
        "duplicate key ending in deny",
        0,
        '{"decision": null, "decision": "deny", "reason": "r"}',
        "",
        "JSON reply repeats a member name",
    ),
    (
        "duplicate key ending in null",
        0,
        '{"decision": "deny", "reason": "r", "decision": null}',
        "",
        "JSON reply repeats a member name",
    ),
    (
        "duplicate key with the same value",
        0,
        '{"reason": "r", "reason": "r"}',
        "",
        "JSON reply repeats a member name",
    ),
    (
        "byte-order mark",
        0,
        '﻿{"decision": "deny", "reason": "x"}',
        "",
        "stdout starts with a byte-order mark",
    ),
    (
        "byte-order mark alone",
        0,
        "﻿",
        "",
        "stdout starts with a byte-order mark",
    ),
    ("deep nesting", 0, "[" * 100_000, "", "JSON reply is nested too deeply"),
    (
        "JSON on stderr with empty stdout",
        0,
        "",
        '{"decision": "deny", "reason": "r"}',
        "empty stdout with JSON on stderr is ambiguous",
    ),
    (
        "scalar JSON on stderr with empty stdout",
        0,
        " ",
        "123",
        "empty stdout with JSON on stderr is ambiguous",
    ),
    (
        "exit 2 without a reason",
        2,
        "",
        "",
        "exit 2 without a blocking reason on stderr",
    ),
    (
        "exit 2 with only stdout",
        2,
        '{"decision": "deny", "reason": "r"}',
        "",
        "exit 2 with stdout is ambiguous",
    ),
    (
        "exit 2 with stdout and stderr",
        2,
        "{}",
        "blocked",
        "exit 2 with stdout is ambiguous",
    ),
    (
        "exit 2 with JSON on stderr",
        2,
        "",
        '{"decision": "allow"}',
        "exit 2 with JSON on stderr is ambiguous",
    ),
    (
        "exit 2 with null on stderr",
        2,
        "",
        "null",
        "exit 2 with JSON on stderr is ambiguous",
    ),
    (
        "exit 2 with deeply nested stderr",
        2,
        "",
        "[" * 100_000,
        "exit 2 with JSON on stderr is ambiguous",
    ),
)


class GeminiContractFixtureTests(unittest.TestCase):
    def test_documented_replies(self) -> None:
        for label, code, stdout, stderr, outcome, detail, effect in DOCUMENTED:
            with self.subTest(label):
                got = reply(code, stdout, stderr)
                self.assertEqual(got[0], outcome)
                self.assertEqual(got[1], detail)
                self.assertEqual(effect_for(got[0], "deny"), effect)

    def test_unsupported_replies_are_indeterminate_invalid_output(self) -> None:
        for label, code, stdout, stderr, detail in UNSUPPORTED:
            with self.subTest(label):
                outcome, text = reply(code, stdout, stderr)
                self.assertEqual(outcome, INVALID)
                self.assertTrue(text.startswith(detail), (text, detail))
                for ask_effect in ("deny", "allow", "indeterminate"):
                    self.assertEqual(effect_for(outcome, ask_effect), "indeterminate")

    def test_ask_is_never_emitted(self) -> None:
        # `--ask-as` maps only the `ask` outcome, which this contract never emits.
        bodies = [row[1:4] for row in DOCUMENTED + UNSUPPORTED]
        outcomes = {reply(*body)[0] for body in bodies}
        self.assertNotIn("ask", outcomes)

    def test_every_documented_and_unsupported_label_is_unique(self) -> None:
        labels = [row[0] for row in DOCUMENTED + UNSUPPORTED]
        self.assertEqual(len(labels), len(set(labels)))

    def test_payload_carries_the_documented_fields_for_a_shell_call(self) -> None:
        workspace = Path(tempfile.gettempdir()) / "fictional-workspace"
        payload = get_adapter("gemini").build_payload(
            {"command": "inert text", "cwd": "src/pkg"}, workspace=workspace, index=4
        )
        self.assertEqual(
            set(payload),
            {
                "cwd",
                "hook_event_name",
                "session_id",
                "timestamp",
                "tool_input",
                "tool_name",
                "transcript_path",
            },
        )
        self.assertEqual(payload["hook_event_name"], "BeforeTool")
        self.assertEqual(payload["tool_name"], "run_shell_command")
        self.assertEqual(payload["tool_input"], {"command": "inert text"})
        self.assertEqual(payload["cwd"], str(workspace / "src" / "pkg"))
        self.assertIsInstance(payload["transcript_path"], str)
        self.assertRegex(payload["timestamp"], r"^\d{4}-\d\d-\d\dT[\d:.]+Z$")
        json.dumps(payload)

    def test_payload_is_independent_of_the_event_index(self) -> None:
        adapter = get_adapter("gemini")
        event = {"command": "inert"}
        first = adapter.build_payload(event, workspace=Path("w"), index=0)
        later = adapter.build_payload(event, workspace=Path("w"), index=9)
        self.assertEqual(first, later)

    def test_cwd_mapping_reuses_the_workspace_relative_rule(self) -> None:
        workspace = Path(tempfile.gettempdir()) / "fictional-workspace"
        cases = (
            ("a/../b", ("a", "b")),
            ("src\\pkg/deep", ("src", "pkg", "deep")),
            (None, ()),
        )
        for cwd, parts in cases:
            event = {"command": "inert"}
            if cwd is not None:
                event["cwd"] = cwd
            with self.subTest(cwd=cwd):
                payload = get_adapter("gemini").build_payload(
                    event, workspace=workspace, index=0
                )
                self.assertEqual(payload["cwd"], str(workspace.joinpath(*parts)))

    def test_only_documented_environment_variables_are_provided(self) -> None:
        env = get_adapter("gemini").environment(Path("w"))
        self.assertEqual(
            env,
            {
                "GEMINI_PROJECT_DIR": "w",
                "GEMINI_SESSION_ID": "replay-session",
                "CLAUDE_PROJECT_DIR": "w",
            },
        )
        # Not derivable per event or per machine, so not invented.
        self.assertNotIn("GEMINI_CWD", env)
        self.assertNotIn("GEMINI_PLANS_DIR", env)

    def test_contract_identity(self) -> None:
        self.assertEqual(get_adapter("gemini").contract_id, "gemini-beforetool.v1")
        self.assertEqual(get_adapter("gemini").name, "gemini")
        self.assertIn("gemini", RUNTIMES)

    def test_other_contracts_are_unchanged(self) -> None:
        self.assertEqual(get_adapter("claude").contract_id, "claude-pretooluse.v1")
        self.assertEqual(get_adapter("codex").contract_id, "codex-pretooluse.v1")
        self.assertEqual(
            get_adapter("codex-legacy").contract_id, "codex-legacy-floor.v1"
        )

    def test_unknown_runtime_is_still_rejected(self) -> None:
        for name in ("gemini-cli", "Gemini", "gemini-beforetool", ""):
            with self.subTest(name), self.assertRaisesRegex(ValueError, "unsupported"):
                get_adapter(name)


class GeminiContractProcessTests(unittest.TestCase):
    """The same hook, run for real under `gemini` and `claude`."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def record(self, runtime: str, commands, **options):
        events = [
            dict(
                schema_version="command-event.v1",
                event_id=f"synthetic-{index}",
                timestamp="2026-01-01T00:00:00Z",
                command=command,
                source="synthetic",
            )
            for index, command in enumerate(commands)
        ]
        output = self.root / runtime
        spec = HookSpec(
            argv=(sys.executable, str(FIXTURE)),
            runtime=runtime,
            timeout=20.0,
            **options,
        )
        summary = record_hook(spec, events, output, policy_id="fixture")
        outcomes = [
            json.loads(line)
            for line in (output / "outcomes.jsonl").read_text().splitlines()
        ]
        decisions = [
            json.loads(line)
            for line in (output / "decisions.jsonl").read_text().splitlines()
        ]
        context = json.loads((output / "hook-context.json").read_bytes())
        return summary, outcomes, decisions, context

    def test_payload_and_environment_reach_the_hook(self) -> None:
        _, outcomes, decisions, _ = self.record("gemini", ["echo-payload"])
        self.assertEqual(outcomes[0]["outcome"], "deny")
        prefix = "deny: "
        self.assertTrue(decisions[0]["reason"].startswith(prefix))
        seen = json.loads(decisions[0]["reason"][len(prefix) :])
        self.assertEqual(
            seen,
            {
                "keys": [
                    "cwd",
                    "hook_event_name",
                    "session_id",
                    "timestamp",
                    "tool_input",
                    "tool_name",
                    "transcript_path",
                ],
                "event": "BeforeTool",
                "tool": "run_shell_command",
                "command": "echo-payload",
                "project": True,
                "session": "replay-session",
                "claude_alias": True,
                "cwd": True,
            },
        )

    def test_classification_is_applied_and_differs_from_claude(self) -> None:
        commands = [
            "gemini-deny",
            "gemini-block",
            "gemini-allow",
            "gemini-ask",
            "gemini-stop",
            "gemini-rewrite",
            "gemini-polluted",
            "exit-two",
        ]
        _, gemini, gemini_decisions, gemini_context = self.record("gemini", commands)
        _, claude, _, claude_context = self.record("claude", commands)
        self.assertEqual(
            [item["outcome"] for item in gemini],
            [
                "deny",
                "deny",
                "allow",
                INVALID,
                "stop",
                INVALID,
                INVALID,
                "deny",
            ],
        )
        self.assertEqual(
            [item["effect"] for item in gemini_decisions],
            [
                "deny",
                "deny",
                "allow",
                "indeterminate",
                "deny",
                "indeterminate",
                "indeterminate",
                "deny",
            ],
        )
        # The Claude grammar does not know a bare `decision: deny`.
        self.assertEqual(claude[0]["outcome"], INVALID)
        self.assertNotEqual(gemini[0]["outcome"], claude[0]["outcome"])
        self.assertTrue(
            gemini_decisions[3]["reason"].startswith(
                "invalid-output: decision is not allow, deny or block"
            ),
            gemini_decisions[3]["reason"],
        )
        self.assertEqual(
            gemini_context["descriptor"]["adapter"]["contract_id"],
            "gemini-beforetool.v1",
        )
        self.assertEqual(
            claude_context["descriptor"]["adapter"]["contract_id"],
            "claude-pretooluse.v1",
        )
        self.assertNotEqual(gemini_context["context_id"], claude_context["context_id"])
        for context in (gemini_context, claude_context):
            hook_context.validate_hook_context(context)

    def test_ask_as_has_no_effect_under_gemini(self) -> None:
        _, _, decisions, _ = self.record("gemini", ["gemini-ask"], ask_effect="allow")
        self.assertEqual(decisions[0]["effect"], "indeterminate")


if __name__ == "__main__":
    unittest.main()
