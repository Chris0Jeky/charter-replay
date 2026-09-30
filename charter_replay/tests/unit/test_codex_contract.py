"""`codex-pretooluse.v1`: synthetic reply fixtures and a real-process contract.

The fixtures are derived from the documented Codex PreToolUse hook grammar (see
docs/RUNTIME_CONTRACTS.md). They model the documentation, not a running Codex.
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

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "hooks" / "scripted_hook.py"
)
INVALID = "invalid-output"


def specific(**fields) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", **fields}})


def reply(code: int, stdout: str = "", stderr: str = ""):
    return get_adapter("codex").classify(code, stdout, stderr)


# (label, exit code, stdout, stderr, outcome, detail prefix, harness effect)
DOCUMENTED = (
    ("exit 0, no output", 0, "", "", "allow", "exit 0, no output", "allow"),
    ("exit 0, whitespace", 0, " \n", "", "allow", "exit 0, no output", "allow"),
    (
        "plain text stdout is ignored",
        0,
        "hello",
        "",
        "allow",
        "exit 0, plain-text stdout ignored",
        "allow",
    ),
    ("empty JSON object", 0, "{}", "", "allow", "no decision field", "allow"),
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
        "additionalContext only",
        0,
        '{"hookSpecificOutput": {"hookEventName": "PreToolUse",'
        ' "additionalContext": "ctx"}}',
        "",
        "allow",
        "no decision field",
        "allow",
    ),
    ("exit 2 with stderr", 2, "", " no way \n", "deny", "no way", "deny"),
    (
        "exit 2, stdout ignored",
        2,
        specific(permissionDecision="allow", updatedInput={"command": "x"}),
        "blocked",
        "deny",
        "blocked",
        "deny",
    ),
    (
        "permissionDecision deny",
        0,
        specific(permissionDecision="deny", permissionDecisionReason=" why "),
        "",
        "deny",
        "why",
        "deny",
    ),
    (
        "legacy decision block",
        0,
        '{"decision": "block", "reason": "old"}',
        "",
        "deny",
        "old",
        "deny",
    ),
    (
        "legacy block beside additionalContext",
        0,
        '{"decision": "block", "reason": "old", "hookSpecificOutput":'
        ' {"hookEventName": "PreToolUse", "additionalContext": "c"}}',
        "",
        "deny",
        "old",
        "deny",
    ),
    ("other exit code", 1, "", "boom\nmore", "crash", "exit 1: boom", "indeterminate"),
    ("high exit code", 127, "", "", "crash", "exit 127", "indeterminate"),
)

UNSUPPORTED = (
    ("ask", 0, specific(permissionDecision="ask"), "ask is unsupported by codex"),
    (
        "ask with reason",
        0,
        specific(permissionDecision="ask", permissionDecisionReason="confirm"),
        "ask is unsupported by codex",
    ),
    (
        "legacy approve",
        0,
        '{"decision": "approve"}',
        "legacy decision approve is unsupported by codex",
    ),
    (
        "continue false",
        0,
        '{"continue": false, "stopReason": "halt"}',
        "continue:false is unsupported by codex",
    ),
    (
        "stopReason alone",
        0,
        '{"stopReason": "halt"}',
        "stopReason is unsupported by codex",
    ),
    (
        "suppressOutput",
        0,
        '{"suppressOutput": true}',
        "suppressOutput is unsupported by codex",
    ),
    (
        "allow without updatedInput",
        0,
        specific(permissionDecision="allow"),
        "permissionDecision allow without updatedInput",
    ),
    (
        "allow with updatedInput is a rewrite",
        0,
        specific(permissionDecision="allow", updatedInput={"command": "ls"}),
        "allow with updatedInput rewrites the command",
    ),
    (
        "updatedInput without allow",
        0,
        specific(permissionDecision="deny", updatedInput={"command": "ls"}),
        "updatedInput without permissionDecision allow",
    ),
    (
        "updatedInput alone",
        0,
        specific(updatedInput={"command": "ls"}),
        "updatedInput without permissionDecision allow",
    ),
    (
        "deny without reason",
        0,
        specific(permissionDecision="deny"),
        "deny without a permissionDecisionReason",
    ),
    (
        "deny with blank reason",
        0,
        specific(permissionDecision="deny", permissionDecisionReason="  "),
        "deny without a permissionDecisionReason",
    ),
    (
        "reason without decision",
        0,
        specific(permissionDecisionReason="why"),
        "permissionDecisionReason without permissionDecision",
    ),
    (
        "block without reason",
        0,
        '{"decision": "block"}',
        "legacy decision block without a reason",
    ),
    (
        "legacy reason alone",
        0,
        '{"reason": "why"}',
        "reason without decision",
    ),
    (
        "unknown decision word",
        0,
        '{"decision": "maybe"}',
        "decision is not approve or block",
    ),
    (
        "unknown permission word",
        0,
        specific(permissionDecision="maybe"),
        "permissionDecision is not allow, deny or ask",
    ),
    (
        "unknown top-level field",
        0,
        '{"decision": "block", "reason": "r", "extra": 1}',
        "unknown field 'extra'",
    ),
    (
        "unknown hookSpecificOutput field",
        0,
        specific(permissionDecision="deny", permissionDecisionReason="r", extra=1),
        "unknown hookSpecificOutput field 'extra'",
    ),
    (
        "missing hookEventName",
        0,
        '{"hookSpecificOutput": {"permissionDecision": "deny",'
        ' "permissionDecisionReason": "r"}}',
        "hookSpecificOutput has no hookEventName",
    ),
    (
        "other hookEventName",
        0,
        '{"hookSpecificOutput": {"hookEventName": "PostToolUse",'
        ' "permissionDecision": "deny", "permissionDecisionReason": "r"}}',
        "hookEventName is not PreToolUse",
    ),
    (
        "mixed modern and legacy",
        0,
        '{"decision": "block", "reason": "r", "hookSpecificOutput":'
        ' {"hookEventName": "PreToolUse", "permissionDecision": "deny",'
        ' "permissionDecisionReason": "r"}}',
        "mixes hookSpecificOutput and legacy decision fields",
    ),
    ("continue not boolean", 0, '{"continue": "no"}', "continue must be a boolean"),
    (
        "reason not text",
        0,
        '{"decision": "block", "reason": 5}',
        "reason must be a string",
    ),
    (
        "hookSpecificOutput not object",
        0,
        '{"hookSpecificOutput": "deny"}',
        "hookSpecificOutput must be an object",
    ),
    ("malformed JSON object", 0, '{"decision": ', "stdout looks like JSON but"),
    ("bracket text", 0, "[warn] careful", "stdout looks like JSON but"),
    ("JSON array", 0, "[]", "JSON reply is not an object"),
    ("JSON scalar", 0, '"deny"', "JSON reply is not an object"),
    ("JSON number", 0, "0", "JSON reply is not an object"),
    (
        "exit 2 without a reason",
        2,
        specific(permissionDecision="deny", permissionDecisionReason="r"),
        "exit 2 without a blocking reason on stderr",
    ),
)


class CodexContractFixtureTests(unittest.TestCase):
    def test_documented_replies(self) -> None:
        for label, code, stdout, stderr, outcome, detail, effect in DOCUMENTED:
            with self.subTest(label):
                got = reply(code, stdout, stderr)
                self.assertEqual(got[0], outcome)
                self.assertEqual(got[1], detail)
                self.assertEqual(effect_for(got[0], "deny"), effect)

    def test_unsupported_replies_are_indeterminate_invalid_output(self) -> None:
        for label, code, stdout, detail in UNSUPPORTED:
            with self.subTest(label):
                outcome, text = reply(code, stdout)
                self.assertEqual(outcome, INVALID)
                self.assertTrue(text.startswith(detail), (text, detail))
                for ask_effect in ("deny", "allow", "indeterminate"):
                    self.assertEqual(effect_for(outcome, ask_effect), "indeterminate")

    def test_ask_never_reaches_the_ask_effect_mapping(self) -> None:
        # `--ask-as` maps only the `ask` outcome, which this contract never emits.
        outcomes = {reply(0, body)[0] for _, _, body, _ in UNSUPPORTED}
        self.assertNotIn("ask", outcomes)
        self.assertNotIn("stop", outcomes)

    def test_payload_carries_the_documented_fields_for_a_shell_call(self) -> None:
        workspace = Path(tempfile.gettempdir()) / "fictional-workspace"
        payload = get_adapter("codex").build_payload(
            {"command": "inert text", "cwd": "src/pkg"}, workspace=workspace, index=4
        )
        required = {
            "cwd",
            "hook_event_name",
            "model",
            "permission_mode",
            "session_id",
            "tool_input",
            "tool_name",
            "tool_use_id",
            "transcript_path",
            "turn_id",
        }
        self.assertEqual(set(payload), required)
        self.assertEqual(payload["hook_event_name"], "PreToolUse")
        self.assertEqual(payload["tool_name"], "Bash")
        self.assertEqual(payload["tool_input"], {"command": "inert text"})
        self.assertIsNone(payload["transcript_path"])
        self.assertEqual(payload["turn_id"], "replay-turn-000004")
        self.assertEqual(payload["tool_use_id"], "replay-000004")
        self.assertEqual(payload["cwd"], str(workspace / "src" / "pkg"))
        json.dumps(payload)

    def test_no_undocumented_environment_variable_is_provided(self) -> None:
        self.assertEqual(get_adapter("codex").environment(Path("w")), {})
        legacy = get_adapter("codex-legacy").environment(Path("w"))
        self.assertEqual(legacy, {"CLAUDE_PROJECT_DIR": "w"})

    def test_contract_identities(self) -> None:
        self.assertEqual(get_adapter("codex").contract_id, "codex-pretooluse.v1")
        self.assertEqual(
            get_adapter("codex-legacy").contract_id, "codex-legacy-floor.v1"
        )
        self.assertIn("codex", RUNTIMES)
        self.assertIn("codex-legacy", RUNTIMES)

    def test_unknown_runtime_is_still_rejected(self) -> None:
        for name in ("codex-v1", "Codex", "codex_legacy", ""):
            with self.subTest(name), self.assertRaisesRegex(ValueError, "unsupported"):
                get_adapter(name)


class CodexContractProcessTests(unittest.TestCase):
    """The same hook, run for real under both Codex runtime names."""

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

    def test_ask_is_deny_under_the_floor_and_indeterminate_under_the_contract(
        self,
    ) -> None:
        commands = ["json-ask", "json-deny", "legacy-block", "json-allow", "exit-two"]
        _, current, current_decisions, current_context = self.record("codex", commands)
        _, legacy, legacy_decisions, legacy_context = self.record(
            "codex-legacy", commands
        )
        self.assertEqual(
            [item["outcome"] for item in current],
            ["invalid-output", "deny", "deny", "invalid-output", "deny"],
        )
        self.assertEqual(
            [item["outcome"] for item in legacy],
            ["deny", "deny", "deny", "allow", "deny"],
        )
        self.assertEqual(
            [item["effect"] for item in current_decisions],
            ["indeterminate", "deny", "deny", "indeterminate", "deny"],
        )
        self.assertEqual(
            [item["effect"] for item in legacy_decisions],
            ["deny", "deny", "deny", "allow", "deny"],
        )
        self.assertTrue(
            current_decisions[0]["reason"].startswith(
                "invalid-output: ask is unsupported by codex"
            ),
            current_decisions[0]["reason"],
        )
        self.assertEqual(
            legacy_decisions[0]["reason"], "deny: ask is unsupported on codex: confirm"
        )
        self.assertEqual(
            current_context["descriptor"]["adapter"]["contract_id"],
            "codex-pretooluse.v1",
        )
        self.assertEqual(
            legacy_context["descriptor"]["adapter"]["contract_id"],
            "codex-legacy-floor.v1",
        )
        self.assertNotEqual(current_context["context_id"], legacy_context["context_id"])
        for context in (current_context, legacy_context):
            hook_context.validate_hook_context(context)

    def test_ask_as_has_no_effect_under_the_current_contract(self) -> None:
        _, _, decisions, _ = self.record("codex", ["json-ask"], ask_effect="allow")
        self.assertEqual(decisions[0]["effect"], "indeterminate")

    def test_hook_sees_no_project_dir_only_under_the_current_contract(self) -> None:
        probe = self.root / "probe.py"
        lines = [
            "import os, sys",
            "if 'CLAUDE_PROJECT_DIR' in os.environ:",
            "    print('project dir present', file=sys.stderr)",
            "    sys.exit(2)",
        ]
        probe.write_bytes("\n".join(lines).encode("utf-8") + b"\n")
        results = {}
        for runtime in ("codex", "codex-legacy"):
            spec = HookSpec(
                argv=(sys.executable, str(probe)), runtime=runtime, timeout=20.0
            )
            event = dict(
                schema_version="command-event.v1",
                event_id="synthetic-0",
                timestamp="2026-01-01T00:00:00Z",
                command="inert",
                source="synthetic",
            )
            output = self.root / f"probe-{runtime}"
            record_hook(spec, [event], output, policy_id="probe")
            line = (output / "decisions.jsonl").read_text().splitlines()[0]
            results[runtime] = json.loads(line)["effect"]
        self.assertEqual(results, {"codex": "allow", "codex-legacy": "deny"})


if __name__ == "__main__":
    unittest.main()
