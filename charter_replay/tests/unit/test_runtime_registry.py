"""The adapter registry extracts grammar without changing supported contracts."""

from pathlib import Path
import tempfile
import unittest

from charter_replay import hooks


class RuntimeRegistryTests(unittest.TestCase):
    def adapters(self):
        from charter_replay import adapters

        return adapters

    def test_registry_keeps_existing_order_and_distinct_contracts(self):
        adapters = self.adapters()
        self.assertEqual(adapters.RUNTIMES, ("claude", "codex"))
        self.assertEqual(hooks.RUNTIMES, adapters.RUNTIMES)
        self.assertEqual(
            len({adapters.get_adapter(n).contract_id for n in adapters.RUNTIMES}), 2
        )
        for name in adapters.RUNTIMES:
            self.assertEqual(adapters.get_adapter(name).name, name)

    def test_unknown_adapter_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported runtime"):
            self.adapters().get_adapter("unknown")

    def test_payload_and_environment_preserve_legacy_contract(self):
        event = {"command": "inert text; not executed", "cwd": "a/../b"}
        workspace = Path(tempfile.gettempdir()) / "fictional-workspace"
        for name in self.adapters().RUNTIMES:
            adapter = self.adapters().get_adapter(name)
            expected = {
                "session_id": "replay-session",
                "transcript_path": str(workspace / ".replay" / "transcript.jsonl"),
                "cwd": str(workspace / "a" / "b"),
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": event["command"]},
                "tool_use_id": "replay-000003",
                "model": f"{name}-replay",
            }
            with self.subTest(runtime=name):
                self.assertEqual(
                    adapter.build_payload(event, workspace=workspace, index=3), expected
                )
                self.assertEqual(
                    hooks.build_payload(
                        event, runtime=name, workspace=workspace, index=3
                    ),
                    expected,
                )
                self.assertEqual(
                    adapter.environment(workspace),
                    {"CLAUDE_PROJECT_DIR": str(workspace)},
                )

    def test_completed_reply_parity_including_existing_codex_floor(self):
        replies = [
            (0, "", "", ("allow", "exit 0, no output")),
            (2, "ignored", "blocked", ("deny", "blocked")),
            (7, "", "bad\nmore", ("crash", "exit 7: bad")),
            (
                0,
                "[]",
                "",
                ("invalid-output", "JSON reply without a recognised decision"),
            ),
            (0, '{"continue":false}', "", ("stop", "continue is false")),
            (0, '{"decision":"approve"}', "", ("allow", "")),
        ]
        for name in self.adapters().RUNTIMES:
            adapter = self.adapters().get_adapter(name)
            for code, stdout, stderr, expected in replies:
                with self.subTest(runtime=name, reply=stdout, code=code):
                    self.assertEqual(adapter.classify(code, stdout, stderr), expected)
                    self.assertEqual(
                        hooks.classify(code, stdout, stderr, runtime=name), expected
                    )
        ask = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"why"}}'
        self.assertEqual(
            self.adapters().get_adapter("claude").classify(0, ask, ""), ("ask", "why")
        )
        self.assertEqual(
            self.adapters().get_adapter("codex").classify(0, ask, ""),
            ("deny", "ask is unsupported on codex: why"),
        )


if __name__ == "__main__":
    unittest.main()
