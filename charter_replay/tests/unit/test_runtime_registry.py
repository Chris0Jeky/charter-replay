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
        self.assertEqual(
            adapters.RUNTIMES, ("claude", "codex", "codex-legacy", "gemini")
        )
        self.assertEqual(hooks.RUNTIMES, adapters.RUNTIMES)
        self.assertEqual(
            len({adapters.get_adapter(n).contract_id for n in adapters.RUNTIMES}), 4
        )
        for name in adapters.RUNTIMES:
            self.assertEqual(adapters.get_adapter(name).name, name)

    def test_unknown_adapter_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported runtime"):
            self.adapters().get_adapter("unknown")

    def test_payload_and_environment_preserve_legacy_contract(self):
        workspace = Path(tempfile.gettempdir()) / "fictional-workspace"
        # Corpus cwd values and the workspace-relative directory they must yield:
        # a stripped `..`, a nested path, a Windows-style separator and no cwd.
        cases = (
            ("a/../b", ("a", "b")),
            ("src/pkg/deep", ("src", "pkg", "deep")),
            ("src\\pkg/deep", ("src", "pkg", "deep")),
            (None, ()),
        )
        # The current Codex and Gemini contracts have their own payloads and
        # environments (test_codex_contract, test_gemini_contract); the claude and
        # legacy-floor payloads are the v0.1 one.
        for name in ("claude", "codex-legacy"):
            adapter = self.adapters().get_adapter(name)
            for cwd, parts in cases:
                event = {"command": "inert text; not executed"}
                if cwd is not None:
                    event["cwd"] = cwd
                expected = {
                    "session_id": "replay-session",
                    "transcript_path": str(workspace / ".replay" / "transcript.jsonl"),
                    "cwd": str(workspace.joinpath(*parts)),
                    "permission_mode": "default",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": event["command"]},
                    "tool_use_id": "replay-000003",
                    "model": (
                        "codex-replay" if name == "codex-legacy" else "claude-replay"
                    ),
                }
                with self.subTest(runtime=name, cwd=cwd):
                    self.assertEqual(
                        adapter.build_payload(event, workspace=workspace, index=3),
                        expected,
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

    def test_unhashable_runtime_is_a_value_error_not_a_type_error(self):
        for bad in ([], {}, ["claude"]):
            with (
                self.subTest(bad=bad),
                self.assertRaisesRegex(ValueError, "unsupported runtime"),
            ):
                self.adapters().get_adapter(bad)

    def test_completed_reply_parity_for_claude_and_the_legacy_codex_floor(self):
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
        for name in ("claude", "codex-legacy"):
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
            self.adapters().get_adapter("codex-legacy").classify(0, ask, ""),
            ("deny", "ask is unsupported on codex: why"),
        )


if __name__ == "__main__":
    unittest.main()
