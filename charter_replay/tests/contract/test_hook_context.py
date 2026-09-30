"""Recording writes an input-only context that outcomes cannot influence."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import app, hook_context, hooks
from charter_replay.tests.contract import test_cli as fixtures

EVENTS = [
    dict(
        schema_version="command-event.v1",
        event_id=f"synthetic-{index}",
        timestamp="2026-01-01T00:00:00Z",
        command="inert command data, never executed",
        source="synthetic",
    )
    for index in range(2)
]
ALLOW = "raise SystemExit(0)\n"


class HookContextRecordingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.script = self.root / "guard.py"
        self.script.write_text(ALLOW, encoding="utf-8", newline="\n")
        self.template = self.root / "template"
        self.template.mkdir()
        (self.template / "rules.txt").write_bytes(b"rules one\n")
        self.count = 0

    def spec(self, *extra, **options):
        argv = (sys.executable, str(self.script), *extra)
        return hooks.HookSpec(argv, **options)

    def record(self, spec=None, template="default", **kwargs):
        self.count += 1
        output = self.root / f"recording-{self.count}"
        summary = hooks.record_hook(
            spec or self.spec(),
            EVENTS,
            output,
            policy_id="synthetic-hook",
            workspace_template=self.template if template == "default" else template,
            **kwargs,
        )
        return output, summary

    @staticmethod
    def decisions(output: Path) -> bytes:
        return (output / "decisions.jsonl").read_bytes()

    def test_configuration_changes_alter_the_id_but_not_identical_decisions(self):
        base, base_summary = self.record()
        (self.template / "rules.txt").write_bytes(b"rules two\n")
        changed_template, _ = self.record()
        variants = {
            "template bytes": changed_template,
            "ask effect": self.record(self.spec(ask_effect="allow"))[0],
            "runtime": self.record(self.spec(runtime="codex"))[0],
            "timeout": self.record(self.spec(timeout=7))[0],
            "jobs": self.record(jobs=2)[0],
        }
        seen = {base_summary["context_id"]}
        for name, output in variants.items():
            with self.subTest(name):
                self.assertEqual(self.decisions(output), self.decisions(base))
                document = json.loads((output / "hook-context.json").read_bytes())
                hook_context.validate_hook_context(document)
                self.assertNotIn(document["context_id"], seen)
                seen.add(document["context_id"])

    def test_different_decisions_under_identical_captured_inputs_share_an_id(self):
        flag = self.root / "external.flag"
        gate = self.root / "gate.py"
        gate.write_text(
            f"import sys\nfrom pathlib import Path\n"
            f"sys.exit(2 if Path({str(flag)!r}).exists() else 0)\n",
            encoding="utf-8",
            newline="\n",
        )
        spec = hooks.HookSpec((sys.executable, str(gate)))
        allowed, first = self.record(spec)
        flag.write_bytes(b"mutable external state")
        denied, second = self.record(spec)
        self.assertNotEqual(self.decisions(allowed), self.decisions(denied))
        self.assertEqual(first["context_id"], second["context_id"])
        self.assertEqual(first["failures"], [])
        self.assertEqual(second["failures"], [])
        self.assertIn(
            "mutable-external-state",
            json.loads((allowed / "hook-context.json").read_bytes())["descriptor"][
                "unbound"
            ],
        )

    def test_context_file_is_byte_reproducible_and_relocatable(self):
        first, _ = self.record()
        second, _ = self.record()
        name = "hook-context.json"
        self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        raw = (first / name).read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r", raw)
        self.assertEqual(raw, hook_context.hook_context_bytes(json.loads(raw)))
        self.assertNotIn(str(self.root).encode(), raw)

    def test_manifest_and_decisions_stay_context_free(self):
        output, summary = self.record()
        manifest = json.loads((output / "decisions.jsonl.manifest.json").read_bytes())
        self.assertEqual(
            set(manifest),
            {
                "schema_version",
                "policy_id",
                "policy_commit",
                "decisions_file",
                "decisions_sha256",
                "decision_count",
            },
        )
        self.assertNotIn(summary["context_id"], json.dumps(manifest))
        self.assertNotIn(summary["context_id"].encode(), self.decisions(output))

    def test_summary_reports_the_initial_id(self):
        output, summary = self.record()
        stored = json.loads((output / "hook-context.json").read_bytes())
        self.assertEqual(summary["context_id"], stored["context_id"])
        self.assertEqual(summary["failures"], [])

    def test_template_changed_by_the_hook_is_a_context_failure(self):
        mutator = self.root / "mutator.py"
        mutator.write_text(
            "from pathlib import Path\n"
            f"path = Path({str(self.template / 'rules.txt')!r})\n"
            "path.write_bytes(path.read_bytes() + b'more\\n')\n",
            encoding="utf-8",
            newline="\n",
        )
        output, summary = self.record(hooks.HookSpec((sys.executable, str(mutator))))
        codes = [failure["code"] for failure in summary["failures"]]
        self.assertEqual(codes, ["hook-context-changed"])
        # The stored descriptor is the initial one, and replies are untouched.
        stored = json.loads((output / "hook-context.json").read_bytes())
        self.assertEqual(stored["context_id"], summary["context_id"])
        self.assertEqual(summary["outcomes"]["allow"], len(EVENTS))
        self.assertNotIn(str(self.root), json.dumps(summary))

    def test_output_path_created_by_the_hook_is_not_a_context_change(self):
        result = self.root / "result.json"
        writer = self.root / "writer.py"
        writer.write_text(
            "import sys\nfrom pathlib import Path\n"
            "Path(sys.argv[1]).write_text('{}')\n",
            encoding="utf-8",
            newline="\n",
        )
        spec = hooks.HookSpec((sys.executable, str(writer), str(result)))
        output, summary = self.record(spec)
        self.assertTrue(result.is_file(), "the hook must have created its output")
        # Only the context check is asserted: the legacy fingerprint has its own
        # behaviour for such a path, which is not this descriptor's concern.
        codes = [failure["code"] for failure in summary["failures"]]
        self.assertNotIn("hook-context-changed", codes)
        self.assertNotIn("hook-context-unreadable", codes)
        kinds = [
            item["kind"]
            for item in json.loads((output / "hook-context.json").read_bytes())[
                "descriptor"
            ]["hook"]["argv"]
        ]
        self.assertEqual(kinds, ["executable", "file", "word"])

    def test_deleted_pinned_file_is_a_context_failure(self):
        remover = self.root / "remover.py"
        remover.write_text(
            "import sys\nfrom pathlib import Path\n"
            "Path(sys.argv[1]).unlink(missing_ok=True)\n",
            encoding="utf-8",
            newline="\n",
        )
        helper = self.root / "helper.txt"
        helper.write_bytes(b"helper")
        spec = hooks.HookSpec((sys.executable, str(remover), str(helper)))
        _output, summary = self.record(spec)
        self.assertIn(
            "hook-context-changed", [failure["code"] for failure in summary["failures"]]
        )

    def test_descriptor_read_failure_starts_nothing_and_writes_nothing(self):
        with (
            mock.patch.object(
                hook_context,
                "describe_hook_context",
                side_effect=OSError("private path"),
            ),
            mock.patch.object(hooks, "prepare_workspace") as workspace,
            mock.patch.object(hooks, "run_hook") as launch,
        ):
            with self.assertRaises(hooks.HookSpecError) as failure:
                self.record()
        workspace.assert_not_called()
        launch.assert_not_called()
        self.assertFalse((self.root / "recording-1").exists())
        self.assertNotIn("private path", str(failure.exception))

    def test_descriptor_is_computed_before_workspaces_and_again_afterwards(self):
        order = []
        real = hook_context.describe_hook_context

        def describe(*args, **kwargs):
            order.append("describe")
            return real(*args, **kwargs)

        def workspace(template):
            order.append("workspace")
            raise OSError("stop")

        with (
            mock.patch.object(hook_context, "describe_hook_context", describe),
            mock.patch.object(hooks, "prepare_workspace", side_effect=workspace),
        ):
            self.record()
        self.assertEqual(order, ["describe", "workspace", "workspace", "describe"])

    def test_unreadable_recheck_is_a_fixed_source_failure(self):
        real = hook_context.describe_hook_context
        calls = []

        def describe(*args, **kwargs):
            calls.append(1)
            if len(calls) > 1:
                raise OSError("private path")
            return real(*args, **kwargs)

        with mock.patch.object(hook_context, "describe_hook_context", describe):
            _output, summary = self.record()
        self.assertEqual(summary["failures"][0]["code"], "hook-context-unreadable")
        self.assertNotIn("private path", json.dumps(summary))

    def invoke(self, argv):
        stream = io.StringIO()
        with redirect_stdout(stream), redirect_stderr(io.StringIO()):
            return app.main(argv), stream.getvalue()

    def test_cli_record_exits_three_when_the_template_changes_mid_run(self):
        mutator = self.root / "mutator.py"
        mutator.write_text(
            "from pathlib import Path\n"
            f"Path({str(self.template / 'late.txt')!r}).write_bytes(b'late')\n",
            encoding="utf-8",
            newline="\n",
        )
        with fixtures.CliTests().fixture("same") as data:
            corpus = data[1]
            code, printed = self.invoke(
                [
                    "record",
                    "--hook",
                    json.dumps([sys.executable, str(mutator)]),
                    "--corpus",
                    str(corpus),
                    "--output",
                    str(self.root / "cli-recording"),
                    "--workspace",
                    str(self.template),
                ]
            )
        self.assertEqual(code, 3)
        summary = json.loads(printed)
        self.assertEqual(
            [failure["code"] for failure in summary["failures"]],
            ["hook-context-changed"],
        )

    def test_cli_hooks_summary_carries_both_context_ids(self):
        good = json.dumps([sys.executable, str(self.script)])
        other = self.root / "other.py"
        other.write_text("import sys\n", encoding="utf-8", newline="\n")
        with fixtures.CliTests().fixture("same") as data:
            corpus = data[1]
            output = self.root / "hooks-run"
            code, _ = self.invoke(
                [
                    "hooks",
                    "--baseline",
                    good,
                    "--candidate",
                    json.dumps([sys.executable, str(other)]),
                    "--corpus",
                    str(corpus),
                    "--output",
                    str(output),
                ]
            )
        self.assertIn(code, (0, 1))
        summary = json.loads((output / "summary.json").read_bytes())
        for side in ("baseline", "candidate"):
            stored = json.loads((output / side / "hook-context.json").read_bytes())
            hook_context.validate_hook_context(stored)
            self.assertEqual(summary["contexts"][side], stored["context_id"])
        self.assertNotEqual(
            summary["contexts"]["baseline"], summary["contexts"]["candidate"]
        )
        markdown = (output / "summary.md").read_text(encoding="utf-8")
        self.assertIn("Hook context IDs (hook-context.v1)", markdown)
        self.assertIn(summary["contexts"]["baseline"], markdown)
        self.assertIn("not execution authentication", markdown)


if __name__ == "__main__":
    unittest.main()
