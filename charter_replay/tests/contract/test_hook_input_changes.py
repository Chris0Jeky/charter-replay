"""Observed source edits must not become healthy, misattributed recordings."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import app, hooks
from charter_replay.digests import sha256_bytes
from charter_replay.manifests import build_corpus_manifest, manifest_json_bytes


class HookInputChangeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.script = self.root / "guard.py"
        self.script.write_bytes(b"pass\n")
        self.spec = hooks.HookSpec((sys.executable, str(self.script)))
        self.events = [
            dict(
                schema_version="command-event.v1",
                event_id="synthetic-event",
                timestamp="2026-01-01T00:00:00Z",
                command="inert command data, never executed",
                source="synthetic",
            )
        ]
        self.output = self.root / "recording"
        self.initial = hooks.hook_identity(self.spec.argv)
        self.allow = hooks.HookOutcome("allow", "Synthetic reply.", 0, 7)

    def record(self):
        return hooks.record_hook(
            self.spec, self.events, self.output, policy_id="synthetic-hook"
        )

    def manifest(self):
        return json.loads((self.output / "decisions.jsonl.manifest.json").read_bytes())

    def corpus(self):
        corpus = self.root / "corpus"
        corpus.mkdir()
        case = dict(
            schema_version="charter-case.v1",
            event_id=self.events[0]["event_id"],
            case_class="opaque",
            case_family="synthetic-input-change",
            rationale="Inert source-health fixture.",
            provenance="synthetic",
        )
        (corpus / "events.jsonl").write_bytes(
            (json.dumps(self.events[0]) + "\n").encode("utf-8")
        )
        (corpus / "cases.jsonl").write_bytes((json.dumps(case) + "\n").encode("utf-8"))
        manifest = build_corpus_manifest(
            corpus_id="synthetic-input-change",
            event_count=1,
            base_directory=corpus,
            files=["events.jsonl", "cases.jsonl"],
        )
        (corpus / "corpus-manifest.json").write_bytes(manifest_json_bytes(manifest))
        return corpus

    def test_changed_script_retains_initial_identity_and_reports_source_failure(self):
        def change(*args, **kwargs):
            self.script.write_bytes(b"# a different version\npass\n")
            return self.allow

        with mock.patch.object(hooks, "run_hook", side_effect=change):
            summary = self.record()
        self.assertEqual(self.manifest()["policy_commit"], self.initial[:40])
        self.assertEqual(summary["outcomes"]["allow"], 1)
        self.assertEqual(summary["failures"][0]["code"], "hook-input-changed")
        self.assertNotIn(str(self.root), json.dumps(summary))

    def test_deleted_script_does_not_replace_original_fingerprint_with_a_path_word(
        self,
    ):
        def remove(*args, **kwargs):
            self.script.unlink()
            return self.allow

        with mock.patch.object(hooks, "run_hook", side_effect=remove):
            summary = self.record()
        self.assertEqual(self.manifest()["policy_commit"], self.initial[:40])
        self.assertEqual(summary["failures"][0]["code"], "hook-input-changed")

    def test_initial_read_failure_starts_nothing_and_writes_nothing(self):
        with (
            mock.patch.object(
                hooks, "hook_identity", side_effect=OSError("private path")
            ),
            mock.patch.object(
                hooks, "prepare_workspace", wraps=hooks.prepare_workspace
            ) as workspace,
            mock.patch.object(hooks, "run_hook", return_value=self.allow) as launch,
        ):
            with self.assertRaises(hooks.HookSpecError) as failure:
                self.record()
        workspace.assert_not_called()
        launch.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertNotIn("private path", str(failure.exception))

    def test_post_read_failure_keeps_reply_and_initial_manifest_identity(self):
        with (
            mock.patch.object(hooks, "run_hook", return_value=self.allow),
            mock.patch.object(
                hooks,
                "hook_identity",
                side_effect=[self.initial, OSError("private path")],
            ),
        ):
            summary = self.record()
        self.assertEqual(self.manifest()["policy_commit"], self.initial[:40])
        self.assertTrue(summary["failures"], "a failed post-read is not healthy")
        self.assertEqual(summary["failures"][0]["code"], "hook-input-unreadable")
        decision = json.loads((self.output / "decisions.jsonl").read_bytes())
        self.assertEqual(decision["effect"], "allow")
        self.assertNotIn("private path", json.dumps(summary))

    def test_identity_observations_bracket_workspace_and_invocation(self):
        order = []
        real_identity = hooks.hook_identity
        real_workspace = hooks.prepare_workspace

        def identity(argv, **kwargs):
            order.append("identity")
            return real_identity(argv, **kwargs)

        def workspace(template):
            order.append("workspace")
            return real_workspace(template)

        def launch(*args, **kwargs):
            order.append("invoke")
            return self.allow

        with (
            mock.patch.object(hooks, "hook_identity", side_effect=identity),
            mock.patch.object(hooks, "prepare_workspace", side_effect=workspace),
            mock.patch.object(hooks, "run_hook", side_effect=launch),
        ):
            self.record()
        self.assertEqual(order, ["identity", "workspace", "invoke", "identity"])

    def test_unchanged_inputs_keep_existing_manifest_and_measurements_contracts(self):
        with mock.patch.object(hooks, "run_hook", return_value=self.allow):
            summary = self.record()
        manifest = self.manifest()
        self.assertEqual(manifest["policy_commit"], self.initial[:40])
        self.assertEqual(summary["failures"], [])
        self.assertEqual(manifest["decision_count"], 1)
        self.assertEqual(
            manifest["decisions_sha256"],
            sha256_bytes((self.output / "decisions.jsonl").read_bytes()),
        )
        self.assertEqual(
            json.loads((self.output / "outcomes.jsonl").read_bytes())["elapsed_ms"], 7
        )
        self.assertTrue((self.output / "measurements.json").is_file())

    def test_output_path_created_by_the_hook_is_not_an_input_change(self):
        self.script.write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "Path(sys.argv[1]).write_text('{}', encoding='utf-8')\n",
            encoding="utf-8",
        )
        log = self.root / "hook-log.json"
        argv = hooks.parse_hook_command(
            json.dumps([sys.executable, str(self.script), str(log)])
        )
        self.spec = hooks.HookSpec(argv)
        initial = hooks.hook_identity(argv)
        summary = self.record()
        self.assertTrue(log.is_file(), "the synthetic hook wrote its output path")
        self.assertEqual(summary["failures"], [])
        self.assertEqual(summary["outcomes"]["allow"], 1)
        self.assertEqual(self.manifest()["policy_commit"], initial[:40])

    def test_file_positions_keep_the_legacy_digest_and_mark_vanished_files(self):
        argv = (sys.executable, str(self.script), "--flag")
        positions = hooks.hook_file_positions(argv)
        self.assertEqual(positions, frozenset({1}))
        before = hooks.hook_identity(argv, file_positions=positions)
        self.assertEqual(before, hooks.hook_identity(argv))
        self.script.unlink()
        vanished = hooks.hook_identity(argv, file_positions=positions)
        self.assertNotEqual(vanished, before)
        # Not the digest of the path as a plain word either.
        self.assertNotEqual(vanished, hooks.hook_identity(argv))

    def test_existing_process_failure_and_observed_input_change_both_survive(self):
        def crash(*args, **kwargs):
            self.script.write_bytes(b"# changed\n")
            return hooks.HookOutcome("crash", "Synthetic crash.", 7, 9)

        with mock.patch.object(hooks, "run_hook", side_effect=crash):
            summary = self.record()
        self.assertEqual(
            {failure["code"] for failure in summary["failures"]},
            {"hook-crash", "hook-input-changed"},
        )

    def test_cli_record_marks_real_self_modification_as_source_failure(self):
        self.script.write_text(
            "from pathlib import Path\n"
            "path = Path(__file__)\n"
            "path.write_bytes(path.read_bytes() + b'# self-modified\\n')\n",
            encoding="utf-8",
        )
        command = json.dumps(self.spec.argv)
        initial = hooks.hook_identity(hooks.parse_hook_command(command))
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = app.main(
                [
                    "record",
                    "--hook",
                    command,
                    "--corpus",
                    str(self.corpus()),
                    "--output",
                    str(self.output),
                ]
            )
        self.assertEqual(code, 3)
        self.assertEqual(self.manifest()["policy_commit"], initial[:40])
        printed = json.loads(stream.getvalue())
        self.assertEqual(printed["outcomes"]["allow"], 1)
        # Exit 3 alone could come from any source failure.
        self.assertIn(
            "hook-input-changed", {failure["code"] for failure in printed["failures"]}
        )

    def test_identical_allow_replies_cannot_hide_real_self_modifying_hooks(self):
        code = (
            "from pathlib import Path\n"
            "path = Path(__file__)\n"
            "path.write_bytes(path.read_bytes() + b'# self-modified\\n')\n"
        )
        second = self.root / "candidate.py"
        self.script.write_text(code, encoding="utf-8")
        second.write_text(code, encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            exit_code = app.main(
                [
                    "hooks",
                    "--baseline",
                    json.dumps(self.spec.argv),
                    "--candidate",
                    json.dumps([sys.executable, str(second)]),
                    "--corpus",
                    str(self.corpus()),
                    "--output",
                    str(self.output),
                ]
            )
        self.assertEqual(exit_code, 3)
        report = json.loads((self.output / "report" / "report.json").read_bytes())
        self.assertEqual(report["counts"]["unchanged"], 1)
        self.assertEqual(report["gate"]["status"], "error")
        for side in ("baseline", "candidate"):
            self.assertEqual(
                report["source_failures"][side][0]["code"], "hook-input-changed"
            )
        self.assertIn(
            "Gate: **ERROR**",
            (self.output / "report" / "pr-comment-aggregate.md").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
