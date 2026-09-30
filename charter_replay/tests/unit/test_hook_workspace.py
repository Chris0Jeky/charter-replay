"""Each event owns its cwd, writable state and cleanup lifecycle."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import hooks
from charter_replay.policy_sources import SourceFailure
from charter_replay.tests.unit.test_hook_adapter import _event

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "hooks" / "workspace_hook.py"
)


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.spec = hooks.HookSpec((sys.executable, str(FIXTURE)), timeout=20)

    def record(self, events, *, jobs=1, template=None):
        output = self.root / f"output-{jobs}"
        summary = hooks.record_hook(
            self.spec,
            events,
            output,
            policy_id="fixture",
            jobs=jobs,
            workspace_template=template,
        )
        records = [
            json.loads(line)
            for line in (output / "decisions.jsonl").read_text("utf-8").splitlines()
        ]
        return summary, records

    def test_each_serial_and_parallel_event_starts_with_fresh_state(self):
        events = [_event(f"state-{index}", "state") for index in range(4)]
        for jobs in (1, 4):
            with self.subTest(jobs=jobs):
                summary, records = self.record(events, jobs=jobs)
                self.assertEqual(summary["outcomes"]["allow"], 4)
                self.assertEqual(summary["failures"], [])
                self.assertEqual(
                    [row["event_id"] for row in records],
                    [row["event_id"] for row in events],
                )
                self.assertEqual([row["effect"] for row in records], ["allow"] * 4)

    def test_process_cwd_matches_payload_and_template_is_not_mutated(self):
        template = self.root / "template"
        (template / "nested").mkdir(parents=True)
        source = template / "nested" / "fixture.txt"
        source.write_text("original", encoding="utf-8")
        events = [_event(f"cwd-{index}", "cwd", "nested") for index in range(3)]
        summary, records = self.record(events, jobs=3, template=template)
        self.assertEqual(summary["outcomes"]["allow"], 3)
        self.assertEqual([row["effect"] for row in records], ["allow"] * 3)
        self.assertEqual(source.read_text("utf-8"), "original")

    def test_failed_copy_removes_partial_workspace(self):
        temporary_root = self.root / "partial"
        temporary_root.mkdir()

        def failed_copy(source, destination):
            destination.mkdir()
            (destination / "partial.txt").write_text("partial", encoding="utf-8")
            raise OSError("synthetic copy failure")

        with mock.patch.object(
            hooks.tempfile, "mkdtemp", return_value=str(temporary_root)
        ):
            with mock.patch.object(hooks.shutil, "copytree", side_effect=failed_copy):
                with self.assertRaises(OSError):
                    hooks.prepare_workspace(self.root / "template")
        self.assertFalse(temporary_root.exists())

    def test_readonly_state_is_cleaned_after_every_event(self):
        workspaces = []
        real_prepare = hooks.prepare_workspace

        def track(template):
            workspace = real_prepare(template)
            workspaces.append(workspace)
            return workspace

        with mock.patch.object(hooks, "prepare_workspace", side_effect=track):
            summary, _ = self.record(
                [_event(f"readonly-{i}", "readonly") for i in range(3)], jobs=3
            )
        self.assertEqual(summary["outcomes"]["allow"], 3)
        self.assertEqual(len(workspaces), 3)
        self.assertTrue(all(not path.parent.exists() for path in workspaces))

    def test_cleanup_failure_remains_visible_without_rewriting_the_hook_reply(self):
        def failed_cleanup(root):
            shutil.rmtree(root)
            return SourceFailure("synthetic", "forced cleanup failure")

        with mock.patch.object(
            hooks, "_cleanup_snapshot_root", side_effect=failed_cleanup
        ):
            summary, records = self.record([_event("cleanup", "allow")])
        self.assertEqual(records[0]["effect"], "allow")
        self.assertEqual(
            summary["failures"][0]["code"], "hook-workspace-cleanup-failed"
        )
        self.assertEqual(summary["failures"][0]["event_id"], "cleanup")

    def test_outside_payload_cwd_is_rejected_before_process_start(self):
        workspace = self.root / "workspace"
        workspace.mkdir()
        payload = hooks.build_payload(
            _event("outside", "allow"), runtime="claude", workspace=workspace, index=0
        )
        payload["cwd"] = str(self.root)
        with mock.patch.object(
            hooks,
            "_run_policy_process",
            side_effect=AssertionError("outside cwd invoked"),
        ) as launch:
            with self.assertRaises(hooks.HookSpecError):
                hooks.run_hook(self.spec, payload, workspace=workspace)
            launch.assert_not_called()

    def test_failed_copy_with_failed_cleanup_is_reported_not_lost(self):
        template = self.root / "template"
        template.mkdir()
        real_cleanup = hooks._cleanup_snapshot_root

        def failed_cleanup(root):
            # Report the failure, but really remove the directory: a mocked
            # cleanup that removes nothing leaks a `hook-replay-*` temp directory.
            real_cleanup(root)
            return SourceFailure("synthetic", "forced cleanup failure")

        with (
            mock.patch.object(
                hooks.shutil, "copytree", side_effect=OSError("synthetic copy failure")
            ),
            mock.patch.object(
                hooks, "_cleanup_snapshot_root", side_effect=failed_cleanup
            ),
        ):
            summary, records = self.record(
                [_event("copy-clean", "allow")], template=template
            )
        self.assertEqual(records[0]["effect"], "indeterminate")
        self.assertEqual(
            [failure["code"] for failure in summary["failures"]],
            ["hook-start-failed", "hook-workspace-cleanup-failed"],
        )
        self.assertEqual(summary["failures"][1]["event_id"], "copy-clean")
        self.assertEqual(summary["outcomes"]["start-failed"], 1)

    def test_failed_copy_with_clean_cleanup_reports_only_start_failed(self):
        template = self.root / "template"
        template.mkdir()
        with mock.patch.object(
            hooks.shutil, "copytree", side_effect=OSError("synthetic copy failure")
        ):
            summary, _records = self.record(
                [_event("copy-only", "allow")], template=template
            )
        self.assertEqual(
            [failure["code"] for failure in summary["failures"]],
            ["hook-start-failed"],
        )

    def test_out_of_workspace_cwd_is_recorded_as_start_failed_for_that_event(self):
        real_run_hook = hooks.run_hook

        def reject_first(spec, payload, *, workspace):
            if payload["tool_input"]["command"] == "reject":
                raise hooks.HookSpecError("hook cwd must stay inside its workspace")
            return real_run_hook(spec, payload, workspace=workspace)

        events = [_event("cwd-0", "reject"), _event("cwd-1", "allow")]
        with mock.patch.object(hooks, "run_hook", side_effect=reject_first):
            summary, records = self.record(events)
        self.assertEqual([row["effect"] for row in records], ["indeterminate", "allow"])
        self.assertEqual(summary["outcomes"]["start-failed"], 1)
        self.assertEqual(summary["outcomes"]["allow"], 1)
        outcomes = (self.root / "output-1" / "outcomes.jsonl").read_text("utf-8")
        self.assertIn('"outcome":"start-failed"', outcomes)
        self.assertIn("outside its workspace", records[0]["reason"])

    def test_preparation_failure_becomes_a_recorded_source_failure(self):
        with mock.patch.object(
            hooks, "prepare_workspace", side_effect=OSError("synthetic failure")
        ):
            summary, records = self.record([_event("prepare", "allow")])
        self.assertEqual(records[0]["effect"], "indeterminate")
        self.assertEqual(summary["failures"][0]["code"], "hook-start-failed")

    def test_corpus_text_is_not_executed(self):
        marker = self.root / "must-not-exist"
        text = f'{sys.executable} -c "from pathlib import Path; Path({str(marker)!r}).touch()"'
        _, records = self.record([_event("inert", text)])
        self.assertEqual(records[0]["effect"], "allow")
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
