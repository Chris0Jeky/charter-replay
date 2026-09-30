"""Review views participate in the same kernel report publication transaction."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from charter_replay import cli
from charter_replay.tests.contract import test_cli as fixtures
from charter_replay.tests.contract.test_hook_failures import arguments, command, invoke


class ReviewOutputTests(unittest.TestCase):
    def test_hook_failure_gate_matches_the_html_and_both_pr_views(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            hook = command("raise SystemExit(7)")
            self.assertEqual(invoke(arguments(corpus, output, hook, hook)), 3)
            report = output / "report"
            self.assertIn("ERROR", (report / "report.html").read_text("utf-8"))
            for name in ("pr-comment.md", "pr-comment-aggregate.md"):
                self.assertIn("Gate: **ERROR**", (report / name).read_text("utf-8"))

    def test_kernel_replay_also_emits_views_without_running_a_hook(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, recording, _ = data
            output = directory / "out"
            code = invoke(
                [
                    "replay",
                    "--baseline",
                    f"recorded:{recording}",
                    "--candidate",
                    f"recorded:{recording}",
                    "--corpus",
                    str(corpus),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(code, 0)
            for name in ("report.html", "pr-comment.md", "pr-comment-aggregate.md"):
                self.assertTrue((output / name).is_file())

    def test_auxiliary_artifact_failure_rolls_back_the_kernel_artifact_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"
            output.mkdir()
            names = ("run-manifest.json", "report.json", "report.md")
            for name in names:
                (output / name).write_bytes(b"previous")
            (output / "report.html").mkdir()
            with self.assertRaises(OSError):
                cli._publish_report_set(
                    output,
                    run_manifest_bytes=b"new",
                    report_bytes=b"new",
                    markdown_bytes=b"new",
                    html_bytes=b"new",
                    comment_bytes=b"new",
                    aggregate_bytes=b"new",
                )
            for name in names:
                self.assertEqual((output / name).read_bytes(), b"previous")
            self.assertFalse((output / "pr-comment.md").exists())
            self.assertFalse((output / "pr-comment-aggregate.md").exists())

    def _publish_failing_on(self, output, failing_name, *, break_unlink=False):
        """Publish six artifacts; the move of `failing_name` into place fails."""
        real_replace = Path.replace

        def replace(source, target):
            # Only the staged -> output move of the chosen artifact is broken,
            # so earlier artifacts are already linked and must be rolled back.
            if source.parent.name == "staged" and source.name == failing_name:
                raise OSError("synthetic move failure")
            return real_replace(source, target)

        patches = [
            mock.patch.object(Path, "replace", autospec=True, side_effect=replace)
        ]
        if break_unlink:
            patches.append(
                mock.patch.object(
                    Path, "unlink", autospec=True, side_effect=OSError("stuck")
                )
            )
        with patches[0], patches[1] if break_unlink else mock.MagicMock():
            cli._publish_report_set(
                output,
                run_manifest_bytes=b"new",
                report_bytes=b"new",
                markdown_bytes=b"new",
                html_bytes=b"new",
                comment_bytes=b"new",
                aggregate_bytes=b"new",
            )

    def test_failure_after_the_first_links_unlinks_new_and_restores_previous(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"
            output.mkdir()
            previous = ("run-manifest.json", "report.json", "report.md")
            for name in previous:
                (output / name).write_bytes(b"previous")
            with self.assertRaises(OSError) as raised:
                self._publish_failing_on(output, "pr-comment.md")
            self.assertIn("synthetic move failure", str(raised.exception))
            # run-manifest, report, report.md and report.html were linked before
            # the failure: the first three are restored, the new html is removed.
            for name in previous:
                self.assertEqual((output / name).read_bytes(), b"previous", name)
            self.assertEqual(
                sorted(entry.name for entry in output.iterdir()), sorted(previous)
            )
            self.assertEqual(
                [entry.name for entry in Path(temporary).iterdir()], ["out"]
            )

    def test_incomplete_rollback_is_reported_and_keeps_recovery_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"
            output.mkdir()
            (output / "report.json").write_bytes(b"previous")
            with self.assertRaises(OSError) as raised:
                self._publish_failing_on(output, "report.md", break_unlink=True)
            self.assertIn("rollback was incomplete", str(raised.exception))
            retained = [
                entry
                for entry in Path(temporary).iterdir()
                if entry.name.startswith(".replay-output-")
            ]
            self.assertEqual(len(retained), 1)
            # The previous report was restored over the new one, the unlink that
            # failed left a new file behind, and the staged copy is kept.
            self.assertEqual((output / "report.json").read_bytes(), b"previous")
            self.assertEqual((output / "run-manifest.json").read_bytes(), b"new")
            self.assertEqual(
                (retained[0] / "staged" / "report.md").read_bytes(), b"new"
            )


if __name__ == "__main__":
    unittest.main()
