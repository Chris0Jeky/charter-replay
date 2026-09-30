"""Review views participate in the same kernel report publication transaction."""

from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
