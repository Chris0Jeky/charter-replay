"""A failed `hooks` rerun must not leave the previous run's files looking current."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from charter_replay import app
from charter_replay.review_reports import REPORT_FILES
from charter_replay.tests.contract import test_cli as fixtures

STALE_MARK = b"stale from an earlier run\n"


def _hook() -> str:
    return json.dumps([sys.executable, "-c", "pass"])


def _argv(corpus: Path, output: Path) -> list[str]:
    return [
        "hooks",
        "--baseline",
        _hook(),
        "--candidate",
        _hook(),
        "--corpus",
        str(corpus),
        "--output",
        str(output),
    ]


def _invoke(argv: list[str]) -> tuple[int, str]:
    stderr = io.StringIO()
    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
        try:
            return app.main(argv), stderr.getvalue()
        except SystemExit as exc:
            return int(exc.code), stderr.getvalue()


def _seed(output: Path) -> list[Path]:
    seeded = [output / "summary.json", output / "summary.md"]
    seeded += [output / "report" / name for name in REPORT_FILES]
    for side in ("baseline", "candidate"):
        seeded += [output / side / name for name in app.RECORDING_FILES]
    for path in seeded:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(STALE_MARK)
    return seeded


class StaleOutputTests(unittest.TestCase):
    def test_recording_failure_leaves_no_earlier_derived_file(self):
        failures = {
            "record_hook raises": mock.patch.object(
                app, "record_hook", side_effect=OSError("disk full")
            ),
            "write fails midway": mock.patch(
                "charter_replay.hooks.latency_summary", side_effect=OSError("disk full")
            ),
        }
        for label, patched in failures.items():
            with self.subTest(label), fixtures.CliTests().fixture("same") as data:
                directory, corpus, _, _ = data
                output = directory / "out"
                seeded = _seed(output)
                with patched:
                    code, stderr = _invoke(_argv(corpus, output))
                self.assertEqual(code, 3)
                self.assertIn("output failed", stderr)
                for path in seeded:
                    if path.exists():
                        self.assertNotEqual(
                            path.read_bytes(), STALE_MARK, f"stale {path.name}"
                        )

    def test_success_replaces_every_stale_file(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            seeded = _seed(output)
            self.assertEqual(_invoke(_argv(corpus, output))[0], 0)
            for path in seeded:
                self.assertNotEqual(path.read_bytes(), STALE_MARK, path.name)

    def test_invalid_input_writes_and_removes_nothing(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            seeded = _seed(output)
            argv = _argv(corpus, output)
            argv[argv.index("--baseline") + 1] = json.dumps(
                [sys.executable, "missing-hook-xyz.py"]
            )
            code, _stderr = _invoke(argv)
            self.assertEqual(code, 2)
            self.assertTrue(all(path.read_bytes() == STALE_MARK for path in seeded))

    def test_linked_report_directory_is_refused_and_nothing_is_removed(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            elsewhere = directory / "elsewhere"
            elsewhere.mkdir()
            (elsewhere / "report.json").write_bytes(STALE_MARK)
            output.mkdir()
            (output / "summary.json").write_bytes(STALE_MARK)
            try:
                (output / "report").symlink_to(elsewhere, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")
            code, stderr = _invoke(_argv(corpus, output))
            self.assertEqual(code, 2)
            self.assertIn("is a link", stderr)
            self.assertEqual((elsewhere / "report.json").read_bytes(), STALE_MARK)
            self.assertEqual((output / "summary.json").read_bytes(), STALE_MARK)

    def test_non_regular_entry_on_a_derived_name_is_refused_before_any_removal(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            (output / "report" / "report.md").mkdir(parents=True)
            (output / "summary.md").write_bytes(STALE_MARK)
            code, stderr = _invoke(_argv(corpus, output))
            self.assertEqual(code, 2)
            self.assertIn("not a regular file", stderr)
            self.assertEqual((output / "summary.md").read_bytes(), STALE_MARK)


class ExitThreeDiagnosticTests(unittest.TestCase):
    def test_gate_error_and_output_failure_are_told_apart(self):
        crash = json.dumps([sys.executable, "-c", "raise SystemExit(7)"])
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            argv = _argv(corpus, directory / "gate")
            argv[argv.index("--baseline") + 1] = crash
            code, gate_stderr = _invoke(argv)
            self.assertEqual(code, 3)
            self.assertIn("replay gate error", gate_stderr)
            self.assertNotIn("output failed", gate_stderr)
            with mock.patch.object(
                app.kernel, "_publish_report_set", side_effect=OSError("disk full")
            ):
                code, output_stderr = _invoke(_argv(corpus, directory / "publish"))
            self.assertEqual(code, 3)
            self.assertIn("replay output failed", output_stderr)
            self.assertNotIn("gate error", output_stderr)

    def test_record_failures_are_a_gate_error_not_an_output_failure(self):
        crash = json.dumps([sys.executable, "-c", "raise SystemExit(7)"])
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            code, stderr = _invoke(
                [
                    "record",
                    "--hook",
                    crash,
                    "--corpus",
                    str(corpus),
                    "--output",
                    str(directory / "rec"),
                ]
            )
            self.assertEqual(code, 3)
            self.assertIn("gate error", stderr)
            self.assertNotIn("output failed", stderr)


if __name__ == "__main__":
    unittest.main()
