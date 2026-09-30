"""A failed `hooks` rerun must not leave the previous run's files looking current."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import unittest
from unittest import mock

from charter_replay import app
from charter_replay.review_reports import REPORT_FILES
from charter_replay.tests.contract import test_cli as fixtures
from charter_replay.tests.links import link_directory

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
            # Either side invalid: removal must wait until both are admitted.
            for side in ("--baseline", "--candidate"):
                with self.subTest(side=side):
                    argv = _argv(corpus, output)
                    argv[argv.index(side) + 1] = json.dumps(
                        [sys.executable, "missing-hook-xyz.py"]
                    )
                    code, _stderr = _invoke(argv)
                    self.assertEqual(code, 2)
                    self.assertTrue(
                        all(path.read_bytes() == STALE_MARK for path in seeded)
                    )

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

    @unittest.skipUnless(os.name == "nt", "NTFS junctions")
    def test_linked_report_junction_is_refused_and_nothing_is_removed(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            elsewhere = directory / "elsewhere"
            elsewhere.mkdir()
            (elsewhere / "report.json").write_bytes(STALE_MARK)
            output.mkdir()
            (output / "summary.json").write_bytes(STALE_MARK)
            link_directory(self, output / "report", elsewhere, junction=True)
            code, stderr = _invoke(_argv(corpus, output))
            self.assertEqual(code, 2)
            self.assertIn("is a link", stderr)
            self.assertEqual((elsewhere / "report.json").read_bytes(), STALE_MARK)
            self.assertEqual((output / "summary.json").read_bytes(), STALE_MARK)

    def test_a_locked_file_does_not_stop_the_other_removals(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            seeded = _seed(output)
            locked = output / "summary.json"
            real_unlink = Path.unlink

            def unlink(path, *args, **kwargs):
                if path == locked:
                    raise PermissionError("locked by another process")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(Path, "unlink", unlink):
                code, stderr = _invoke(_argv(corpus, output))
            self.assertEqual(code, 3)
            self.assertIn("output failed: 1 stale output file(s)", stderr)
            self.assertNotIn(str(directory), stderr)
            self.assertNotIn("locked", stderr)
            # Every other stale file went, and no recording was started.
            self.assertEqual([path for path in seeded if path.exists()], [locked])

    def test_every_failed_removal_is_counted_once_in_one_error(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            seeded = _seed(output)
            with mock.patch.object(Path, "unlink", side_effect=PermissionError):
                code, stderr = _invoke(_argv(corpus, output))
            self.assertEqual(code, 3)
            self.assertIn(f"output failed: {len(seeded)} stale", stderr)
            self.assertEqual(stderr.count("output failed"), 1)
            self.assertTrue(all(path.exists() for path in seeded))

    def test_a_subdirectory_swapped_for_a_link_after_the_check_is_not_followed(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "out"
            seeded = _seed(output)
            elsewhere = directory / "elsewhere"
            elsewhere.mkdir()
            (elsewhere / "report.json").write_bytes(STALE_MARK)
            real = app._unlink_stale
            swaps = []

            def swapped_after_the_check(target, root):
                # `_derived_artifacts` already saw a plain directory here.
                if target.parent.name == "report" and not swaps:
                    swaps.append(target)
                    shutil.rmtree(root / "report")
                    link_directory(self, root / "report", elsewhere)
                return real(target, root)

            with mock.patch.object(app, "_unlink_stale", swapped_after_the_check):
                code, stderr = _invoke(_argv(corpus, output))
            self.assertEqual(code, 3)
            self.assertIn(f"output failed: {len(REPORT_FILES)} stale", stderr)
            self.assertEqual((elsewhere / "report.json").read_bytes(), STALE_MARK)
            for path in seeded:
                if path.parent.name != "report":
                    self.assertFalse(path.exists(), path.name)

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


class LinkDetectionTests(unittest.TestCase):
    """Only redirecting reparse points count as links (OneDrive placeholders don't)."""

    REPARSE = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT

    def metadata(self, tag):
        return mock.Mock(
            st_mode=stat.S_IFDIR | 0o755,
            st_file_attributes=self.REPARSE,
            st_reparse_tag=tag,
        )

    def is_link(self, tag):
        path = mock.Mock(spec=Path)
        path.lstat.return_value = self.metadata(tag)
        with (
            mock.patch.object(stat, "FILE_ATTRIBUTE_REPARSE_POINT", self.REPARSE),
            mock.patch.object(app, "_LINK_REPARSE_TAGS", frozenset({1, 2})),
        ):
            return app._is_link(path)

    def test_symlink_and_junction_tags_are_links(self):
        self.assertTrue(self.is_link(1))
        self.assertTrue(self.is_link(2))

    def test_other_reparse_tags_are_not_links(self):
        # IO_REPARSE_TAG_CLOUD_6 marks a OneDrive placeholder directory.
        self.assertFalse(self.is_link(0x9000601A))


if __name__ == "__main__":
    unittest.main()
