"""End to end: two versions of the example hook compared over the charter corpus."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from charter_replay.app import main

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "charter_replay" / "corpora" / "charter"
GUARDS = REPO / "examples" / "toy-guard"


def _hook(name: str) -> str:
    return json.dumps([sys.executable, str(GUARDS / name)])


class HookDiffTests(unittest.TestCase):
    def test_toy_guard_upgrade_reports_its_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "run"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "hooks",
                        "--baseline",
                        _hook("guard_v1.py"),
                        "--candidate",
                        _hook("guard_v2.py"),
                        "--corpus",
                        str(CORPUS),
                        "--output",
                        str(output),
                        "--jobs",
                        "4",
                    ]
                )
            self.assertEqual(code, 1)
            summary = json.loads((output / "summary.json").read_text("utf-8"))
            self.assertEqual(summary["counts"]["newly-allowed"], 4)
            self.assertEqual(summary["counts"]["newly-denied"], 1)
            self.assertEqual(summary["counts"]["newly-indeterminate"], 0)
            self.assertEqual(
                summary["by_case_class"]["dangerous"].get("newly-allowed"), 1
            )
            self.assertEqual(summary["outcomes"]["candidate"]["crash"], 0)
            for name in ("report.json", "report.md", "run-manifest.json"):
                self.assertTrue((output / "report" / name).is_file(), name)
            markdown = (output / "summary.md").read_text("utf-8")
            self.assertIn("no corpus command was executed", markdown)

    def test_same_hook_twice_passes_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "hooks",
                        "--baseline",
                        _hook("guard_v1.py"),
                        "--candidate",
                        _hook("guard_v1.py"),
                        "--corpus",
                        str(CORPUS),
                        "--output",
                        str(Path(tmp) / "run"),
                    ]
                )
            self.assertEqual(code, 0)

    def test_bad_hook_command_is_input_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "record",
                        "--hook",
                        "[",
                        "--corpus",
                        str(CORPUS),
                        "--output",
                        tmp,
                    ]
                )
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
