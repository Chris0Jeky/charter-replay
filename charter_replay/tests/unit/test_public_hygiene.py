"""Public files of the replay tool carry no machine paths or private names."""

from __future__ import annotations

import json
from pathlib import Path
import re
import tempfile
import unittest

from charter_replay import cli as kernel

REPO = Path(__file__).resolve().parents[3]
PUBLIC = [
    *sorted((REPO / "charter_replay").glob("*.py")),
    REPO / "README.md",
    REPO / "pyproject.toml",
    *sorted(path for path in (REPO / "examples").rglob("*") if path.is_file()),
]
# Assembled so this file does not match itself.
PRIVATE_WORDS = ["mu" + "se", "her" + "mes", "claude" + "-config"]
USER_PATH = re.compile(r"[A-Za-z]:[\/]+Users[\/]+[A-Za-z]|/(?:home|Users)/[a-z]")


class PublicHygieneTests(unittest.TestCase):
    def test_no_machine_paths_or_private_names(self) -> None:
        pattern = re.compile(
            r"(?i)\b(?:" + "|".join(map(re.escape, PRIVATE_WORDS)) + r")\b"
        )
        for path in PUBLIC:
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=path.relative_to(REPO).as_posix()):
                self.assertIsNone(USER_PATH.search(text))
                self.assertIsNone(pattern.search(text))


class ExampleReportTests(unittest.TestCase):
    def test_committed_toy_report_reproduces_from_its_recordings(self) -> None:
        example = REPO / "examples" / "toy-guard" / "report"
        with tempfile.TemporaryDirectory() as tmp:
            code = kernel.main(
                [
                    "replay",
                    "--baseline",
                    f"recorded:{example / 'baseline' / 'decisions.jsonl'}",
                    "--candidate",
                    f"recorded:{example / 'candidate' / 'decisions.jsonl'}",
                    "--corpus",
                    str(REPO / "charter_replay" / "corpora" / "charter"),
                    "--output",
                    tmp,
                ]
            )
            fresh = json.loads(Path(tmp, "report.json").read_text("utf-8"))
        committed = json.loads((example / "report.json").read_text("utf-8"))
        self.assertEqual(code, 1)
        for report in (fresh, committed):
            report.pop("generated_at")
        self.assertEqual(fresh, committed)


if __name__ == "__main__":
    unittest.main()
