from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

from charter_replay.cli import main

ROOT = Path(__file__).parents[2]
BASELINE = ROOT / "charter_replay" / "fixtures" / "legacy-decisions.jsonl"
CANDIDATE = (
    ROOT
    / "charter_replay"
    / "tests"
    / "fixtures"
    / "process_policies"
    / "reference_candidate.py"
)
CORPUS = ROOT / "charter_replay" / "corpora" / "charter" / "events.jsonl"
EXTRACTION_MANIFEST = ROOT / "docs" / "extraction" / "public-v0-manifest.json"


class DeterminismTests(unittest.TestCase):
    @staticmethod
    def _stage_reference_inputs(root: Path) -> tuple[Path, Path, Path]:
        baseline = root / "fixtures" / "legacy-decisions.jsonl"
        baseline.parent.mkdir(parents=True)
        shutil.copy2(BASELINE, baseline)
        shutil.copy2(
            Path(f"{BASELINE}.manifest.json"), Path(f"{baseline}.manifest.json")
        )

        candidate = root / "policies" / "reference_candidate.py"
        candidate.parent.mkdir(parents=True)
        shutil.copy2(CANDIDATE, candidate)

        corpus = root / "corpora" / "charter"
        shutil.copytree(CORPUS.parent, corpus)
        return baseline, candidate, corpus / "events.jsonl"

    def test_two_portable_reference_runs_match_and_finish_under_sixty_seconds(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            temporary_root = Path(raw_directory)
            first_inputs = self._stage_reference_inputs(
                temporary_root / "fictional-alpha-checkout"
            )
            second_inputs = self._stage_reference_inputs(
                temporary_root / "fictional-beta-checkout"
            )
            first_output = temporary_root / "alpha-artifacts" / "proof"
            second_output = temporary_root / "beta-results" / "replay"

            def run_once(inputs: tuple[Path, Path, Path], output: Path):
                baseline, candidate, corpus = inputs
                arguments = [
                    "replay",
                    "--baseline",
                    f"recorded:{baseline}",
                    "--candidate",
                    f"process:{sys.executable},{candidate}",
                    "--corpus",
                    str(corpus),
                    "--output",
                    str(output),
                ]
                self.assertEqual(0, main(arguments))
                return {
                    name: (output / name).read_bytes()
                    for name in ("run-manifest.json", "report.json", "report.md")
                }

            started = time.perf_counter()
            with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "0"}):
                first = run_once(first_inputs, first_output)
                second = run_once(second_inputs, second_output)
            elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 60)
        self.assertEqual(first["run-manifest.json"], second["run-manifest.json"])
        self.assertEqual(first["report.json"], second["report.json"])
        self.assertNotEqual(first["report.md"], second["report.md"])
        self.assertNotIn(b"reproduction_argv", first["report.json"])
        manifest = json.loads(first["run-manifest.json"])
        report = json.loads(first["report.json"])
        self.assertEqual(manifest["run_id"], report["run_id"])
        self.assertEqual("1970-01-01T00:00:00Z", manifest["generated_at"])
        self.assertNotIn("reproduction_command", report)
        self.assertEqual(50, report["counts"]["unchanged"])
        self.assertEqual("pass", report["gate"]["status"])
        expected_ids = [
            json.loads(line)["event_id"]
            for line in CORPUS.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            expected_ids,
            [row["event"]["event_id"] for row in report["results"]],
        )
        first_markdown = first["report.md"].decode("utf-8")
        second_markdown = second["report.md"].decode("utf-8")
        self.assertIn("structured argv (portable source of truth)", first_markdown)
        self.assertIn(
            (
                "Windows PowerShell rendering for this host:"
                if os.name == "nt"
                else "POSIX sh rendering for this host:"
            ),
            first_markdown,
        )
        self.assertIn(str(first_output), first_markdown)
        self.assertIn(str(second_output), second_markdown)


if __name__ == "__main__":
    unittest.main()
