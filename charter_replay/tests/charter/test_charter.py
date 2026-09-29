from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import sys
import unittest

from charter_replay.compare import compare_decisions
from charter_replay.corpus import (
    validate_charter_cases,
    validate_command_events,
    validate_policy_decisions,
)
from charter_replay.manifests import load_corpus_manifest
from charter_replay.policy_sources import ProcessDecisionSource, RecordedDecisionSource

ROOT = Path(__file__).parents[3]
CORPUS_DIRECTORY = ROOT / "charter_replay" / "corpora" / "charter"
EVENTS_PATH = CORPUS_DIRECTORY / "events.jsonl"
CASES_PATH = CORPUS_DIRECTORY / "cases.jsonl"
MANIFEST_PATH = CORPUS_DIRECTORY / "corpus-manifest.json"
BASELINE_PATH = ROOT / "charter_replay" / "fixtures" / "legacy-decisions.jsonl"
CANDIDATE_PATH = (
    ROOT
    / "charter_replay"
    / "tests"
    / "fixtures"
    / "process_policies"
    / "reference_candidate.py"
)

PRIVATE_PATTERNS = (
    re.compile(r"(?i)C:\\Users\\"),
    re.compile(r"(?i)/home/"),
    re.compile(r"(?i)github\.com"),
    re.compile(r"(?i)(?:ghp_|github_pat_|AKIA|Bearer\s|sk-[A-Za-z0-9])"),
    re.compile(r"(?i)https?://"),
)


def load_jsonl(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class CharterCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.events = validate_command_events(load_jsonl(EVENTS_PATH))
        cls.cases = validate_charter_cases(load_jsonl(CASES_PATH))
        cls.baseline = validate_policy_decisions(load_jsonl(BASELINE_PATH))

    def test_manifest_binds_fifty_paired_records(self) -> None:
        loaded = load_corpus_manifest(MANIFEST_PATH)
        self.assertEqual("charter-v0.1", loaded.value["corpus_id"])
        self.assertEqual(50, loaded.value["event_count"])
        self.assertEqual(50, len(self.events))
        self.assertEqual(50, len(self.cases))
        self.assertEqual(
            [event["event_id"] for event in self.events],
            [case["event_id"] for case in self.cases],
        )

    def test_composition_is_exactly_twenty_twenty_ten(self) -> None:
        counts = Counter(case["case_class"] for case in self.cases)
        self.assertEqual(
            {"dangerous": 20, "benign": 20, "opaque": 10},
            dict(counts),
        )

    def test_every_record_is_fictional_synthetic_or_redacted(self) -> None:
        serialized = "\n".join(
            json.dumps(value, sort_keys=True) for value in [*self.events, *self.cases]
        )
        for pattern in PRIVATE_PATTERNS:
            with self.subTest(pattern=pattern.pattern):
                self.assertIsNone(pattern.search(serialized))
        self.assertTrue(
            all(event["cwd"].startswith("sandbox/") for event in self.events)
        )
        self.assertTrue(
            all(
                event["source"] == case["provenance"]
                for event, case in zip(self.events, self.cases, strict=True)
            )
        )
        self.assertEqual(
            {"synthetic", "historical-redacted"},
            {event["source"] for event in self.events},
        )

    def test_synthetic_recording_matches_class_contract(self) -> None:
        result = RecordedDecisionSource(BASELINE_PATH).evaluate(self.events)
        self.assertTrue(result.is_valid)
        expected = {
            "dangerous": "deny",
            "benign": "allow",
            "opaque": "indeterminate",
        }
        effects_by_id = {
            decision["event_id"]: decision["effect"] for decision in result.decisions
        }
        for case in self.cases:
            self.assertEqual(
                expected[case["case_class"]], effects_by_id[case["event_id"]]
            )
        self.assertTrue(
            all("Synthetic charter baseline" in row["reason"] for row in self.baseline)
        )
        manifest = json.loads(
            Path(f"{BASELINE_PATH}.manifest.json").read_text(encoding="utf-8")
        )
        self.assertIn("synthetic", manifest["policy_id"])

    def test_reference_candidate_is_complete_and_semantically_unchanged(self) -> None:
        candidate = ProcessDecisionSource(
            [sys.executable, str(CANDIDATE_PATH)]
        ).evaluate(self.events)
        self.assertTrue(candidate.is_valid)
        comparison = compare_decisions(
            self.events,
            self.baseline,
            list(candidate.decisions),
            case_values=self.cases,
        )
        self.assertEqual(50, comparison.counts["unchanged"])
        self.assertEqual(
            0,
            sum(
                count
                for classification, count in comparison.counts.items()
                if classification != "unchanged"
            ),
        )


if __name__ == "__main__":
    unittest.main()
