"""charter-v0.2: schema, the preserved v0.1 prefix, balance and public hygiene."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from charter_replay import cli as kernel

CORPORA = Path(__file__).resolve().parents[2] / "corpora"
USER_PATH = re.compile(r"(?i)[A-Za-z]:[\/]+Users[\/]+[A-Za-z]|/home/[a-z]")


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


class CharterV02Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = kernel._load_charter_corpus(str(CORPORA / "charter-v0.2"))

    def test_loads_through_the_kernel(self) -> None:
        self.assertEqual(self.corpus.corpus_id, "charter-v0.2")
        self.assertGreaterEqual(self.corpus.event_count, 300)

    def test_charter_v01_is_an_unchanged_prefix(self) -> None:
        for name in ("events.jsonl", "cases.jsonl"):
            old = _lines(CORPORA / "charter" / name)
            new = _lines(CORPORA / "charter-v0.2" / name)
            self.assertEqual(new[: len(old)], old, name)

    def test_measures_both_directions(self) -> None:
        classes = [case["case_class"] for case in self.corpus.cases]
        self.assertGreaterEqual(classes.count("benign"), 150)
        self.assertGreaterEqual(classes.count("dangerous"), 150)

    def test_no_machine_paths_or_credential_shapes(self) -> None:
        for event in self.corpus.events:
            with self.subTest(event_id=event["event_id"]):
                command = event["command"]
                self.assertIsNone(USER_PATH.search(command))
                self.assertIsNone(re.search(r"[0-9a-f]{32}|gh[pousr]_|AKIA", command))
                self.assertLessEqual(len(command), 250)
        ids = [event["event_id"] for event in self.corpus.events]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(json.dumps(i).isascii() for i in ids))


if __name__ == "__main__":
    unittest.main()
