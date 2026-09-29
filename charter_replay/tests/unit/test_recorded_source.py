from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from charter_replay.policy_sources import RecordedDecisionSource

EVENTS = [
    {
        "schema_version": "command-event.v1",
        "event_id": "git-force-main-001",
        "timestamp": "2026-07-30T12:00:00Z",
        "command": "git push origin main --force",
        "cwd": "/fictional/shop-api",
        "source": "synthetic",
    },
    {
        "schema_version": "command-event.v1",
        "event_id": "git-status-001",
        "timestamp": "2026-07-30T12:01:00Z",
        "command": "git status --short",
        "cwd": "/fictional/shop-api",
        "source": "synthetic",
    },
]

DECISIONS = [
    {
        "schema_version": "policy-decision.v1",
        "event_id": "git-force-main-001",
        "effect": "deny",
        "reason": "The recorded baseline denied this event.",
    },
    {
        "schema_version": "policy-decision.v1",
        "event_id": "git-status-001",
        "effect": "allow",
        "reason": "The recorded baseline allowed this event.",
    },
]


class RecordedSourceTests(unittest.TestCase):
    @contextmanager
    def recording(self, decisions, *, manifest_updates=None):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            decision_path = directory / "decisions.jsonl"
            content = "".join(
                (
                    f"{json.dumps(value, sort_keys=True, separators=(',', ':'))}\n"
                    if not isinstance(value, str)
                    else f"{value}\n"
                )
                for value in decisions
            )
            decision_path.write_text(content, encoding="utf-8", newline="\n")
            manifest = {
                "schema_version": "recorded-policy-manifest.v1",
                "policy_id": "floor-v1-final",
                "policy_commit": "02bd14cfe094f9b6af85b966de481ff3f45264cf",
                "decisions_file": decision_path.name,
                "decisions_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "decision_count": len(decisions),
            }
            manifest.update(manifest_updates or {})
            Path(f"{decision_path}.manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8", newline="\n"
            )
            yield decision_path

    def test_complete_recording_returns_ordered_decisions(self) -> None:
        fixture = Path(__file__).parents[2] / "fixtures" / "recorded" / "complete.jsonl"
        result = RecordedDecisionSource(fixture).evaluate(EVENTS)
        self.assertTrue(result.is_valid)
        self.assertEqual(["deny", "allow"], [row["effect"] for row in result.decisions])

    def test_captured_inputs_must_be_supplied_as_a_pair(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be supplied together"):
            RecordedDecisionSource("decisions.jsonl", decisions_bytes=b"")

    def test_missing_record_becomes_indeterminate(self) -> None:
        with self.recording(DECISIONS[:1]) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertFalse(result.is_valid)
        self.assertEqual(["deny", "indeterminate"], self.effects(result))
        self.assertEqual(["recording-missing-event"], self.failure_codes(result))

    def test_duplicate_record_becomes_indeterminate(self) -> None:
        with self.recording([DECISIONS[0], DECISIONS[0], DECISIONS[1]]) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertEqual(["indeterminate", "allow"], self.effects(result))
        self.assertIn("recording-duplicate-event", self.failure_codes(result))

    def test_malformed_and_missing_records_are_reported(self) -> None:
        with self.recording(["{not json", DECISIONS[1]]) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertEqual(["indeterminate", "allow"], self.effects(result))
        self.assertEqual(
            ["recording-json-invalid", "recording-missing-event"],
            self.failure_codes(result),
        )

    def test_duplicate_json_key_is_invalid_and_fails_closed(self) -> None:
        duplicate_effect = (
            '{"schema_version":"policy-decision.v1",'
            '"event_id":"git-force-main-001","effect":"allow",'
            '"effect":"deny","reason":"ambiguous"}'
        )
        with self.recording([duplicate_effect, DECISIONS[1]]) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertEqual(["indeterminate", "allow"], self.effects(result))
        self.assertEqual(
            ["recording-json-invalid", "recording-missing-event"],
            self.failure_codes(result),
        )

    def test_non_lf_record_separator_fails_closed(self) -> None:
        with self.recording(DECISIONS) as path:
            content = "\v".join(
                json.dumps(value, sort_keys=True, separators=(",", ":"))
                for value in DECISIONS
            ).encode("utf-8")
            path.write_bytes(content)
            manifest_path = Path(f"{path}.manifest.json")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["decisions_sha256"] = hashlib.sha256(content).hexdigest()
            manifest_path.write_text(
                json.dumps(manifest), encoding="utf-8", newline="\n"
            )
            result = RecordedDecisionSource(path).evaluate(EVENTS)

        self.assertEqual(["indeterminate", "indeterminate"], self.effects(result))
        self.assertEqual(["recording-count-mismatch"], self.failure_codes(result))

    def test_invalid_schema_record_becomes_indeterminate(self) -> None:
        invalid = {**DECISIONS[0], "effect": "warn"}
        with self.recording([invalid, DECISIONS[1]]) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertEqual(["indeterminate", "allow"], self.effects(result))
        self.assertEqual(["recording-schema-invalid"], self.failure_codes(result))

    def test_unexpected_record_fails_validation_without_reordering(self) -> None:
        unexpected = {**DECISIONS[0], "event_id": "unknown-001"}
        with self.recording([*DECISIONS, unexpected]) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertEqual(["deny", "allow"], self.effects(result))
        self.assertEqual(["recording-unexpected-event"], self.failure_codes(result))

    def test_digest_mismatch_makes_every_event_indeterminate(self) -> None:
        with self.recording(
            DECISIONS, manifest_updates={"decisions_sha256": "0" * 64}
        ) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertEqual(["indeterminate", "indeterminate"], self.effects(result))
        self.assertEqual(["recording-digest-mismatch"], self.failure_codes(result))

    def test_manifest_file_mismatch_makes_every_event_indeterminate(self) -> None:
        with self.recording(
            DECISIONS, manifest_updates={"decisions_file": "other.jsonl"}
        ) as path:
            result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertEqual(["indeterminate", "indeterminate"], self.effects(result))
        self.assertEqual(["recording-file-mismatch"], self.failure_codes(result))

    def test_evaluation_never_imports_the_legacy_dispatcher(self) -> None:
        original_import = __import__

        def guarded_import(name, *args, **kwargs):
            if name == "templates.hooks.dispatch":
                raise AssertionError("legacy dispatcher import attempted")
            return original_import(name, *args, **kwargs)

        with self.recording(DECISIONS) as path:
            with mock.patch("builtins.__import__", side_effect=guarded_import):
                result = RecordedDecisionSource(path).evaluate(EVENTS)
        self.assertTrue(result.is_valid)

    @staticmethod
    def effects(result) -> list[str]:
        return [decision["effect"] for decision in result.decisions]

    @staticmethod
    def failure_codes(result) -> list[str]:
        return [failure.code for failure in result.failures]


if __name__ == "__main__":
    unittest.main()
