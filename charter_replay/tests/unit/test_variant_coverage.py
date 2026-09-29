"""Coverage counts come from verified rows, not names or supplied summaries."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from charter_replay import app, cli
from charter_replay.compare import compare_decisions
from charter_replay.manifests import build_run_manifest
from charter_replay.reports import build_json_report
from charter_replay.tests.unit.test_variants import DOMAIN, write_source
from charter_replay.variant_packs import generate_pack


class VariantCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        write_source(self.source)
        self.pack = self.root / "pack"
        self.lineage = generate_pack(self.source, self.pack, domain=DOMAIN)
        self.loaded = cli._load_charter_corpus(str(self.pack))
        self.path = self.root / "report.json"
        self.report = self.make_report()
        self.save()

    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("charter_replay.variant_coverage"),
            "verified coverage is missing",
        )
        return importlib.import_module("charter_replay.variant_coverage")

    def make_report(self):
        baseline, candidate = [], []
        for event, case in zip(self.loaded.events, self.loaded.cases):
            expected = "deny" if case["case_class"] == "dangerous" else "allow"
            for side, records in (("baseline", baseline), ("candidate", candidate)):
                effect = expected
                if side == "candidate" and event["command"].startswith("env "):
                    effect = "allow" if expected == "deny" else "deny"
                records.append(
                    dict(
                        schema_version="policy-decision.v1",
                        event_id=event["event_id"],
                        effect=effect,
                        reason="private-reason-marker",
                    )
                )
        compared = compare_decisions(
            self.loaded.events, baseline, candidate, case_values=self.loaded.cases
        )
        manifest = build_run_manifest(
            generated_at="2026-01-01T00:00:00Z",
            baseline=dict(kind="recorded", id="private-base", sha256="a" * 64),
            candidate=dict(kind="recorded", id="private-next", sha256="b" * 64),
            corpus=dict(
                id=self.loaded.corpus_id,
                manifest_sha256=self.lineage["output_manifest_sha256"],
                event_count=self.loaded.event_count,
            ),
            fail_on=["newly-allowed", "newly-indeterminate"],
        )
        return build_json_report(compared, manifest)

    def save(self):
        self.path.write_bytes(json.dumps(self.report).encode())

    def coverage(self):
        return self.module().build_coverage(self.source, self.pack, self.path)

    def test_variant_only_regressions_are_not_hidden_by_unchanged_seeds(self):
        result = self.coverage()
        self.assertEqual(result["by_origin"]["seed"]["unchanged"], 2)
        self.assertEqual(result["by_origin"]["derived"]["newly-allowed"], 1)
        self.assertEqual(result["by_origin"]["derived"]["newly-denied"], 1)
        self.assertEqual(result["clusters"]["unchanged_seeds_with_changed_variants"], 2)
        wrapper = result["by_transform"]["env-wrapper.v1"]
        self.assertEqual(wrapper["generated"], 2)
        self.assertEqual(wrapper["shape_effects"]["candidate"]["deny->allow"], 1)
        self.assertEqual(wrapper["shape_effects"]["candidate"]["allow->deny"], 1)
        self.assertEqual(wrapper["shape_effects"]["baseline"]["deny->deny"], 1)

    def test_reordered_rows_are_stable_and_the_report_is_not_modified(self):
        before = self.path.read_bytes()
        first = self.coverage()
        self.assertEqual(self.path.read_bytes(), before)
        self.report["results"].reverse()
        self.save()
        self.assertEqual(first, self.coverage())

    def test_aggregates_omit_private_ids_commands_families_and_identity(self):
        result = self.coverage()
        text = json.dumps(result)
        for secret in (
            "private-", "seed-0", "git push", "fixture", self.report["run_id"]
        ):
            self.assertNotIn(secret, text)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(self.lineage["source_manifest_sha256"], text)
        self.assertNotIn(self.lineage["output_manifest_sha256"], text)
        self.assertIn("not authenticated", text)

    def test_wrong_manifest_identity_count_and_bool_counts_are_rejected(self):
        original = deepcopy(self.report)
        for field, value in (
            ("id", "other-corpus"),
            ("event_count", 7),
            ("manifest_sha256", "a" * 64),
        ):
            self.report = deepcopy(original)
            self.report["corpus"][field] = value
            self.save()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.coverage()
        self.report = deepcopy(original)
        self.report["counts"]["newly-allowed"] = True
        self.save()
        with self.assertRaises(ValueError):
            self.coverage()

    def test_missing_duplicate_or_extra_rows_are_rejected(self):
        original = deepcopy(self.report)
        for rows in (
            original["results"][:-1],
            original["results"] + original["results"][:1],
            original["results"][:-1] + original["results"][:1],
        ):
            self.report["results"] = rows
            self.save()
            with self.assertRaises(ValueError):
                self.coverage()

    def test_command_context_label_decision_and_classification_must_match(self):
        original = deepcopy(self.report)
        changes = (
            ("event", "command", "git clean"),
            ("event", "cwd", "different-context"),
            ("case", "case_class", "benign"),
            ("baseline", "effect", "not-an-effect"),
            ("candidate", "event_id", "seed-1"),
            ("candidate", "reason", "multi\nline"),
        )
        for section, field, value in changes:
            self.report = deepcopy(original)
            self.report["results"][0][section][field] = value
            self.save()
            with (
                self.subTest(section=section, field=field),
                self.assertRaises(ValueError),
            ):
                self.coverage()
        self.report = deepcopy(original)
        self.report["results"][0]["classification"] = "newly-allowed"
        self.save()
        with self.assertRaises(ValueError):
            self.coverage()

    def test_tampered_lineage_and_pack_fail_before_aggregation(self):
        for filename in ("lineage.json", "events.jsonl"):
            path = self.pack / filename
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                self.coverage()
            path.write_bytes(original)

    def test_indeterminate_is_a_distinct_shape_outcome(self):
        self.report["results"][-1]["candidate"]["effect"] = "indeterminate"
        self.report["results"][-1]["classification"] = "newly-indeterminate"
        self.report["counts"]["newly-denied"] -= 1
        self.report["counts"]["newly-indeterminate"] += 1
        self.save()
        result = self.coverage()
        wrapper = result["by_transform"]["env-wrapper.v1"]
        self.assertEqual(
            wrapper["shape_effects"]["candidate"]["allow->indeterminate"], 1
        )
        self.assertEqual(wrapper["changes"]["newly-indeterminate"], 1)

    def test_malformed_duplicate_deep_and_nonfinite_json_are_rejected(self):
        self.module()
        for data in (
            b"{",
            b'{"schema_version":1,"schema_version":2}',
            b"[" * 2000,
            b"NaN",
        ):
            self.path.write_bytes(data)
            with self.assertRaises(ValueError):
                self.coverage()

    def test_unchanged_diff_can_still_have_within_policy_shape_disagreement(self):
        row = next(
            row for row in self.report["results"]
            if row["event"]["command"].startswith("'git'")
            and row["case"]["case_class"] == "dangerous"
        )
        row["baseline"]["effect"] = "allow"
        row["candidate"]["effect"] = "allow"
        self.save()
        quoted = self.coverage()["by_transform"]["quote-words.v1"]
        self.assertEqual(quoted["changes"]["unchanged"], 2)
        for side in ("baseline", "candidate"):
            self.assertEqual(quoted["shape_effects"][side]["deny->allow"], 1)

    def test_exponent_overflow_in_ignored_fields_is_rejected(self):
        self.path.write_text(
            json.dumps(self.report)[:-1] + ', "unused": 1e999}', encoding="utf-8"
        )
        with self.assertRaises(ValueError):
            self.coverage()

    def test_report_budget_is_enforced_before_json_decode(self):
        module = self.module()
        with mock.patch.object(module, "MAX_REPORT_BYTES", 16):
            with self.assertRaises(ValueError):
                self.coverage()

    def test_coverage_never_launches_a_process(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("launch")):
            self.coverage()

    def test_no_supported_shapes_still_reports_every_seed_and_skip(self):
        import shutil

        shutil.rmtree(self.source)
        shutil.rmtree(self.pack)
        write_source(
            self.source, [("echo literal", "benign"), ("git status", "opaque")]
        )
        self.lineage = generate_pack(self.source, self.pack, domain=DOMAIN)
        self.loaded = cli._load_charter_corpus(str(self.pack))
        self.report = self.make_report()
        self.save()
        result = self.coverage()
        self.assertEqual(result["counts"], {"seeds": 2, "derived": 0, "skipped": 6})
        self.assertEqual(result["clusters"]["seeds_with_variants"], 0)
        self.assertTrue(
            all(value == 0 for value in result["by_origin"]["derived"].values())
        )

    def test_malformed_row_shapes_fail_with_bounded_diagnostics(self):
        original = deepcopy(self.report)
        for value in (None, [], "private-malformed-marker", {}):
            self.report = deepcopy(original)
            self.report["results"][0]["event"] = value
            self.save()
            with self.assertRaisesRegex(
                ValueError, "verified coverage contract"
            ) as failure:
                self.coverage()
            self.assertNotIn("private-malformed-marker", str(failure.exception))

    def test_admitted_bytes_are_not_reopened_for_aggregation(self):
        module = self.module()
        expected = self.coverage()
        read = module._read_regular

        def change_after_capture(path, limit):
            if path == self.path:
                (self.pack / "events.jsonl").write_bytes(b"changed after capture")
                (self.source / "events.jsonl").write_bytes(b"changed after capture")
            return read(path, limit)

        with mock.patch.object(
            module, "_read_regular", side_effect=change_after_capture
        ):
            self.assertEqual(self.coverage(), expected)
        with self.assertRaises(ValueError):
            self.coverage()

    def test_source_failures_do_not_turn_projection_success_into_a_gate_pass(self):
        self.report["gate"]["status"] = "error"
        self.report["source_failures"]["candidate"] = [
            {"code": "process-failed", "message": "private-process-message"}
        ]
        self.save()
        result = self.coverage()
        self.assertEqual(result["status"], "verified-projection")
        self.assertNotIn("gate", result)
        self.assertIn("gate and execution are not verified", json.dumps(result))
        self.assertNotIn("private-process-message", json.dumps(result))

    def test_cli_outputs_only_aggregate_json_and_input_errors_are_two(self):
        self.module()
        arguments = [
            "variants",
            "coverage",
            "--source",
            str(self.source),
            "--pack",
            str(self.pack),
            "--report",
            str(self.path),
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(app.main(arguments), 0)
        self.assertEqual(json.loads(output.getvalue()), self.coverage())
        self.path.write_bytes(b"{}")
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(app.main(arguments), 2)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
