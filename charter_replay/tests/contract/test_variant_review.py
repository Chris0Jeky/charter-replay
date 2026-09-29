"""Offline review admits captured evidence before producing any trusted views."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
import importlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from charter_replay import app, cli
from charter_replay.compare import compare_decisions
from charter_replay.manifests import build_corpus_manifest, build_run_manifest
from charter_replay.manifests import manifest_json_bytes
from charter_replay.policy_sources import SourceFailure
from charter_replay.reports import build_json_report, report_json_bytes
from charter_replay.variant_packs import generate_pack


class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class VariantReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        events, cases = [], []
        for number, (command, label) in enumerate(
            (("rm sandbox/fictional", "dangerous"), ("git status", "benign"))
        ):
            event_id = f"private-id-{number}"
            events.append(dict(
                schema_version="command-event.v1", event_id=event_id,
                timestamp="2026-01-01T00:00:00Z", source="synthetic",
                command=command, cwd="sandbox/project",
            ))
            cases.append(dict(
                schema_version="charter-case.v1", event_id=event_id,
                case_class=label, case_family="private-family-marker",
                rationale="Synthetic evidence, not an execution claim.",
                provenance="synthetic",
            ))
        for name, rows in (("events.jsonl", events), ("cases.jsonl", cases)):
            (self.source / name).write_bytes(
                b"".join((json.dumps(row) + "\n").encode() for row in rows)
            )
        manifest = build_corpus_manifest(
            corpus_id="private-source", event_count=2,
            base_directory=self.source, files=["events.jsonl", "cases.jsonl"],
        )
        (self.source / "corpus-manifest.json").write_bytes(manifest_json_bytes(manifest))
        self.pack = self.root / "pack"
        self.lineage = generate_pack(self.source, self.pack, domain="posix-external.v1")
        self.loaded = cli._load_charter_corpus(str(self.pack))
        baseline, candidate = [], []
        for event, case in zip(self.loaded.events, self.loaded.cases):
            for side, records in (("baseline", baseline), ("candidate", candidate)):
                effect = "deny" if case["case_class"] == "dangerous" else "allow"
                if event["command"].startswith("'"):
                    effect = "allow"
                if side == "candidate" and event["command"].startswith("env "):
                    effect = "allow" if effect == "deny" else "deny"
                records.append(dict(
                    schema_version="policy-decision.v1", event_id=event["event_id"],
                    effect=effect, reason="private-reason-marker",
                ))
        self.compared = compare_decisions(
            self.loaded.events, baseline, candidate, case_values=self.loaded.cases,
        )
        self.manifest = build_run_manifest(
            generated_at="2026-01-01T00:00:00Z",
            baseline=dict(kind="recorded", id="private-base", sha256="a" * 64),
            candidate=dict(kind="recorded", id="private-next", sha256="b" * 64),
            corpus=dict(id=self.loaded.corpus_id, event_count=self.loaded.event_count,
                        manifest_sha256=self.loaded.manifest_sha256),
            fail_on=["newly-allowed", "newly-indeterminate"],
        )
        self.report = build_json_report(self.compared, self.manifest)
        self.report_path = self.root / "report.json"
        self.manifest_path = self.root / "run-manifest.json"
        self.output = self.root / "review"
        self.save()

    def save(self):
        self.report_path.write_bytes(report_json_bytes(self.report))
        self.manifest_path.write_bytes(manifest_json_bytes(self.manifest))

    def module(self):
        self.assertIsNotNone(importlib.util.find_spec("charter_replay.variant_review"),
                             "capture-bound variant review is missing")
        return importlib.import_module("charter_replay.variant_review")

    def build(self):
        return self.module().build_review(
            self.source, self.pack, self.report_path, self.manifest_path,
        )

    def publish(self):
        return self.module().publish_review(
            self.source, self.pack, self.report_path, self.manifest_path, self.output,
        )

    def test_swapped_report_corpus_is_rejected_without_output(self):
        self.report["corpus"]["manifest_sha256"] = "f" * 64
        self.save()
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(self.output.exists())

    def test_detached_coverage_counts_are_not_an_admission_shortcut(self):
        self.report["variant_coverage"] = {"status": "verified-projection", "counts": {}}
        self.save()
        with self.assertRaises(ValueError):
            self.build()

    def test_missing_lineage_is_rejected_without_output(self):
        (self.pack / "lineage.json").unlink()
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(self.output.exists())

    def test_gate_run_identity_policy_and_timestamp_are_recomputed(self):
        original = deepcopy(self.report)
        mutations = (
            ("gate", dict(status="pass", fail_on=[], triggered=[])),
            ("run_id", "f" * 64),
            ("generated_at", "2025-01-01T00:00:00Z"),
            ("policies", dict(baseline=self.report["policies"]["candidate"],
                              candidate=self.report["policies"]["baseline"])),
            ("limitations", ["unearned safety claim"]),
        )
        for key, value in mutations:
            self.report = dict(original, **{key: value})
            self.save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.build()

    def test_forged_run_manifest_and_unbound_extra_fields_are_rejected(self):
        original = deepcopy(self.manifest)
        for key, value in (("run_id", "f" * 64), ("runner_version", "other-runner"),
                           ("extra", "unexpected")):
            self.manifest = dict(original, **{key: value})
            self.save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.build()

    def test_changed_variants_and_shared_shape_disagreements_are_distinct(self):
        files, code = self.build()
        self.assertEqual(code, 1)
        details = json.loads(files["variant-review.json"])
        coverage = json.loads(files["variant-coverage.json"])
        self.assertEqual(coverage["clusters"]["unchanged_seeds_with_changed_variants"], 2)
        self.assertEqual(details["shape_disagreements"]["shared"],
                         {"variants": 1, "seeds": 1})
        markup = files["report.html"].decode()
        self.assertIn("Unchanged seeds with changed variants", markup)
        self.assertIn("Shared shape disagreements", markup)
        self.assertIn("Seed to shape effects", markup)
        self.assertIn("indeterminate", markup)

    def test_source_failure_keeps_error_gate_and_exit_three(self):
        self.report = build_json_report(
            self.compared, self.manifest,
            candidate_failures=(SourceFailure("hook-crash", "Synthetic failure."),),
        )
        self.save()
        files, code = self.build()
        self.assertEqual(code, 3)
        self.assertIn("Gate: **ERROR**", files["pr-comment-aggregate.md"].decode())
        self.assertIn("gate-error", files["report.html"].decode())
        self.report["gate"]["status"] = "pass"
        self.save()
        with self.assertRaises(ValueError):
            self.build()

    def test_malformed_or_wrong_event_failure_cannot_assert_source_health(self):
        original = deepcopy(self.report)
        for failure in (None, {}, {"code": 1, "message": "bad"},
                        {"code": "hook-crash", "message": "bad", "event_id": "wrong"},
                        {"code": "hook-crash", "message": "bad", "extra": "x"}):
            self.report = deepcopy(original)
            self.report["source_failures"]["baseline"] = [failure]
            self.report["gate"]["status"] = "error"
            self.save()
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.build()

    def test_aggregate_comment_omits_private_text_and_all_identities(self):
        files, _ = self.build()
        text = files["pr-comment-aggregate.md"].decode()
        for secret in ("private-", "rm sandbox", "git status", str(self.root),
                       self.manifest["run_id"], self.loaded.manifest_sha256):
            self.assertNotIn(secret, text)
        self.assertIn("not authenticated", text)
        self.assertIn("small counts", text)
        self.assertLessEqual(len(files["pr-comment.md"]), 16000)
        self.assertLessEqual(len(files["pr-comment-aggregate.md"]), 16000)

    def test_hostile_reasons_remain_text_and_csp_remains_exact(self):
        payload = '"><img src=x onerror="window.injected=1"><script>1</script>|\u202e'
        for row in self.report["results"]:
            row["baseline"]["reason"] = payload
        self.save()
        files, _ = self.build()
        markup = files["report.html"].decode()
        tags = Elements(markup).tags
        self.assertEqual(sum(tag == "script" for tag, _ in tags), 1)
        self.assertFalse(any(tag == "img" for tag, _ in tags))
        self.assertFalse(any(k.startswith("on") for _, attrs in tags for k in attrs))
        self.assertIn("&lt;script&gt;", markup)
        self.assertNotIn("\u202e", markup)
        self.assertIn("\\u202e", markup)
        self.assertIn("script-src", markup)
        self.assertIn("noscript", markup)

    def test_identical_inputs_produce_identical_bytes_and_never_launch(self):
        before = self.report_path.read_bytes(), self.manifest_path.read_bytes()
        with mock.patch("subprocess.Popen", side_effect=AssertionError("launch")):
            first = self.build()
            self.assertEqual(first, self.build())
        self.assertEqual(before, (self.report_path.read_bytes(), self.manifest_path.read_bytes()))
        self.assertNotIn(str(self.root).encode(), b"".join(first[0].values()))

    def test_reordered_rows_render_canonical_views_but_bind_distinct_input_bytes(self):
        first, _ = self.build()
        self.report["results"].reverse()
        self.save()
        second, _ = self.build()
        for name in ("report.html", "report.json", "pr-comment.md", "variant-coverage.json"):
            self.assertEqual(first[name], second[name], name)
        self.assertNotEqual(first["review-manifest.json"], second["review-manifest.json"])

    def test_malformed_nonfinite_duplicate_and_deep_json_are_rejected(self):
        self.module()
        for raw in (b"{", b"[" * 2000, b"NaN", b'{"x":1,"x":2}',
                    b'{"unused":1e999}', b'"\\ud800"'):
            self.report_path.write_bytes(raw)
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                self.build()

    def test_bound_report_reader_rejects_oversized_input(self):
        module = self.module()
        with mock.patch.object(module, "MAX_REPORT_BYTES", 16):
            with self.assertRaises(ValueError):
                self.build()

    def test_report_replacement_after_capture_does_not_change_the_views(self):
        module = self.module()
        first, _ = self.build()
        original_read = module._read_regular
        def replace_after_read(path, limit):
            data = original_read(path, limit)
            if Path(path) == self.report_path:
                self.report_path.write_bytes(b"not the admitted report")
            return data
        with mock.patch.object(module, "_read_regular", side_effect=replace_after_read):
            self.assertEqual(self.build()[0], first)
        with self.assertRaises(ValueError):
            self.build()

    def test_publication_preserves_inputs_and_commits_a_complete_digest_set(self):
        from charter_replay.digests import sha256_bytes
        before = self.report_path.read_bytes(), self.manifest_path.read_bytes()
        self.assertEqual(self.publish(), 1)
        marker = json.loads((self.output / "review-manifest.json").read_bytes())
        names = {path.name for path in self.output.iterdir()} - {"review-manifest.json"}
        self.assertEqual(set(marker["files"]), names)
        for name, digest in marker["files"].items():
            self.assertEqual(sha256_bytes((self.output / name).read_bytes()), digest)
        self.assertEqual(before, (self.report_path.read_bytes(), self.manifest_path.read_bytes()))

    def test_existing_output_and_input_nested_destinations_are_refused(self):
        module = self.module()
        self.output.mkdir()
        (self.output / "keep").write_bytes(b"other writer")
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual((self.output / "keep").read_bytes(), b"other writer")
        for directory in (self.source, self.pack):
            with self.assertRaises(ValueError):
                module.publish_review(self.source, self.pack, self.report_path,
                                      self.manifest_path, directory / "nested")
            self.assertFalse((directory / "nested").exists())

    def test_failed_publication_rolls_back_owned_files_and_preserves_other_writer(self):
        self.module()
        publisher = importlib.import_module("charter_replay.publication")
        original_link = publisher.os.link
        order = []
        def fail_marker(source, target):
            order.append(Path(target).name)
            if Path(target).name == "review-manifest.json":
                (self.output / "other").write_bytes(b"keep")
                raise OSError("injected publication failure")
            return original_link(source, target)
        with mock.patch.object(publisher.os, "link", side_effect=fail_marker):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(order[-1], "review-manifest.json")
        self.assertEqual([p.name for p in self.output.iterdir()], ["other"])
        self.assertFalse(any(p.name.startswith(".charter-publish-") for p in self.root.iterdir()))

    def test_cli_preserves_gate_and_does_not_print_a_result_on_invalid_evidence(self):
        self.module()
        argv = ["variants", "review", "--source", str(self.source), "--pack", str(self.pack),
                "--report", str(self.report_path), "--run-manifest", str(self.manifest_path),
                "--output", str(self.output)]
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(app.main(argv), 1)
        self.assertEqual(json.loads(stdout.getvalue())["gate"], "fail")
        self.report_path.write_bytes(b"{}")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(app.main(argv[:-1] + [str(self.root / "bad")]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(str(self.root), stderr.getvalue())

    def test_pr_origin_breakdown_includes_resolved_indeterminate_and_transforms(self):
        files, _ = self.build()
        text = files["pr-comment-aggregate.md"].decode()
        self.assertIn("Resolved indeterminate", text)
        self.assertIn("env-wrapper.v1", text)
        self.assertIn("quote-words.v1", text)

    def test_cli_publication_failure_returns_three_without_success_output(self):
        self.module()
        argv = ["variants", "review", "--source", str(self.source), "--pack", str(self.pack),
                "--report", str(self.report_path), "--run-manifest", str(self.manifest_path),
                "--output", str(self.output)]
        output = io.StringIO()
        with mock.patch("charter_replay.publication.os.link", side_effect=OSError("no links")):
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(app.main(argv), 3)
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(self.output.exists())

    def test_review_verification_regenerates_instead_of_trusting_rebound_digests(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, "verify_review", None)), "review verification is missing")
        self.assertEqual(self.publish(), 1)
        self.assertEqual(module.verify_review(self.source, self.pack, self.report_path,
                                             self.manifest_path, self.output), 1)
        from charter_replay.digests import sha256_bytes
        html = self.output / "report.html"
        html.write_bytes(html.read_bytes().replace(b"Shared shape disagreements", b"Unsupported claim"))
        marker_path = self.output / "review-manifest.json"
        marker = json.loads(marker_path.read_bytes())
        marker["files"]["report.html"] = sha256_bytes(html.read_bytes())
        marker_path.write_bytes(manifest_json_bytes(marker))
        with self.assertRaises(ValueError):
            module.verify_review(self.source, self.pack, self.report_path, self.manifest_path, self.output)

    def test_verify_review_cli_keeps_original_gate_without_writing(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, "verify_review", None)), "review verification is missing")
        self.publish()
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        argv = ["variants", "verify-review", "--source", str(self.source), "--pack", str(self.pack),
                "--report", str(self.report_path), "--run-manifest", str(self.manifest_path),
                "--review", str(self.output)]
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(app.main(argv), 1)
        self.assertEqual(json.loads(out.getvalue()), {"gate": "fail", "status": "review-verified"})
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, before)

    def test_variant_summary_precedes_scores_and_matrices_use_native_details(self):
        files, _ = self.build()
        markup = files["report.html"].decode()
        self.assertLess(markup.index('id="variant-review"'), markup.index("<h2>Supplied-label agreement"))
        self.assertIn('<details class="panel"><summary>Seed to shape effects</summary>', markup)

    def test_clean_comparison_returns_zero_and_source_errors_return_three(self):
        self.module()
        for row in self.report["results"]:
            row["candidate"] = dict(row["baseline"])
        compared = compare_decisions(
            self.loaded.events,
            [row["baseline"] for row in self.report["results"]],
            [row["candidate"] for row in self.report["results"]],
            case_values=self.loaded.cases,
        )
        self.report = build_json_report(compared, self.manifest)
        self.save()
        self.assertEqual(self.build()[1], 0)
        self.report = build_json_report(compared, self.manifest,
                                       baseline_failures=(SourceFailure("hook-timeout", "Synthetic timeout."),))
        self.save()
        self.assertEqual(self.build()[1], 3)


if __name__ == "__main__":
    unittest.main()
