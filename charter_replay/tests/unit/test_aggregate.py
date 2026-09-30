"""The aggregate carries fixed-vocabulary counts and refuses to carry anything else."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest import mock

from charter_replay import aggregate
from charter_replay.compare import DIFF_CLASSES, compare_decisions
from charter_replay.corpus import CASE_CLASSES
from charter_replay.hooks import OUTCOMES
from charter_replay.manifests import build_run_manifest, manifest_json_bytes
from charter_replay.policy_sources import SourceFailure
from charter_replay.reports import build_json_report, report_json_bytes
from charter_replay.review_reports import COMMENT_LIMIT_BYTES

SCHEMAS = Path(aggregate.__file__).parent / "schemas"
PAYLOADS = (
    '"><img src=x onerror="window.__x=1"><script>alert(1)</script>',
    "[click](https://evil.example/leak) @everyone @octocat ```fence```",
    "PRIVATE-" + "x" * 10_000,
    "café-中文-\U0001f600-‮RTL",
)
# Effects for the rows below: (baseline, candidate) covers every diff class.
EFFECTS = (
    ("allow", "allow"),
    ("deny", "allow"),
    ("allow", "deny"),
    ("allow", "indeterminate"),
    ("indeterminate", "deny"),
    ("allow", "allow"),
)
FAMILY_NAMES = (*DIFF_CLASSES, "gate", "hook", "counts", "baseline")


def build(
    *,
    failures: tuple[list, list] = ([], []),
    families: tuple[str, ...] = FAMILY_NAMES,
    corpus_id: str = "private-corpus-marker",
    policy: str = "private-policy-marker",
):
    """Return (report, report_bytes, manifest_bytes) for a hostile private corpus."""
    events, cases, baseline, candidate = [], [], [], []
    labels = sorted(CASE_CLASSES)
    for index, (before, after) in enumerate(EFFECTS):
        payload = PAYLOADS[index % len(PAYLOADS)]
        event_id = f"private-event-{index}-{payload}"
        events.append(
            {
                "schema_version": "command-event.v1",
                "event_id": event_id,
                "timestamp": "2026-01-01T00:00:00Z",
                "source": "synthetic",
                "command": f"private-command-marker {payload}",
            }
        )
        cases.append(
            {
                "schema_version": "charter-case.v1",
                "event_id": event_id,
                "case_class": labels[index % len(labels)],
                "case_family": families[index % len(families)],
                "rationale": f"private-rationale-marker {payload}",
                "provenance": "synthetic",
            }
        )
        for records, effect in ((baseline, before), (candidate, after)):
            records.append(
                {
                    "schema_version": "policy-decision.v1",
                    "event_id": event_id,
                    "effect": effect,
                    "reason": f"private-reason-marker {payload[:300]}",
                }
            )
    manifest = build_run_manifest(
        generated_at="2026-01-01T00:00:00Z",
        baseline={"kind": "recorded", "id": policy, "sha256": "a" * 64},
        candidate={"kind": "recorded", "id": policy + "-2", "sha256": "b" * 64},
        corpus={
            "id": corpus_id,
            "event_count": len(events),
            "manifest_sha256": "c" * 64,
        },
        fail_on=("newly-allowed", "newly-indeterminate"),
    )
    compared = compare_decisions(events, baseline, candidate, case_values=cases)
    report = build_json_report(
        compared,
        manifest,
        baseline_failures=tuple(SourceFailure(**item) for item in failures[0]),
        candidate_failures=tuple(SourceFailure(**item) for item in failures[1]),
    )
    return report, report_json_bytes(report), manifest_json_bytes(manifest)


def rewrite(data: bytes, change) -> bytes:
    value = json.loads(data)
    change(value)
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


class BuilderTests(unittest.TestCase):
    def test_counts_are_fixed_vocabulary_and_match_the_report(self):
        report, _, _ = build(
            failures=(
                [
                    {"code": "hook-timeout", "message": "m"},
                    {"code": "some-unknown-code", "message": "m"},
                ],
                [{"code": "hook-crash", "message": "m"}],
            )
        )
        outcomes = {
            side: dict.fromkeys(OUTCOMES, 0) | {"allow": 4, "deny": 2}
            for side in ("baseline", "candidate")
        }
        document = aggregate.build_aggregate(report, hook_outcomes=outcomes)
        self.assertEqual(document["schema_version"], "aggregate.v1")
        self.assertEqual(document["events"], len(EFFECTS))
        self.assertEqual(document["counts"], report["counts"])
        self.assertEqual(sum(document["case_classes"].values()), len(EFFECTS))
        self.assertEqual(set(document["case_classes"]), CASE_CLASSES)
        self.assertEqual(document["source_failures"]["baseline"]["hook-timeout"], 1)
        self.assertEqual(document["source_failures"]["baseline"]["other"], 1)
        self.assertEqual(document["source_failures"]["candidate"]["hook-crash"], 1)
        self.assertEqual(document["gate"]["status"], "error")
        self.assertEqual(document["hook_outcomes"], outcomes)

    def test_no_hook_outcomes_is_null_not_guessed(self):
        report, _, _ = build()
        self.assertIsNone(aggregate.build_aggregate(report)["hook_outcomes"])

    def test_case_classes_match_the_schema_vocabulary(self):
        schema = json.loads(
            (SCHEMAS / "charter-case.v1.schema.json").read_text("utf-8")
        )
        self.assertEqual(
            set(schema["properties"]["case_class"]["enum"]), set(CASE_CLASSES)
        )

    def test_failure_codes_cover_every_code_the_tool_emits(self):
        for code in (
            "hook-output-limit",
            "hook-start-failed",
            "hook-invalid-output",
            "process-timeout",
            "recording-digest-mismatch",
            "process-missing-event",
        ):
            self.assertIn(code, aggregate.FAILURE_CODES)

    def test_hook_outcomes_must_be_complete_and_cover_every_event(self):
        report, _, _ = build()
        full = {
            side: dict.fromkeys(OUTCOMES, 0) | {"allow": len(EFFECTS)}
            for side in ("baseline", "candidate")
        }
        aggregate.build_aggregate(report, hook_outcomes=full)
        short = deepcopy(full)
        del short["baseline"]["crash"]
        wrong = deepcopy(full)
        wrong["candidate"]["allow"] = 1
        extra = deepcopy(full)
        extra["baseline"]["free-text"] = 0
        for bad in (short, wrong, extra, {"baseline": full["baseline"]}):
            with self.assertRaises(aggregate.AggregateInputError):
                aggregate.build_aggregate(report, hook_outcomes=bad)

    def test_documents_outside_the_fixed_shape_are_refused_by_both_renderers(self):
        report, _, _ = build()
        document = aggregate.build_aggregate(report)
        for name, change in (
            ("extra key", lambda d: d.update(family="private-family")),
            ("free-text status", lambda d: d["gate"].update(status="private-x")),
            ("free-text class", lambda d: d["case_classes"].update(private=1)),
            ("negative", lambda d: d["counts"].update(unchanged=-1)),
            ("bool count", lambda d: d["counts"].update(unchanged=True)),
            ("huge", lambda d: d.update(events=10**13)),
        ):
            broken = deepcopy(document)
            change(broken)
            for render in (aggregate.render_json, aggregate.render_markdown):
                with self.subTest(name, render=render.__name__):
                    with self.assertRaises(aggregate.AggregateInputError):
                        render(broken)


class HostileFixtureTests(unittest.TestCase):
    def test_no_corpus_text_reaches_either_artifact(self):
        report, _, _ = build(
            failures=(
                [{"code": "weird-" + "z" * 50, "message": "private-message-marker"}],
                [],
            )
        )
        files = aggregate.build_files(
            report,
            texts=("/private/corpus/path-marker", "/private/output/path-marker"),
        )
        self.assertEqual(set(files), set(aggregate.AGGREGATE_FILES))
        blob = b"\n".join(files.values()).decode("ascii")
        needles = {"private-", "PRIVATE-", "evil.example", "octocat", "onerror"}
        needles |= {"<script", "<img", "```", "RTL", "path-marker", "@"}
        for needle in needles:
            self.assertNotIn(needle, blob, needle)
        for row in report["results"]:
            for value in (
                row["event"]["event_id"],
                row["event"]["command"],
                row["case"]["rationale"],
                row["baseline"]["reason"],
            ):
                self.assertNotIn(value, blob)
        for name in ("private-corpus-marker", "private-policy-marker"):
            self.assertNotIn(name, blob)
        # A control character or non-ASCII byte cannot appear at all.
        self.assertTrue(all(byte < 128 for byte in b"".join(files.values())))

    def test_families_named_like_fixed_words_do_not_trip_the_check(self):
        report, _, _ = build()
        families = {row["case"]["case_family"] for row in report["results"]}
        self.assertIn("unchanged", families)
        self.assertIn("newly-allowed", families)
        files = aggregate.build_files(report)
        self.assertTrue(
            files[aggregate.AGGREGATE_MD].startswith(b"<!-- charter-replay:")
        )

    def test_rendered_words_and_punctuation_are_not_leaks(self):
        # Status words, `none`/`null` and indentation are fixed output, so a
        # corpus value equal to one of them must not refuse an honest aggregate.
        for families in (("ERROR", "PASS", "FAIL"), ("none", "null"), ("    ", "----")):
            with self.subTest(families=families):
                report, _, _ = build(families=families)
                aggregate.build_files(report, texts=families)

    def test_short_and_numeric_values_are_not_leaks(self):
        report, _, _ = build(families=("abc", "12345", "1"))
        aggregate.build_files(report, texts=("12345", "abc"))

    def test_markdown_marker_and_hard_bound(self):
        report, _, _ = build()
        markdown = aggregate.build_files(report)[aggregate.AGGREGATE_MD]
        self.assertTrue(markdown.startswith(b"<!-- charter-replay:aggregate.v1 -->\n"))
        self.assertLessEqual(len(markdown), aggregate.MAX_MARKDOWN_BYTES)


class LeakCheckMutationTests(unittest.TestCase):
    """A deliberately broken renderer must be caught by the leak check."""

    def refuses(self, patched: str, leaked, texts=()):
        report, _, _ = build()
        original = getattr(aggregate, patched)

        def broken(document):
            data = original(document)
            return data + leaked.encode("utf-8")

        with mock.patch.object(aggregate, patched, broken):
            with self.assertRaises(aggregate.AggregateRefused) as caught:
                aggregate.build_files(report, texts=texts)
        message = str(caught.exception)
        self.assertNotIn(leaked, message)
        self.assertEqual(
            message, "aggregate refused: it contained corpus text; nothing was written"
        )

    def test_injected_event_id_is_refused_in_markdown_and_json(self):
        report, _, _ = build()
        event_id = report["results"][1]["event"]["event_id"]
        for patched in ("render_markdown", "render_json"):
            with self.subTest(patched):
                self.refuses(patched, event_id)

    def test_injected_fields_of_every_kind_are_refused(self):
        report, _, _ = build()
        row = report["results"][0]
        leaks = (
            row["event"]["command"],
            row["case"]["rationale"],
            row["baseline"]["reason"],
            "private-corpus-marker",
            "private-policy-marker",
        )
        for leaked in leaks:
            with self.subTest(leaked[:24]):
                self.refuses("render_markdown", leaked)

    def test_injected_path_is_refused(self):
        self.refuses(
            "render_json", "/private/where/it/lives", ("/private/where/it/lives",)
        )

    def test_json_escaped_form_is_also_refused(self):
        report, _, _ = build()
        value = report["results"][3]["event"]["event_id"]
        escaped = json.dumps(value)[1:-1]
        self.assertNotEqual(escaped, value)
        self.refuses("render_json", escaped)

    def test_the_check_cannot_be_disarmed_by_a_patched_renderer(self):
        # The exemption for fixed text is a constant, not a render, so a broken
        # renderer cannot widen it by leaking the value into every render.
        report, _, _ = build()
        leaked = report["results"][1]["event"]["event_id"]
        self.assertNotIn(leaked, aggregate._STATIC_TEXT)
        self.refuses("render_markdown", leaked)


class DeterminismAndBoundTests(unittest.TestCase):
    def test_identical_reports_give_identical_bytes(self):
        first = aggregate.build_files(build()[0])
        second = aggregate.build_files(deepcopy(build()[0]))
        self.assertEqual(first, second)
        self.assertTrue(first[aggregate.AGGREGATE_JSON].endswith(b"\n"))
        self.assertNotIn(b"\r", first[aggregate.AGGREGATE_JSON])
        value = json.loads(first[aggregate.AGGREGATE_JSON])
        self.assertEqual(list(value), sorted(value))
        text = first[aggregate.AGGREGATE_JSON].decode("ascii")
        for word in ("generated_at", "elapsed", "run_id", "sha256", "timestamp"):
            self.assertNotIn(word, text)

    def worst_case(self) -> dict:
        big = aggregate.MAX_COUNT
        return {
            "schema_version": aggregate.AGGREGATE_VERSION,
            "gate": {
                "status": "error",
                "fail_on": sorted(aggregate.RUN_GATE_CLASSES),
                "triggered": sorted(aggregate.RUN_GATE_CLASSES),
            },
            "events": big,
            "counts": dict.fromkeys(DIFF_CLASSES, big),
            "case_classes": dict.fromkeys(sorted(CASE_CLASSES), big),
            "hook_outcomes": {
                side: dict.fromkeys(OUTCOMES, big) for side in ("baseline", "candidate")
            },
            "source_failures": {
                side: dict.fromkeys(aggregate.FAILURE_KEYS, big)
                for side in ("baseline", "candidate")
            },
        }

    def test_the_whole_vocabulary_at_the_largest_count_fits_the_bounds(self):
        # Fails only when a fixed vocabulary grows past the bound: raise the
        # constants and the Action summary bound together, deliberately.
        document = self.worst_case()
        size_json = len(aggregate.render_json(document))
        size_md = len(aggregate.render_markdown(document))
        self.assertLessEqual(size_json, aggregate.MAX_JSON_BYTES)
        self.assertLessEqual(size_md, aggregate.MAX_MARKDOWN_BYTES)
        self.assertLess(aggregate.MAX_MARKDOWN_BYTES, COMMENT_LIMIT_BYTES)
        self.assertLess(aggregate.MAX_MARKDOWN_BYTES, 61_440)
        # The bounds stay close to the worst case, so growth is noticed.
        self.assertGreater(size_md * 2, aggregate.MAX_MARKDOWN_BYTES)
        self.assertGreater(size_json * 2, aggregate.MAX_JSON_BYTES)

    def test_a_document_over_the_bound_is_refused(self):
        document = self.worst_case()
        with mock.patch.object(aggregate, "MAX_MARKDOWN_BYTES", 100):
            with self.assertRaises(aggregate.AggregateInputError):
                aggregate.render_markdown(document)
        with mock.patch.object(aggregate, "MAX_JSON_BYTES", 100):
            with self.assertRaises(aggregate.AggregateInputError):
                aggregate.render_json(document)


class AdmissionTests(unittest.TestCase):
    def test_a_consistent_report_is_admitted_unchanged(self):
        report, report_bytes, manifest_bytes = build()
        self.assertEqual(aggregate.admit_report(report_bytes, manifest_bytes), report)

    def test_tampering_is_refused_with_a_fixed_message(self):
        report, report_bytes, manifest_bytes = build()

        def flip_class(value):
            value["results"][0]["classification"] = "newly-allowed"

        def bump_count(value):
            value["counts"]["unchanged"] += 1

        def open_gate(value):
            value["gate"]["status"] = "pass"

        def swap_effect(value):
            value["results"][1]["candidate"]["effect"] = "deny"

        def drop_row(value):
            value["results"].pop()

        def add_key(value):
            value["extra"] = 1

        def other_corpus(value):
            value["corpus"]["id"] = "different"

        cases = {
            "classification": rewrite(report_bytes, flip_class),
            "counts": rewrite(report_bytes, bump_count),
            "gate": rewrite(report_bytes, open_gate),
            "effect": rewrite(report_bytes, swap_effect),
            "row dropped": rewrite(report_bytes, drop_row),
            "extra key": rewrite(report_bytes, add_key),
            "corpus": rewrite(report_bytes, other_corpus),
            "duplicate key": report_bytes.replace(
                b'"schema_version"', b'"schema_version": "x", "schema_version"', 1
            ),
            "nan": report_bytes.replace(b'"counts"', b'"nan": NaN, "counts"', 1),
            "not json": b"{",
            "empty": b"",
        }
        for label, tampered in cases.items():
            with self.subTest(label):
                with self.assertRaises(aggregate.AggregateInputError) as caught:
                    aggregate.admit_report(tampered, manifest_bytes)
                self.assertEqual(
                    str(caught.exception),
                    "report does not match its run manifest; nothing was aggregated",
                )

        def other_run(value):
            value["run_id"] = "0" * 64

        def other_fail_on(value):
            value["fail_on"] = ["newly-denied"]

        for label, change in (("run id", other_run), ("fail_on", other_fail_on)):
            with self.subTest("manifest " + label):
                with self.assertRaises(aggregate.AggregateInputError):
                    aggregate.admit_report(
                        report_bytes, rewrite(manifest_bytes, change)
                    )

    def test_source_failures_must_match_their_gate(self):
        _, report_bytes, manifest_bytes = build(
            failures=([{"code": "hook-crash", "message": "m"}], [])
        )

        def hide(value):
            value["source_failures"]["baseline"] = []

        with self.assertRaises(aggregate.AggregateInputError):
            aggregate.admit_report(rewrite(report_bytes, hide), manifest_bytes)
        aggregate.admit_report(report_bytes, manifest_bytes)


if __name__ == "__main__":
    unittest.main()
