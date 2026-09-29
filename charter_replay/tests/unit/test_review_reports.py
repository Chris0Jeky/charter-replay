"""Offline and PR views treat every corpus-provided field as untrusted text."""

from copy import deepcopy
from html.parser import HTMLParser
import importlib
import unittest

from charter_replay import app
from charter_replay.compare import compare_decisions
from charter_replay.manifests import build_run_manifest
from charter_replay.reports import build_json_report


def make_report():
    events, cases, baseline, candidate = [], [], [], []
    rows = (
        ("first-benign", "benign", "allow", "deny"),
        ("danger-priority", "dangerous", "deny", "allow"),
        ("opaque-unstable", "opaque", "allow", "indeterminate"),
        ("unchanged", "benign", "allow", "allow"),
    )
    for event_id, label, before, after in rows:
        events.append(
            {
                "schema_version": "command-event.v1",
                "event_id": event_id,
                "timestamp": "2026-01-01T00:00:00Z",
                "source": "synthetic",
                "command": f"private-command-marker {event_id}",
            }
        )
        cases.append(
            {
                "schema_version": "charter-case.v1",
                "event_id": event_id,
                "case_class": label,
                "case_family": "private-family-marker",
                "rationale": "Synthetic renderer fixture.",
                "provenance": "synthetic",
            }
        )
        for records, effect in ((baseline, before), (candidate, after)):
            records.append(
                {
                    "schema_version": "policy-decision.v1",
                    "event_id": event_id,
                    "effect": effect,
                    "reason": "private-reason-marker",
                }
            )
    manifest = build_run_manifest(
        generated_at="2026-01-01T00:00:00Z",
        baseline={"kind": "recorded", "id": "baseline-private", "sha256": "a" * 64},
        candidate={"kind": "recorded", "id": "candidate-private", "sha256": "b" * 64},
        corpus={
            "id": "private-corpus-marker",
            "event_count": len(events),
            "manifest_sha256": "c" * 64,
        },
        fail_on=("newly-allowed", "newly-indeterminate"),
    )
    compared = compare_decisions(events, baseline, candidate, case_values=cases)
    return build_json_report(compared, manifest)


class Elements(HTMLParser):
    def __init__(self, markup):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class ReviewRendererTests(unittest.TestCase):
    def renderers(self):
        return importlib.import_module("charter_replay.review_reports")

    def test_html_is_standalone_with_accessible_filters_and_full_rows(self):
        markup = self.renderers().render_html(make_report())
        tags = Elements(markup).elements
        self.assertEqual(sum(tag == "script" for tag, _ in tags), 1)
        self.assertTrue(any(tag == "noscript" for tag, _ in tags))
        self.assertTrue(
            any(
                attrs.get("http-equiv") == "Content-Security-Policy"
                for _, attrs in tags
            )
        )
        self.assertEqual(sum("data-case" in attrs for _, attrs in tags), 4)
        labels = {attrs.get("for") for tag, attrs in tags if tag == "label"}
        self.assertTrue(
            {
                "filter-class",
                "filter-family",
                "filter-baseline",
                "filter-candidate",
                "filter-diff",
                "filter-origin",
                "search",
            }.issubset(labels)
        )
        self.assertTrue(any(attrs.get("aria-live") == "polite" for _, attrs in tags))
        self.assertFalse(any("src" in attrs for _, attrs in tags))
        self.assertIn("private-command-marker", markup)
        self.assertIn("Supplied-label agreement", markup)

    def test_hostile_html_attributes_and_controls_remain_visible_text(self):
        report = make_report()
        payload = '\"><img src=x onerror="window.__injected=1"><script>window.__injected=1</script>|\u202e'
        for row in report["results"]:
            row["event"]["event_id"] = payload
            row["event"]["command"] = payload
            row["case"]["case_family"] = payload
            row["candidate"]["reason"] = payload
        markup = self.renderers().render_html(report)
        tags = Elements(markup).elements
        self.assertEqual(sum(tag == "script" for tag, _ in tags), 1)
        self.assertFalse(any(tag == "img" for tag, _ in tags))
        self.assertFalse(
            any(key.startswith("on") for _, attrs in tags for key in attrs)
        )
        self.assertNotIn("\u202e", markup)
        self.assertIn("\\u202e", markup)
        self.assertIn("&lt;script&gt;", markup)

    def test_rendering_is_byte_stable_and_does_not_mutate_the_report(self):
        report = make_report()
        original = deepcopy(report)
        first = self.renderers().render_html(report)
        self.assertEqual(first.encode(), self.renderers().render_html(report).encode())
        self.assertEqual(report, original)

    def test_pr_text_prioritizes_dangerous_relaxations_and_omits_private_bodies(self):
        renderer = self.renderers()
        report = make_report()
        text = renderer.render_pr_comment(report)
        self.assertTrue(text.startswith("<!-- charter-replay:review.v1 -->"))
        self.assertLess(
            text.index(renderer.markdown_literal("danger-priority")),
            text.index(renderer.markdown_literal("first-benign")),
        )
        self.assertIn("Gate: **FAIL**", text)
        for value in (
            "private-command-marker",
            "private-reason-marker",
            "private-family-marker",
        ):
            self.assertNotIn(value, text)
        self.assertNotIn(renderer.markdown_literal("unchanged"), text)

    def test_aggregate_text_contains_no_corpus_case_or_policy_identifiers(self):
        report = make_report()
        text = self.renderers().render_pr_comment(report, aggregate_only=True)
        for value in (
            "private",
            report["run_id"],
            "danger-priority",
            "first-benign",
            "opaque-unstable",
            "baseline-private",
            "candidate-private",
        ):
            self.assertNotIn(value, text)
        self.assertIn("newly-allowed", text)
        self.assertIn("No corpus command was executed", text)

    def test_pr_text_is_bounded_even_for_large_untrusted_identifiers(self):
        report = make_report()
        report["results"] = report["results"] * 100
        for row in report["results"]:
            row["event"]["event_id"] = "!" * 100_000
        text = self.renderers().render_pr_comment(report, limit=100)
        self.assertLessEqual(len(text.encode("utf-8")), 16_000)
        self.assertIn("omitted", text)

    def test_comment_limits_are_validated(self):
        for limit in (-1, 101, True):
            with self.assertRaises(ValueError):
                self.renderers().render_pr_comment(make_report(), limit=limit)

    def test_markdown_literal_neutralizes_links_mentions_and_table_syntax(self):
        text = self.renderers().markdown_literal(
            "@someone|[click](https://fixture.invalid)`<img>\nrow"
        )
        for raw in ("@someone", "|", "[click]", "`", "<img>", "\n"):
            self.assertNotIn(raw, text)
        self.assertIn("&#64;", text)
        self.assertTrue(text.startswith("<code>"))

    def test_existing_hook_summary_also_escapes_family_markup(self):
        report = make_report()
        report["results"][0]["case"]["case_family"] = (
            "<script>unsafe</script>|[click](url)"
        )
        summary = app.breakdown(report)
        outcomes = {
            name: {"outcomes": {"allow": 0}} for name in ("baseline", "candidate")
        }
        text = app.render_summary(summary, outcomes)
        self.assertNotIn("<script>", text)
        self.assertNotIn("|[click](url)", text)

    def test_optional_report_link_accepts_only_plain_https_without_credentials(self):
        renderer = self.renderers()
        report = make_report()
        for url in (
            "javascript:alert(1)",
            "data:text/html,x",
            "https://user:secret@example.test/",
            "https://example.test/\nnext",
        ):
            with self.assertRaises(ValueError):
                renderer.render_pr_comment(report, report_url=url)
        text = renderer.render_pr_comment(
            report, report_url="https://github.com/example/repo/actions/runs/1"
        )
        self.assertIn("Full HTML report", text)


if __name__ == "__main__":
    unittest.main()
