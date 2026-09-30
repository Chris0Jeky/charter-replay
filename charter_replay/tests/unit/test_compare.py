from __future__ import annotations

import json
import unittest

from charter_replay.compare import ComparisonError, compare_decisions
from charter_replay.policy_sources import SourceFailure
from charter_replay.reports import (
    DECISION_REPLAY_LIMITATION,
    build_json_report,
    render_markdown_report,
    report_json_bytes,
)

EFFECTS = [
    ("unchanged-allow", "allow", "allow", "unchanged"),
    ("unchanged-deny", "deny", "deny", "unchanged"),
    ("newly-allowed", "deny", "allow", "newly-allowed"),
    ("newly-denied", "allow", "deny", "newly-denied"),
    ("newly-indeterminate", "allow", "indeterminate", "newly-indeterminate"),
    (
        "resolved-indeterminate",
        "indeterminate",
        "deny",
        "resolved-indeterminate",
    ),
]


def event(event_id: str) -> dict[str, str]:
    return {
        "schema_version": "command-event.v1",
        "event_id": event_id,
        "timestamp": "2026-07-30T12:00:00Z",
        "command": f"echo fictional {event_id}",
        "source": "synthetic",
    }


def decision(event_id: str, effect: str, policy: str) -> dict[str, str]:
    return {
        "schema_version": "policy-decision.v1",
        "event_id": event_id,
        "effect": effect,
        "reason": f"{policy} returned {effect} for the synthetic fixture.",
    }


def charter_case(event_id: str) -> dict[str, str]:
    return {
        "schema_version": "charter-case.v1",
        "event_id": event_id,
        "case_class": "opaque",
        "case_family": "synthetic-comparison",
        "rationale": "This fixture tests effect comparison only.",
        "provenance": "synthetic",
    }


class ComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [event(row[0]) for row in EFFECTS]
        self.baseline = [decision(row[0], row[1], "baseline") for row in EFFECTS]
        self.candidate = [decision(row[0], row[2], "candidate") for row in EFFECTS]
        self.cases = [charter_case(row[0]) for row in EFFECTS]
        self.manifest = {
            "run_id": "f" * 64,
            "generated_at": "2026-07-30T12:00:00Z",
            "baseline": {
                "kind": "recorded",
                "id": "floor-v1-final",
                "sha256": "1" * 64,
            },
            "candidate": {
                "kind": "process",
                "id": "candidate-policy",
                "sha256": "2" * 64,
            },
            "corpus": {
                "id": "charter-v0.1",
                "manifest_sha256": "3" * 64,
                "event_count": len(self.events),
            },
            "fail_on": ["newly-allowed", "newly-indeterminate"],
        }

    def test_all_five_classes_follow_corpus_order_and_preserve_reasons(self) -> None:
        result = compare_decisions(
            self.events,
            list(reversed(self.baseline)),
            list(reversed(self.candidate)),
            case_values=list(reversed(self.cases)),
        )
        self.assertEqual(
            [row[0] for row in EFFECTS],
            [row.event["event_id"] for row in result.results],
        )
        self.assertEqual(
            [row[3] for row in EFFECTS],
            [row.classification for row in result.results],
        )
        self.assertEqual(
            {
                "unchanged": 2,
                "newly-allowed": 1,
                "newly-denied": 1,
                "newly-indeterminate": 1,
                "resolved-indeterminate": 1,
            },
            result.counts,
        )
        self.assertEqual(
            "candidate returned allow for the synthetic fixture.",
            result.results[2].candidate["reason"],
        )
        self.assertEqual("opaque", result.results[0].case["case_class"])

    def test_command_text_and_charter_class_do_not_drive_classification(self) -> None:
        events = [
            {**self.events[0], "command": "git push origin main --force"},
        ]
        cases = [{**self.cases[0], "case_class": "dangerous"}]
        result = compare_decisions(
            events, [self.baseline[0]], [self.candidate[0]], case_values=cases
        )
        self.assertEqual("unchanged", result.results[0].classification)

    def test_missing_or_unexpected_decisions_and_cases_fail(self) -> None:
        with self.assertRaisesRegex(ComparisonError, "missing"):
            compare_decisions(self.events, self.baseline[:-1], self.candidate)
        unexpected = decision("unexpected", "allow", "candidate")
        with self.assertRaisesRegex(ComparisonError, "unexpected"):
            compare_decisions(self.events, self.baseline, [*self.candidate, unexpected])
        with self.assertRaisesRegex(ComparisonError, "charter cases"):
            compare_decisions(
                self.events,
                self.baseline,
                self.candidate,
                case_values=self.cases[:-1],
            )

    def test_json_and_markdown_report_state_limits_and_operational_identity(
        self,
    ) -> None:
        comparison = compare_decisions(
            self.events, self.baseline, self.candidate, case_values=self.cases
        )
        report = build_json_report(comparison, self.manifest)
        self.assertEqual("fail", report["gate"]["status"])
        self.assertEqual(
            ["newly-allowed", "newly-indeterminate"],
            report["gate"]["triggered"],
        )
        self.assertEqual(len(self.events), len(report["results"]))
        self.assertIn(DECISION_REPLAY_LIMITATION, report["limitations"])
        self.assertNotIn("reproduction_command", report)

        argv = ["/opt/Python Tools/python3", "-m", "charter_replay.cli", "replay"]
        markdown = render_markdown_report(
            report, reproduction_argv=argv, reproduction_shell="posix-sh"
        )
        opening = markdown.split("## Event results", maxsplit=1)[0]
        for expected in (
            "Counts:",
            "Gate: **FAIL**",
            "Baseline: `floor-v1-final`",
            "Candidate: `candidate-policy`",
            "Corpus: `charter-v0.1`",
            "Reproduce with structured argv (portable source of truth):",
            "POSIX sh rendering for this host:",
        ):
            self.assertIn(expected, opening)
        self.assertIn(json.dumps(argv), opening)
        self.assertIn(
            "'/opt/Python Tools/python3' -m charter_replay.cli replay", opening
        )
        self.assertIn(DECISION_REPLAY_LIMITATION, markdown)

    def test_reproduction_rendering_is_exact_for_posix_and_powershell(self) -> None:
        report = build_json_report(
            compare_decisions(
                self.events,
                self.baseline,
                self.candidate,
                case_values=self.cases,
            ),
            self.manifest,
        )
        posix_argv = [
            "/opt/Python Tools/python3",
            "-m",
            "charter_replay.cli",
            "--output",
            "/tmp/Policy Lab/owner's report",
        ]
        posix = render_markdown_report(
            report, reproduction_argv=posix_argv, reproduction_shell="posix-sh"
        )
        self.assertIn(json.dumps(posix_argv), posix)
        self.assertIn(
            "    '/opt/Python Tools/python3' -m charter_replay.cli --output "
            "'/tmp/Policy Lab/owner'\"'\"'s report'",
            posix,
        )

        windows_argv = [
            r"C:\Program Files\Python\python.exe",
            "-m",
            "charter_replay.cli",
            "--output",
            r"C:\Policy Lab\owner's report & 100% [proof]",
        ]
        powershell = render_markdown_report(
            report,
            reproduction_argv=windows_argv,
            reproduction_shell="powershell",
        )
        self.assertIn(json.dumps(windows_argv), powershell)
        self.assertIn(
            "    & 'C:\\Program Files\\Python\\python.exe' '-m' "
            "'charter_replay.cli' '--output' "
            "'C:\\Policy Lab\\owner''s report & 100% [proof]'",
            powershell,
        )

    def test_shell_rendering_omits_values_outside_the_proved_subset(self) -> None:
        report = build_json_report(
            compare_decisions(
                self.events,
                self.baseline,
                self.candidate,
                case_values=self.cases,
            ),
            self.manifest,
        )
        argv = ["python", "", 'contains"quote', "line\nbreak"]
        markdown = render_markdown_report(
            report, reproduction_argv=argv, reproduction_shell="powershell"
        )
        self.assertIn(json.dumps(argv), markdown)
        self.assertIn("Windows PowerShell rendering omitted:", markdown)
        self.assertNotIn("    & ", markdown)

    def test_powershell_rendering_omits_a_trailing_backslash_argument(self) -> None:
        report = build_json_report(
            compare_decisions(
                self.events,
                self.baseline,
                self.candidate,
                case_values=self.cases,
            ),
            self.manifest,
        )
        argv = ["python", "--output", "C:\\Policy Lab\\"]
        markdown = render_markdown_report(
            report, reproduction_argv=argv, reproduction_shell="powershell"
        )
        self.assertIn(json.dumps(argv), markdown)
        self.assertIn("Windows PowerShell rendering omitted:", markdown)
        self.assertNotIn("    & ", markdown)

    def test_powershell_rendering_omits_smart_quote_injection(self) -> None:
        report = build_json_report(
            compare_decisions(
                self.events,
                self.baseline,
                self.candidate,
                case_values=self.cases,
            ),
            self.manifest,
        )
        payload = "before\u2019 ; Write-Output __SMART_QUOTE_INJECTION__ ; \u2018after"
        argv = ["python", "--output", payload]
        markdown = render_markdown_report(
            report, reproduction_argv=argv, reproduction_shell="powershell"
        )
        self.assertIn(payload, markdown)
        self.assertIn("Windows PowerShell rendering omitted:", markdown)
        self.assertNotIn("    & ", markdown)

    def test_markdown_table_renders_policy_text_literally_without_changing_json(
        self,
    ) -> None:
        hostile_id = "evt<!--"
        later_id = "later-event"
        hostile_reason = (
            'policy returned allow <img src="https://example.invalid/pixel"> & ok.'
        )
        events = [event(hostile_id), event(later_id)]
        baseline = [
            {**decision(hostile_id, "allow", "baseline"), "reason": hostile_reason},
            decision(later_id, "allow", "baseline"),
        ]
        candidate = [
            {**decision(hostile_id, "allow", "candidate"), "reason": hostile_reason},
            decision(later_id, "allow", "candidate"),
        ]
        comparison = compare_decisions(events, baseline, candidate)
        manifest = {
            "run_id": "f" * 64,
            "generated_at": "2026-07-30T12:00:00Z",
            "baseline": {
                "kind": "recorded",
                "id": "floor-v1-final",
                "sha256": "1" * 64,
            },
            "candidate": {
                "kind": "recorded",
                "id": "candidate-policy",
                "sha256": "2" * 64,
            },
            "corpus": {
                "id": "hostile-markdown-fixture",
                "manifest_sha256": "3" * 64,
                "event_count": len(events),
            },
            "fail_on": ["newly-allowed"],
        }

        report = build_json_report(comparison, manifest)
        serialized_report = json.loads(report_json_bytes(report))
        markdown = render_markdown_report(
            report,
            reproduction_argv=["replay", "fixture"],
            reproduction_shell="posix-sh",
        )

        self.assertEqual(
            hostile_id, serialized_report["results"][0]["event"]["event_id"]
        )
        self.assertEqual(
            hostile_reason, serialized_report["results"][0]["baseline"]["reason"]
        )
        self.assertNotIn("<!--", markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("example.invalid", markdown)
        self.assertIn("<code>evt&#60;&#33;&#45;&#45;</code>", markdown)
        self.assertIn(
            "<code>allow&#58; policy returned allow &#60;img src&#61;", markdown
        )
        self.assertLess(
            markdown.index("later&#45;event"), markdown.index("## Limitations")
        )

    def test_markdown_table_neutralizes_links_mentions_backticks_and_breaks(
        self,
    ) -> None:
        hostile_id = "evt|`[x](https://example.invalid/e)`"
        hostile_reason = (
            "see [docs](https://example.invalid/r) cc @octocat #123 `tick` | cell "
            "next line ![i](https://example.invalid/p.png) ‮"
        )
        events = [event(hostile_id)]
        baseline = [
            {**decision(hostile_id, "allow", "baseline"), "reason": hostile_reason}
        ]
        candidate = [
            {**decision(hostile_id, "deny", "candidate"), "reason": hostile_reason}
        ]
        comparison = compare_decisions(events, baseline, candidate)
        manifest = {
            "run_id": "e" * 64,
            "generated_at": "2026-07-30T12:00:00Z",
            "baseline": {"kind": "recorded", "id": "b", "sha256": "1" * 64},
            "candidate": {"kind": "recorded", "id": "c", "sha256": "2" * 64},
            "corpus": {
                "id": "hostile",
                "manifest_sha256": "3" * 64,
                "event_count": 1,
            },
            "fail_on": ["newly-allowed"],
        }
        report = build_json_report(comparison, manifest)
        markdown = render_markdown_report(
            report, reproduction_argv=["replay"], reproduction_shell="posix-sh"
        )
        rows = markdown.split("| Event | Classification | Baseline | Candidate |")[1]
        rows = rows.split("## Limitations")[0]
        table_lines = [line for line in rows.splitlines() if line.startswith("| ")]
        # One event row: a raw line break in the text would add another line.
        self.assertEqual(1, len(table_lines))
        data_row = table_lines[-1]
        # Four cells only: a raw pipe or line break would add a cell or a line.
        self.assertEqual(5, data_row.count("|"))
        for raw in ("[docs]", "](", "@octocat", "`tick`", "https://", "‮", "!["):
            self.assertNotIn(raw, data_row)
        self.assertNotIn("`", data_row)
        self.assertIn("&#64;octocat", data_row)
        # The bidi control shows as an escape whose backslash is itself an entity.
        self.assertIn("&#92;u202e", data_row)
        # The machine-readable report keeps the exact text.
        serialized = json.loads(report_json_bytes(report))
        self.assertEqual(hostile_reason, serialized["results"][0]["baseline"]["reason"])
        self.assertEqual(hostile_id, serialized["results"][0]["event"]["event_id"])

    def test_source_failure_lines_render_event_id_and_message_literally(self) -> None:
        failure = SourceFailure(
            code="policy-failed",
            message="broke [x](https://example.invalid/m) `tick`",
            event_id="e`1",
        )
        report = build_json_report(
            compare_decisions(self.events, self.baseline, self.candidate),
            self.manifest,
            baseline_failures=(failure,),
        )
        markdown = render_markdown_report(
            report, reproduction_argv=["replay"], reproduction_shell="posix-sh"
        )
        section = markdown.split("## Source failures")[1]
        self.assertNotIn("https://", section)
        self.assertEqual(2, section.count("`"))  # only the code span


if __name__ == "__main__":
    unittest.main()
