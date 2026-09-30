"""The two development stacks must coexist through the public CLI."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from charter_replay import app
from charter_replay.hooks import HookOutcome
from charter_replay.manifests import build_corpus_manifest, manifest_json_bytes


class StackIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("charter_replay.variant_coverage"),
            "variant and review stacks are not integrated",
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        events, cases = [], []
        for index, (command, label) in enumerate(
            (("git status", "benign"), ("rm sandbox/fixture", "dangerous"))
        ):
            event_id = f"synthetic-{index}"
            events.append(
                dict(
                    schema_version="command-event.v1",
                    event_id=event_id,
                    timestamp="2026-01-01T00:00:00Z",
                    source="synthetic",
                    command=command,
                )
            )
            cases.append(
                dict(
                    schema_version="charter-case.v1",
                    event_id=event_id,
                    case_class=label,
                    case_family="stack-fixture",
                    rationale="Inert integration fixture.",
                    provenance="synthetic",
                )
            )
        for name, rows in (("events.jsonl", events), ("cases.jsonl", cases)):
            (self.source / name).write_bytes(
                b"".join((json.dumps(row) + "\n").encode() for row in rows)
            )
        manifest = build_corpus_manifest(
            corpus_id="stack-fixture",
            event_count=2,
            base_directory=self.source,
            files=["events.jsonl", "cases.jsonl"],
        )
        (self.source / "corpus-manifest.json").write_bytes(
            manifest_json_bytes(manifest)
        )
        self.pack = self.root / "pack"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                app.main(
                    [
                        "variants",
                        "generate",
                        "--source",
                        str(self.source),
                        "--output",
                        str(self.pack),
                        "--domain",
                        "posix-external.v1",
                    ]
                ),
                0,
            )

    def hooks(self, before, after):
        output = self.root / "replay"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = app.main(
                [
                    "hooks",
                    "--baseline",
                    before,
                    "--candidate",
                    after,
                    "--corpus",
                    str(self.pack),
                    "--output",
                    str(output),
                    "--jobs",
                    "2",
                ]
            )
        return code, output

    def coverage(self, output):
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(
                app.main(
                    [
                        "variants",
                        "coverage",
                        "--source",
                        str(self.source),
                        "--pack",
                        str(self.pack),
                        "--report",
                        str(output / "report" / "report.json"),
                    ]
                ),
                0,
            )
        return json.loads(stream.getvalue())

    def test_generate_real_hooks_html_and_coverage_form_one_workflow(self):
        before = json.dumps([sys.executable, "-c", "import sys; sys.exit(2)"])
        after = json.dumps([sys.executable, "-c", "pass"])
        code, output = self.hooks(before, after)
        self.assertEqual(code, 1)
        summary = json.loads((output / "summary.json").read_bytes())
        self.assertEqual(summary["gate"]["status"], "fail")
        self.assertIn("label_agreement", summary)
        self.assertTrue((output / "baseline" / "measurements.json").is_file())
        for name in ("report.html", "pr-comment.md", "pr-comment-aggregate.md"):
            self.assertTrue((output / "report" / name).is_file(), name)
        coverage = self.coverage(output)
        self.assertEqual(coverage["by_origin"]["seed"]["newly-allowed"], 2)
        self.assertEqual(coverage["by_origin"]["derived"]["newly-allowed"], 6)

    def test_source_failure_is_not_hidden_by_valid_variant_projection(self):
        hook = json.dumps([sys.executable, "-c", "pass"])
        with patch(
            "charter_replay.hooks.run_hook",
            return_value=HookOutcome("crash", "synthetic failure", 7, 1),
        ):
            code, output = self.hooks(hook, hook)
        self.assertEqual(code, 3)
        report = json.loads((output / "report" / "report.json").read_bytes())
        self.assertEqual(report["gate"]["status"], "error")
        self.assertTrue(report["source_failures"]["candidate"])
        self.assertEqual(self.coverage(output)["status"], "verified-projection")
        self.assertIn(
            "Gate: **ERROR**",
            (output / "report" / "pr-comment-aggregate.md").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
