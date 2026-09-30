"""`hooks` writes a verified aggregate; `aggregate` rebuilds it from a report directory."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import aggregate
from charter_replay.app import main

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "charter_replay" / "corpora" / "charter"
GUARDS = REPO / "examples" / "toy-guard"
REFUSAL = "aggregate refused: it contained corpus text; nothing was written"


def _hook(name: str) -> str:
    return json.dumps([sys.executable, str(GUARDS / name)])


def _invoke(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = int(exc.code)
    return code, out.getvalue(), err.getvalue()


def _hooks(output: Path, candidate: str = "guard_v2.py") -> tuple[int, str, str]:
    return _invoke(
        [
            "hooks",
            "--baseline",
            _hook("guard_v1.py"),
            "--candidate",
            _hook(candidate),
            "--corpus",
            str(CORPUS),
            "--output",
            str(output),
        ]
    )


def _corpus_text() -> set[str]:
    values: set[str] = set()
    for name in ("cases.jsonl", "events.jsonl"):
        for line in (CORPUS / name).read_text("utf-8").splitlines():
            record = json.loads(line)
            values.update(
                str(value)
                for key, value in record.items()
                if key in ("event_id", "case_family", "rationale", "command")
            )
    return values


class HooksWritesAggregateTests(unittest.TestCase):
    def test_toy_guard_aggregate_has_counts_and_no_corpus_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "run"
            code, _, stderr = _hooks(output)
            self.assertEqual(code, 1, stderr)
            data = json.loads((output / "aggregate.json").read_text("utf-8"))
            self.assertEqual(data["schema_version"], "aggregate.v1")
            self.assertEqual(data["gate"]["status"], "fail")
            self.assertEqual(data["counts"]["newly-allowed"], 4)
            self.assertEqual(data["counts"]["newly-denied"], 1)
            self.assertEqual(sum(data["counts"].values()), data["events"])
            self.assertEqual(sum(data["case_classes"].values()), data["events"])
            self.assertEqual(data["case_classes"]["opaque"], 10)
            outcomes = data["hook_outcomes"]
            self.assertEqual(sum(outcomes["candidate"].values()), data["events"])
            self.assertEqual(outcomes["candidate"]["crash"], 0)
            self.assertEqual(sum(data["source_failures"]["baseline"].values()), 0)
            markdown = (output / "aggregate.md").read_text("utf-8")
            self.assertTrue(markdown.startswith("<!-- charter-replay:aggregate.v1 -->"))
            self.assertLessEqual(len(markdown.encode()), aggregate.MAX_MARKDOWN_BYTES)
            blob = json.dumps(data) + markdown
            families = {
                json.loads(line)["case_family"]
                for line in (CORPUS / "cases.jsonl").read_text("utf-8").splitlines()
            }
            self.assertGreater(len(families), 10)
            for value in _corpus_text():
                self.assertNotIn(value, blob, value)
            for path in (CORPUS, output, output.parent):
                self.assertNotIn(str(path), blob)
            # The full summary still exists and is unchanged in kind.
            summary = json.loads((output / "summary.json").read_text("utf-8"))
            self.assertIn("shared-history-rewrite", summary["by_case_family"])

    def test_the_same_run_twice_writes_identical_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "one", Path(tmp) / "two"
            self.assertEqual(_hooks(first)[0], 1)
            self.assertEqual(_hooks(second)[0], 1)
            for name in aggregate.AGGREGATE_FILES:
                self.assertEqual(
                    (first / name).read_bytes(), (second / name).read_bytes(), name
                )
            # A rerun into the same output replaces the files with equal bytes.
            before = (first / "aggregate.json").read_bytes()
            self.assertEqual(_hooks(first)[0], 1)
            self.assertEqual((first / "aggregate.json").read_bytes(), before)

    def test_a_passing_run_reports_a_passing_aggregate(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "run"
            self.assertEqual(_hooks(output, "guard_v1.py")[0], 0)
            data = json.loads((output / "aggregate.json").read_text("utf-8"))
            self.assertEqual(data["gate"]["status"], "pass")
            self.assertEqual(data["counts"]["unchanged"], data["events"])

    def test_a_leaking_renderer_fails_the_run_but_keeps_the_summary(self):
        real = aggregate.render_markdown

        def broken(document):
            return real(document) + b"\ndanger-force-push-main\n"

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "run"
            with mock.patch.object(aggregate, "render_markdown", broken):
                code, _, stderr = _hooks(output)
            self.assertEqual(code, 3)
            self.assertIn(REFUSAL, stderr)
            self.assertNotIn("danger-force-push-main", stderr)
            self.assertTrue((output / "summary.json").is_file())
            self.assertTrue((output / "summary.md").is_file())
            for name in aggregate.AGGREGATE_FILES:
                self.assertFalse((output / name).exists(), name)


class StandaloneAggregateTests(unittest.TestCase):
    def run_hooks(self, tmp: str) -> Path:
        output = Path(tmp) / "run"
        self.assertEqual(_hooks(output)[0], 1)
        return output

    def test_rebuilds_the_same_document_from_a_report_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_hooks(tmp)
            target = Path(tmp) / "agg.json"
            markdown = Path(tmp) / "agg.md"
            code, out, err = _invoke(
                [
                    "aggregate",
                    "--report",
                    str(run / "report"),
                    "--output",
                    str(target),
                    "--markdown",
                    str(markdown),
                ]
            )
            self.assertEqual((code, out, err), (0, "", ""))
            standalone = json.loads(target.read_text("utf-8"))
            automatic = json.loads((run / "aggregate.json").read_text("utf-8"))
            # A kernel report directory has no hook outcomes; they are null.
            self.assertIsNone(standalone.pop("hook_outcomes"))
            self.assertIsNotNone(automatic.pop("hook_outcomes"))
            self.assertEqual(standalone, automatic)
            self.assertTrue(
                markdown.read_text("utf-8").startswith(aggregate.AGGREGATE_MARKER)
            )
            second = Path(tmp) / "again.json"
            self.assertEqual(
                _invoke(
                    [
                        "aggregate",
                        "--report",
                        str(run / "report"),
                        "--output",
                        str(second),
                    ]
                )[0],
                0,
            )
            self.assertEqual(second.read_bytes(), target.read_bytes())

    def test_an_existing_output_is_refused_and_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_hooks(tmp)
            target = Path(tmp) / "agg.json"
            target.write_bytes(b"keep me")
            fresh = Path(tmp) / "fresh.md"
            code, _, err = _invoke(
                [
                    "aggregate",
                    "--report",
                    str(run / "report"),
                    "--output",
                    str(target),
                    "--markdown",
                    str(fresh),
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("nothing is overwritten", err)
            self.assertEqual(target.read_bytes(), b"keep me")
            self.assertFalse(fresh.exists())
            code, _, _ = _invoke(
                [
                    "aggregate",
                    "--report",
                    str(run / "report"),
                    "--output",
                    str(fresh),
                    "--markdown",
                    str(fresh),
                ]
            )
            self.assertEqual(code, 2)
            self.assertFalse(fresh.exists())

    def test_a_tampered_report_or_manifest_is_refused_without_echo(self):
        for name, mutate in (
            (
                "report.json",
                lambda text: text.replace('"newly-allowed": 4', '"newly-allowed": 0'),
            ),
            ("report.json", lambda text: text.replace('"fail"', '"pass"', 1)),
            (
                "run-manifest.json",
                lambda text: text.replace('"newly-allowed"', '"newly-denied"', 1),
            ),
            ("report.json", lambda text: text[:-40]),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                run = self.run_hooks(tmp)
                path = run / "report" / name
                original = path.read_text("utf-8")
                changed = mutate(original)
                self.assertNotEqual(changed, original)
                path.write_text(changed, encoding="utf-8", newline="\n")
                target = Path(tmp) / "agg.json"
                code, out, err = _invoke(
                    [
                        "aggregate",
                        "--report",
                        str(run / "report"),
                        "--output",
                        str(target),
                    ]
                )
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("does not match its run manifest", err)
                self.assertNotIn(tmp, err)
                self.assertFalse(target.exists())

    def test_a_missing_or_linked_report_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            code, _, err = _invoke(
                [
                    "aggregate",
                    "--report",
                    str(empty),
                    "--output",
                    str(Path(tmp) / "a.json"),
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("needs readable report.json", err)
            run = self.run_hooks(tmp)
            copy = Path(tmp) / "linked"
            copy.mkdir()
            (copy / "run-manifest.json").write_bytes(
                (run / "report" / "run-manifest.json").read_bytes()
            )
            try:
                (copy / "report.json").symlink_to(run / "report" / "report.json")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")
            code, _, _ = _invoke(
                [
                    "aggregate",
                    "--report",
                    str(copy),
                    "--output",
                    str(Path(tmp) / "b.json"),
                ]
            )
            self.assertEqual(code, 2)

    def test_a_leaking_renderer_exits_3_with_a_fixed_message(self):
        real = aggregate.render_json

        def broken(document):
            return real(document) + b"\ndanger-force-push-main\n"

        with tempfile.TemporaryDirectory() as tmp:
            run = self.run_hooks(tmp)
            target = Path(tmp) / "agg.json"
            with mock.patch.object(aggregate, "render_json", broken):
                code, out, err = _invoke(
                    [
                        "aggregate",
                        "--report",
                        str(run / "report"),
                        "--output",
                        str(target),
                    ]
                )
            self.assertEqual((code, out), (3, ""))
            self.assertEqual(err.strip(), "charter-replay: " + REFUSAL)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
