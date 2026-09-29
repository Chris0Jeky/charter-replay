"""Hook observations retain source failure semantics across recorded replay."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from charter_replay import app, hooks
from charter_replay.tests.contract import test_cli as fixtures


def command(code: str) -> str:
    return json.dumps([sys.executable, "-c", code])


def invoke(argv: list[str]) -> int:
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        try:
            return app.main(argv)
        except SystemExit as exc:
            return int(exc.code)


def arguments(
    corpus: Path, output: Path, baseline: str, candidate: str
) -> list[str]:
    return [
        "hooks",
        "--baseline",
        baseline,
        "--candidate",
        candidate,
        "--corpus",
        str(corpus),
        "--output",
        str(output),
        "--jobs",
        "2",
    ]


class HookFailureTests(unittest.TestCase):
    def test_identical_failed_hooks_never_pass_an_unchanged_gate(self):
        failures = (
            (command("raise SystemExit(7)"), "crash", []),
            (command("print('not JSON')"), "invalid-output", []),
            (
                command("import time; time.sleep(30)"),
                "timeout",
                ["--hook-timeout", "0.1"],
            ),
            (json.dumps(["missing-hook-fixture-binary-xyz"]), "start-failed", []),
        )
        for hook, outcome, options in failures:
            with self.subTest(outcome=outcome):
                with fixtures.CliTests().fixture("same") as data:
                    directory, corpus, _, _ = data
                    output = directory / "hooks-output"
                    argv = arguments(corpus, output, hook, hook) + options
                    self.assertEqual(invoke(argv), 3)
                    report = json.loads(
                        (output / "report" / "report.json").read_bytes()
                    )
                    summary = json.loads((output / "summary.json").read_bytes())
                    self.assertEqual(report["counts"]["unchanged"], 2)
                    self.assertEqual(report["gate"]["status"], "error")
                    self.assertEqual(summary["gate"], report["gate"])
                    self.assertEqual(
                        summary["source_failures"], report["source_failures"]
                    )
                    for side in ("baseline", "candidate"):
                        observed = report["source_failures"][side]
                        self.assertEqual(len(observed), 2)
                        self.assertEqual(observed[0]["code"], f"hook-{outcome}")
                        self.assertEqual(summary["outcomes"][side][outcome], 2)
                    self.assertIn(
                        "Gate: **ERROR**",
                        (output / "report" / "report.md").read_text("utf-8"),
                    )
                    self.assertIn(
                        "Gate: **error**",
                        (output / "summary.md").read_text("utf-8"),
                    )
                    self.assertNotIn(str(directory), json.dumps(report))

    def test_process_failure_takes_precedence_over_a_triggered_regression(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "hooks-output"
            argv = arguments(
                corpus, output, command("pass"), command("raise SystemExit(7)")
            )
            self.assertEqual(invoke(argv), 3)
            report = json.loads((output / "report" / "report.json").read_bytes())
            self.assertEqual(report["gate"]["triggered"], ["newly-indeterminate"])
            self.assertEqual(report["gate"]["status"], "error")
            self.assertEqual(report["source_failures"]["baseline"], [])

    def test_record_returns_source_failure_but_keeps_loadable_decisions(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            output = directory / "recording"
            code = invoke(
                [
                    "record",
                    "--hook",
                    command("raise SystemExit(7)"),
                    "--corpus",
                    str(corpus),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(code, 3)
            source = app.kernel._load_recorded_source(str(output / "decisions.jsonl"))
            result = source.source.evaluate(fixtures.EVENTS)
            self.assertFalse(result.failures)
            self.assertEqual(
                [row["effect"] for row in result.decisions], ["indeterminate"] * 2
            )

    def test_healthy_allow_and_block_still_return_zero_and_one(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            allow, deny = command("pass"), command("raise SystemExit(2)")
            same = arguments(corpus, directory / "same", allow, allow)
            changed = arguments(corpus, directory / "changed", deny, allow)
            self.assertEqual(invoke(same), 0)
            self.assertEqual(invoke(changed), 1)

    def test_comparison_uses_the_exact_corpus_captured_before_hook_execution(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            original = app.kernel._load_charter_corpus(str(corpus))
            real_record = app.record_hook

            def record_and_replace_corpus(*args, **kwargs):
                summary = real_record(*args, **kwargs)
                changed = [
                    dict(event, command="changed after capture")
                    for event in fixtures.EVENTS
                ]
                (corpus / "events.jsonl").write_bytes(fixtures.jsonl_bytes(changed))
                manifest = fixtures.build_corpus_manifest(
                    corpus_id="replacement",
                    event_count=2,
                    base_directory=corpus,
                    files=["events.jsonl", "cases.jsonl"],
                )
                (corpus / "corpus-manifest.json").write_bytes(
                    fixtures.manifest_json_bytes(manifest)
                )
                return summary

            output = directory / "out"
            with mock.patch.object(
                app, "record_hook", side_effect=record_and_replace_corpus
            ):
                argv = arguments(corpus, output, command("pass"), command("pass"))
                self.assertEqual(invoke(argv), 0)
            report = json.loads((output / "report" / "report.json").read_bytes())
            self.assertEqual(
                report["corpus"]["manifest_sha256"], original.manifest_sha256
            )
            self.assertEqual(report["corpus"]["id"], original.corpus_id)
            self.assertEqual(
                [row["event"]["command"] for row in report["results"]],
                [event["command"] for event in fixtures.EVENTS],
            )

    def test_corpus_binding_error_still_returns_two_without_launch(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            (corpus / "events.jsonl").write_text("altered\n", encoding="utf-8")
            with mock.patch.object(app, "record_hook") as launch:
                argv = arguments(
                    corpus, directory / "out", command("pass"), command("pass")
                )
                self.assertEqual(invoke(argv), 2)
                launch.assert_not_called()


class HookAdmissionTests(unittest.TestCase):
    def test_invalid_second_side_command_or_workspace_runs_neither_hook(self):
        invalid = (
            ["--candidate", "["],
            ["--candidate", json.dumps(["bad\x00hook"])],
            ["--candidate-workspace", "missing-template-fixture"],
        )
        for options in invalid:
            with self.subTest(options=options):
                self.assert_invalid_before_launch(options)

    def assert_invalid_before_launch(self, options):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, _, _ = data
            with mock.patch.object(
                app,
                "record_hook",
                side_effect=AssertionError("hook started before admission"),
            ) as launch:
                argv = arguments(
                    corpus, directory / "out", command("pass"), command("pass")
                )
                self.assertEqual(invoke(argv + options), 2)
                launch.assert_not_called()

    def test_invalid_gate_timeout_and_jobs_run_neither_hook(self):
        invalid = (
            ["--fail-on", "unknown"],
            ["--fail-on", "newly-allowed,newly-allowed"],
            ["--hook-timeout", "nan"],
            ["--hook-timeout", "inf"],
            ["--hook-timeout", "0"],
            ["--hook-timeout", "-1"],
            ["--hook-timeout", "86401"],
            ["--jobs", "0"],
            ["--jobs", "-2"],
        )
        for options in invalid:
            with self.subTest(options=options):
                self.assert_invalid_before_launch(options)

    def test_direct_recorder_rejects_invalid_limits_before_workspace(self):
        invalid = (
            (float("nan"), 1),
            (float("inf"), 1),
            (0.0, 1),
            (10.0, 0),
            (10.0, -1),
        )
        for timeout, jobs in invalid:
            with self.subTest(timeout=timeout, jobs=jobs):
                spec = hooks.HookSpec((sys.executable, "-c", "pass"), timeout=timeout)
                with mock.patch.object(
                    hooks,
                    "prepare_workspace",
                    side_effect=AssertionError("workspace created before admission"),
                ):
                    with self.assertRaises(hooks.HookSpecError):
                        hooks.record_hook(
                            spec,
                            fixtures.EVENTS,
                            Path("unused"),
                            policy_id="fixture",
                            jobs=jobs,
                        )


if __name__ == "__main__":
    unittest.main()
