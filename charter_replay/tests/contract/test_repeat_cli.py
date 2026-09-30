"""`repeat` end to end with real synthetic hook processes in temporary directories.

The synthetic hooks keep their state in a counter file whose absolute path is
written into the script text, outside argv and the workspace template, so the
hook context is the same for every repeat. Corpus commands are inert data.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import app, repeat
from charter_replay.manifests import build_corpus_manifest, manifest_json_bytes

# The hook body is chosen per test; `n` counts invocations across all repeats.
PRELUDE = """\
import json, sys
from pathlib import Path
sys.stdin.read()
counter = Path({counter!r})
n = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n + 1))
"""
ALLOW = 'print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", '
ALLOW += '"permissionDecision": "allow", "permissionDecisionReason": %s}}))\n'
DENY_ON_ODD = """\
if n % 2:
    print("no", file=sys.stderr)
    sys.exit(2)
"""
STOP = 'print(json.dumps({"continue": False, "stopReason": "no"}))\n'
BODIES = {
    "deterministic": "sys.exit(0)\n",
    # Three events per repeat, so parity of n flips for every event each repeat.
    "effect": DENY_ON_ODD,
    "outcome": DENY_ON_ODD + STOP,
    "reason": ALLOW % '"run %d" % n',
}


class RepeatCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.counter = self.root / "state" / "counter.txt"
        self.counter.parent.mkdir()
        self.parent = self.root / "out"
        self.parent.mkdir()
        self.output = self.parent / "repeat"
        self.corpus = self.build_corpus(3)

    def build_corpus(self, count, *, prefix="synthetic-", name="corpus"):
        corpus = self.root / name
        corpus.mkdir()
        events, cases = [], []
        for number in range(count):
            event_id = f"{prefix}{number}"
            events.append(
                dict(
                    schema_version="command-event.v1",
                    event_id=event_id,
                    timestamp="2026-01-01T00:00:00Z",
                    command="inert command data, never executed",
                    source="synthetic",
                )
            )
            cases.append(
                dict(
                    schema_version="charter-case.v1",
                    event_id=event_id,
                    case_class="opaque",
                    case_family="synthetic-repeat",
                    rationale="Inert repeat-mode fixture.",
                    provenance="synthetic",
                )
            )
        for name, rows in (("events.jsonl", events), ("cases.jsonl", cases)):
            (corpus / name).write_bytes(
                "".join(json.dumps(row) + "\n" for row in rows).encode("utf-8")
            )
        manifest = build_corpus_manifest(
            corpus_id="synthetic-repeat",
            event_count=count,
            base_directory=corpus,
            files=["events.jsonl", "cases.jsonl"],
        )
        (corpus / "corpus-manifest.json").write_bytes(manifest_json_bytes(manifest))
        return corpus

    def hook(self, body, *, extra="", name="hook.py"):
        script = self.root / name
        text = (
            PRELUDE.format(counter=str(self.counter)) + extra + BODIES.get(body, body)
        )
        script.write_text(text, encoding="utf-8")
        return script

    def run_repeat(self, script, *arguments, output=None, extra_argv=()):
        command = json.dumps([sys.executable, str(script), *extra_argv])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = app.main(
                    [
                        "repeat",
                        "--hook",
                        command,
                        "--corpus",
                        str(self.corpus),
                        "--output",
                        str(output or self.output),
                        "--jobs",
                        "1",
                        *arguments,
                    ]
                )
            except SystemExit as exit_:
                code = exit_.code
        return code, stdout.getvalue(), stderr.getvalue()

    def stability(self, output=None):
        return json.loads(((output or self.output) / "stability.json").read_bytes())

    def classes(self, document):
        return {row["class"] for row in document["rows"]}

    def test_deterministic_hook_is_stable_and_publishes_the_full_layout(self):
        code, printed, _ = self.run_repeat(self.hook("deterministic"), "--repeats", "3")
        self.assertEqual(code, 0)
        document = self.stability()
        self.assertEqual(document["counts"]["stable"], 3)
        self.assertEqual(document["comparable_repeats"], 3)
        self.assertEqual(document["gate"]["status"], "pass")
        for name in ("stability.json", "stability.md", "measurements.json"):
            self.assertTrue((self.output / name).is_file(), name)
        for number in ("01", "02", "03"):
            run = self.output / "runs" / number
            for name in ("decisions.jsonl", "outcomes.jsonl", "hook-context.json"):
                self.assertTrue((run / name).is_file(), f"{number}/{name}")
        recorded = json.loads(
            (self.output / "runs" / "01" / "hook-context.json").read_bytes()
        )
        self.assertEqual(document["context_id"], recorded["context_id"])
        self.assertIn("no corpus command was executed", printed)
        # Timing lives only in measurements.json.
        self.assertNotIn("elapsed", (self.output / "stability.json").read_text())
        measured = json.loads((self.output / "measurements.json").read_bytes())
        self.assertEqual(len(measured["repeats"]), 3)
        leftovers = [p.name for p in self.parent.iterdir() if p.name.startswith(".")]
        self.assertEqual(leftovers, [])

    def test_identical_observations_give_byte_identical_stability_json(self):
        script = self.hook("deterministic")
        second = self.parent / "second"
        self.assertEqual(self.run_repeat(script, "--repeats", "2")[0], 0)
        self.assertEqual(self.run_repeat(script, "--repeats", "2", output=second)[0], 0)
        self.assertEqual(
            (self.output / "stability.json").read_bytes(),
            (second / "stability.json").read_bytes(),
        )
        self.assertEqual(
            (self.output / "stability.md").read_bytes(),
            (second / "stability.md").read_bytes(),
        )

    def test_random_effect_hook_is_effect_varies_and_fails_the_default_gate(self):
        code, _, _ = self.run_repeat(self.hook("effect"), "--repeats", "2")
        self.assertEqual(code, 1)
        document = self.stability()
        self.assertEqual(document["counts"]["effect-varies"], 3)
        for row in document["rows"]:
            self.assertEqual(
                {(v["effect"], v["outcome"]) for v in row["variants"]},
                {("allow", "allow"), ("deny", "deny")},
            )

    def test_a_legacy_code_page_stdout_does_not_change_the_exit_code(self):
        # A cp1252 pipe cannot encode these letters; the summary is printed only
        # after the output is published, so printing must not turn 1 into 2.
        # Three events, so the hook's counter parity flips for each of them.
        self.corpus = self.build_corpus(
            3, prefix="événement-日本-", name="unicode-corpus"
        )
        raw = io.BytesIO()
        legacy = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
        command = json.dumps([sys.executable, str(self.hook("effect"))])
        argv = ["repeat", "--hook", command, "--corpus", str(self.corpus)]
        argv += ["--output", str(self.output), "--jobs", "1", "--repeats", "2"]
        with (
            mock.patch.object(sys, "stdout", legacy),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            code = app.main(argv)
        self.assertEqual(code, 1, stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue((self.output / "stability.md").is_file())
        self.assertIn("日本".encode("utf-8"), raw.getvalue())

    def test_counter_alternation_keeps_the_context_unchanged(self):
        self.run_repeat(self.hook("effect"), "--repeats", "3")
        ids = {
            json.loads((self.output / "runs" / n / "hook-context.json").read_bytes())[
                "context_id"
            ]
            for n in ("01", "02", "03")
        }
        self.assertEqual(len(ids), 1)
        self.assertEqual(self.stability()["comparable_repeats"], 3)

    def test_outcome_only_variation_is_outcome_varies(self):
        # exit 2 (deny) versus `continue: false` (stop) are both a deny effect.
        code, _, _ = self.run_repeat(self.hook("outcome"), "--repeats", "2")
        self.assertEqual(code, 0, "outcome-varies is outside the default --fail-on")
        document = self.stability()
        self.assertEqual(self.classes(document), {"outcome-varies"})
        self.assertEqual(
            {(v["effect"], v["outcome"]) for v in document["rows"][0]["variants"]},
            {("deny", "deny"), ("deny", "stop")},
        )
        code, _, _ = self.run_repeat(
            self.hook("outcome"),
            "--repeats",
            "2",
            "--fail-on",
            "outcome-varies",
            output=self.parent / "gated",
        )
        self.assertEqual(code, 1)

    def test_reason_only_variation_is_reason_varies_and_counts_digests(self):
        code, _, _ = self.run_repeat(self.hook("reason"), "--repeats", "4")
        self.assertEqual(code, 0)
        document = self.stability()
        self.assertEqual(self.classes(document), {"reason-varies"})
        for row in document["rows"]:
            self.assertEqual(len(row["variants"]), 1)
            self.assertEqual(len(row["reasons"]), 4)
        self.assertNotIn("run ", (self.output / "stability.json").read_text())
        code, _, _ = self.run_repeat(
            self.hook("reason"),
            "--repeats",
            "2",
            "--fail-on",
            "reason-varies",
            output=self.parent / "gated",
        )
        self.assertEqual(code, 1)

    def test_context_changed_between_repeats_is_exit_3_and_not_merged(self):
        data = self.root / "data.txt"
        data.write_text("initial\n", encoding="utf-8")
        # The third invocation is the last event of repeat 1: change an argv file.
        edit = f"if n == 2:\n    Path({str(data)!r}).write_text('changed\\n')\n"
        script = self.hook("deterministic", extra=edit)
        code, _, _ = self.run_repeat(script, "--repeats", "3", extra_argv=[str(data)])
        self.assertEqual(code, 3)
        document = self.stability()
        self.assertEqual(document["gate"]["status"], "error")
        # Repeat 1 saw its own inputs change; later repeats start in a new context.
        self.assertIn(
            "hook-context-changed", document["repeat_runs"][0]["source_failures"]
        )
        for run in document["repeat_runs"][1:]:
            self.assertFalse(run["context_matches"])
            self.assertEqual(run["source_failures"], {"repeat-context-changed": 1})
        self.assertEqual(document["comparable_repeats"], 1)
        for row in document["rows"]:
            self.assertEqual(sum(v["count"] for v in row["variants"]), 1)

    def test_source_failure_outranks_a_selected_class(self):
        crash = "if n == 0:\n    sys.exit(1)\n"
        script = self.hook(BODIES["effect"], extra=crash)
        code, _, _ = self.run_repeat(script, "--repeats", "2")
        self.assertEqual(code, 3)
        document = self.stability()
        self.assertGreater(document["counts"]["effect-varies"], 0)
        self.assertEqual(
            document["repeat_runs"][0]["source_failures"], {"hook-crash": 1}
        )

    def test_repeats_outside_two_to_fifty_start_no_hook_and_write_nothing(self):
        script = self.hook("deterministic")
        with mock.patch.object(repeat, "record_hook") as launch:
            for value in ("1", "51", "0", "-2", "abc", "2.5"):
                code, _, error = self.run_repeat(script, "--repeats", value)
                self.assertEqual(code, 2, value)
                self.assertNotIn(str(self.root), error)
            launch.assert_not_called()
        self.assertFalse(self.counter.exists(), "no hook process was started")
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_repeats_is_required(self):
        code, _, _ = self.run_repeat(self.hook("deterministic"))
        self.assertEqual(code, 2)
        self.assertFalse(self.counter.exists())

    def test_existing_output_is_refused_untouched_before_any_hook_runs(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_text("mine", encoding="utf-8")
        code, _, error = self.run_repeat(self.hook("deterministic"), "--repeats", "2")
        self.assertEqual(code, 2)
        self.assertEqual([p.name for p in self.output.iterdir()], ["keep.txt"])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "mine")
        self.assertFalse(self.counter.exists(), "no hook process was started")
        self.assertNotIn(str(self.root), error)
        self.assertEqual([p.name for p in self.parent.iterdir()], ["repeat"])

    def test_output_inside_the_workspace_template_is_refused_before_any_hook(self):
        # Staging beside the output would leak earlier repeats into later ones.
        code, _, error = self.run_repeat(
            self.hook("deterministic"),
            "--repeats",
            "2",
            "--workspace",
            str(self.parent),
        )
        self.assertEqual(code, 2)
        self.assertFalse(self.counter.exists(), "no hook process was started")
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assertNotIn(str(self.root), error)

    def test_existing_output_file_is_refused(self):
        self.output.write_text("a file", encoding="utf-8")
        code, _, _ = self.run_repeat(self.hook("deterministic"), "--repeats", "2")
        self.assertEqual(code, 2)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "a file")

    def test_invalid_fail_on_is_refused_before_any_hook_runs(self):
        for value in ("stable", "effect-varies,effect-varies", ""):
            code, _, _ = self.run_repeat(
                self.hook("deterministic"), "--repeats", "2", "--fail-on", value
            )
            self.assertEqual(code, 2, value)
        self.assertFalse(self.counter.exists())

    def test_output_that_appears_during_publication_is_not_overwritten(self):
        script = self.hook("deterministic")
        real = repeat.measurements_bytes

        def appears(records):
            # After staging is built, before the re-check and the rename.
            self.output.mkdir()
            return real(records)

        with mock.patch.object(repeat, "measurements_bytes", side_effect=appears):
            code, _, error = self.run_repeat(script, "--repeats", "2")
        self.assertEqual(code, 2)
        self.assertIn("output appeared during publication", error)
        self.assertNotIn(str(self.root), error)
        self.assertEqual(list(self.output.iterdir()), [], "the newcomer is untouched")
        self.assertEqual([p.name for p in self.parent.iterdir()], ["repeat"])

    def test_a_file_that_appears_during_publication_is_not_replaced(self):
        script = self.hook("deterministic")
        real = repeat.measurements_bytes

        def appears(records):
            self.output.write_text("a file", encoding="utf-8")
            return real(records)

        with mock.patch.object(repeat, "measurements_bytes", side_effect=appears):
            code, _, _ = self.run_repeat(script, "--repeats", "2")
        self.assertEqual(code, 2)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "a file")
        self.assertEqual([p.name for p in self.parent.iterdir()], ["repeat"])

    def rename_failing(self, failures):
        """Fail the staging rename `failures` times (None: always), then work."""

        real = os.rename
        calls = []

        def rename(source, destination, *args, **kwargs):
            if Path(destination) == self.output:
                calls.append(1)
                if failures is None or len(calls) <= failures:
                    raise PermissionError("held by a sync client")
            return real(source, destination, *args, **kwargs)

        return mock.patch.object(repeat.os, "rename", rename), calls

    def test_a_transiently_locked_rename_is_retried_and_published(self):
        patched, calls = self.rename_failing(2)
        with patched, mock.patch.object(repeat.time, "sleep") as sleep:
            code, _, _ = self.run_repeat(self.hook("deterministic"), "--repeats", "2")
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertTrue((self.output / "stability.json").is_file())
        self.assertEqual([p.name for p in self.parent.iterdir()], ["repeat"])

    def test_a_rename_that_stays_locked_keeps_the_recordings_and_says_so(self):
        patched, calls = self.rename_failing(None)
        with patched, mock.patch.object(repeat.time, "sleep"):
            code, stdout, error = self.run_repeat(
                self.hook("deterministic"), "--repeats", "2"
            )
        self.assertEqual(code, 3)
        self.assertEqual(len(calls), repeat._RENAME_ATTEMPTS)
        self.assertIn("kept in a hidden", error)
        self.assertNotIn(str(self.root), error)
        self.assertFalse(self.output.exists())
        (kept,) = self.parent.iterdir()
        self.assertTrue(kept.name.startswith(".charter-repeat-"))
        self.assertTrue((kept / "stability.json").is_file())
        self.assertEqual(len(list((kept / "runs").iterdir())), 2)

    def test_other_rename_errors_are_not_retried_and_leave_no_staging(self):
        real = os.rename

        def rename(source, destination, *args, **kwargs):
            if Path(destination) == self.output:
                raise OSError("device full")
            return real(source, destination, *args, **kwargs)

        with (
            mock.patch.object(repeat.os, "rename", rename),
            mock.patch.object(repeat.time, "sleep") as sleep,
        ):
            code, _, error = self.run_repeat(
                self.hook("deterministic"), "--repeats", "2"
            )
        self.assertEqual(code, 3)
        self.assertIn("output failed (OSError)", error)
        sleep.assert_not_called()
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_a_crash_midway_leaves_no_output_and_no_staging(self):
        script = self.hook("deterministic")
        real = repeat.record_hook
        calls = []

        def crashing(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise KeyboardInterrupt
            return real(*args, **kwargs)

        with mock.patch.object(repeat, "record_hook", side_effect=crashing):
            with self.assertRaises(KeyboardInterrupt):
                self.run_repeat(script, "--repeats", "3")
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_repeat_one_failure_is_an_input_error_not_a_source_failure(self):
        with mock.patch.object(
            repeat, "record_hook", side_effect=app.HookSpecError("bad hook")
        ):
            code, _, _ = self.run_repeat(self.hook("deterministic"), "--repeats", "2")
        self.assertEqual(code, 2)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_a_later_repeat_that_cannot_start_is_a_source_failure(self):
        real = repeat.record_hook
        calls = []

        def flaky(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise app.HookSpecError("hook input fingerprint could not be read")
            return real(*args, **kwargs)

        with mock.patch.object(repeat, "record_hook", side_effect=flaky):
            code, _, _ = self.run_repeat(self.hook("deterministic"), "--repeats", "3")
        self.assertEqual(code, 3)
        document = self.stability()
        self.assertEqual(
            document["repeat_runs"][1]["source_failures"], {"repeat-not-recorded": 1}
        )
        self.assertEqual(document["comparable_repeats"], 2)


if __name__ == "__main__":
    unittest.main()
