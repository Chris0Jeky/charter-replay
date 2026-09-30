"""A hook's stdout and stderr are bounded and an overflow kills its whole family.

Real synthetic hooks (`fixtures/hooks/output_hook.py`) print on purpose. The
limits are small (64 KiB) so the tests stay quick; corpus commands are inert.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from charter_replay import app, hook_context, hooks, policy_sources, repeat
from charter_replay.manifests import build_corpus_manifest, manifest_json_bytes
from charter_replay.tests.contract import test_process_source as process_fixtures
from charter_replay.tests.unit.test_hook_adapter import _event

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "hooks" / "output_hook.py"
LIMIT = 64 * 1024


def hook_argv(mode: str, limit: int, *extra: str) -> tuple[str, ...]:
    return (sys.executable, str(FIXTURE), mode, str(limit), *extra)


class RunHookTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def run_one(self, mode: str, *, limit: int = LIMIT, timeout: float = 30.0):
        extra = (str(self.root / "flooder.pid"),) if mode.startswith("family") else ()
        spec = hooks.HookSpec(
            hook_argv(mode, limit, *extra), timeout=timeout, output_limit=limit
        )
        workspace = hooks.prepare_workspace(None)
        self.addCleanup(hooks._cleanup_snapshot_root, workspace.parent)
        payload = hooks.build_payload(
            _event("flood-1", "inert command data"),
            runtime="claude",
            workspace=workspace,
            index=0,
        )
        started = time.monotonic()
        outcome = hooks.run_hook(spec, payload, workspace=workspace)
        return outcome, time.monotonic() - started

    def assert_flooder_gone(self):
        pid_file = self.root / "flooder.pid"
        self.assertTrue(pid_file.is_file(), "the descendant never started")
        pid = int(pid_file.read_text(encoding="ascii"))
        for _attempt in range(200):
            if not process_fixtures.ProcessSourceTests._process_is_running(pid):
                return
            time.sleep(0.01)
        self.fail(f"descendant {pid} is still running after the output limit")

    def assert_limit_outcome(self, outcome, stream: str | None):
        self.assertEqual("output-limit", outcome.outcome)
        self.assertIsNone(outcome.exit_code)
        if stream is not None:
            self.assertEqual(f"{stream} exceeded {LIMIT} bytes", outcome.detail)
        self.assertNotIn("x", outcome.detail.replace("exceeded", ""))

    def test_unbounded_stdout_is_cut_off_long_before_the_timeout(self):
        outcome, elapsed = self.run_one("stdout-flood")
        self.assert_limit_outcome(outcome, "stdout")
        self.assertLess(elapsed, 20)

    def test_unbounded_stderr_is_cut_off_long_before_the_timeout(self):
        outcome, elapsed = self.run_one("stderr-flood")
        self.assert_limit_outcome(outcome, "stderr")
        self.assertLess(elapsed, 20)

    def test_output_of_exactly_the_limit_is_a_normal_outcome(self):
        outcome, _ = self.run_one("stdout-exact")
        self.assertEqual(("allow", 0), (outcome.outcome, outcome.exit_code))
        outcome, _ = self.run_one("stderr-exact")
        self.assertEqual(("deny", 2), (outcome.outcome, outcome.exit_code))

    def test_one_byte_over_the_limit_is_an_overflow_even_if_the_hook_exits(self):
        outcome, _ = self.run_one("stdout-over")
        self.assert_limit_outcome(outcome, "stdout")
        outcome, _ = self.run_one("stderr-over")
        self.assert_limit_outcome(outcome, "stderr")

    def test_a_descendant_still_printing_as_the_parent_exits_is_killed(self):
        outcome, _ = self.run_one("family-exit")
        self.assert_limit_outcome(outcome, "stdout")
        self.assert_flooder_gone()

    def test_the_watchdog_kills_the_family_of_a_parent_that_keeps_running(self):
        # The parent sleeps for a minute: only the watchdog can end this early.
        outcome, elapsed = self.run_one("family-sleep", timeout=45)
        self.assert_limit_outcome(outcome, "stdout")
        self.assertLess(elapsed, 30)
        self.assert_flooder_gone()

    def test_no_temporary_file_or_workspace_outlives_an_overflow(self):
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.object(tempfile, "tempdir", raw):
                output = Path(raw) / "kept" / "recording"
                summary = hooks.record_hook(
                    hooks.HookSpec(
                        hook_argv("stdout-flood", LIMIT),
                        timeout=30,
                        output_limit=LIMIT,
                    ),
                    [_event("flood-1", "inert")],
                    output,
                    policy_id="flood",
                )
            self.assertEqual(1, summary["outcomes"]["output-limit"])
            leftovers = [p for p in Path(raw).iterdir() if p.name != "kept"]
            self.assertEqual([], leftovers)


class SupervisorTests(unittest.TestCase):
    """The runner itself: bounded reads, one kill path, an unchanged default."""

    @staticmethod
    def stub(written: bytes, kwargs_seen: list):
        def finish(_argv, *, stdout_stream, stderr_stream, **kwargs):
            kwargs_seen.append(kwargs)
            stdout_stream.write(written)
            return 0, False

        return finish

    def run_stubbed(self, written: bytes, seen: list, **options):
        with (
            mock.patch.object(
                policy_sources,
                "_run_windows_policy_process",
                side_effect=self.stub(written, seen),
            ),
            mock.patch.object(
                policy_sources,
                "_run_posix_policy_process",
                side_effect=self.stub(written, seen),
            ),
        ):
            return policy_sources._run_policy_process(
                ["synthetic"],
                b"",
                timeout_seconds=1.0,
                cwd=None,
                environment=None,
                **options,
            )

    def test_the_default_passes_no_limit_to_either_runner(self):
        seen: list = []
        result = self.run_stubbed(b"y" * 5000, seen)
        self.assertEqual(b"y" * 5000, result.stdout)
        self.assertEqual(1, len(seen))
        self.assertNotIn("output_limit", seen[0])

    def test_a_limit_reaches_the_runner_and_output_at_it_is_returned(self):
        seen: list = []
        result = self.run_stubbed(b"y" * 4096, seen, output_limit=4096)
        self.assertEqual(b"y" * 4096, result.stdout)
        self.assertEqual(4096, seen[0]["output_limit"])

    def test_reads_stay_bounded_when_output_appears_after_the_sizing(self):
        # An escaped descendant can write between the sizing and the read.
        reads: list[int] = []
        original = policy_sources._read_process_stream

        def observed(stream, limit=None):
            data = original(stream, limit)
            reads.append(len(data))
            return data

        with (
            mock.patch.object(policy_sources, "_stream_over_limit", return_value=None),
            mock.patch.object(policy_sources, "_read_process_stream", observed),
        ):
            with self.assertRaises(policy_sources.ProcessOutputLimitExceeded) as caught:
                self.run_stubbed(b"z" * 300_000, [], output_limit=2048)
        self.assertEqual("stdout", caught.exception.stream)
        self.assertEqual([2049, 0], reads)

    def test_read_process_stream_reads_at_most_one_byte_past_the_limit(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"q" * 10_000)
            self.assertEqual(11, len(policy_sources._read_process_stream(stream, 10)))
            self.assertEqual(
                10_000, len(policy_sources._read_process_stream(stream, 10_000))
            )
            self.assertEqual(10_000, len(policy_sources._read_process_stream(stream)))

    def test_kernel_process_sources_never_ask_for_a_limit(self):
        events = [
            {
                "schema_version": "command-event.v1",
                "event_id": "git-status-001",
                "timestamp": "2026-07-30T12:01:00Z",
                "command": "git status --short",
                "cwd": "/fictional/shop-api",
                "source": "synthetic",
            }
        ]
        with mock.patch.object(
            policy_sources,
            "_run_policy_process",
            wraps=policy_sources._run_policy_process,
        ) as run:
            source = policy_sources.ProcessDecisionSource(
                [*process_fixtures.FIXTURE_COMMAND, "success"], timeout_seconds=10.0
            )
            self.assertTrue(source.evaluate(events).is_valid)
        self.assertEqual(1, run.call_count)
        self.assertNotIn("output_limit", run.call_args.kwargs)

    def test_the_wait_is_the_plain_timed_wait_without_a_limit(self):
        process = mock.Mock(spec=subprocess.Popen)
        process.wait.side_effect = subprocess.TimeoutExpired("x", 3.0)
        self.assertTrue(policy_sources._wait_for_process(process, 3.0))
        process.wait.assert_called_once_with(timeout=3.0)

    def test_a_timeout_still_wins_when_the_output_is_within_the_limit(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            policy_sources._run_policy_process(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                b"",
                timeout_seconds=0.3,
                cwd=None,
                environment=None,
                output_limit=1024,
            )


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.marker = self.root / "hook-ran"
        self.corpus = self.build_corpus()
        script = self.root / "hook.py"
        script.write_text(
            "import sys\nfrom pathlib import Path\nsys.stdin.read()\n"
            f"Path({str(self.marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        self.command = json.dumps([sys.executable, str(script)])

    def build_corpus(self) -> Path:
        corpus = self.root / "corpus"
        corpus.mkdir()
        event = dict(
            schema_version="command-event.v1",
            event_id="synthetic-0",
            timestamp="2026-01-01T00:00:00Z",
            command="inert command data, never executed",
            source="synthetic",
        )
        case = dict(
            schema_version="charter-case.v1",
            event_id="synthetic-0",
            case_class="opaque",
            case_family="synthetic-limit",
            rationale="Inert output-limit fixture.",
            provenance="synthetic",
        )
        for name, row in (("events.jsonl", event), ("cases.jsonl", case)):
            (corpus / name).write_bytes((json.dumps(row) + "\n").encode("utf-8"))
        manifest = build_corpus_manifest(
            corpus_id="synthetic-limit",
            event_count=1,
            base_directory=corpus,
            files=["events.jsonl", "cases.jsonl"],
        )
        (corpus / "corpus-manifest.json").write_bytes(manifest_json_bytes(manifest))
        return corpus

    def invoke(self, command: str, *options: str) -> tuple[int, str]:
        output = self.root / f"out-{len(list(self.root.glob('out-*')))}"
        base = {
            "record": ["--hook", self.command],
            "hooks": ["--baseline", self.command, "--candidate", self.command],
            "repeat": ["--hook", self.command, "--repeats", "2"],
        }[command]
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            try:
                code = app.main(
                    [
                        command,
                        *base,
                        "--corpus",
                        str(self.corpus),
                        "--output",
                        str(output),
                        "--jobs",
                        "1",
                        *options,
                    ]
                )
            except SystemExit as exit_:
                code = exit_.code
        return code, stderr.getvalue()

    def test_an_out_of_range_or_malformed_limit_exits_2_before_any_hook_runs(self):
        for command in ("record", "hooks", "repeat"):
            for value in ("1023", "67108865", "0", "-1024", "1e5", "1_024", "", "x"):
                with self.subTest(command=command, value=value):
                    code, message = self.invoke(command, "--hook-output-limit", value)
                    self.assertEqual(2, code)
                    self.assertIn("--hook-output-limit", message)
                    self.assertFalse(self.marker.exists())

    def test_the_bounds_themselves_are_admitted(self):
        for command in ("record", "hooks", "repeat"):
            for value in ("1024", "67108864"):
                with self.subTest(command=command, value=value):
                    code, message = self.invoke(command, "--hook-output-limit", value)
                    self.assertEqual(0, code, message)
                    self.assertTrue(self.marker.exists())
                    self.marker.unlink()

    def test_a_spec_outside_the_bounds_is_refused_before_any_hook_runs(self):
        for value in (1023, 64 * 1024 * 1024 + 1, 0, -1, True, 1.5, "1024", None):
            with self.subTest(value=value):
                spec = hooks.HookSpec(
                    (sys.executable, "-c", "pass"), output_limit=value
                )
                with self.assertRaises(hooks.HookSpecError):
                    hooks.record_hook(
                        spec,
                        [_event("e", "inert")],
                        self.root / "never",
                        policy_id="x",
                    )
                self.assertFalse((self.root / "never").exists())

    def flood_command(self) -> str:
        return json.dumps(list(hook_argv("stdout-flood", 1024)))

    def test_the_cli_limit_reaches_the_hook_and_is_recorded(self):
        self.command = self.flood_command()
        code, _ = self.invoke("record", "--hook-output-limit", "4096")
        self.assertEqual(3, code)
        out = self.root / "out-0"
        rows = [
            json.loads(line)
            for line in (out / "outcomes.jsonl").read_text("utf-8").splitlines()
        ]
        self.assertEqual(["output-limit"], [row["outcome"] for row in rows])
        decision = json.loads((out / "decisions.jsonl").read_text("utf-8"))
        self.assertEqual("indeterminate", decision["effect"])
        self.assertEqual("output-limit: stdout exceeded 4096 bytes", decision["reason"])
        context = json.loads((out / "hook-context.json").read_text("utf-8"))
        self.assertEqual(4096, context["descriptor"]["execution"]["output_limit_bytes"])
        measurements = json.loads((out / "measurements.json").read_text("utf-8"))
        self.assertEqual(1, measurements["sample_count"])

    def test_hooks_reports_the_overflow_as_a_source_failure_on_both_sides(self):
        self.command = self.flood_command()
        code, _ = self.invoke("hooks", "--hook-output-limit", "2048")
        self.assertEqual(3, code)
        out = self.root / "out-0"
        summary = json.loads((out / "summary.json").read_text("utf-8"))
        report = json.loads((out / "report" / "report.json").read_text("utf-8"))
        for side in ("baseline", "candidate"):
            self.assertEqual(1, summary["outcomes"][side]["output-limit"])
            failures = report["source_failures"][side]
            self.assertEqual(["hook-output-limit"], [item["code"] for item in failures])
        self.assertEqual("error", report["gate"]["status"])

    def test_repeat_accepts_the_new_outcome_and_exits_3(self):
        self.command = self.flood_command()
        code, _ = self.invoke("repeat", "--hook-output-limit", "2048")
        self.assertEqual(3, code)
        document = json.loads(
            (self.root / "out-0" / "stability.json").read_text("utf-8")
        )
        self.assertEqual(1, document["counts"]["stable"])
        self.assertEqual({"stable"}, {row["class"] for row in document["rows"]})
        variants = [item for row in document["rows"] for item in row["variants"]]
        self.assertEqual(
            [("indeterminate", "output-limit", 2)],
            [(v["effect"], v["outcome"], v["count"]) for v in variants],
        )
        for run in document["repeat_runs"]:
            self.assertEqual({"hook-output-limit": 1}, run["source_failures"])

    def test_the_outcome_is_registered_where_outcomes_are_enumerated(self):
        self.assertIn("output-limit", hooks.OUTCOMES)
        self.assertIn("output-limit", hooks.FAILURE_OUTCOMES)
        self.assertEqual("indeterminate", hooks.effect_for("output-limit", "deny"))
        self.assertIs(hooks.OUTCOMES, repeat.OUTCOMES)


class ContextTests(unittest.TestCase):
    def describe(self, **options) -> dict:
        spec = hooks.HookSpec((sys.executable, "-c", "pass"), **options)
        return hook_context.describe_hook_context(spec, workspace_template=None, jobs=1)

    def test_the_limit_is_an_execution_setting_and_changes_the_identity(self):
        default = self.describe()
        self.assertEqual(
            hooks.DEFAULT_OUTPUT_LIMIT, default["execution"]["output_limit_bytes"]
        )
        other = self.describe(output_limit=4096)
        self.assertEqual(4096, other["execution"]["output_limit_bytes"])
        self.assertNotEqual(
            hook_context.context_id(default), hook_context.context_id(other)
        )
        self.assertEqual(
            hook_context.context_id(other),
            hook_context.context_id(self.describe(output_limit=4096)),
        )

    def test_new_documents_validate_and_reject_a_bad_limit(self):
        document = hook_context.context_document(self.describe(output_limit=4096))
        hook_context.validate_hook_context(document)
        for value in (1023, 64 * 1024 * 1024 + 1, True, 4096.0, "4096", None):
            with self.subTest(value=value):
                bad = copy.deepcopy(document)
                bad["descriptor"]["execution"]["output_limit_bytes"] = value
                bad["context_id"] = hook_context.context_id(bad["descriptor"])
                with self.assertRaisesRegex(ValueError, "output_limit_bytes"):
                    hook_context.validate_hook_context(bad)

    def test_a_document_written_before_the_field_existed_still_validates(self):
        descriptor = self.describe()
        del descriptor["execution"]["output_limit_bytes"]
        old = hook_context.context_document(descriptor)
        self.assertEqual({"timeout_seconds", "jobs"}, set(descriptor["execution"]))
        hook_context.validate_hook_context(old)
        # The id of an old file is still the id of its own bytes.
        self.assertNotEqual(
            old["context_id"],
            hook_context.context_document(self.describe())["context_id"],
        )

    def test_other_execution_keys_are_still_rejected(self):
        document = hook_context.context_document(self.describe())
        document["descriptor"]["execution"]["extra"] = 1
        document["context_id"] = hook_context.context_id(document["descriptor"])
        with self.assertRaises(ValueError):
            hook_context.validate_hook_context(document)


if __name__ == "__main__":
    unittest.main()
