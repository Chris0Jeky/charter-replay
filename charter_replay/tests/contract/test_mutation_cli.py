"""Mutation evaluation through real synthetic hooks; corpus text remains inert."""

from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay import app
from charter_replay.manifests import build_corpus_manifest, manifest_json_bytes
from charter_replay.tests.no_launch import forbid_process_launch


class MutationCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / "result"
        self.sentinel = self.root / "corpus-command-was-executed"
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        events = [
            dict(
                schema_version="command-event.v1",
                event_id=f"synthetic-{n}",
                timestamp="2026-01-01T00:00:00Z",
                source="synthetic",
                command=f"synthetic-{n}; touch {self.sentinel}",
            )
            for n in range(2)
        ]
        cases = [
            dict(
                schema_version="charter-case.v1",
                event_id=e["event_id"],
                case_class="opaque",
                case_family="synthetic-mutation",
                rationale="Inert mutation fixture.",
                provenance="synthetic",
            )
            for e in events
        ]
        for name, rows in (("events.jsonl", events), ("cases.jsonl", cases)):
            (self.corpus / name).write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
        manifest = build_corpus_manifest(
            corpus_id="synthetic-mutation",
            event_count=2,
            base_directory=self.corpus,
            files=["events.jsonl", "cases.jsonl"],
        )
        (self.corpus / "corpus-manifest.json").write_bytes(
            manifest_json_bytes(manifest)
        )
        self.baseline = self.hook(
            "baseline", "sys.exit(2 if 'synthetic-0' in command else 0)"
        )
        self.plan = self.root / "plan.json"

    def hook(self, name, body):
        script = self.root / f"{name}.py"
        script.write_text(
            "import json, sys, time\nfrom pathlib import Path\n"
            "payload = json.load(sys.stdin)\ncommand = payload['tool_input']['command']\n"
            + body
            + "\n",
            encoding="utf-8",
        )
        return [sys.executable, str(script)]

    def write_plan(self, mutants, *, baseline=None):
        self.plan.write_text(
            json.dumps(
                dict(
                    schema_version="mutation-plan.v1",
                    baseline=baseline or self.baseline,
                    mutants=[dict(id=name, hook=hook) for name, hook in mutants],
                )
            ),
            encoding="utf-8",
        )

    def run_cli(self, *extra, output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = app.main(
                    [
                        "mutate",
                        "--plan",
                        str(self.plan),
                        "--corpus",
                        str(self.corpus),
                        "--output",
                        str(output or self.output),
                        "--hook-timeout",
                        "0.5",
                        *extra,
                    ]
                )
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def document(self):
        return json.loads((self.output / "mutation.json").read_bytes())

    def test_all_four_statuses_use_only_healthy_effect_differences(self):
        survivor = self.hook(
            "survivor",
            "print('different reason', file=sys.stderr)\n"
            "sys.exit(2 if 'synthetic-0' in command else 0)",
        )
        self.write_plan(
            [
                ("killed", self.hook("killed", "sys.exit(0)")),
                ("survived", survivor),
                ("invalid", self.hook("invalid", "sys.exit(1)")),
                ("timeout", self.hook("timeout", "time.sleep(5)")),
            ]
        )
        code, printed, _ = self.run_cli()
        self.assertEqual(code, 3)
        doc = self.document()
        self.assertEqual(
            doc["counts"], dict(killed=1, survived=1, invalid=1, timeout=1)
        )
        self.assertEqual(doc["score"], dict(numerator=1, denominator=2, rate=0.5))
        self.assertEqual(doc["baseline"]["status"], "healthy")
        self.assertEqual(doc["mutants"][0]["changed_event_ids"], ["synthetic-0"])
        self.assertFalse(self.sentinel.exists())
        self.assertIn("no corpus command was executed", printed)
        self.assertEqual(
            sorted(p.name for p in self.output.iterdir()),
            ["mutation.json", "mutation.md"],
        )
        self.assertFalse(
            any(p.name.startswith(".charter-mutation-") for p in self.root.iterdir())
        )

    def test_baseline_failure_skips_mutants_and_has_no_score(self):
        marker = self.root / "mutant-ran"
        self.write_plan(
            [("skipped", self.hook("skipped", f"Path({str(marker)!r}).touch()"))],
            baseline=self.hook("bad-baseline", "sys.exit(1)"),
        )
        self.assertEqual(self.run_cli()[0], 3)
        doc = self.document()
        self.assertEqual(doc["baseline"]["status"], "invalid")
        self.assertFalse(marker.exists())
        self.assertFalse(doc["mutants"][0]["executed"])
        self.assertEqual(doc["score"]["denominator"], 0)
        self.assertIsNone(doc["score"]["rate"])

    def test_baseline_effect_instability_skips_mutants(self):
        state = self.root / "state"
        body = (
            f"state = Path({str(state)!r})\n"
            "n = int(state.read_text()) if state.exists() else 0\n"
            "state.write_text(str(n+1))\nsys.exit(2 if n >= 2 else 0)"
        )
        self.write_plan([("mutant", self.baseline)], baseline=self.hook("flaky", body))
        self.assertEqual(self.run_cli()[0], 3)
        self.assertEqual(self.document()["baseline"]["status"], "unstable")
        self.assertFalse(self.document()["mutants"][0]["executed"])

    def test_valid_reports_are_byte_identical_and_survivors_exit_one(self):
        self.write_plan([("same", self.baseline)])
        self.assertEqual(self.run_cli()[0], 1)
        other = self.root / "second"
        self.assertEqual(self.run_cli(output=other)[0], 1)
        for name in ("mutation.json", "mutation.md"):
            self.assertEqual(
                (self.output / name).read_bytes(), (other / name).read_bytes()
            )
        text = (self.output / "mutation.json").read_text()
        for token in ("elapsed", str(self.root), "tool_input", "command", "reason"):
            self.assertNotIn(token, text)

    def test_all_killed_exit_zero(self):
        self.write_plan([("allow-all", self.hook("allow-all", "sys.exit(0)"))])
        self.assertEqual(self.run_cli()[0], 0)

    def test_invalid_last_hook_is_admitted_before_any_process(self):
        self.write_plan(
            [("good", self.baseline), ("missing", [sys.executable, "missing.py"])]
        )
        with forbid_process_launch():
            self.assertEqual(self.run_cli()[0], 2)
        self.assertFalse(self.output.exists())

    def test_budget_and_existing_destination_reject_before_launch(self):
        self.write_plan([("same", self.baseline)])
        with forbid_process_launch():
            self.assertEqual(self.run_cli("--max-invocations", "5")[0], 2)
            self.assertEqual(self.run_cli("--max-timeout-seconds", "2")[0], 2)
            self.output.mkdir()
            self.assertEqual(self.run_cli()[0], 2)

    def test_duplicate_plan_keys_reject_before_launch(self):
        self.write_plan([("same", self.baseline)])
        text = self.plan.read_text().replace(
            '"schema_version":', '"schema_version": "wrong", "schema_version":', 1
        )
        self.plan.write_text(text)
        with forbid_process_launch():
            self.assertEqual(self.run_cli()[0], 2)

    def test_failed_mutant_is_invalid_even_when_another_event_changes(self):
        self.write_plan(
            [
                (
                    "mixed",
                    self.hook(
                        "mixed", "sys.exit(0 if 'synthetic-0' in command else 1)"
                    ),
                )
            ]
        )
        self.assertEqual(self.run_cli()[0], 3)
        self.assertEqual(self.document()["counts"]["killed"], 0)
        self.assertEqual(self.document()["counts"]["invalid"], 1)

    def test_mutant_input_changed_by_baseline_is_not_executed(self):
        candidate = self.hook("candidate", "sys.exit(0)")
        baseline = self.hook(
            "changing-baseline",
            f"Path({candidate[1]!r}).write_text('import sys; sys.exit(0)')\nsys.exit(0)",
        )
        self.write_plan([("changed", candidate)], baseline=baseline)
        self.assertEqual(self.run_cli()[0], 3)
        doc = self.document()
        self.assertEqual(doc["counts"]["invalid"], 1)
        self.assertFalse(doc["mutants"][0]["executed"])

    def test_ordinary_plan_argument_does_not_resolve_against_cli_cwd(self):
        observed = self.root / "observed-argument"
        baseline = self.hook(
            "argument", f"Path({str(observed)!r}).write_text(sys.argv[-1])\nsys.exit(0)"
        )
        baseline.append("README.md")
        self.write_plan([("same", baseline)], baseline=baseline)
        self.assertEqual(self.run_cli()[0], 1)
        self.assertEqual(observed.read_text(), "README.md")
        from charter_replay import mutation

        admitted, _ = mutation.load_plan(
            str(self.plan),
            runtime="claude",
            timeout=0.5,
            ask_effect="deny",
            output_limit=1024,
        )
        self.assertEqual(admitted.descriptor["hook"]["argv"][-1]["kind"], "word")

    def test_total_hook_byte_budget_is_checked_before_hashing_inputs(self):
        from charter_replay import mutation, hook_context

        self.write_plan([("same", self.baseline)])
        with mock.patch.object(mutation, "MAX_HOOK_BYTES", 1):
            with mock.patch.object(
                hook_context,
                "_hash_file",
                side_effect=AssertionError("input read before budget admission"),
            ):
                with self.assertRaisesRegex(ValueError, "total byte limit"):
                    mutation.load_plan(
                        str(self.plan),
                        runtime="claude",
                        timeout=0.5,
                        ask_effect="deny",
                        output_limit=1024,
                    )

    def test_nested_corpus_json_is_refused_before_launch(self):
        self.write_plan([("same", self.baseline)])
        (self.corpus / "events.jsonl").write_text(
            "[" * 50000 + "0" + "]" * 50000 + "\n"
        )
        manifest = build_corpus_manifest(
            corpus_id="synthetic-mutation",
            event_count=2,
            base_directory=self.corpus,
            files=["events.jsonl", "cases.jsonl"],
        )
        (self.corpus / "corpus-manifest.json").write_bytes(
            manifest_json_bytes(manifest)
        )
        with forbid_process_launch():
            code, _, diagnostic = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("nested", diagnostic)
        self.assertFalse(self.output.exists())

    def test_bounded_fingerprint_refuses_growing_file(self):
        from charter_replay.hooks import hook_identity

        script = Path(self.baseline[1])
        with self.assertRaisesRegex(OSError, "byte limit"):
            hook_identity(self.baseline, max_file_bytes=script.stat().st_size - 1)

    def test_context_hashing_honors_evaluator_file_limit(self):
        from charter_replay import hook_context
        from charter_replay.hooks import HookSpec

        descriptor = hook_context.describe_hook_context(
            HookSpec(tuple(self.baseline)),
            workspace_template=None,
            jobs=1,
            max_file_bytes=1,
        )
        self.assertEqual(descriptor["hook"]["argv"][1]["status"], "unbound")
        self.assertEqual(descriptor["hook"]["argv"][1]["reason"], "limit-exceeded")

    def test_plan_relative_directory_is_refused_before_launch(self):
        (self.root / "synthetic-rules").mkdir()
        baseline = [*self.baseline, "synthetic-rules"]
        self.write_plan([("same", baseline)], baseline=baseline)
        with forbid_process_launch():
            code, _, diagnostic = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("directory arguments", diagnostic)

    def test_output_overflow_is_invalid_and_never_killed(self):
        self.write_plan([("overflow", self.hook("overflow", "print('x' * 10000)"))])
        self.assertEqual(self.run_cli("--hook-output-limit", "1024")[0], 3)
        doc = self.document()
        self.assertEqual(doc["counts"]["invalid"], 1)
        self.assertEqual(doc["counts"]["killed"], 0)
        # Each event runs a fresh process; another event can have an additional
        # source failure. Require real overflow evidence without assuming every
        # invocation fails in exactly the same way.
        self.assertIn("hook-output-limit", doc["mutants"][0]["failure_codes"])

    def test_overflow_and_stream_creation_failure_preserve_invalid_accounting(self):
        from charter_replay import hooks, policy_sources

        mutant = self.hook("overflow", "print('x' * 10000)")
        self.write_plan([("overflow", mutant)])
        real_runner = hooks._run_policy_process
        real_hook = hooks.run_hook
        mutant_invocations = 0
        first_outcome = None

        def observed_hook(spec, payload, *, workspace):
            nonlocal first_outcome
            outcome = real_hook(spec, payload, workspace=workspace)
            if tuple(spec.argv[1:]) == tuple(mutant[1:]) and first_outcome is None:
                detail = (
                    outcome.detail
                    if outcome.outcome in ("output-limit", "start-failed")
                    else "<detail omitted>"
                )
                first_outcome = (outcome.outcome, detail)
            return outcome

        def resource_limited_runner(argv, input_bytes, **options):
            nonlocal mutant_invocations
            if tuple(argv[1:]) == tuple(mutant[1:]):
                mutant_invocations += 1
                if mutant_invocations == 2:
                    # The first event really overflows; the second cannot create
                    # its streams. This does not identify the prior macOS cause.
                    with mock.patch.object(
                        policy_sources.tempfile,
                        "TemporaryFile",
                        side_effect=OSError(
                            errno.EMFILE,
                            "synthetic temporary-stream resource exhaustion",
                        ),
                    ):
                        return real_runner(argv, input_bytes, **options)
            return real_runner(argv, input_bytes, **options)

        with (
            mock.patch.object(
                hooks, "_run_policy_process", side_effect=resource_limited_runner
            ),
            mock.patch.object(hooks, "run_hook", side_effect=observed_hook),
        ):
            code, _, _ = self.run_cli("--hook-output-limit", "1024")

        doc = self.document()
        diagnostic = f"first mutant outcome: {first_outcome!r}"
        self.assertEqual(code, 3, diagnostic)
        self.assertEqual(doc["baseline"]["status"], "healthy", diagnostic)
        self.assertEqual(
            doc["counts"], dict(killed=0, survived=0, invalid=1, timeout=0), diagnostic
        )
        self.assertEqual(
            doc["mutants"][0]["failure_codes"],
            ["hook-output-limit", "hook-start-failed"],
            diagnostic,
        )
        self.assertEqual(doc["mutants"][0]["changed_event_ids"], [], diagnostic)
        self.assertEqual(
            doc["score"], dict(numerator=0, denominator=0, rate=None), diagnostic
        )
