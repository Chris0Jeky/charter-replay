from __future__ import annotations

from contextlib import contextmanager, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import charter_replay.policy_sources as policy_sources
from charter_replay.cli import (
    _load_charter_corpus,
    _load_process_source,
    _load_recorded_source,
    main,
)
from charter_replay.manifests import (
    build_corpus_manifest,
    build_run_manifest,
    load_corpus_manifest,
    manifest_json_bytes,
)
from charter_replay.policy_sources import PolicySourceResult, SourceFailure
from charter_replay.reports import _shell_reproduction_command

EVENTS = [
    {
        "schema_version": "command-event.v1",
        "event_id": "force-main",
        "timestamp": "2026-07-30T12:00:00Z",
        "command": "git push origin main --force",
        "source": "synthetic",
    },
    {
        "schema_version": "command-event.v1",
        "event_id": "status",
        "timestamp": "2026-07-30T12:01:00Z",
        "command": "git status --short",
        "source": "synthetic",
    },
]
CASES = [
    {
        "schema_version": "charter-case.v1",
        "event_id": "force-main",
        "case_class": "dangerous",
        "case_family": "shared-history-rewrite",
        "rationale": "A force push can rewrite shared history.",
        "provenance": "synthetic",
    },
    {
        "schema_version": "charter-case.v1",
        "event_id": "status",
        "case_class": "benign",
        "case_family": "read-only-git",
        "rationale": "Status reads repository state.",
        "provenance": "synthetic",
    },
]
BASELINE = [
    {
        "schema_version": "policy-decision.v1",
        "event_id": "force-main",
        "effect": "deny",
        "reason": "The fixture baseline denied a force push.",
    },
    {
        "schema_version": "policy-decision.v1",
        "event_id": "status",
        "effect": "allow",
        "reason": "The fixture baseline allowed status.",
    },
]


def jsonl_bytes(values) -> bytes:
    return "".join(
        f"{json.dumps(value, sort_keys=True, separators=(',', ':'))}\n"
        for value in values
    ).encode("utf-8")


class CliTests(unittest.TestCase):
    @contextmanager
    def fixture(self, mode: str):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            corpus = directory / "corpus"
            corpus.mkdir()
            (corpus / "events.jsonl").write_bytes(jsonl_bytes(EVENTS))
            (corpus / "cases.jsonl").write_bytes(jsonl_bytes(CASES))
            corpus_manifest = build_corpus_manifest(
                corpus_id="charter-v0.1",
                event_count=len(EVENTS),
                base_directory=corpus,
                files=["events.jsonl", "cases.jsonl"],
            )
            (corpus / "corpus-manifest.json").write_bytes(
                manifest_json_bytes(corpus_manifest)
            )

            recording = directory / "baseline.jsonl"
            decision_bytes = jsonl_bytes(BASELINE)
            recording.write_bytes(decision_bytes)
            sidecar = {
                "schema_version": "recorded-policy-manifest.v1",
                "policy_id": "floor-v1-final",
                "policy_commit": "0" * 40,
                "decisions_file": recording.name,
                "decisions_sha256": hashlib.sha256(decision_bytes).hexdigest(),
                "decision_count": len(BASELINE),
            }
            Path(f"{recording}.manifest.json").write_bytes(manifest_json_bytes(sidecar))

            policy_directory = directory / "policies"
            policy_directory.mkdir()
            candidate = policy_directory / f"candidate_{mode}.py"
            candidate.write_text(
                self.policy_script(mode), encoding="utf-8", newline="\n"
            )
            yield directory, corpus, recording, candidate

    @staticmethod
    def policy_script(mode: str) -> str:
        return f"""import json
import sys

events = [json.loads(line) for line in sys.stdin if line.strip()]
for index, event in enumerate(events):
    effect = "deny" if "--force" in event["command"] else "allow"
    if {mode!r} == "regression" and index == 0:
        effect = "allow"
    print(json.dumps({{
        "schema_version": "policy-decision.v1",
        "event_id": event["event_id"],
        "effect": effect,
        "reason": "Synthetic CLI candidate returned " + effect + ".",
    }}, sort_keys=True, separators=(",", ":")))
    if {mode!r} == "failure" and index == 0:
        raise SystemExit(9)
"""

    @staticmethod
    def replay_args(corpus: Path, recording: Path, candidate: Path, output: Path):
        return [
            "replay",
            "--baseline",
            f"recorded:{recording}",
            "--candidate",
            f"process:{sys.executable},{candidate}",
            "--corpus",
            str(corpus / "events.jsonl"),
            "--output",
            str(output),
        ]

    def test_exit_zero_writes_all_reports_for_a_clean_comparison(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            output = directory / "clean-report"
            with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "0"}):
                exit_code = main(self.replay_args(corpus, recording, candidate, output))
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(0, exit_code)
            self.assertEqual("pass", report["gate"]["status"])
            self.assertEqual("1970-01-01T00:00:00Z", report["generated_at"])
            self.assertEqual(2, report["counts"]["unchanged"])
            self.assertNotIn("reproduction_command", report)
            self.assertTrue((output / "report.md").is_file())
            self.assertTrue((output / "run-manifest.json").is_file())

    def test_exit_one_writes_reports_before_returning_regression(self) -> None:
        with self.fixture("regression") as (
            directory,
            corpus,
            recording,
            candidate,
        ):
            output = directory / "regression-report"
            exit_code = main(self.replay_args(corpus, recording, candidate, output))
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(1, exit_code)
            self.assertEqual("fail", report["gate"]["status"])
            self.assertEqual(["newly-allowed"], report["gate"]["triggered"])
            self.assertNotIn("reproduction_command", report)
            markdown = (output / "report.md").read_text(encoding="utf-8")
            self.assertIn("structured argv (portable source of truth)", markdown)
            self.assertIn(
                json.dumps([sys.executable, "-m", "charter_replay.cli"])[1:-1], markdown
            )
            expected_shell = (
                "Windows PowerShell rendering for this host:"
                if os.name == "nt"
                else "POSIX sh rendering for this host:"
            )
            self.assertIn(expected_shell, markdown)
            self.assertIn(str(output), markdown)
            self.assertTrue((output / "run-manifest.json").is_file())

    def test_host_reproduction_forms_preserve_the_proved_argv_subset(self) -> None:
        script = "import sys;print(chr(31).join(sys.argv[1:]))"
        if os.name == "nt":
            expected = [
                r"C:\Policy Lab\owner's report & 100% [proof]",
                "dollar$ caret^ bang! semi;",
            ]
            shell = "powershell"
            shell_argv = [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
            ]
        else:
            expected = [
                "/tmp/Policy Lab/owner's report & 100% [proof]",
                "dollar$ caret^ bang! semi;",
            ]
            shell = "posix-sh"
            shell_argv = ["/bin/sh", "-c"]
        argv = [sys.executable, "-c", script, *expected]
        direct = subprocess.run(argv, check=False, capture_output=True, text=True)
        self.assertEqual(0, direct.returncode, direct.stderr)
        self.assertEqual(chr(31).join(expected) + "\n", direct.stdout)

        command = _shell_reproduction_command(argv, shell)
        self.assertIsNotNone(command)
        rendered = subprocess.run(
            [*shell_argv, command], check=False, capture_output=True, text=True
        )
        self.assertEqual(0, rendered.returncode, rendered.stderr)
        self.assertEqual(chr(31).join(expected) + "\n", rendered.stdout)

    def test_exit_two_rejects_a_digest_mismatch_without_policy_execution(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            (corpus / "events.jsonl").write_bytes(b"changed\n")
            output = directory / "invalid-report"
            exit_code = main(self.replay_args(corpus, recording, candidate, output))
            self.assertEqual(2, exit_code)
            self.assertFalse(output.exists())

    def test_corpus_load_parses_the_exact_validated_bytes(self) -> None:
        with self.fixture("same") as (_, corpus, _recording, _candidate):
            replacement_events = [
                {**event, "command": f"replacement command {index}"}
                for index, event in enumerate(EVENTS)
            ]
            replacement_cases = [
                {**case, "rationale": f"Replacement rationale {index}."}
                for index, case in enumerate(CASES)
            ]
            begin_mutation = threading.Event()
            mutation_complete = threading.Event()

            def replace_corpus() -> None:
                begin_mutation.wait()
                (corpus / "events.jsonl").write_bytes(jsonl_bytes(replacement_events))
                (corpus / "cases.jsonl").write_bytes(jsonl_bytes(replacement_cases))
                mutation_complete.set()

            def load_then_replace(path):
                loaded = load_corpus_manifest(path)
                begin_mutation.set()
                self.assertTrue(mutation_complete.wait(timeout=5.0))
                return loaded

            writer = threading.Thread(target=replace_corpus)
            writer.start()
            with mock.patch(
                "charter_replay.cli.load_corpus_manifest",
                side_effect=load_then_replace,
            ):
                loaded = _load_charter_corpus(str(corpus))
            writer.join(timeout=5.0)

            self.assertFalse(writer.is_alive())
            self.assertEqual(EVENTS, loaded.events)
            self.assertEqual(CASES, loaded.cases)
            self.assertEqual(
                replacement_events,
                [
                    json.loads(line)
                    for line in (corpus / "events.jsonl")
                    .read_text(encoding="utf-8")
                    .splitlines()
                ],
            )
            self.assertEqual(
                replacement_cases,
                [
                    json.loads(line)
                    for line in (corpus / "cases.jsonl")
                    .read_text(encoding="utf-8")
                    .splitlines()
                ],
            )

    def test_recorded_load_evaluates_the_exact_validated_bytes(self) -> None:
        with self.fixture("same") as (_, _corpus, recording, _candidate):
            loaded = _load_recorded_source(str(recording))
            original_identity = dict(loaded.identity)
            replacement = [
                {**decision, "effect": "allow" if index == 0 else "deny"}
                for index, decision in enumerate(BASELINE)
            ]
            replacement_bytes = jsonl_bytes(replacement)
            recording.write_bytes(replacement_bytes)
            manifest_path = Path(f"{recording}.manifest.json")
            replacement_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            replacement_manifest["policy_id"] = "replacement-policy"
            replacement_manifest["policy_commit"] = "f" * 40
            replacement_manifest["decisions_sha256"] = hashlib.sha256(
                replacement_bytes
            ).hexdigest()
            replacement_manifest_bytes = manifest_json_bytes(replacement_manifest)
            manifest_path.write_bytes(replacement_manifest_bytes)

            result = loaded.source.evaluate(EVENTS)

        self.assertEqual(["deny", "allow"], [row["effect"] for row in result.decisions])
        self.assertTrue(result.is_valid)
        self.assertEqual(original_identity, loaded.identity)
        self.assertNotEqual(
            original_identity["sha256"],
            hashlib.sha256(replacement_manifest_bytes).hexdigest(),
        )

    def test_exit_two_rejects_an_empty_corpus_before_loading_policies(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            (corpus / "events.jsonl").write_bytes(b"")
            (corpus / "cases.jsonl").write_bytes(b"")
            empty_sha256 = hashlib.sha256(b"").hexdigest()
            manifest = {
                "schema_version": "corpus-manifest.v1",
                "corpus_id": "empty-v0",
                "event_count": 0,
                "files": [
                    {"path": "events.jsonl", "sha256": empty_sha256},
                    {"path": "cases.jsonl", "sha256": empty_sha256},
                ],
            }
            (corpus / "corpus-manifest.json").write_bytes(manifest_json_bytes(manifest))
            output = directory / "empty-report"
            with mock.patch(
                "charter_replay.cli._load_policy_source",
                side_effect=AssertionError("policy source loaded"),
            ) as load_policy:
                exit_code = main(self.replay_args(corpus, recording, candidate, output))

            self.assertEqual(2, exit_code)
            load_policy.assert_not_called()
            self.assertFalse(output.exists())

    def test_exit_two_rejects_empty_records_under_a_positive_manifest(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            (corpus / "events.jsonl").write_bytes(b"")
            (corpus / "cases.jsonl").write_bytes(b"")
            empty_sha256 = hashlib.sha256(b"").hexdigest()
            manifest = {
                "schema_version": "corpus-manifest.v1",
                "corpus_id": "truncated-v0",
                "event_count": 1,
                "files": [
                    {"path": "events.jsonl", "sha256": empty_sha256},
                    {"path": "cases.jsonl", "sha256": empty_sha256},
                ],
            }
            (corpus / "corpus-manifest.json").write_bytes(manifest_json_bytes(manifest))
            output = directory / "truncated-report"
            with mock.patch(
                "charter_replay.cli._load_policy_source",
                side_effect=AssertionError("policy source loaded"),
            ) as load_policy:
                exit_code = main(self.replay_args(corpus, recording, candidate, output))

            self.assertEqual(2, exit_code)
            load_policy.assert_not_called()
            self.assertFalse(output.exists())

    def test_invalid_recording_is_rejected_before_process_execution(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            invalid = [{**BASELINE[0], "effect": "warn"}, BASELINE[1]]
            decision_bytes = jsonl_bytes(invalid)
            recording.write_bytes(decision_bytes)
            sidecar_path = Path(f"{recording}.manifest.json")
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            sidecar["decisions_sha256"] = hashlib.sha256(decision_bytes).hexdigest()
            sidecar_path.write_bytes(manifest_json_bytes(sidecar))
            output = directory / "invalid-recording-report"
            with mock.patch(
                "charter_replay.cli.ProcessDecisionSource.evaluate",
                side_effect=AssertionError("process policy executed"),
            ):
                exit_code = main(self.replay_args(corpus, recording, candidate, output))
            self.assertEqual(2, exit_code)
            self.assertFalse(output.exists())

    def test_exit_three_writes_reports_for_process_failure(self) -> None:
        with self.fixture("failure") as (
            directory,
            corpus,
            recording,
            candidate,
        ):
            output = directory / "failure-report"
            exit_code = main(self.replay_args(corpus, recording, candidate, output))
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(3, exit_code)
            self.assertEqual("error", report["gate"]["status"])
            self.assertEqual(
                ["process-exit-nonzero", "process-missing-event"],
                [failure["code"] for failure in report["source_failures"]["candidate"]],
            )
            self.assertTrue((output / "report.md").is_file())
            self.assertTrue((output / "run-manifest.json").is_file())

    def test_output_publication_failure_restores_the_previous_report_set(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            output = directory / "existing-report"
            output.mkdir()
            previous = {
                "run-manifest.json": b'{"old":"manifest"}\n',
                "report.json": b'{"old":"report"}\n',
                "report.md": b"old report\n",
            }
            for name, content in previous.items():
                (output / name).write_bytes(content)

            original_replace = Path.replace

            def reject_locked_report(path, target):
                if path == output / "report.json":
                    raise PermissionError("synthetic locked report")
                return original_replace(path, target)

            stderr = io.StringIO()
            with (
                mock.patch.object(
                    Path, "replace", autospec=True, side_effect=reject_locked_report
                ),
                redirect_stderr(stderr),
            ):
                exit_code = main(self.replay_args(corpus, recording, candidate, output))

            self.assertEqual(3, exit_code)
            self.assertIn("replay output failed", stderr.getvalue())
            self.assertEqual(
                previous,
                {name: (output / name).read_bytes() for name in previous},
            )
            self.assertFalse(list(directory.glob(".replay-output-*")))

    def test_timeout_changes_process_identity_and_run_id(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            normal_output = directory / "normal-report"
            normal_exit = main(
                self.replay_args(corpus, recording, candidate, normal_output)
            )
            timeout_output = directory / "timeout-report"
            timeout_args = self.replay_args(
                corpus, recording, candidate, timeout_output
            )
            timeout_args.extend(["--timeout", "0.000001"])
            timeout_exit = main(timeout_args)

            normal_report = json.loads(
                (normal_output / "report.json").read_text(encoding="utf-8")
            )
            timeout_report = json.loads(
                (timeout_output / "report.json").read_text(encoding="utf-8")
            )

        self.assertEqual(0, normal_exit)
        self.assertEqual(3, timeout_exit)
        self.assertEqual("pass", normal_report["gate"]["status"])
        self.assertEqual("error", timeout_report["gate"]["status"])
        self.assertNotEqual(normal_report["run_id"], timeout_report["run_id"])

    def test_fail_on_accepts_only_the_three_supported_classes(self) -> None:
        with self.fixture("same") as (directory, corpus, recording, candidate):
            args = self.replay_args(corpus, recording, candidate, directory / "report")
            args.extend(["--fail-on", "resolved-indeterminate"])
            with self.assertRaises(SystemExit) as raised:
                main(args)
            self.assertEqual(2, raised.exception.code)

    def test_process_executable_and_invocation_are_bound_without_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "candidate.py"
            policy.write_text("pass\n", encoding="utf-8", newline="\n")
            first_executable = directory / "first.exe"
            second_executable = directory / "second.exe"
            first_executable.write_bytes(b"first synthetic executable")
            second_executable.write_bytes(b"second synthetic executable")
            first = _load_process_source(f"{first_executable},{policy}", 1.0)
            second = _load_process_source(f"{second_executable},{policy}", 1.0)
            with_flag = _load_process_source(
                f"{first_executable},--isolated,{policy}", 1.0
            )
            with_longer_timeout = _load_process_source(
                f"{first_executable},{policy}", 2.0
            )

        self.assertNotEqual(first.identity["sha256"], second.identity["sha256"])
        self.assertNotEqual(first.identity["sha256"], with_flag.identity["sha256"])
        self.assertNotEqual(
            first.identity["sha256"], with_longer_timeout.identity["sha256"]
        )
        self.assertEqual({"kind", "id", "sha256"}, set(first.identity))
        self.assertNotIn(raw_directory, json.dumps(first.identity))

        common = {
            "generated_at": "2026-07-30T12:00:00Z",
            "baseline": {
                "kind": "recorded",
                "id": "baseline",
                "sha256": "1" * 64,
            },
            "corpus": {
                "id": "charter-v0.1",
                "manifest_sha256": "2" * 64,
                "event_count": 1,
            },
            "fail_on": ["newly-allowed"],
        }
        first_manifest = build_run_manifest(candidate=first.identity, **common)
        second_manifest = build_run_manifest(candidate=second.identity, **common)
        longer_timeout_manifest = build_run_manifest(
            candidate=with_longer_timeout.identity, **common
        )
        self.assertNotEqual(first_manifest["run_id"], second_manifest["run_id"])
        self.assertNotEqual(first_manifest["run_id"], longer_timeout_manifest["run_id"])

    def test_process_snapshot_parent_changes_identity_and_run_id_without_disclosure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            first_parent = directory / "first-snapshots"
            second_parent = directory / "second-snapshots"
            policy.write_text("pass\n", encoding="utf-8", newline="\n")
            first_parent.mkdir()
            second_parent.mkdir()

            with mock.patch(
                "charter_replay.cli.tempfile.gettempdir", return_value=str(first_parent)
            ):
                first = _load_process_source(f"{sys.executable},{policy}", 5.0)
            with mock.patch(
                "charter_replay.cli.tempfile.gettempdir",
                return_value=str(second_parent),
            ):
                second = _load_process_source(f"{sys.executable},{policy}", 5.0)

            common = {
                "generated_at": "2026-07-30T12:00:00Z",
                "baseline": {
                    "kind": "recorded",
                    "id": "baseline",
                    "sha256": "1" * 64,
                },
                "corpus": {
                    "id": "charter-v0.1",
                    "manifest_sha256": "2" * 64,
                    "event_count": len(EVENTS),
                },
                "fail_on": ["newly-allowed"],
            }
            first_manifest = build_run_manifest(candidate=first.identity, **common)
            second_manifest = build_run_manifest(candidate=second.identity, **common)
            serialized = json.dumps(
                [first.identity, second.identity, first_manifest, second_manifest]
            )

        self.assertEqual(first_parent.resolve(), first.source.snapshot_parent)
        self.assertEqual(second_parent.resolve(), second.source.snapshot_parent)
        self.assertNotEqual(first.identity, second.identity)
        self.assertNotEqual(first_manifest["run_id"], second_manifest["run_id"])
        self.assertNotIn(str(first_parent), serialized)
        self.assertNotIn(str(second_parent), serialized)

    def test_process_executable_alias_name_is_bound_before_target_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            alias = directory / (
                "policy-alias.exe" if os.name == "nt" else "policy-alias"
            )
            alias.write_bytes(b"lexical alias placeholder\n")
            policy = directory / "policy.py"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            target = Path(sys.executable).resolve()
            original_resolve = Path.resolve

            def redirected_resolve(path, *args, **kwargs):
                if path == alias:
                    return target
                return original_resolve(path, *args, **kwargs)

            def resolved_command(command):
                return str(alias if command == "policy-alias" else target)

            with (
                mock.patch(
                    "charter_replay.cli.shutil.which", side_effect=resolved_command
                ),
                mock.patch.object(
                    Path, "resolve", autospec=True, side_effect=redirected_resolve
                ),
            ):
                alias_source = _load_process_source(f"policy-alias,{policy}", 5.0)
                target_source = _load_process_source(f"{target},{policy}", 5.0)

            with mock.patch(
                "charter_replay.policy_sources._run_policy_process",
                wraps=policy_sources._run_policy_process,
            ) as process_run:
                result = alias_source.source.evaluate(EVENTS)

        self.assertEqual((), result.failures)
        self.assertNotEqual(alias_source.identity, target_source.identity)
        self.assertEqual(alias.name, Path(process_run.call_args.args[0][0]).name)
        self.assertEqual(target, alias_source.source.executable_binding[0])

    def test_python_and_python3_resolve_to_their_requested_path_targets(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            python_target = directory / (
                "python-target.exe" if os.name == "nt" else "python-target"
            )
            python3_target = directory / (
                "python3-target.exe" if os.name == "nt" else "python3-target"
            )
            python_target.write_bytes(b"synthetic python executable\n")
            python3_target.write_bytes(b"different synthetic python3 executable\n")
            policy = directory / "policy.py"
            policy.write_text("pass\n", encoding="utf-8", newline="\n")
            resolved = {
                "python": str(python_target),
                "python3": str(python3_target),
            }

            with mock.patch(
                "charter_replay.cli.shutil.which", side_effect=resolved.__getitem__
            ):
                python_source = _load_process_source(f"python,{policy}", 5.0)
                python3_source = _load_process_source(f"python3,{policy}", 5.0)

        self.assertEqual(
            python_target.resolve(), python_source.source.executable_binding[0]
        )
        self.assertEqual(
            python3_target.resolve(), python3_source.source.executable_binding[0]
        )
        self.assertNotEqual(python_source.identity, python3_source.identity)

    @unittest.skipIf(os.name == "nt", "POSIX executable symlink semantics")
    def test_process_executable_symlink_keeps_direct_invocation_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            executable_directory = directory / "bin"
            policy_directory = directory / "policy"
            executable_directory.mkdir()
            policy_directory.mkdir()
            target = executable_directory / "target-policy"
            alias = executable_directory / "alias-policy"
            target.write_text(
                f"#!{sys.executable}\n"
                "import json\n"
                "from pathlib import Path\n"
                "import sys\n"
                "effect = 'allow' if Path(sys.argv[0]).name == 'alias-policy' else 'deny'\n"
                "for event in map(json.loads, sys.stdin):\n"
                "    print(json.dumps({'schema_version': 'policy-decision.v1', "
                "'event_id': event['event_id'], 'effect': effect, "
                "'reason': Path(sys.argv[0]).name}))\n",
                encoding="utf-8",
                newline="\n",
            )
            os.chmod(target, 0o755)
            alias.symlink_to(target)
            policy = policy_directory / "policy.txt"
            policy.write_text("bound policy\n", encoding="utf-8", newline="\n")
            input_bytes = "".join(
                f"{json.dumps(event, sort_keys=True, separators=(',', ':'))}\n"
                for event in EVENTS
            ).encode("utf-8")

            direct_alias = subprocess.run(
                [str(alias), str(policy)],
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            direct_target = subprocess.run(
                [str(target), str(policy)],
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            alias_source = _load_process_source(f"{alias},{policy}", 5.0)
            target_source = _load_process_source(f"{target},{policy}", 5.0)
            replay_alias = alias_source.source.evaluate(EVENTS)
            replay_target = target_source.source.evaluate(EVENTS)

        self.assertIn(b'"effect": "allow"', direct_alias.stdout)
        self.assertIn(b'"effect": "deny"', direct_target.stdout)
        self.assertEqual(
            ["allow", "allow"], [row["effect"] for row in replay_alias.decisions]
        )
        self.assertEqual(
            ["deny", "deny"], [row["effect"] for row in replay_target.decisions]
        )
        self.assertNotEqual(alias_source.identity, target_source.identity)

    def test_process_policy_parent_tree_changes_identity_and_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "rules.py"
            policy.write_text(
                "import json\n"
                "import sys\n"
                "from rules import EFFECT\n"
                "for event in map(json.loads, sys.stdin):\n"
                '    print(json.dumps({"schema_version": "policy-decision.v1", '
                '"event_id": event["event_id"], "effect": EFFECT, '
                '"reason": "Sibling rule."}))\n',
                encoding="utf-8",
                newline="\n",
            )
            helper.write_text('EFFECT = "deny"\n', encoding="utf-8", newline="\n")
            denied = _load_process_source(f"{sys.executable},{policy}", 5.0)
            denied_result = denied.source.evaluate(EVENTS)

            helper.write_text('EFFECT = "allow"\n', encoding="utf-8", newline="\n")
            allowed = _load_process_source(f"{sys.executable},{policy}", 5.0)
            allowed_result = allowed.source.evaluate(EVENTS)

        self.assertEqual(
            ["deny", "deny"], [row["effect"] for row in denied_result.decisions]
        )
        self.assertEqual(
            ["allow", "allow"], [row["effect"] for row in allowed_result.decisions]
        )
        self.assertNotEqual(denied.identity["sha256"], allowed.identity["sha256"])

        common = {
            "generated_at": "2026-07-30T12:00:00Z",
            "baseline": {
                "kind": "recorded",
                "id": "baseline",
                "sha256": "1" * 64,
            },
            "corpus": {
                "id": "charter-v0.1",
                "manifest_sha256": "2" * 64,
                "event_count": len(EVENTS),
            },
            "fail_on": ["newly-allowed"],
        }
        denied_manifest = build_run_manifest(candidate=denied.identity, **common)
        allowed_manifest = build_run_manifest(candidate=allowed.identity, **common)
        self.assertNotEqual(denied_manifest["run_id"], allowed_manifest["run_id"])

    def test_process_policy_permissions_bind_behavior_and_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            probe = directory / "mode-probe"
            policy.write_text(
                "import json\n"
                "import os\n"
                "import stat\n"
                "import sys\n"
                "effect = 'allow' if os.stat('mode-probe').st_mode & stat.S_IWUSR else 'deny'\n"
                "for event in map(json.loads, sys.stdin):\n"
                '    print(json.dumps({"schema_version": "policy-decision.v1", '
                '"event_id": event["event_id"], "effect": effect, '
                '"reason": "Preserved permission probe."}))\n',
                encoding="utf-8",
                newline="\n",
            )
            probe.write_bytes(b"same bytes\n")
            os.chmod(probe, 0o666)
            writable = _load_process_source(f"{sys.executable},{policy}", 5.0)
            writable_result = writable.source.evaluate(EVENTS)

            os.chmod(probe, 0o444)
            read_only = _load_process_source(f"{sys.executable},{policy}", 5.0)
            read_only_result = read_only.source.evaluate(EVENTS)

        self.assertEqual(
            ["allow", "allow"],
            [decision["effect"] for decision in writable_result.decisions],
        )
        self.assertEqual(
            ["deny", "deny"],
            [decision["effect"] for decision in read_only_result.decisions],
        )
        self.assertEqual((), writable_result.failures)
        self.assertEqual((), read_only_result.failures)
        self.assertNotEqual(writable.identity["sha256"], read_only.identity["sha256"])
        common = {
            "generated_at": "2026-07-30T12:00:00Z",
            "baseline": {
                "kind": "recorded",
                "id": "baseline",
                "sha256": "1" * 64,
            },
            "corpus": {
                "id": "charter-v0.1",
                "manifest_sha256": "2" * 64,
                "event_count": len(EVENTS),
            },
            "fail_on": ["newly-allowed"],
        }
        writable_manifest = build_run_manifest(candidate=writable.identity, **common)
        read_only_manifest = build_run_manifest(candidate=read_only.identity, **common)
        self.assertNotEqual(writable_manifest["run_id"], read_only_manifest["run_id"])

    @unittest.skipIf(os.name == "nt", "Windows has no portable POSIX execute bits")
    def test_process_helper_executable_bits_change_identity_and_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "helper"
            policy.write_text("pass\n", encoding="utf-8", newline="\n")
            helper.write_bytes(b"#!/bin/sh\nexit 0\n")
            os.chmod(helper, 0o644)
            non_executable = _load_process_source(f"{sys.executable},{policy}", 5.0)

            os.chmod(helper, 0o755)
            executable = _load_process_source(f"{sys.executable},{policy}", 5.0)

        self.assertNotEqual(
            non_executable.identity["sha256"], executable.identity["sha256"]
        )
        common = {
            "generated_at": "2026-07-30T12:00:00Z",
            "baseline": {
                "kind": "recorded",
                "id": "baseline",
                "sha256": "1" * 64,
            },
            "corpus": {
                "id": "charter-v0.1",
                "manifest_sha256": "2" * 64,
                "event_count": len(EVENTS),
            },
            "fail_on": ["newly-allowed"],
        }
        non_executable_manifest = build_run_manifest(
            candidate=non_executable.identity, **common
        )
        executable_manifest = build_run_manifest(
            candidate=executable.identity, **common
        )
        self.assertNotEqual(
            non_executable_manifest["run_id"], executable_manifest["run_id"]
        )

    def test_process_executable_permissions_change_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            executable_directory = directory / "bin"
            policy_directory = directory / "policy"
            executable_directory.mkdir()
            policy_directory.mkdir()
            executable = executable_directory / (
                "python-copy.exe" if os.name == "nt" else "python-copy"
            )
            policy = policy_directory / "policy.py"
            shutil.copy2(sys.executable, executable)
            policy.write_text("pass\n", encoding="utf-8", newline="\n")
            os.chmod(executable, 0o755)
            writable_identity = _load_process_source(
                f"{executable},{policy}", 5.0
            ).identity

            os.chmod(executable, 0o555)
            read_only_identity = _load_process_source(
                f"{executable},{policy}", 5.0
            ).identity

        self.assertNotEqual(writable_identity["sha256"], read_only_identity["sha256"])

    def test_process_helper_permissions_are_revalidated_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "helper"
            policy.write_text("pass\n", encoding="utf-8", newline="\n")
            helper.write_bytes(b"#!/bin/sh\nexit 0\n")
            os.chmod(helper, 0o666)
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)

            os.chmod(helper, 0o444)
            with mock.patch(
                "charter_replay.policy_sources._run_policy_process"
            ) as process_run:
                result = loaded.source.evaluate(EVENTS)

        process_run.assert_not_called()
        self.assertEqual(
            ["process-input-changed"],
            [failure.code for failure in result.failures],
        )
        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )

    def test_process_policy_tree_is_revalidated_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "rules.py"
            policy.write_text(
                "import json\n"
                "import sys\n"
                "from rules import EFFECT\n"
                "for event in map(json.loads, sys.stdin):\n"
                '    print(json.dumps({"schema_version": "policy-decision.v1", '
                '"event_id": event["event_id"], "effect": EFFECT, '
                '"reason": "Sibling rule."}))\n',
                encoding="utf-8",
                newline="\n",
            )
            helper.write_text('EFFECT = "deny"\n', encoding="utf-8", newline="\n")
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)

            helper.write_text('EFFECT = "allow"\n', encoding="utf-8", newline="\n")
            result = loaded.source.evaluate(EVENTS)

        self.assertEqual(
            ["process-input-changed"],
            [failure.code for failure in result.failures],
        )
        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )

    def test_process_snapshot_runs_bound_inputs_after_original_tree_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "rules.py"
            policy.write_text(
                "import json\n"
                "import sys\n"
                "from rules import EFFECT\n"
                "for event in map(json.loads, sys.stdin):\n"
                '    print(json.dumps({"schema_version": "policy-decision.v1", '
                '"event_id": event["event_id"], "effect": EFFECT, '
                '"reason": "Snapshotted sibling rule."}))\n',
                encoding="utf-8",
                newline="\n",
            )
            helper.write_text('EFFECT = "deny"\n', encoding="utf-8", newline="\n")
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            original_prepare = loaded.source._prepare_input_snapshot
            original_evaluate = loaded.source._evaluate_runtime
            snapshot_roots: list[Path] = []
            begin_mutation = threading.Event()
            mutation_complete = threading.Event()

            def remember_snapshot(events):
                snapshot = original_prepare(events)
                self.assertIsNotNone(snapshot)
                self.assertNotIsInstance(snapshot, PolicySourceResult)
                snapshot_roots.append(snapshot.root)
                return snapshot

            def mutate_original() -> None:
                begin_mutation.wait()
                helper.write_text('EFFECT = "allow"\n', encoding="utf-8", newline="\n")
                mutation_complete.set()

            def mutate_before_real_launch(events, *, argv, cwd):
                begin_mutation.set()
                self.assertTrue(mutation_complete.wait(timeout=5.0))
                return original_evaluate(events, argv=argv, cwd=cwd)

            writer = threading.Thread(target=mutate_original)
            writer.start()

            with (
                mock.patch.object(
                    loaded.source,
                    "_prepare_input_snapshot",
                    side_effect=remember_snapshot,
                ),
                mock.patch.object(
                    loaded.source,
                    "_evaluate_runtime",
                    side_effect=mutate_before_real_launch,
                ),
                mock.patch(
                    "charter_replay.policy_sources._run_policy_process",
                    wraps=policy_sources._run_policy_process,
                ) as process_run,
            ):
                result = loaded.source.evaluate(EVENTS)
            writer.join(timeout=5.0)
            self.assertFalse(writer.is_alive())

            launched_argv = process_run.call_args.args[0]
            launched_cwd = Path(process_run.call_args.kwargs["cwd"])

        self.assertEqual(
            ["deny", "deny"], [decision["effect"] for decision in result.decisions]
        )
        self.assertEqual(1, len(snapshot_roots))
        self.assertEqual(
            snapshot_roots[0] / "executable" / loaded.source.executable_binding[1],
            Path(launched_argv[0]),
        )
        self.assertEqual(snapshot_roots[0] / "policy", launched_cwd)
        self.assertNotEqual(Path(sys.executable), Path(launched_argv[0]))
        self.assertFalse(snapshot_roots[0].exists())
        self.assertNotIn(str(snapshot_roots[0]), json.dumps(loaded.identity))
        self.assertNotIn(str(snapshot_roots[0]), json.dumps(result.diagnostics))
        self.assertNotIn(
            str(snapshot_roots[0]), json.dumps(result.failures, default=str)
        )

    def test_process_snapshot_paths_are_stable_for_one_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy_directory = directory / "source"
            snapshot_parent = directory / "snapshots"
            changed_parent = directory / "changed-snapshots"
            policy_directory.mkdir()
            snapshot_parent.mkdir()
            changed_parent.mkdir()
            policy = policy_directory / "policy.py"
            policy.write_text(
                "import hashlib\n"
                "import json\n"
                "import os\n"
                "import sys\n"
                "visible = '|'.join((os.getcwd(), sys.argv[0], __file__))\n"
                "effect = ('allow' if hashlib.sha256(visible.encode('utf-8')).digest()[0] & 1 "
                "else 'deny')\n"
                "for event in map(json.loads, sys.stdin):\n"
                "    print(json.dumps({'schema_version': 'policy-decision.v1', "
                "'event_id': event['event_id'], 'effect': effect, 'reason': visible}))\n",
                encoding="utf-8",
                newline="\n",
            )
            with mock.patch(
                "charter_replay.cli.tempfile.gettempdir",
                return_value=str(snapshot_parent),
            ):
                first_source = _load_process_source(f"{sys.executable},{policy}", 5.0)
                second_source = _load_process_source(f"{sys.executable},{policy}", 5.0)
            snapshot_root = snapshot_parent / (
                f"replay-process-inputs-{first_source.identity['sha256']}"
            )

            with mock.patch(
                "charter_replay.policy_sources.tempfile.gettempdir",
                return_value=str(changed_parent),
            ):
                first = first_source.source.evaluate(EVENTS)
                self.assertFalse(snapshot_root.exists())
                second = second_source.source.evaluate(EVENTS)

        self.assertEqual(first_source.identity, second_source.identity)
        self.assertEqual((), first.failures)
        self.assertEqual((), second.failures)
        self.assertEqual(first.decisions, second.decisions)
        visible_cwd_raw, visible_argv0, visible_file_raw = first.decisions[0][
            "reason"
        ].split("|")
        visible_cwd = Path(visible_cwd_raw)
        visible_file = Path(visible_file_raw)
        self.assertEqual("policy", visible_cwd.name)
        self.assertEqual(snapshot_root.name, visible_cwd.parent.name)
        self.assertEqual(snapshot_parent.name, visible_cwd.parent.parent.name)
        self.assertEqual("policy.py", visible_argv0)
        self.assertEqual(visible_cwd / "policy.py", visible_file)
        self.assertNotIn(changed_parent.name, first.decisions[0]["reason"])
        self.assertFalse(snapshot_root.exists())

    def test_process_snapshot_parent_disappearance_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            snapshot_parent = directory / "snapshots"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            snapshot_parent.mkdir()
            with mock.patch(
                "charter_replay.cli.tempfile.gettempdir",
                return_value=str(snapshot_parent),
            ):
                loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            snapshot_parent.rmdir()

            with mock.patch(
                "charter_replay.policy_sources._run_policy_process"
            ) as process_run:
                result = loaded.source.evaluate(EVENTS)

        process_run.assert_not_called()
        self.assertEqual(
            ["process-snapshot-unavailable"],
            [failure.code for failure in result.failures],
        )
        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )

    def test_process_snapshot_normalizes_policy_and_runner_mtimes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy_directory = directory / "source"
            snapshot_parent = directory / "snapshots"
            policy_directory.mkdir()
            snapshot_parent.mkdir()
            policy = policy_directory / "policy.py"
            helper = policy_directory / "helper.txt"
            expected = policy_sources.SNAPSHOT_MTIME_NS
            policy.write_text(
                "import json\n"
                "from pathlib import Path\n"
                "import sys\n"
                f"expected = {expected}\n"
                "paths = (Path(__file__), Path('helper.txt'), Path.cwd(), "
                "Path(sys.executable), Path(sys.executable).parent, Path.cwd().parent)\n"
                "observed = [path.stat().st_mtime_ns for path in paths]\n"
                "effect = 'allow' if all(value == expected for value in observed) else 'deny'\n"
                "for event in map(json.loads, sys.stdin):\n"
                "    print(json.dumps({'schema_version': 'policy-decision.v1', "
                "'event_id': event['event_id'], 'effect': effect, "
                "'reason': ','.join(map(str, observed))}))\n",
                encoding="utf-8",
                newline="\n",
            )
            helper.write_bytes(b"same helper bytes\n")

            outcomes = []
            source_mtimes = (expected, expected + 2_000_000_000)
            for source_mtime in source_mtimes:
                for path in (policy, helper, policy_directory):
                    metadata = path.stat()
                    os.utime(path, ns=(metadata.st_atime_ns, source_mtime))
                with mock.patch(
                    "charter_replay.cli.tempfile.gettempdir",
                    return_value=str(snapshot_parent),
                ):
                    loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
                result = loaded.source.evaluate(EVENTS)
                outcomes.append((loaded, result))
                self.assertEqual(source_mtime, policy.stat().st_mtime_ns)
                self.assertEqual(source_mtime, helper.stat().st_mtime_ns)
                self.assertEqual(source_mtime, policy_directory.stat().st_mtime_ns)

            common = {
                "generated_at": "2026-07-30T12:00:00Z",
                "baseline": {
                    "kind": "recorded",
                    "id": "baseline",
                    "sha256": "1" * 64,
                },
                "corpus": {
                    "id": "charter-v0.1",
                    "manifest_sha256": "2" * 64,
                    "event_count": len(EVENTS),
                },
                "fail_on": ["newly-allowed"],
            }
            manifests = [
                build_run_manifest(candidate=loaded.identity, **common)
                for loaded, _result in outcomes
            ]

        self.assertEqual(outcomes[0][0].identity, outcomes[1][0].identity)
        self.assertEqual(manifests[0]["run_id"], manifests[1]["run_id"])
        for _loaded, result in outcomes:
            self.assertEqual((), result.failures)
            self.assertEqual(
                ["allow", "allow"],
                [decision["effect"] for decision in result.decisions],
            )
            self.assertEqual(
                [str(expected)] * 6,
                result.decisions[0]["reason"].split(","),
            )

    def test_process_snapshot_mtime_normalization_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            snapshot_root = loaded.source.snapshot_parent / (
                f"replay-process-inputs-{loaded.identity['sha256']}"
            )

            with (
                mock.patch(
                    "charter_replay.policy_sources._normalize_snapshot_mtimes",
                    side_effect=OSError("synthetic normalization failure"),
                ),
                mock.patch(
                    "charter_replay.policy_sources._run_policy_process"
                ) as process_run,
            ):
                result = loaded.source.evaluate(EVENTS)

        process_run.assert_not_called()
        self.assertFalse(snapshot_root.exists())
        self.assertEqual(
            ["process-snapshot-unavailable"],
            [failure.code for failure in result.failures],
        )
        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )

    @unittest.skipIf(os.name == "nt", "POSIX umask controls directory modes")
    def test_process_snapshot_runner_directory_modes_ignore_umask(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            policy.write_text(
                "import json\n"
                "from pathlib import Path\n"
                "import stat\n"
                "import sys\n"
                "executable_dir = Path(sys.executable).parent\n"
                "visible = ':'.join(f'{stat.S_IMODE(path.stat().st_mode):04o}' "
                "for path in (executable_dir.parent, executable_dir))\n"
                "for event in map(json.loads, sys.stdin):\n"
                "    print(json.dumps({'schema_version': 'policy-decision.v1', "
                "'event_id': event['event_id'], 'effect': 'deny', 'reason': visible}))\n",
                encoding="utf-8",
                newline="\n",
            )

            outcomes = []
            for mask in (0o022, 0o077):
                previous = os.umask(mask)
                try:
                    loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
                    result = loaded.source.evaluate(EVENTS)
                finally:
                    os.umask(previous)
                outcomes.append((loaded.identity, result))

        self.assertEqual(outcomes[0][0], outcomes[1][0])
        self.assertEqual(outcomes[0][1].decisions, outcomes[1][1].decisions)
        self.assertEqual((), outcomes[0][1].failures)
        self.assertEqual((), outcomes[1][1].failures)
        self.assertEqual("0700:0700", outcomes[0][1].decisions[0]["reason"])

    def test_process_snapshot_rejects_overlap_with_bound_policy_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            policy_directory = Path(raw_directory)
            policy = policy_directory / "policy.py"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            with mock.patch(
                "charter_replay.cli.tempfile.gettempdir",
                return_value=str(policy_directory),
            ):
                loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            snapshot_root = policy_directory / (
                f"replay-process-inputs-{loaded.identity['sha256']}"
            )

            with (
                mock.patch("charter_replay.policy_sources.shutil.copytree") as copytree,
                mock.patch(
                    "charter_replay.policy_sources._run_policy_process"
                ) as process_run,
            ):
                result = loaded.source.evaluate(EVENTS)

        copytree.assert_not_called()
        process_run.assert_not_called()
        self.assertFalse(snapshot_root.exists())
        self.assertEqual(
            ["process-snapshot-overlaps-input"],
            [failure.code for failure in result.failures],
        )
        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )

    def test_process_snapshot_does_not_reuse_an_existing_identity_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy_directory = directory / "source"
            snapshot_parent = directory / "snapshots"
            policy_directory.mkdir()
            snapshot_parent.mkdir()
            policy = policy_directory / "policy.py"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            with mock.patch(
                "charter_replay.cli.tempfile.gettempdir",
                return_value=str(snapshot_parent),
            ):
                loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            snapshot_root = snapshot_parent / (
                f"replay-process-inputs-{loaded.identity['sha256']}"
            )
            snapshot_root.mkdir()
            sentinel = snapshot_root / "not-owned.txt"
            sentinel.write_bytes(b"do not remove\n")

            with mock.patch(
                "charter_replay.policy_sources._run_policy_process"
            ) as process_run:
                result = loaded.source.evaluate(EVENTS)

            process_run.assert_not_called()
            self.assertEqual(
                ["process-snapshot-unavailable"],
                [failure.code for failure in result.failures],
            )
            self.assertEqual(
                ["indeterminate", "indeterminate"],
                [decision["effect"] for decision in result.decisions],
            )
            self.assertEqual(b"do not remove\n", sentinel.read_bytes())

    def test_process_snapshot_cleanup_failure_is_a_source_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            original_cleanup = policy_sources._ProcessInputSnapshot.cleanup

            def clean_then_report_failure(snapshot):
                original_cleanup(snapshot)
                return SourceFailure(
                    "process-snapshot-cleanup-failed",
                    "Synthetic cleanup failure.",
                )

            with mock.patch.object(
                policy_sources._ProcessInputSnapshot,
                "cleanup",
                autospec=True,
                side_effect=clean_then_report_failure,
            ):
                result = loaded.source.evaluate(EVENTS)

        self.assertIn(
            "process-snapshot-cleanup-failed",
            [failure.code for failure in result.failures],
        )

    @unittest.skipIf(os.name == "nt", "Windows directory modes are not portable")
    def test_process_snapshot_cleans_read_only_directories(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            nested = directory / "nested"
            nested.mkdir()
            (nested / "fixture.txt").write_bytes(b"same bytes\n")
            policy = directory / "policy.py"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            os.chmod(nested, 0o555)
            os.chmod(directory, 0o555)
            snapshot_roots: list[Path] = []
            try:
                loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
                original_prepare = loaded.source._prepare_input_snapshot

                def remember_snapshot(events):
                    snapshot = original_prepare(events)
                    self.assertIsNotNone(snapshot)
                    self.assertNotIsInstance(snapshot, PolicySourceResult)
                    snapshot_roots.append(snapshot.root)
                    return snapshot

                with mock.patch.object(
                    loaded.source,
                    "_prepare_input_snapshot",
                    side_effect=remember_snapshot,
                ):
                    result = loaded.source.evaluate(EVENTS)
            finally:
                os.chmod(directory, 0o755)
                os.chmod(nested, 0o755)

        self.assertEqual((), result.failures)
        self.assertEqual(1, len(snapshot_roots))
        self.assertFalse(snapshot_roots[0].exists())

    def test_process_snapshot_change_during_launch_invalidates_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "rules.py"
            policy.write_text(
                "import json\n"
                "import sys\n"
                "from rules import EFFECT\n"
                "for event in map(json.loads, sys.stdin):\n"
                '    print(json.dumps({"schema_version": "policy-decision.v1", '
                '"event_id": event["event_id"], "effect": EFFECT, '
                '"reason": "Mutable snapshot probe."}))\n',
                encoding="utf-8",
                newline="\n",
            )
            helper.write_text('EFFECT = "deny"\n', encoding="utf-8", newline="\n")
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            original_evaluate = loaded.source._evaluate_runtime

            def mutate_snapshot_then_run(events, *, argv, cwd):
                (Path(cwd) / "rules.py").write_text(
                    'EFFECT = "allow"\n', encoding="utf-8", newline="\n"
                )
                return original_evaluate(events, argv=argv, cwd=cwd)

            with mock.patch.object(
                loaded.source,
                "_evaluate_runtime",
                side_effect=mutate_snapshot_then_run,
            ):
                result = loaded.source.evaluate(EVENTS)

        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )
        self.assertIn(
            "process-snapshot-changed", [failure.code for failure in result.failures]
        )

    def test_process_snapshot_mtime_change_during_launch_invalidates_decisions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "rules.py"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            helper.write_text('EFFECT = "deny"\n', encoding="utf-8", newline="\n")
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            original_evaluate = loaded.source._evaluate_runtime

            def touch_snapshot_then_run(events, *, argv, cwd):
                snapshot_helper = Path(cwd) / helper.name
                metadata = snapshot_helper.stat()
                os.utime(
                    snapshot_helper,
                    ns=(
                        metadata.st_atime_ns,
                        policy_sources.SNAPSHOT_MTIME_NS + 1_000_000_000,
                    ),
                )
                return original_evaluate(events, argv=argv, cwd=cwd)

            with mock.patch.object(
                loaded.source,
                "_evaluate_runtime",
                side_effect=touch_snapshot_then_run,
            ):
                result = loaded.source.evaluate(EVENTS)

        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )
        self.assertEqual(
            ["process-snapshot-changed"],
            [failure.code for failure in result.failures],
        )

    @unittest.skipIf(os.name == "nt", "Windows read-only cleanup has separate coverage")
    def test_process_snapshot_permission_change_invalidates_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            policy = directory / "policy.py"
            helper = directory / "mode-probe"
            policy.write_text(
                self.policy_script("same"), encoding="utf-8", newline="\n"
            )
            helper.write_bytes(b"same bytes\n")
            os.chmod(helper, 0o666)
            loaded = _load_process_source(f"{sys.executable},{policy}", 5.0)
            original_evaluate = loaded.source._evaluate_runtime

            def mutate_snapshot_then_run(events, *, argv, cwd):
                os.chmod(Path(cwd) / helper.name, 0o444)
                return original_evaluate(events, argv=argv, cwd=cwd)

            with mock.patch.object(
                loaded.source,
                "_evaluate_runtime",
                side_effect=mutate_snapshot_then_run,
            ):
                result = loaded.source.evaluate(EVENTS)

        self.assertEqual(
            ["indeterminate", "indeterminate"],
            [decision["effect"] for decision in result.decisions],
        )
        self.assertEqual(
            ["process-snapshot-changed"],
            [failure.code for failure in result.failures],
        )

    def test_process_policy_symlink_keeps_supplied_parent_and_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            target_parent = directory / "target"
            supplied_parent = directory / "supplied"
            target_parent.mkdir()
            supplied_parent.mkdir()
            target = target_parent / "real.py"
            target.write_text("pass\n", encoding="utf-8", newline="\n")
            supplied = supplied_parent / "selected.py"
            try:
                supplied.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            loaded = _load_process_source(f"{sys.executable},{supplied}", 1.0)

        self.assertEqual(str(supplied_parent.absolute()), loaded.source.cwd)
        self.assertEqual("selected.py", loaded.source.argv[-1])

    def test_process_policy_runtime_uses_lexical_path_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            target_parent = directory / "target"
            supplied_parent = directory / "supplied"
            target_parent.mkdir()
            supplied_parent.mkdir()
            target = target_parent / "real.py"
            supplied = supplied_parent / "selected.py"
            target.write_text("pass\n", encoding="utf-8", newline="\n")
            supplied.write_text("pass\n", encoding="utf-8", newline="\n")
            original_resolve = Path.resolve

            def redirected_resolve(path, *args, **kwargs):
                if path == supplied:
                    return target
                return original_resolve(path, *args, **kwargs)

            with mock.patch.object(
                Path, "resolve", autospec=True, side_effect=redirected_resolve
            ):
                loaded = _load_process_source(f"{sys.executable},{supplied}", 1.0)

        self.assertEqual(str(supplied_parent.absolute()), loaded.source.cwd)
        self.assertEqual("selected.py", loaded.source.argv[-1])

    def test_validate_accepts_directory_and_rejects_changed_bytes(self) -> None:
        with self.fixture("same") as (_, corpus, _recording, _candidate):
            self.assertEqual(0, main(["validate", "--corpus", str(corpus)]))
            self.assertEqual(
                0,
                main(["validate", "--corpus", str(corpus / "corpus-manifest.json")]),
            )
            self.assertEqual(
                0, main(["validate", "--corpus", str(corpus / "events.jsonl")])
            )
            self.assertEqual(
                2, main(["validate", "--corpus", str(corpus / "cases.jsonl")])
            )
            self.assertEqual(
                2, main(["validate", "--corpus", str(corpus / "missing.jsonl")])
            )
            (corpus / "cases.jsonl").write_bytes(b"changed\n")
            self.assertEqual(2, main(["validate", "--corpus", str(corpus)]))

    def test_validate_rejects_non_lf_jsonl_with_matching_manifest(self) -> None:
        with self.fixture("same") as (_, corpus, _recording, _candidate):
            event_bytes = "\v".join(
                json.dumps(value, sort_keys=True, separators=(",", ":"))
                for value in EVENTS
            ).encode("utf-8")
            (corpus / "events.jsonl").write_bytes(event_bytes)
            corpus_manifest = build_corpus_manifest(
                corpus_id="charter-v0.1",
                event_count=len(EVENTS),
                base_directory=corpus,
                files=["events.jsonl", "cases.jsonl"],
            )
            (corpus / "corpus-manifest.json").write_bytes(
                manifest_json_bytes(corpus_manifest)
            )

            self.assertEqual(2, main(["validate", "--corpus", str(corpus)]))


if __name__ == "__main__":
    unittest.main()
