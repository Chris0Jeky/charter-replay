"""Portable process labels and bounded CLI wait-input contracts."""

from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from charter_replay import cli
from charter_replay.tests.contract import test_cli as fixtures

ROOT = Path(__file__).resolve().parents[3]


class ProcessIdentifierTests(unittest.TestCase):
    def test_filename_matrix_runs_with_hash_derived_portable_identifiers(self):
        names = (
            "candidate policy.py",
            "_candidate.py",
            ".candidate.py",
            "candidaté.py",
            "candidate-policy.py",
            "p" * 130 + ".py",
        )
        for name in names:
            with self.subTest(name=name), fixtures.CliTests().fixture("same") as data:
                directory, corpus, recording, original = data
                source = directory / "source"
                source.mkdir()
                candidate = original.rename(source / name)
                output = directory / "reports"
                argv = fixtures.CliTests.replay_args(
                    corpus, recording, candidate, output
                )
                with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "0"}):
                    self.assertEqual(0, cli.main(argv))
                    first = (output / "run-manifest.json").read_bytes()
                    self.assertEqual(0, cli.main(argv))
                    second = (output / "run-manifest.json").read_bytes()
                self.assertEqual(first, second)
                manifest = json.loads(first)
                identity = manifest["candidate"]
                self.assertEqual("process-" + identity["sha256"], identity["id"])
                self.assertRegex(identity["id"], r"^process-[0-9a-f]{64}$")
                self.assertNotIn(name, first.decode("utf-8"))
                report = json.loads((output / "report.json").read_bytes())
                self.assertEqual("pass", report["gate"]["status"])
                for artifact in (manifest, report):
                    self.assertNotIn(str(directory), json.dumps(artifact))

    def test_distinct_names_do_not_collapse_to_one_sanitized_label(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, _corpus, _recording, original = data
            source = directory / "source"
            source.mkdir()
            names = ("a b.py", "a_b.py", "a-b.py", "a.b.py")
            for name in names:
                (source / name).write_bytes(original.read_bytes())
            identities = []
            for name in names:
                loaded = cli._load_process_source(
                    f"{sys.executable},{source / name}", 30.0
                )
                identities.append(loaded.identity)
            self.assertEqual(len(names), len({row["id"] for row in identities}))
            self.assertEqual(len(names), len({row["sha256"] for row in identities}))

    def test_existing_semantic_digest_stays_bound_to_content_and_timeout(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, _corpus, _recording, original = data
            source = directory / "source"
            source.mkdir()
            candidate = original.rename(source / "policy.py")
            reference = f"{sys.executable},{candidate}"
            first = cli._load_process_source(reference, 30.0).identity
            same = cli._load_process_source(reference, 30.0).identity
            timeout = cli._load_process_source(reference, 31.0).identity
            candidate.write_text("pass\n", encoding="utf-8")
            changed = cli._load_process_source(reference, 30.0).identity
            self.assertEqual(first, same)
            self.assertEqual(3, len({row["id"] for row in (first, timeout, changed)}))
            for row in (first, timeout, changed):
                self.assertEqual("process-" + row["sha256"], row["id"])

    def test_label_migration_preserves_semantic_digest_and_run_id(self):
        with fixtures.CliTests().fixture("same") as data:
            _directory, corpus_path, _recording, candidate = data
            identity = cli._load_process_source(
                f"{sys.executable},{candidate}", 30.0
            ).identity
            old_identity = {**identity, "id": candidate.stem}
            corpus = cli._load_charter_corpus(str(corpus_path))
            common = {
                "generated_at": "1970-01-01T00:00:00Z",
                "baseline": old_identity,
                "corpus": {
                    "id": corpus.corpus_id,
                    "manifest_sha256": corpus.manifest_sha256,
                    "event_count": corpus.event_count,
                },
                "fail_on": cli.DEFAULT_FAIL_ON,
            }
            old = cli.build_run_manifest(candidate=old_identity, **common)
            current = cli.build_run_manifest(candidate=identity, **common)
            self.assertNotEqual(old["candidate"]["id"], current["candidate"]["id"])
            self.assertEqual(old["candidate"]["sha256"], current["candidate"]["sha256"])
            self.assertEqual(old["run_id"], current["run_id"])


class TimeoutInputTests(unittest.TestCase):
    @staticmethod
    def args(value):
        return [
            "replay",
            "--baseline",
            "recorded:not-read.jsonl",
            "--candidate",
            "process:not-launched,policy.py",
            "--corpus",
            "not-read",
            "--output",
            "not-created",
            "--timeout=" + value,
        ]

    def test_invalid_timeout_is_rejected_before_loading_any_input(self):
        for value in ("0", "-1", "nan", "inf", "-inf", "86400.1", "1e100", "bad"):
            with self.subTest(value=value):
                diagnostic = io.StringIO()
                with (
                    redirect_stderr(diagnostic),
                    mock.patch.object(cli, "_load_charter_corpus") as corpus,
                    mock.patch.object(cli, "_load_policy_source") as source,
                    mock.patch.object(cli, "_publish_report_set") as publish,
                ):
                    with self.assertRaises(SystemExit) as raised:
                        cli.main(self.args(value))
                self.assertEqual(2, raised.exception.code)
                self.assertIn("86400", diagnostic.getvalue())
                self.assertNotIn("Traceback", diagnostic.getvalue())
                corpus.assert_not_called()
                source.assert_not_called()
                publish.assert_not_called()

    def test_positive_timeout_range_and_existing_default_are_preserved(self):
        for raw, expected in (
            ("0.000001", 0.000001),
            ("30", 30.0),
            ("86400", 86400.0),
        ):
            with self.subTest(value=raw):
                parsed = cli._parser().parse_args(self.args(raw))
                self.assertEqual(expected, parsed.timeout)
        without_timeout = self.args("30")[:-1]
        self.assertEqual(30.0, cli._parser().parse_args(without_timeout).timeout)

    def test_real_cli_rejects_extreme_wait_without_launch_or_output(self):
        with fixtures.CliTests().fixture("same") as data:
            directory, corpus, recording, candidate = data
            marker = directory / "launched.txt"
            candidate.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('launched', encoding='utf-8')\n"
                + fixtures.CliTests.policy_script("same"),
                encoding="utf-8",
            )
            output = directory / "reports"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "charter_replay.cli",
                    *fixtures.CliTests.replay_args(
                        corpus, recording, candidate, output
                    ),
                    "--timeout",
                    "1e100",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(2, completed.returncode, completed.stderr)
            self.assertIn("86400", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
