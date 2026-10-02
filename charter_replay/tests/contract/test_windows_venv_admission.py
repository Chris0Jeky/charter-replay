"""Real Windows admission checks for CPython's nonrelocatable venv launchers."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from charter_replay.cli import _is_windows_venv_launcher
from charter_replay.digests import sha256_file

_CONTROLLER_CHECK = r"""
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import sys
from unittest import mock

from charter_replay.cli import ReplayInputError, _load_process_source, main
from charter_replay.policy_sources import ProcessDecisionSource
from charter_replay.tests.contract.test_cli import CliTests

selected = sys.executable if sys.argv[1] == "self" else sys.argv[1]
expected = sys.argv[2]
if expected.endswith("-no-base"):
    del sys._base_executable
    expected = expected.removesuffix("-no-base")
json_argv = sys.argv[3] == "json"
fixture = CliTests()
with fixture.fixture("same") as (directory, corpus, recording, policy):
    argv = [selected, str(policy)]
    raw = json.dumps(argv) if json_argv else ",".join(argv)
    if expected == "reject":
        try:
            _load_process_source(raw, 5, json_argv=json_argv)
        except ReplayInputError as exc:
            message = str(exc)
            assert "Windows virtualenv launcher" in message, message
            assert "native" in message, message
            assert selected not in message and str(directory) not in message
        else:
            raise AssertionError("Windows virtualenv launcher was admitted")
        output = directory / "never-published"
        args = fixture.replay_args(corpus, recording, policy, output)
        args[args.index("--candidate") + 1] = (
            "process-json:" if json_argv else "process:"
        ) + raw
        with (
            mock.patch.object(ProcessDecisionSource, "_prepare_input_snapshot",
                side_effect=AssertionError("launcher reached snapshot creation")),
            mock.patch("charter_replay.policy_sources._run_policy_process",
                side_effect=AssertionError("launcher reached invocation")),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            assert main(args) == 2
        assert stderr.getvalue() == "replay input invalid: " + message + "\n", stderr.getvalue()
        assert not output.exists(), "unsupported launcher published artifacts"
    elif expected == "accept-load":
        loaded = _load_process_source(raw, 5, json_argv=json_argv)
        assert loaded.kind == "process"
    else:
        output = directory / "native-report"
        args = fixture.replay_args(corpus, recording, policy, output)
        args[args.index("--candidate") + 1] = (
            "process-json:" if json_argv else "process:"
        ) + raw
        assert main(args) == 0
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        assert report["gate"]["status"] == "pass"
        assert report["counts"]["unchanged"] == 2
        assert (output / "run-manifest.json").is_file()
"""


@unittest.skipUnless(os.name == "nt", "requires real Windows CPython launchers")
class WindowsVenvAdmissionTests(unittest.TestCase):
    def test_native_bytes_are_accepted_when_a_template_contains_a_native_copy(
        self,
    ) -> None:
        native = Path(sys._base_executable).resolve()
        digest = sha256_file(native)
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            templates = root / "Lib" / "venv" / "scripts" / "nt"
            templates.mkdir(parents=True)
            shutil.copy2(native, templates / "python.exe")
            with mock.patch.object(sys, "base_prefix", str(root)):
                self.assertFalse(_is_windows_venv_launcher(digest))

    def test_native_and_created_venv_admission_for_both_argv_encodings(self) -> None:
        native = Path(sys._base_executable).resolve()
        checkout = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            environment = root / "synthetic-venv"
            created = subprocess.run(
                [str(native), "-B", "-m", "venv", "--without-pip", str(environment)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(0, created.returncode, created.stderr)
            launcher = environment / "Scripts" / "python.exe"
            configuration = (environment / "pyvenv.cfg").read_text(encoding="utf-8")
            self.assertIn("include-system-site-packages = false", configuration)
            alias = root / "synthetic-launcher-alias.exe"
            shutil.copy2(launcher, alias)
            native_copy_dir = root / "generic" / "Scripts"
            native_copy_dir.mkdir(parents=True)
            native_copy = native_copy_dir / "python.exe"
            shutil.copy2(native, native_copy)
            (native_copy_dir.parent / "pyvenv.cfg").write_text(
                configuration, encoding="utf-8"
            )
            combinations = [
                (native, "self", "accept"),
                (launcher, "self", "reject"),
                (native, str(launcher), "reject"),
                (native, str(alias), "reject"),
                (launcher, str(alias), "reject"),
                (native, str(native_copy), "accept-load"),
                (native, "self", "accept-no-base"),
                (native, str(alias), "reject-no-base"),
                (launcher, "self", "reject-no-base"),
            ]
            for encoding in ("legacy", "json"):
                for controller, selected, expected in combinations:
                    with self.subTest(
                        controller=controller, selected=selected, encoding=encoding
                    ):
                        checked = subprocess.run(
                            [
                                str(controller),
                                "-B",
                                "-c",
                                _CONTROLLER_CHECK,
                                selected,
                                expected,
                                encoding,
                            ],
                            cwd=checkout,
                            capture_output=True,
                            text=True,
                            timeout=15,
                        )
                        self.assertEqual(0, checked.returncode, checked.stderr)
