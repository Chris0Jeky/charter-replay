"""The Windows supervisor marker is not a POSIX start-failure protocol."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from charter_replay import policy_sources
from charter_replay.tests.contract import test_process_source as fixtures


class WrapperMarkerTests(unittest.TestCase):
    def run_stubbed(self, platform, returncode, stderr, *, timed_out=False):
        def finish(_argv, *, stdin_stream, stdout_stream, stderr_stream, **kwargs):
            self.assertEqual(b"input\n", stdin_stream.read())
            stdout_stream.write(b"valid-output\n")
            stderr_stream.write(stderr)
            self.assertEqual(0.25, kwargs["timeout_seconds"])
            return returncode, timed_out

        with (
            mock.patch.object(policy_sources, "os", SimpleNamespace(name=platform)),
            mock.patch.object(
                policy_sources, "_run_windows_policy_process", side_effect=finish
            ) as windows,
            mock.patch.object(
                policy_sources, "_run_posix_policy_process", side_effect=finish
            ) as posix,
        ):
            try:
                return policy_sources._run_policy_process(
                    ["synthetic-policy"],
                    b"input\n",
                    timeout_seconds=0.25,
                    cwd=None,
                    environment=None,
                )
            finally:
                self.assertEqual(1 if platform == "nt" else 0, windows.call_count)
                self.assertEqual(0 if platform == "nt" else 1, posix.call_count)

    def test_posix_marker_keeps_ordinary_exit_and_streams(self):
        stderr = b"replay-wrapper-exec-failed:synthetic\n"
        result = self.run_stubbed("posix", 127, stderr)
        self.assertEqual(127, result.returncode)
        self.assertEqual(b"valid-output\n", result.stdout)
        self.assertEqual(stderr, result.stderr)

    def test_windows_reserved_marker_still_reports_start_failure(self):
        with self.assertRaisesRegex(OSError, "executable could not start"):
            self.run_stubbed("nt", 127, b"replay-wrapper-exec-failed:synthetic\n")

    def test_nonmatching_status_or_prefix_is_not_a_start_failure(self):
        for platform in ("nt", "posix"):
            for code, stderr in (
                (0, b"replay-wrapper-exec-failed:synthetic\n"),
                (126, b"replay-wrapper-exec-failed:synthetic\n"),
                (127, b"ordinary-diagnostic\n"),
                (127, b"prefix replay-wrapper-exec-failed:synthetic\n"),
            ):
                with self.subTest(platform=platform, code=code, stderr=stderr):
                    result = self.run_stubbed(platform, code, stderr)
                    self.assertEqual(code, result.returncode)
                    self.assertEqual(b"valid-output\n", result.stdout)

    def test_timeout_takes_precedence_over_any_marker(self):
        for platform in ("nt", "posix"):
            with self.subTest(platform=platform):
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.run_stubbed(
                        platform,
                        127,
                        b"replay-wrapper-exec-failed:synthetic\n",
                        timed_out=True,
                    )

    def test_real_host_process_preserves_the_declared_platform_contract(self):
        rows = [
            {
                "schema_version": "policy-decision.v1",
                "event_id": event["event_id"],
                "effect": effect,
                "reason": "Synthetic marker control.",
            }
            for event, effect in zip(fixtures.EVENTS, ("deny", "allow"), strict=True)
        ]
        stdout = "".join(json.dumps(row) + "\n" for row in rows)
        code = (
            "import sys; "
            f"sys.stdout.write({stdout!r}); sys.stdout.flush(); "
            "sys.stderr.write('replay-wrapper-exec-failed:synthetic\\n'); "
            "sys.stderr.flush(); raise SystemExit(127)"
        )
        source = policy_sources.ProcessDecisionSource(
            [sys.executable, "-I", "-S", "-c", code], timeout_seconds=5.0
        )
        result = source.evaluate(fixtures.EVENTS)
        self.assertFalse(result.is_valid)
        if os.name == "nt":
            self.assertEqual(
                ["process-start-failed"], [failure.code for failure in result.failures]
            )
            self.assertEqual(
                ["indeterminate", "indeterminate"],
                [row["effect"] for row in result.decisions],
            )
        else:
            self.assertEqual(
                ["process-exit-nonzero"], [failure.code for failure in result.failures]
            )
            self.assertEqual(
                ["deny", "allow"], [row["effect"] for row in result.decisions]
            )
            self.assertEqual(
                ("replay-wrapper-exec-failed:synthetic",), result.diagnostics
            )


if __name__ == "__main__":
    unittest.main()
