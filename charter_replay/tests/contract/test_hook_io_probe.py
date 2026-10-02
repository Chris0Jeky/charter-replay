"""Bounded synthetic diagnostics exercise the real supervised overflow path."""

import errno
import importlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from copy import deepcopy
from unittest import mock

from charter_replay.tests.no_launch import forbid_process_launch


class HookIoProbeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("examples.hook_io_probe"),
            "the separate bounded synthetic diagnostic probe is missing",
        )
        self.probe = importlib.import_module("examples.hook_io_probe")

    def assert_safe(self, document):
        data = self.probe.render(document)
        self.assertLessEqual(len(data), self.probe.MAX_DIAGNOSTIC_BYTES)
        self.assertNotIn(b"synthetic-private-sentinel", data)
        self.assertNotIn(b"Traceback", data)
        self.assertEqual(json.loads(data), document)

    def test_ordinary_probe_observes_two_real_overflows(self):
        document = self.probe.run_probe(attempts=1)
        self.assert_safe(document)
        self.assertEqual(document["status"], "complete")
        self.assertEqual(document["completed_invocations"], 2)
        self.assertEqual(document["outcomes"]["output-limit"], 2)
        self.assertEqual(document["outcomes"]["start-failed"], 0)
        self.assertEqual(
            [r["outcome"] for r in document["records"] if r["outcome"]],
            ["output-limit", "output-limit"],
        )
        for phase in (
            "stream-create",
            "stream-write",
            "stream-seek",
            "stream-size",
            "stream-close",
            "process-launch",
            "process-wait",
            "process-group-kill",
            "workspace-create",
            "workspace-cleanup",
        ):
            self.assertGreater(document["operations"][phase], 0, phase)

    def test_real_overflow_then_injected_emfile_has_exact_safe_evidence(self):
        document = self.probe.run_probe(attempts=1, inject_emfile=True)
        self.assert_safe(document)
        self.assertEqual(document["status"], "complete")
        self.assertEqual(document["outcomes"]["output-limit"], 1)
        self.assertEqual(document["outcomes"]["start-failed"], 1)
        self.assertEqual(
            [r for r in document["records"] if r["phase"] == "stream-create"],
            [
                dict(
                    ordinal=2,
                    phase="stream-create",
                    error_class="OSError",
                    errno=errno.EMFILE,
                    winerror=None,
                    outcome=None,
                )
            ],
        )

    def test_invalid_attempt_budget_is_refused_before_any_launch(self):
        for attempts in (0, self.probe.MAX_ATTEMPTS + 1, True, "1"):
            with self.subTest(attempts=attempts), forbid_process_launch():
                with self.assertRaisesRegex(ValueError, "attempts"):
                    self.probe.run_probe(attempts=attempts)

    def test_dynamic_exception_names_and_values_cannot_escape(self):
        private_error = type("synthetic-private-sentinel", (OSError,), {})
        error = private_error(-1, "synthetic-private-sentinel /private/path")
        error.winerror = 2**80
        recorder = self.probe.Recorder()
        recorder.ordinal = 1
        recorder.error("stream-read", error)
        document = recorder.document(1, "worker-failed")
        self.assert_safe(document)
        self.assertEqual(document["records"][0]["error_class"], "OSError")
        self.assertIsNone(document["records"][0]["errno"])
        self.assertIsNone(document["records"][0]["winerror"])

    def test_record_cap_keeps_diagnostics_bounded(self):
        recorder = self.probe.Recorder()
        recorder.ordinal = 1
        for _ in range(self.probe.MAX_RECORDS + 5):
            recorder.error("stream-create", OSError(errno.EMFILE, "private"))
        document = recorder.document(1, "worker-failed")
        self.assert_safe(document)
        self.assertEqual(len(document["records"]), self.probe.MAX_RECORDS)
        self.assertTrue(document["records_truncated"])

    def test_outer_timeout_is_fixed_and_keeps_worker_details_private(self):
        with mock.patch.object(
            self.probe.policy_sources,
            "_run_policy_process",
            side_effect=subprocess.TimeoutExpired(
                ["synthetic-private-sentinel"], 1, b"synthetic-private-sentinel"
            ),
        ):
            document = self.probe.run_probe(attempts=1)
        self.assert_safe(document)
        self.assertEqual(document["status"], "worker-timeout")
        self.assertEqual(document["records"][0]["phase"], "probe-supervision")
        self.assertEqual(document["records"][0]["error_class"], "TimeoutExpired")

    def test_worker_output_is_admitted_before_returning_diagnostics(self):
        completed = subprocess.CompletedProcess(
            [], 0, b'{"private": "synthetic-private-sentinel"}', b""
        )
        with mock.patch.object(
            self.probe.policy_sources, "_run_policy_process", return_value=completed
        ):
            document = self.probe.run_probe(attempts=1)
        self.assert_safe(document)
        self.assertEqual(document["status"], "invalid-diagnostics")

    def test_stream_operations_and_closed_descriptor_failure_are_observed(self):
        recorder = self.probe.Recorder()
        recorder.ordinal = 1
        with tempfile.TemporaryFile() as raw:
            stream = self.probe._Stream(raw, recorder)
            stream.write(b"synthetic-private-sentinel")
            stream.flush()
            stream.seek(0)
            self.assertEqual(stream.read(), b"synthetic-private-sentinel")
            stream.fileno()
            for phase in ("write", "flush", "seek", "read", "size"):
                self.assertGreater(recorder.operations["stream-" + phase], 0)
            # A bad descriptor must be attributed to its operation, not lost in
            # a later broad start-failed classification.
            with mock.patch.object(
                raw,
                "fileno",
                side_effect=OSError(errno.EBADF, "synthetic-private-sentinel"),
            ):
                with self.assertRaises(OSError):
                    stream.fileno()
            stream.close()
        document = recorder.document(1, "worker-failed")
        self.assert_safe(document)
        self.assertEqual(document["records"][0]["phase"], "stream-size")
        self.assertEqual(document["records"][0]["errno"], errno.EBADF)

    def test_receipt_rejects_equal_float_or_boolean_primitives_and_missing_work(self):
        recorder = self.probe.Recorder()
        recorder.outcome("output-limit")
        recorder.outcome("output-limit")
        document = recorder.document(1, "complete")
        malformed = []
        changed = deepcopy(document)
        changed["planned_invocations"] = 2.0
        malformed.append(changed)
        for name, value in self.probe.LIMITS.items():
            changed = deepcopy(document)
            changed["limits"][name] = float(value)
            malformed.append(changed)
            if value == 1:
                changed = deepcopy(document)
                changed["limits"][name] = True
                malformed.append(changed)
        changed = deepcopy(document)
        changed["completed_invocations"] = 1
        changed["outcomes"]["output-limit"] = 1
        malformed.append(changed)
        for index, receipt in enumerate(malformed):
            with self.subTest(receipt=index):
                with self.assertRaises(ValueError):
                    self.probe.render(receipt)

    def test_cleanup_refusal_before_rmtree_is_recorded_without_private_text(self):
        hooks = self.probe.hooks
        sources = self.probe.policy_sources
        real_prepare = hooks.prepare_workspace
        real_cleanup = hooks._cleanup_snapshot_root
        created = []

        def prepare(*args):
            workspace = real_prepare(*args)
            created.append(workspace.parent)
            return workspace

        def cleanup(root):
            failure = real_cleanup(root)
            if failure:
                # The diagnostic must never trust a returned failure's text/code.
                return sources.SourceFailure(
                    "synthetic-private-sentinel",
                    "synthetic-private-sentinel /private/path",
                )
            return None

        try:
            with (
                mock.patch.object(hooks, "prepare_workspace", side_effect=prepare),
                mock.patch.object(hooks, "_cleanup_snapshot_root", side_effect=cleanup),
                mock.patch.object(
                    sources.Path,
                    "chmod",
                    side_effect=PermissionError(
                        errno.EACCES, "synthetic-private-sentinel"
                    ),
                ),
            ):
                document = self.probe._worker(1, False)
        finally:
            for root in created:
                self.assertIsNone(real_cleanup(root))
        self.assert_safe(document)
        self.assertEqual(document["outcomes"]["output-limit"], 2)
        self.assertEqual(
            [r for r in document["records"] if r["phase"] == "workspace-cleanup"],
            [
                dict(
                    ordinal=ordinal,
                    phase="workspace-cleanup",
                    error_class="CleanupFailure",
                    errno=None,
                    winerror=None,
                    outcome=None,
                )
                for ordinal in (1, 2)
            ],
        )
