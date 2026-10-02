"""Opt-in, bounded synthetic hook I/O diagnostics; production is unchanged."""

from __future__ import annotations

import argparse
import builtins
from contextlib import ExitStack, contextmanager
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock

from charter_replay import hooks, policy_sources

VERSION = "synthetic-hook-io.v1"
MAX_ATTEMPTS = 3
MAX_RECORDS = 64
MAX_DIAGNOSTIC_BYTES = 16 * 1024
MAX_NUMBER = 2**31 - 1
MAX_OPERATIONS = 10_000
PHASES = (
    "stream-create",
    "stream-write",
    "stream-seek",
    "stream-flush",
    "stream-size",
    "stream-read",
    "stream-close",
    "process-launch",
    "process-wait",
    "process-poll",
    "process-kill",
    "process-group-kill",
    "workspace-create",
    "workspace-cleanup",
    "hook-outcome",
    "probe-supervision",
)
STATUSES = (
    "complete",
    "worker-timeout",
    "worker-failed",
    "invalid-diagnostics",
    "invalid-arguments",
)
ERROR_TYPES = {
    getattr(builtins, name): name
    for name in (
        "OSError",
        "FileNotFoundError",
        "PermissionError",
        "ProcessLookupError",
        "BlockingIOError",
        "IsADirectoryError",
        "NotADirectoryError",
        "TimeoutError",
        "InterruptedError",
        "ChildProcessError",
    )
} | {
    subprocess.TimeoutExpired: "TimeoutExpired",
    policy_sources.ProcessOutputLimitExceeded: "ProcessOutputLimitExceeded",
}
ERROR_NAMES = tuple(ERROR_TYPES.values()) + ("OtherError", "CleanupFailure")
LIMITS = dict(
    max_attempts=MAX_ATTEMPTS,
    max_invocations=2 * MAX_ATTEMPTS,
    hook_timeout_seconds=1,
    outer_timeout_seconds=15,
    max_records=MAX_RECORDS,
    max_bytes=MAX_DIAGNOSTIC_BYTES,
    hook_output_bytes=1024,
)
# The hook and its input deliberately carry this synthetic privacy sentinel.
# Neither those bytes nor exception messages can enter the diagnostic document.
_OVERFLOW = "import sys; sys.stdout.write('synthetic-private-sentinel' + 'x' * 10000)"


def _number(value):
    return value if type(value) is int and 0 <= value <= MAX_NUMBER else None


class Recorder:
    def __init__(self):
        self.ordinal = 0
        self.records = []
        self.truncated = False
        self.operations = dict.fromkeys(PHASES, 0)
        self.outcomes = dict.fromkeys(hooks.OUTCOMES, 0)

    def _append(
        self, phase, error_class=None, number=None, winerror=None, outcome=None
    ):
        if phase not in PHASES:
            raise ValueError("diagnostic phase is invalid")
        if len(self.records) == MAX_RECORDS:
            self.truncated = True
            return
        self.records.append(
            dict(
                ordinal=self.ordinal,
                phase=phase,
                error_class=error_class,
                errno=number,
                winerror=winerror,
                outcome=outcome,
            )
        )

    def error(self, phase, error):
        name = ERROR_TYPES.get(
            type(error), "OSError" if isinstance(error, OSError) else "OtherError"
        )
        self._append(
            phase,
            name,
            _number(getattr(error, "errno", None)),
            _number(getattr(error, "winerror", None)),
        )

    def call(self, phase, function, *args, **kwargs):
        self.operations[phase] = min(MAX_OPERATIONS, self.operations[phase] + 1)
        try:
            return function(*args, **kwargs)
        except OSError as error:
            self.error(phase, error)
            raise

    def outcome(self, outcome):
        self.outcomes[outcome] += 1
        self._append("hook-outcome", outcome=outcome)

    def document(self, attempts, status, injected=False):
        return dict(
            schema_version=VERSION,
            status=status,
            attempts=attempts,
            planned_invocations=2 * attempts,
            completed_invocations=sum(self.outcomes.values()),
            injected_emfile=injected,
            limits=dict(LIMITS),
            operations=dict(self.operations),
            outcomes=dict(self.outcomes),
            records=list(self.records),
            records_truncated=self.truncated,
        )


def render(document):
    """Admit fixed vocabulary and bounded numbers before emitting any bytes."""
    template = Recorder().document(1, "complete")
    if not isinstance(document, dict) or set(document) != set(template):
        raise ValueError("diagnostic shape is invalid")
    if (
        type(document["schema_version"]) is not str
        or document["schema_version"] != VERSION
        or type(document["status"]) is not str
        or document["status"] not in STATUSES
        or type(document["attempts"]) is not int
        or not 1 <= document["attempts"] <= MAX_ATTEMPTS
        or type(document["planned_invocations"]) is not int
        or document["planned_invocations"] != 2 * document["attempts"]
        or type(document["limits"]) is not dict
        or set(document["limits"]) != set(LIMITS)
        or any(
            type(document["limits"][name]) is not int
            or document["limits"][name] != value
            for name, value in LIMITS.items()
        )
        or type(document["injected_emfile"]) is not bool
        or type(document["records_truncated"]) is not bool
    ):
        raise ValueError("diagnostic values are invalid")
    for key, names, maximum in (
        ("operations", PHASES, MAX_OPERATIONS),
        ("outcomes", hooks.OUTCOMES, 2 * MAX_ATTEMPTS),
    ):
        values = document[key]
        if (
            not isinstance(values, dict)
            or set(values) != set(names)
            or any(type(n) is not int or not 0 <= n <= maximum for n in values.values())
        ):
            raise ValueError("diagnostic counts are invalid")
    completed = document["completed_invocations"]
    if (
        type(completed) is not int
        or completed != sum(document["outcomes"].values())
        or not 0 <= completed <= document["planned_invocations"]
        or (
            document["status"] == "complete"
            and completed != document["planned_invocations"]
        )
    ):
        raise ValueError("diagnostic totals are invalid")
    records = document["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("diagnostic record limit exceeded")
    for row in records:
        if (
            not isinstance(row, dict)
            or set(row)
            != {"ordinal", "phase", "error_class", "errno", "winerror", "outcome"}
            or type(row["ordinal"]) is not int
            or not 0 <= row["ordinal"] <= document["planned_invocations"]
            or type(row["phase"]) is not str
            or row["phase"] not in PHASES
            or (row["error_class"] is not None and type(row["error_class"]) is not str)
            or row["error_class"] not in (*ERROR_NAMES, None)
            or (row["outcome"] is not None and type(row["outcome"]) is not str)
            or row["outcome"] not in (*hooks.OUTCOMES, None)
            or any(
                row[key] is not None and _number(row[key]) is None
                for key in ("errno", "winerror")
            )
        ):
            raise ValueError("diagnostic record is invalid")
    data = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("ascii")
    if len(data) > MAX_DIAGNOSTIC_BYTES:
        raise ValueError("diagnostic byte limit exceeded")
    return data


class _Stream:
    def __init__(self, stream, recorder):
        self.stream, self.recorder = stream, recorder

    def __getattr__(self, name):
        attribute = getattr(self.stream, name)
        if name in ("write", "seek", "flush", "read", "close", "fileno"):
            return lambda *args, **kwargs: self.recorder.call(
                "stream-size" if name == "fileno" else "stream-" + name,
                attribute,
                *args,
                **kwargs,
            )
        return attribute

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class _Process:
    def __init__(self, process, recorder):
        self.process, self.recorder = process, recorder

    def __getattr__(self, name):
        attribute = getattr(self.process, name)
        if name in ("wait", "poll", "kill"):
            return lambda *args, **kwargs: self.recorder.call(
                "process-" + name, attribute, *args, **kwargs
            )
        return attribute


class _WindowsKernel:
    def __init__(self, kernel, recorder):
        self.kernel, self.recorder = kernel, recorder

    def __getattr__(self, name):
        attribute = getattr(self.kernel, name)
        if name != "TerminateJobObject":
            return attribute

        def terminate(*args):
            import ctypes

            result = self.recorder.call("process-group-kill", attribute, *args)
            if not result:
                self.recorder.error(
                    "process-group-kill", ctypes.WinError(ctypes.get_last_error())
                )
            return result

        return terminate


@contextmanager
def _instrument(recorder, injected):
    # Patches live only in the isolated probe worker, serially; no production API changes.
    real_file = policy_sources.tempfile.TemporaryFile
    real_popen = policy_sources.subprocess.Popen
    real_stat = policy_sources.os.fstat
    real_remove = policy_sources.shutil.rmtree
    fired = False

    def temporary_file(*args, **kwargs):
        def create():
            nonlocal fired
            if injected and recorder.ordinal == 2 and not fired:
                fired = True
                raise OSError(errno.EMFILE, "synthetic-private-sentinel /private/path")
            return real_file(*args, **kwargs)

        return _Stream(recorder.call("stream-create", create), recorder)

    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(policy_sources.tempfile, "TemporaryFile", temporary_file)
        )
        stack.enter_context(
            mock.patch.object(
                policy_sources.subprocess,
                "Popen",
                lambda *a, **kw: _Process(
                    recorder.call("process-launch", real_popen, *a, **kw), recorder
                ),
            )
        )
        stack.enter_context(
            mock.patch.object(
                policy_sources.os,
                "fstat",
                lambda *a: recorder.call("stream-size", real_stat, *a),
            )
        )
        stack.enter_context(
            mock.patch.object(
                policy_sources.shutil,
                "rmtree",
                lambda *a, **kw: recorder.call(
                    "workspace-cleanup", real_remove, *a, **kw
                ),
            )
        )
        if os.name == "nt":
            real_kernel = policy_sources._windows_kernel32
            stack.enter_context(
                mock.patch.object(
                    policy_sources,
                    "_windows_kernel32",
                    lambda: _WindowsKernel(real_kernel(), recorder),
                )
            )
        else:
            real_kill = policy_sources.os.killpg
            stack.enter_context(
                mock.patch.object(
                    policy_sources.os,
                    "killpg",
                    lambda *a: recorder.call("process-group-kill", real_kill, *a),
                )
            )
        yield


def _worker(attempts, injected):
    recorder = Recorder()
    spec = hooks.HookSpec(
        (sys.executable, "-c", _OVERFLOW), timeout=1, output_limit=1024
    )
    with _instrument(recorder, injected):
        for ordinal in range(1, 2 * attempts + 1):
            recorder.ordinal = ordinal
            workspace = None
            try:
                workspace = recorder.call(
                    "workspace-create", hooks.prepare_workspace, None
                )
                outcome = hooks.run_hook(
                    spec,
                    {
                        "cwd": str(workspace),
                        "tool_input": {"command": "synthetic-private-sentinel"},
                    },
                    workspace=workspace,
                ).outcome
            except OSError:
                outcome = "start-failed"
            finally:
                if workspace is not None:
                    try:
                        failure = recorder.call(
                            "workspace-cleanup",
                            hooks._cleanup_snapshot_root,
                            workspace.parent,
                        )
                    except OSError:
                        # The operation already emitted safe evidence; preserve
                        # the observed hook outcome and continue the bounded probe.
                        pass
                    else:
                        if failure is not None:
                            # The cleanup helper can swallow the original error.
                            # Its returned refusal establishes no class/errno.
                            recorder._append("workspace-cleanup", "CleanupFailure")
            recorder.outcome(outcome)
    return recorder.document(attempts, "complete", injected)


def run_probe(*, attempts=1, inject_emfile=False):
    """Supervise a fixed synthetic worker with a family timeout and output cap."""
    if type(attempts) is not int or not 1 <= attempts <= MAX_ATTEMPTS:
        raise ValueError("probe attempts must be from 1 to 3")
    if type(inject_emfile) is not bool:
        raise ValueError("probe injection flag must be boolean")
    recorder = Recorder()
    argv = [
        sys.executable,
        "-m",
        "examples.hook_io_probe",
        "--worker",
        "--attempts",
        str(attempts),
    ]
    if inject_emfile:
        argv.append("--inject-emfile")
    try:
        completed = policy_sources._run_policy_process(
            argv,
            b"",
            timeout_seconds=LIMITS["outer_timeout_seconds"],
            cwd=str(Path(__file__).resolve().parents[1]),
            environment=hooks._hook_env(Path.cwd()),
            output_limit=MAX_DIAGNOSTIC_BYTES,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
        policy_sources.ProcessOutputLimitExceeded,
    ) as error:
        recorder.error("probe-supervision", error)
        return recorder.document(
            attempts,
            (
                "worker-timeout"
                if isinstance(error, subprocess.TimeoutExpired)
                else "worker-failed"
            ),
            inject_emfile,
        )
    if completed.returncode != 0:
        return recorder.document(attempts, "worker-failed", inject_emfile)
    try:
        if len(completed.stdout) > MAX_DIAGNOSTIC_BYTES:
            raise ValueError("diagnostic byte limit exceeded")
        document = json.loads(completed.stdout)
        render(document)
        if (
            document["attempts"] != attempts
            or document["injected_emfile"] != inject_emfile
        ):
            raise ValueError("diagnostic request does not match")
        return document
    except (ValueError, TypeError, RecursionError):
        return recorder.document(attempts, "invalid-diagnostics", inject_emfile)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("probe arguments are invalid")


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--inject-emfile", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        if not 1 <= args.attempts <= MAX_ATTEMPTS:
            raise ValueError("probe attempts are invalid")
        document = (
            _worker(args.attempts, args.inject_emfile)
            if args.worker
            else run_probe(attempts=args.attempts, inject_emfile=args.inject_emfile)
        )
    except ValueError:
        document = Recorder().document(1, "invalid-arguments")
    sys.stdout.buffer.write(render(document))
    return 0 if document["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
