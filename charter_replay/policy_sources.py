"""Recorded policy decisions and source-result contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

from charter_replay.corpus import (
    POLICY_DECISION_VERSION,
    ValidationError,
    split_jsonl_records,
    validate_command_events,
    validate_policy_decision,
)
from charter_replay.digests import permission_bits, sha256_file, sha256_tree

RECORDED_MANIFEST_VERSION = "recorded-policy-manifest.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PROCESS_CLEANUP_GRACE_SECONDS = 1.0
# How often a hook run's output files are sized while the child runs.
_OUTPUT_LIMIT_POLL_SECONDS = 0.025
_RUNNER_DIRECTORY_MODE = 0o700
SNAPSHOT_MTIME_NS = 946684800_000_000_000
_WINDOWS_EXEC_FAILURE_PREFIX = b"replay-wrapper-exec-failed:"
_WINDOWS_POLICY_WRAPPER = r"""
import ctypes
import json
import os
import subprocess
import sys

event_handle = int(sys.argv[1])
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
kernel32.WaitForSingleObject.restype = ctypes.c_uint32
kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
kernel32.CloseHandle.restype = ctypes.c_int
try:
    if kernel32.WaitForSingleObject(event_handle, 0xFFFFFFFF) != 0:
        raise OSError("policy wrapper start event failed")
finally:
    kernel32.CloseHandle(event_handle)

cwd = json.loads(sys.argv[2])
environment = json.loads(sys.argv[3])
if cwd is not None:
    os.chdir(cwd)
try:
    process = subprocess.Popen(
        sys.argv[4:],
        stdin=sys.stdin.buffer,
        stdout=sys.stdout.buffer,
        stderr=sys.stderr.buffer,
        close_fds=True,
        shell=False,
        env=None if environment is None else environment,
    )
except OSError as exc:
    sys.stderr.write(f"replay-wrapper-exec-failed:{exc.__class__.__name__}\n")
    sys.stderr.flush()
    os._exit(127)
os._exit(process.wait())
"""


def _read_process_stream(stream, limit: int | None = None) -> bytes:
    stream.flush()
    stream.seek(0)
    # A limit bounds the read itself: one byte past it proves an overflow.
    return stream.read() if limit is None else stream.read(limit + 1)


class ProcessOutputLimitExceeded(Exception):
    """A child wrote more than its per-stream output limit; its family is dead."""

    def __init__(self, stream: str, limit: int) -> None:
        super().__init__(f"{stream} exceeded {limit} bytes")
        self.stream = stream
        self.limit = limit


def _stream_over_limit(streams: Sequence[tuple[str, Any]], limit: int) -> str | None:
    """Name the first stream whose file is larger than `limit`, from stat alone."""

    for name, stream in streams:
        if os.fstat(stream.fileno()).st_size > limit:
            return name
    return None


def _wait_for_process(
    process: subprocess.Popen[bytes],
    timeout_seconds: float,
    *,
    output_streams: Sequence[tuple[str, Any]] = (),
    output_limit: int | None = None,
) -> bool:
    """Wait for the child; return True when the timeout elapsed first.

    Without a limit this is the plain timed wait. With one, the wait is sliced
    so both output files are sized between slices, and it ends early, not timed
    out, as soon as either is over the limit (or cannot be sized). The caller
    then takes its ordinary kill path for the whole process family.
    """

    if output_limit is None:
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            return True
        return False
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        try:
            process.wait(timeout=min(_OUTPUT_LIMIT_POLL_SECONDS, remaining))
        except subprocess.TimeoutExpired:
            pass
        else:
            return False
        try:
            if _stream_over_limit(output_streams, output_limit) is not None:
                return False
        except OSError:
            # Unsizeable output is unbounded: stop the family now; the caller's
            # own sizing raises after the kill.
            return False


def _run_posix_policy_process(
    argv: Sequence[str],
    *,
    stdin_stream,
    stdout_stream,
    stderr_stream,
    timeout_seconds: float,
    cwd: str | None,
    environment: Mapping[str, str] | None,
    output_limit: int | None = None,
) -> tuple[int, bool]:
    process = subprocess.Popen(
        list(argv),
        stdin=stdin_stream,
        stdout=stdout_stream,
        stderr=stderr_stream,
        start_new_session=True,
        shell=False,
        cwd=cwd,
        env=environment,
    )
    timed_out = _wait_for_process(
        process,
        timeout_seconds,
        output_streams=(("stdout", stdout_stream), ("stderr", stderr_stream)),
        output_limit=output_limit,
    )
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise OSError("policy process group did not terminate") from exc
    return process.returncode, timed_out


def _windows_kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CreateEventW.argtypes = (
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    )
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.SetEvent.argtypes = (wintypes.HANDLE,)
    kernel32.SetEvent.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _create_windows_kill_job(kernel32):
    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = (
            ("read_operation_count", ctypes.c_uint64),
            ("write_operation_count", ctypes.c_uint64),
            ("other_operation_count", ctypes.c_uint64),
            ("read_transfer_count", ctypes.c_uint64),
            ("write_transfer_count", ctypes.c_uint64),
            ("other_transfer_count", ctypes.c_uint64),
        )

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = (
            ("per_process_user_time_limit", ctypes.c_int64),
            ("per_job_user_time_limit", ctypes.c_int64),
            ("limit_flags", wintypes.DWORD),
            ("minimum_working_set_size", ctypes.c_size_t),
            ("maximum_working_set_size", ctypes.c_size_t),
            ("active_process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority_class", wintypes.DWORD),
            ("scheduling_class", wintypes.DWORD),
        )

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = (
            ("basic_limit_information", _BasicLimitInformation),
            ("io_info", _IoCounters),
            ("process_memory_limit", ctypes.c_size_t),
            ("job_memory_limit", ctypes.c_size_t),
            ("peak_process_memory_used", ctypes.c_size_t),
            ("peak_job_memory_used", ctypes.c_size_t),
        )

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    information = _ExtendedLimitInformation()
    information.basic_limit_information.limit_flags = 0x00002000
    if not kernel32.SetInformationJobObject(
        job,
        9,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(job)
        raise error
    return job


def _run_windows_policy_process(
    argv: Sequence[str],
    *,
    stdin_stream,
    stdout_stream,
    stderr_stream,
    timeout_seconds: float,
    cwd: str | None,
    environment: Mapping[str, str] | None,
    output_limit: int | None = None,
) -> tuple[int, bool]:
    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_kernel32()
    job = _create_windows_kill_job(kernel32)
    event = kernel32.CreateEventW(None, True, False, None)
    if not event:
        error = ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(job)
        raise error
    process: subprocess.Popen[bytes] | None = None
    assigned = False
    timed_out = False
    try:
        os.set_handle_inheritable(int(event), True)
        startup = subprocess.STARTUPINFO()
        startup.lpAttributeList = {"handle_list": [int(event)]}
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _WINDOWS_POLICY_WRAPPER,
                    str(int(event)),
                    json.dumps(cwd),
                    json.dumps(
                        None if environment is None else dict(environment),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    *argv,
                ],
                stdin=stdin_stream,
                stdout=stdout_stream,
                stderr=stderr_stream,
                close_fds=True,
                startupinfo=startup,
                shell=False,
            )
        finally:
            os.set_handle_inheritable(int(event), False)
        if not kernel32.AssignProcessToJobObject(
            job, wintypes.HANDLE(int(process._handle))
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        assigned = True
        if not kernel32.SetEvent(event):
            raise ctypes.WinError(ctypes.get_last_error())
        timed_out = _wait_for_process(
            process,
            timeout_seconds,
            output_streams=(("stdout", stdout_stream), ("stderr", stderr_stream)),
            output_limit=output_limit,
        )
        if not kernel32.TerminateJobObject(job, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        wait_result = kernel32.WaitForSingleObject(
            job, max(1, math.ceil(_PROCESS_CLEANUP_GRACE_SECONDS * 1000))
        )
        if wait_result == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        if wait_result == 0x00000102:
            raise OSError("policy process job did not terminate")
        if process.poll() is None:
            process.wait(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
        return process.returncode, timed_out
    finally:
        if process is not None and process.poll() is None:
            if assigned:
                kernel32.TerminateJobObject(job, 1)
            else:
                process.kill()
            try:
                process.wait(timeout=_PROCESS_CLEANUP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        kernel32.CloseHandle(event)
        kernel32.CloseHandle(job)


def _run_policy_process(
    argv: Sequence[str],
    input_bytes: bytes,
    *,
    timeout_seconds: float,
    cwd: str | None,
    environment: Mapping[str, str] | None,
    output_limit: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run one child to completion, killing its process family on timeout.

    `output_limit` (bytes per stream) is for callers that cannot trust the child
    to stay quiet, such as hook runs. `None`, the kernel `process:` path, adds
    nothing: no sizing, no bounded read, and the runners get no extra argument.
    With a limit, exceeding it kills the family through the same path as a
    timeout and raises ProcessOutputLimitExceeded, which takes precedence over
    a timeout that ran out in the same slice.
    """

    extra = {} if output_limit is None else {"output_limit": output_limit}
    with (
        tempfile.TemporaryFile() as stdin_stream,
        tempfile.TemporaryFile() as stdout_stream,
        tempfile.TemporaryFile() as stderr_stream,
    ):
        stdin_stream.write(input_bytes)
        stdin_stream.seek(0)
        if os.name == "nt":
            returncode, timed_out = _run_windows_policy_process(
                argv,
                stdin_stream=stdin_stream,
                stdout_stream=stdout_stream,
                stderr_stream=stderr_stream,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                environment=environment,
                **extra,
            )
        else:
            returncode, timed_out = _run_posix_policy_process(
                argv,
                stdin_stream=stdin_stream,
                stdout_stream=stdout_stream,
                stderr_stream=stderr_stream,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                environment=environment,
                **extra,
            )
        if output_limit is not None:
            # The family is dead, so the files are final (bar an escapee).
            streams = (("stdout", stdout_stream), ("stderr", stderr_stream))
            overflowed = _stream_over_limit(streams, output_limit)
            if overflowed is not None:
                raise ProcessOutputLimitExceeded(overflowed, output_limit)
        if timed_out:
            raise subprocess.TimeoutExpired(list(argv), timeout_seconds)
        stdout = _read_process_stream(stdout_stream, output_limit)
        stderr = _read_process_stream(stderr_stream, output_limit)
        if output_limit is not None:
            # A descendant that escaped the family may write after the sizing
            # above; the bounded read notices without reading any further.
            for name, data in (("stdout", stdout), ("stderr", stderr)):
                if len(data) > output_limit:
                    raise ProcessOutputLimitExceeded(name, output_limit)
        if (
            os.name == "nt"
            and returncode == 127
            and stderr.startswith(_WINDOWS_EXEC_FAILURE_PREFIX)
        ):
            raise OSError("policy process executable could not start")
        return subprocess.CompletedProcess(list(argv), returncode, stdout, stderr)


class _DuplicateJsonKeyError(ValueError):
    """A JSON object repeated a member name and is structurally ambiguous."""


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKeyError(key)
        value[key] = item
    return value


@dataclass(frozen=True)
class SourceFailure:
    """One machine-readable reason a policy result is not fully trustworthy."""

    code: str
    message: str
    event_id: str | None = None

    def as_dict(self) -> dict[str, str]:
        value = {"code": self.code, "message": self.message}
        if self.event_id is not None:
            value["event_id"] = self.event_id
        return value


@dataclass(frozen=True)
class PolicySourceResult:
    """Ordered decisions plus validation/evaluation failures."""

    decisions: tuple[dict[str, Any], ...]
    failures: tuple[SourceFailure, ...] = ()
    diagnostics: tuple[str, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.failures


def _cleanup_snapshot_root(root: Path) -> SourceFailure | None:
    def is_link_or_reparse(metadata: os.stat_result) -> bool:
        return stat.S_ISLNK(metadata.st_mode) or bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )

    def make_tree_writable(directory: Path) -> None:
        metadata = directory.lstat()
        if is_link_or_reparse(metadata):
            raise OSError("private snapshot root became a link")
        directory.chmod(stat.S_IRWXU)
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if is_link_or_reparse(metadata):
                    continue
                path = Path(entry.path)
                if stat.S_ISDIR(metadata.st_mode):
                    make_tree_writable(path)
                else:
                    path.chmod(stat.S_IRWXU)

    def make_writable_and_retry(function, raw_path, _exc_info) -> None:
        path = Path(raw_path)
        metadata = path.lstat()
        if is_link_or_reparse(metadata):
            if stat.S_ISDIR(metadata.st_mode):
                path.rmdir()
            else:
                path.unlink()
            return
        path.chmod(stat.S_IRWXU)
        function(raw_path)

    try:
        make_tree_writable(root)
        shutil.rmtree(root, onerror=make_writable_and_retry)
    except FileNotFoundError:
        pass
    except OSError:
        pass
    if os.path.lexists(root):
        return SourceFailure(
            "process-snapshot-cleanup-failed",
            "The private policy process snapshot could not be removed.",
        )
    return None


def _raise_walk_error(error: OSError) -> None:
    raise error


def _normalize_snapshot_mtimes(root: Path) -> None:
    """Set every copied modification time to the replay v0 fixed epoch."""

    for raw_directory, directory_names, file_names in os.walk(
        root, topdown=False, onerror=_raise_walk_error
    ):
        directory = Path(raw_directory)
        for name in file_names:
            path = directory / name
            metadata = path.stat()
            os.utime(
                path,
                ns=(metadata.st_atime_ns, SNAPSHOT_MTIME_NS),
            )
        for name in directory_names:
            path = directory / name
            metadata = path.stat()
            os.utime(
                path,
                ns=(metadata.st_atime_ns, SNAPSHOT_MTIME_NS),
            )
    metadata = root.stat()
    os.utime(
        root,
        ns=(metadata.st_atime_ns, SNAPSHOT_MTIME_NS),
    )


def _snapshot_mtimes_are_normalized(root: Path) -> bool:
    """Return whether the root and every copied entry retain the fixed mtime."""

    if root.stat().st_mtime_ns != SNAPSHOT_MTIME_NS:
        return False
    for raw_directory, directory_names, file_names in os.walk(
        root, onerror=_raise_walk_error
    ):
        directory = Path(raw_directory)
        for name in (*directory_names, *file_names):
            if (directory / name).stat().st_mtime_ns != SNAPSHOT_MTIME_NS:
                return False
    return True


@dataclass(frozen=True)
class _ProcessInputSnapshot:
    """Private execution paths that contain the exact bound process inputs."""

    root: Path
    argv: tuple[str, ...]
    cwd: str
    executable_sha256: str
    executable_permissions: str
    policy_sha256: str
    policy_tree_sha256: str

    def verification_failure(self) -> SourceFailure | None:
        executable = Path(self.argv[0])
        policy_tree = Path(self.cwd)
        policy = policy_tree / self.argv[-1]
        try:
            actual_executable = sha256_file(executable)
            actual_executable_permissions = permission_bits(executable)
            actual_policy = sha256_file(policy)
            actual_tree = sha256_tree(policy_tree)
            mtimes_are_normalized = _snapshot_mtimes_are_normalized(self.root)
        except OSError:
            return SourceFailure(
                "process-snapshot-changed",
                "The private policy process snapshot became unavailable.",
            )
        if (
            actual_executable != self.executable_sha256
            or actual_executable_permissions != self.executable_permissions
            or actual_policy != self.policy_sha256
            or actual_tree != self.policy_tree_sha256
            or not mtimes_are_normalized
        ):
            return SourceFailure(
                "process-snapshot-changed",
                "The private policy process snapshot changed after capture.",
            )
        return None

    def cleanup(self) -> SourceFailure | None:
        return _cleanup_snapshot_root(self.root)


@dataclass(frozen=True)
class RecordedPolicyManifest:
    """Validated identity and exact-byte binding for a recorded source."""

    policy_id: str
    policy_commit: str
    decisions_file: str
    decisions_sha256: str
    decision_count: int


def _manifest_path(decisions_path: Path) -> Path:
    return Path(f"{decisions_path}.manifest.json")


def _require_manifest_string(
    value: dict[str, object], field: str, *, pattern: re.Pattern[str] | None = None
) -> str:
    candidate = value.get(field)
    if not isinstance(candidate, str) or not candidate:
        raise ValidationError(f"RecordedPolicyManifest.{field}: expected a string")
    if "\r" in candidate or "\n" in candidate:
        raise ValidationError(f"RecordedPolicyManifest.{field}: must be a single line")
    if pattern is not None and not pattern.fullmatch(candidate):
        raise ValidationError(f"RecordedPolicyManifest.{field}: invalid value")
    return candidate


def validate_recorded_manifest(value: object) -> RecordedPolicyManifest:
    """Validate the bounded recorded-policy sidecar schema."""

    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValidationError("RecordedPolicyManifest: expected a JSON object")
    required = (
        "schema_version",
        "policy_id",
        "policy_commit",
        "decisions_file",
        "decisions_sha256",
        "decision_count",
    )
    missing = [field for field in required if field not in value]
    if missing:
        raise ValidationError(
            "RecordedPolicyManifest: missing required field(s): " + ", ".join(missing)
        )
    unexpected = sorted(set(value) - set(required))
    if unexpected:
        raise ValidationError(
            "RecordedPolicyManifest: unexpected field(s): " + ", ".join(unexpected)
        )
    if value["schema_version"] != RECORDED_MANIFEST_VERSION:
        raise ValidationError(
            "RecordedPolicyManifest.schema_version: expected "
            f"{RECORDED_MANIFEST_VERSION!r}"
        )
    decision_count = value["decision_count"]
    if (
        not isinstance(decision_count, int)
        or isinstance(decision_count, bool)
        or decision_count < 0
    ):
        raise ValidationError(
            "RecordedPolicyManifest.decision_count: expected a non-negative integer"
        )
    return RecordedPolicyManifest(
        policy_id=_require_manifest_string(value, "policy_id"),
        policy_commit=_require_manifest_string(
            value, "policy_commit", pattern=_GIT_COMMIT
        ),
        decisions_file=_require_manifest_string(value, "decisions_file"),
        decisions_sha256=_require_manifest_string(
            value, "decisions_sha256", pattern=_SHA256
        ),
        decision_count=decision_count,
    )


def _indeterminate(event_id: str, code: str, source_label: str) -> dict[str, str]:
    return {
        "schema_version": POLICY_DECISION_VERSION,
        "event_id": event_id,
        "effect": "indeterminate",
        "reason": f"{source_label} decision unavailable: {code}.",
    }


def _all_indeterminate(
    events: list[dict[str, Any]],
    failure: SourceFailure,
    source_label: str,
    *,
    diagnostics: tuple[str, ...] = (),
) -> PolicySourceResult:
    return PolicySourceResult(
        tuple(
            _indeterminate(event["event_id"], failure.code, source_label)
            for event in events
        ),
        (failure,),
        diagnostics,
    )


def _evaluate_decision_lines(
    events: list[dict[str, Any]],
    lines: list[str],
    *,
    code_prefix: str,
    source_label: str,
    require_order: bool,
    initial_failures: Sequence[SourceFailure] = (),
    diagnostics: tuple[str, ...] = (),
) -> PolicySourceResult:
    """Validate JSONL decisions and restore corpus order without guessing."""

    expected_ids = {event["event_id"] for event in events}
    event_positions = {
        event["event_id"]: position for position, event in enumerate(events)
    }
    by_event_id: dict[str, dict[str, Any]] = {}
    untrustworthy_ids: set[str] = set()
    failures = list(initial_failures)
    last_position = -1

    for line_number, line in enumerate(lines, start=1):
        try:
            raw_value = json.loads(line, object_pairs_hook=_unique_json_object)
        except ValueError:
            # JSON syntax, duplicate keys, and decoder integer limits are
            # invalid source evidence, not uncaught runner exceptions.
            failures.append(
                SourceFailure(
                    f"{code_prefix}-json-invalid",
                    f"{source_label} decision line {line_number} is invalid JSON.",
                )
            )
            continue

        raw_event_id = (
            raw_value.get("event_id")
            if isinstance(raw_value, dict)
            and isinstance(raw_value.get("event_id"), str)
            else None
        )
        try:
            decision = validate_policy_decision(raw_value)
        except ValidationError as exc:
            if raw_event_id:
                untrustworthy_ids.add(raw_event_id)
                by_event_id.pop(raw_event_id, None)
            failures.append(
                SourceFailure(
                    f"{code_prefix}-schema-invalid",
                    f"{source_label} decision line {line_number} is invalid: {exc}",
                    raw_event_id,
                )
            )
            continue

        event_id = decision["event_id"]
        if event_id not in expected_ids:
            failures.append(
                SourceFailure(
                    f"{code_prefix}-unexpected-event",
                    f"{source_label} decision has no matching corpus event.",
                    event_id,
                )
            )
            continue
        if event_id in by_event_id or event_id in untrustworthy_ids:
            by_event_id.pop(event_id, None)
            untrustworthy_ids.add(event_id)
            failures.append(
                SourceFailure(
                    f"{code_prefix}-duplicate-event",
                    f"{source_label} decision event_id is duplicated.",
                    event_id,
                )
            )
            continue

        position = event_positions[event_id]
        if require_order and position <= last_position:
            failure = SourceFailure(
                f"{code_prefix}-order-invalid",
                f"{source_label} decisions are not in corpus order.",
                event_id,
            )
            return PolicySourceResult(
                tuple(
                    _indeterminate(event["event_id"], failure.code, source_label)
                    for event in events
                ),
                tuple([*failures, failure]),
                diagnostics,
            )
        last_position = position
        by_event_id[event_id] = decision

    ordered: list[dict[str, Any]] = []
    for event in events:
        event_id = event["event_id"]
        decision = by_event_id.get(event_id)
        if decision is not None and event_id not in untrustworthy_ids:
            ordered.append(decision)
            continue
        if event_id not in untrustworthy_ids:
            failures.append(
                SourceFailure(
                    f"{code_prefix}-missing-event",
                    f"{source_label} decision is missing for the corpus event.",
                    event_id,
                )
            )
            code = f"{code_prefix}-missing-event"
        else:
            code = f"{code_prefix}-untrustworthy-event"
        ordered.append(_indeterminate(event_id, code, source_label))

    return PolicySourceResult(tuple(ordered), tuple(failures), diagnostics)


class RecordedDecisionSource:
    """Read an exact-byte-bound JSONL decision recording without policy execution."""

    def __init__(
        self,
        decisions_path: str | Path,
        manifest_path: str | Path | None = None,
        *,
        decisions_bytes: bytes | None = None,
        manifest_bytes: bytes | None = None,
    ) -> None:
        if (decisions_bytes is None) != (manifest_bytes is None):
            raise ValueError(
                "captured recorded decisions and manifest bytes must be supplied together"
            )
        self.decisions_path = Path(decisions_path)
        self.manifest_path = (
            Path(manifest_path)
            if manifest_path is not None
            else _manifest_path(self.decisions_path)
        )
        self.decisions_bytes = decisions_bytes
        self.manifest_bytes = manifest_bytes

    def evaluate(self, event_values: list[object]) -> PolicySourceResult:
        events = validate_command_events(event_values)

        try:
            manifest_bytes = (
                self.manifest_path.read_bytes()
                if self.manifest_bytes is None
                else self.manifest_bytes
            )
            manifest_value = json.loads(
                manifest_bytes.decode("utf-8"), object_pairs_hook=_unique_json_object
            )
            manifest = validate_recorded_manifest(manifest_value)
        except (OSError, ValueError) as exc:
            failure = SourceFailure(
                "recording-manifest-invalid",
                f"Recorded manifest is invalid: {exc.__class__.__name__}.",
            )
            return _all_indeterminate(events, failure, "Recorded")

        if manifest.decisions_file != self.decisions_path.name:
            failure = SourceFailure(
                "recording-file-mismatch",
                "Recorded manifest names a different decisions file.",
            )
            return _all_indeterminate(events, failure, "Recorded")

        try:
            decision_bytes = (
                self.decisions_path.read_bytes()
                if self.decisions_bytes is None
                else self.decisions_bytes
            )
        except OSError as exc:
            failure = SourceFailure(
                "recording-read-failed",
                f"Recorded decisions could not be read: {exc.__class__.__name__}.",
            )
            return _all_indeterminate(events, failure, "Recorded")

        actual_digest = hashlib.sha256(decision_bytes).hexdigest()
        if actual_digest != manifest.decisions_sha256:
            failure = SourceFailure(
                "recording-digest-mismatch",
                "Recorded decisions do not match the manifest SHA-256.",
            )
            return _all_indeterminate(events, failure, "Recorded")

        try:
            lines = split_jsonl_records(decision_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            failure = SourceFailure(
                "recording-utf8-invalid",
                "Recorded decisions are not valid UTF-8.",
            )
            return _all_indeterminate(events, failure, "Recorded")

        if len(lines) != manifest.decision_count:
            failure = SourceFailure(
                "recording-count-mismatch",
                "Recorded decision count does not match the manifest.",
            )
            return _all_indeterminate(events, failure, "Recorded")

        return _evaluate_decision_lines(
            events,
            lines,
            code_prefix="recording",
            source_label="Recorded",
            require_order=False,
        )


class ProcessDecisionSource:
    """Evaluate a JSONL policy process through a shell-free argv contract."""

    def __init__(self, argv: Sequence[str], *, timeout_seconds: float = 30.0) -> None:
        if isinstance(argv, (str, bytes)) or not argv:
            raise ValueError("process argv must be a non-empty sequence of strings")
        if any(not isinstance(argument, str) for argument in argv) or not argv[0]:
            raise ValueError("process argv must be a non-empty sequence of strings")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("process timeout must be a finite positive number")
        self.argv = tuple(argv)
        self.timeout_seconds = float(timeout_seconds)
        self.cwd: str | None = None
        self.environment: dict[str, str] | None = None
        self.executable_binding: tuple[Path, str, str, str] | None = None
        self.policy_tree_binding: tuple[Path, str, str] | None = None
        self.snapshot_identity: str | None = None
        self.snapshot_parent: Path | None = None

    def with_runtime(
        self,
        *,
        cwd: str | Path,
        environment: Mapping[str, str],
    ) -> ProcessDecisionSource:
        """Bind a deterministic CLI runtime without expanding the process contract."""

        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in environment.items()
        ):
            raise ValueError("process environment must contain only string pairs")
        self.cwd = str(cwd)
        self.environment = dict(environment)
        return self

    def with_input_binding(
        self,
        *,
        executable_path: str | Path,
        executable_invocation_name: str,
        executable_sha256: str,
        executable_permissions: str,
        policy_tree_path: str | Path,
        policy_sha256: str,
        policy_tree_sha256: str,
        snapshot_identity: str,
        snapshot_parent_path: str | Path,
    ) -> ProcessDecisionSource:
        """Bind the executable and policy tree copied into a validated snapshot."""

        if (
            not _SHA256.fullmatch(executable_sha256)
            or not _SHA256.fullmatch(policy_sha256)
            or not _SHA256.fullmatch(policy_tree_sha256)
            or not _SHA256.fullmatch(snapshot_identity)
        ):
            raise ValueError("process input bindings require lowercase SHA-256 digests")
        if not re.fullmatch(r"[0-7]{4}", executable_permissions):
            raise ValueError(
                "process executable binding requires four octal permission digits"
            )
        if (
            not executable_invocation_name
            or executable_invocation_name in {".", ".."}
            or "/" in executable_invocation_name
            or "\\" in executable_invocation_name
            or "\0" in executable_invocation_name
        ):
            raise ValueError(
                "process executable invocation name must be one path component"
            )
        self.executable_binding = (
            Path(executable_path),
            executable_invocation_name,
            executable_sha256,
            executable_permissions,
        )
        self.policy_tree_binding = (
            Path(policy_tree_path),
            policy_sha256,
            policy_tree_sha256,
        )
        bound_snapshot_parent = Path(snapshot_parent_path)
        try:
            resolved_snapshot_parent = bound_snapshot_parent.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(
                "process snapshot parent must be a resolved directory"
            ) from exc
        if (
            not bound_snapshot_parent.is_absolute()
            or bound_snapshot_parent != resolved_snapshot_parent
            or not bound_snapshot_parent.is_dir()
        ):
            raise ValueError("process snapshot parent must be a resolved directory")
        self.snapshot_identity = snapshot_identity
        self.snapshot_parent = bound_snapshot_parent
        return self

    @staticmethod
    def _snapshot_failure(
        events: list[dict[str, Any]],
        *,
        code: str,
        message: str,
        snapshot_root: Path | None = None,
    ) -> PolicySourceResult:
        failure = SourceFailure(code, message)
        result = _all_indeterminate(events, failure, "Process")
        if snapshot_root is None:
            return result
        cleanup_failure = _cleanup_snapshot_root(snapshot_root)
        if cleanup_failure is None:
            return result
        return PolicySourceResult(
            result.decisions,
            result.failures + (cleanup_failure,),
            result.diagnostics,
        )

    def _prepare_input_snapshot(
        self, events: list[dict[str, Any]]
    ) -> _ProcessInputSnapshot | PolicySourceResult | None:
        if self.executable_binding is None and self.policy_tree_binding is None:
            return None
        if (
            self.executable_binding is None
            or self.policy_tree_binding is None
            or self.snapshot_identity is None
            or self.snapshot_parent is None
            or self.cwd is None
            or len(self.argv) < 2
            or Path(self.argv[-1]).name != self.argv[-1]
        ):
            return self._snapshot_failure(
                events,
                code="process-input-binding-invalid",
                message="Policy process input bindings are incomplete.",
            )

        (
            executable_path,
            executable_invocation_name,
            expected_executable,
            expected_executable_permissions,
        ) = self.executable_binding
        policy_tree_path, expected_policy, expected_tree = self.policy_tree_binding
        try:
            if (
                self.snapshot_parent.resolve(strict=True) != self.snapshot_parent
                or not self.snapshot_parent.is_dir()
            ):
                raise OSError
        except (OSError, RuntimeError):
            return self._snapshot_failure(
                events,
                code="process-snapshot-unavailable",
                message="The private policy process snapshot parent became unavailable.",
            )
        snapshot_root = self.snapshot_parent / (
            f"replay-process-inputs-{self.snapshot_identity}"
        )
        try:
            resolved_policy_tree = policy_tree_path.resolve()
            resolved_snapshot_root = snapshot_root.resolve(strict=False)
            if resolved_snapshot_root == resolved_policy_tree or (
                resolved_policy_tree in resolved_snapshot_root.parents
            ):
                return self._snapshot_failure(
                    events,
                    code="process-snapshot-overlaps-input",
                    message=(
                        "The private policy process snapshot would overlap the "
                        "bound policy tree."
                    ),
                )
            snapshot_root.mkdir(mode=_RUNNER_DIRECTORY_MODE)
        except (OSError, RuntimeError):
            return self._snapshot_failure(
                events,
                code="process-snapshot-unavailable",
                message="A private policy process snapshot could not be created.",
            )
        try:
            if os.name != "nt":
                snapshot_root.chmod(_RUNNER_DIRECTORY_MODE)
        except OSError:
            return self._snapshot_failure(
                events,
                code="process-snapshot-unavailable",
                message="A private policy process snapshot could not be secured.",
                snapshot_root=snapshot_root,
            )

        snapshot_executable = snapshot_root / "executable" / executable_invocation_name
        snapshot_policy_tree = snapshot_root / "policy"
        snapshot_policy = snapshot_policy_tree / self.argv[-1]
        try:
            snapshot_executable.parent.mkdir(mode=_RUNNER_DIRECTORY_MODE)
            if os.name != "nt":
                snapshot_executable.parent.chmod(_RUNNER_DIRECTORY_MODE)
            shutil.copy2(executable_path, snapshot_executable)
            for companion in executable_path.parent.iterdir():
                companion_name = companion.name.lower()
                if (
                    companion != executable_path
                    and companion.is_file()
                    and (
                        companion.suffix.lower() in {".dll", ".dylib", ".so"}
                        or ".so." in companion_name
                    )
                ):
                    shutil.copy2(
                        companion,
                        snapshot_executable.parent / companion.name,
                    )
            shutil.copytree(policy_tree_path, snapshot_policy_tree)
        except (OSError, shutil.Error):
            return self._snapshot_failure(
                events,
                code="process-input-changed",
                message=(
                    "Bound policy process inputs became unavailable while their "
                    "private snapshot was created."
                ),
                snapshot_root=snapshot_root,
            )
        try:
            _normalize_snapshot_mtimes(snapshot_root)
        except (OSError, NotImplementedError):
            return self._snapshot_failure(
                events,
                code="process-snapshot-unavailable",
                message="The private policy process snapshot could not be normalized.",
                snapshot_root=snapshot_root,
            )
        try:
            actual_executable = sha256_file(snapshot_executable)
            actual_executable_permissions = permission_bits(snapshot_executable)
            actual_policy = sha256_file(snapshot_policy)
            actual_tree = sha256_tree(snapshot_policy_tree)
        except OSError:
            return self._snapshot_failure(
                events,
                code="process-input-changed",
                message=(
                    "Bound policy process inputs became unavailable while their "
                    "private snapshot was created."
                ),
                snapshot_root=snapshot_root,
            )
        if (
            not snapshot_policy.is_file()
            or actual_executable != expected_executable
            or actual_executable_permissions != expected_executable_permissions
            or actual_policy != expected_policy
            or actual_tree != expected_tree
        ):
            return self._snapshot_failure(
                events,
                code="process-input-changed",
                message=(
                    "Bound policy process inputs changed before their private "
                    "snapshot was complete."
                ),
                snapshot_root=snapshot_root,
            )

        return _ProcessInputSnapshot(
            root=snapshot_root,
            argv=(
                str(snapshot_executable),
                *self.argv[1:-1],
                self.argv[-1],
            ),
            cwd=str(snapshot_policy_tree),
            executable_sha256=expected_executable,
            executable_permissions=expected_executable_permissions,
            policy_sha256=expected_policy,
            policy_tree_sha256=expected_tree,
        )

    def _evaluate_runtime(
        self,
        events: list[dict[str, Any]],
        *,
        argv: Sequence[str],
        cwd: str | None,
    ) -> PolicySourceResult:
        input_bytes = "".join(
            f"{json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}\n"
            for event in events
        ).encode("utf-8")
        try:
            completed = _run_policy_process(
                list(argv),
                input_bytes,
                timeout_seconds=self.timeout_seconds,
                cwd=cwd,
                environment=self.environment,
            )
        except subprocess.TimeoutExpired:
            failure = SourceFailure(
                "process-timeout",
                "Policy process exceeded its configured timeout.",
            )
            return _all_indeterminate(events, failure, "Process")
        except OSError as exc:
            failure = SourceFailure(
                "process-start-failed",
                f"Policy process could not start: {exc.__class__.__name__}.",
            )
            return _all_indeterminate(events, failure, "Process")

        diagnostics = tuple(
            completed.stderr.decode("utf-8", errors="replace").splitlines()
        )
        try:
            lines = split_jsonl_records(completed.stdout.decode("utf-8"))
        except UnicodeDecodeError:
            failure = SourceFailure(
                "process-stdout-utf8-invalid",
                "Policy process standard output is not valid UTF-8.",
            )
            return _all_indeterminate(
                events, failure, "Process", diagnostics=diagnostics
            )

        failures: list[SourceFailure] = []
        if completed.returncode != 0:
            failures.append(
                SourceFailure(
                    "process-exit-nonzero",
                    f"Policy process exited with code {completed.returncode}.",
                )
            )

        return _evaluate_decision_lines(
            events,
            lines,
            code_prefix="process",
            source_label="Process",
            require_order=True,
            initial_failures=failures,
            diagnostics=diagnostics,
        )

    def evaluate(self, event_values: list[object]) -> PolicySourceResult:
        events = validate_command_events(event_values)
        snapshot_or_failure = self._prepare_input_snapshot(events)
        if isinstance(snapshot_or_failure, PolicySourceResult):
            return snapshot_or_failure
        snapshot = snapshot_or_failure
        argv = self.argv if snapshot is None else snapshot.argv
        cwd = self.cwd if snapshot is None else snapshot.cwd
        snapshot_failure = None if snapshot is None else snapshot.verification_failure()
        if snapshot_failure is not None:
            result = _all_indeterminate(events, snapshot_failure, "Process")
        else:
            try:
                result = self._evaluate_runtime(events, argv=argv, cwd=cwd)
            except BaseException:
                if snapshot is not None:
                    snapshot.cleanup()
                raise
        if snapshot is None:
            return result
        post_execution_failure = (
            None if snapshot_failure is not None else snapshot.verification_failure()
        )
        if post_execution_failure is not None:
            invalidated = _all_indeterminate(
                events,
                post_execution_failure,
                "Process",
                diagnostics=result.diagnostics,
            )
            result = PolicySourceResult(
                invalidated.decisions,
                result.failures + invalidated.failures,
                invalidated.diagnostics,
            )
        cleanup_failure = snapshot.cleanup()
        if cleanup_failure is None:
            return result
        return PolicySourceResult(
            result.decisions,
            result.failures + (cleanup_failure,),
            result.diagnostics,
        )
