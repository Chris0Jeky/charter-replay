"""Dependency-free command line entry point for replay v0."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any

from charter_replay.compare import ComparisonError, compare_decisions
from charter_replay.corpus import (
    ValidationError,
    split_jsonl_records,
    validate_charter_cases,
    validate_command_events,
)
from charter_replay.digests import (
    canonical_json_bytes,
    permission_bits,
    sha256_bytes,
    sha256_file,
    sha256_tree,
)
from charter_replay.manifests import (
    ManifestError,
    RUN_GATE_CLASSES,
    build_run_manifest,
    load_corpus_manifest,
    manifest_json_bytes,
)
from charter_replay.policy_sources import (
    PolicySourceResult,
    ProcessDecisionSource,
    RecordedDecisionSource,
    SNAPSHOT_MTIME_NS,
    validate_recorded_manifest,
)
from charter_replay.reports import (
    build_json_report,
    render_markdown_report,
    report_json_bytes,
)

EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_INPUT_INVALID = 2
EXIT_SOURCE_FAILED = 3

DEFAULT_FAIL_ON = ("newly-allowed", "newly-indeterminate")
PROCESS_IDENTITY_VERSION = "process-policy-identity.v9"
PROCESS_ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
}


class ReplayInputError(ValueError):
    """A CLI input cannot satisfy the replay v0 contract."""


@dataclass(frozen=True)
class LoadedCharterCorpus:
    events: list[dict[str, Any]]
    cases: list[dict[str, Any]]
    corpus_id: str
    event_count: int
    manifest_sha256: str


@dataclass(frozen=True)
class LoadedPolicySource:
    kind: str
    source: RecordedDecisionSource | ProcessDecisionSource
    identity: dict[str, str]


def _parse_fail_on(value: str) -> tuple[str, ...]:
    choices = value.split(",") if value else []
    if not choices or any(choice not in RUN_GATE_CLASSES for choice in choices):
        expected = ", ".join(sorted(RUN_GATE_CLASSES))
        raise argparse.ArgumentTypeError(
            f"expected a comma-separated selection from: {expected}"
        )
    if len(set(choices)) != len(choices):
        raise argparse.ArgumentTypeError("--fail-on values must not be duplicated")
    return tuple(choices)


def _parse_timeout(value: str) -> float:
    message = "timeout must be finite, greater than 0 and at most 86400 seconds"
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(message) from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 86400:
        raise argparse.ArgumentTypeError(message)
    return timeout


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m charter_replay.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    replay = subparsers.add_parser("replay", help="compare two policy sources")
    source_help = "recorded:<path>, process:<argv>, or process-json:<JSON-array>"
    replay.add_argument("--baseline", required=True, help=source_help)
    replay.add_argument("--candidate", required=True, help=source_help)
    replay.add_argument("--corpus", required=True)
    replay.add_argument("--output", required=True)
    replay.add_argument(
        "--fail-on",
        type=_parse_fail_on,
        default=DEFAULT_FAIL_ON,
        metavar="CLASS[,CLASS...]",
    )
    replay.add_argument("--timeout", type=_parse_timeout, default=30.0)

    validate = subparsers.add_parser("validate", help="validate a charter corpus")
    validate.add_argument("--corpus", required=True)
    return parser


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ReplayInputError(f"JSON object contains duplicate key {key!r}")
        value[key] = item
    return value


def _read_jsonl_bytes(value: bytes, label: str) -> list[object]:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReplayInputError(f"{label} is not readable UTF-8") from exc
    records: list[object] = []
    for line_number, line in enumerate(split_jsonl_records(text), start=1):
        try:
            records.append(json.loads(line, object_pairs_hook=_unique_json_object))
        except ReplayInputError:
            # Preserve the existing duplicate-key diagnostic.
            raise
        except ValueError as exc:
            raise ReplayInputError(
                f"{label} line {line_number} is not valid JSON"
            ) from exc
    return records


def _resolve_manifest_path(value: str) -> Path:
    path = Path(value)
    if path.is_dir():
        return path / "corpus-manifest.json"
    if path.name == "corpus-manifest.json":
        return path
    if path.name == "events.jsonl":
        return path.parent / "corpus-manifest.json"
    raise ReplayInputError(
        "corpus must name its directory, corpus-manifest.json, or bound events.jsonl"
    )


def _load_charter_corpus(value: str) -> LoadedCharterCorpus:
    manifest_path = _resolve_manifest_path(value)
    loaded = load_corpus_manifest(manifest_path)
    entries = {entry["path"]: entry for entry in loaded.value["files"]}
    captured_files = dict(loaded.file_bytes)
    required_paths = {"events.jsonl", "cases.jsonl"}
    if set(entries) != required_paths or set(captured_files) != required_paths:
        raise ReplayInputError(
            "charter corpus manifest must list exactly events.jsonl and cases.jsonl"
        )

    events = validate_command_events(
        _read_jsonl_bytes(captured_files["events.jsonl"], "events.jsonl")
    )
    cases = validate_charter_cases(
        _read_jsonl_bytes(captured_files["cases.jsonl"], "cases.jsonl")
    )
    if len(events) != loaded.value["event_count"]:
        raise ReplayInputError("corpus event_count does not match events.jsonl")
    if {event["event_id"] for event in events} != {case["event_id"] for case in cases}:
        raise ReplayInputError("charter cases do not match corpus event ids")
    return LoadedCharterCorpus(
        events=events,
        cases=cases,
        corpus_id=loaded.value["corpus_id"],
        event_count=loaded.value["event_count"],
        manifest_sha256=loaded.manifest_sha256,
    )


def _load_recorded_source(raw_path: str) -> LoadedPolicySource:
    path = Path(raw_path)
    manifest_path = Path(f"{path}.manifest.json")
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest_value = json.loads(
            manifest_bytes.decode("utf-8"), object_pairs_hook=_unique_json_object
        )
        manifest = validate_recorded_manifest(manifest_value)
        decision_bytes = path.read_bytes()
    except (ReplayInputError, ValidationError):
        # Structural validation already has its own bounded input diagnostic.
        raise
    except (OSError, ValueError) as exc:
        raise ReplayInputError(
            "recorded source or sidecar is not readable JSON"
        ) from exc
    if manifest.decisions_file != path.name:
        raise ReplayInputError("recorded sidecar names a different decisions file")
    if sha256_bytes(decision_bytes) != manifest.decisions_sha256:
        raise ReplayInputError("recorded source does not match its sidecar digest")
    try:
        line_count = len(split_jsonl_records(decision_bytes.decode("utf-8")))
    except UnicodeDecodeError as exc:
        raise ReplayInputError("recorded source is not valid UTF-8") from exc
    if line_count != manifest.decision_count:
        raise ReplayInputError("recorded source count does not match its sidecar")
    return LoadedPolicySource(
        kind="recorded",
        source=RecordedDecisionSource(
            path,
            manifest_path,
            decisions_bytes=decision_bytes,
            manifest_bytes=manifest_bytes,
        ),
        identity={
            "kind": "recorded",
            "id": manifest.policy_id,
            "sha256": sha256_bytes(manifest_bytes),
        },
    )


def _load_process_source(
    raw_argv: str, timeout: float, *, json_argv: bool = False
) -> LoadedPolicySource:
    if json_argv:
        try:
            argv = json.loads(raw_argv)
        except (ValueError, RecursionError) as exc:
            raise ReplayInputError("process-json source is not valid JSON") from exc
    else:
        # Do not guess JSON from brackets or reinterpret legacy quoting.
        argv = raw_argv.split(",")
    if (
        not isinstance(argv, list)
        or len(argv) < 2
        or any(
            not isinstance(item, str)
            or not item
            or any(character in item for character in "\0\r\n")
            for item in argv
        )
    ):
        raise ReplayInputError(
            "process source requires at least two nonempty, single-line argv strings "
            "without NUL, ending in a policy file"
        )
    try:
        for item in argv:
            item.encode("utf-8")
    except UnicodeError as exc:
        raise ReplayInputError("process argv must contain valid Unicode text") from exc
    policy_path = Path(argv[-1])
    if not policy_path.is_file():
        raise ReplayInputError("process source must end in a readable policy file")
    lexical_policy_path = policy_path.absolute()
    try:
        policy_tree_path = lexical_policy_path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReplayInputError("process policy parent could not be resolved") from exc
    resolved_executable = shutil.which(argv[0])
    executable_path = (
        Path(resolved_executable) if resolved_executable else Path(argv[0])
    )
    invocation_name = executable_path.name
    if not executable_path.is_file():
        raise ReplayInputError("process executable could not be resolved to a file")
    bound_executable_path = executable_path.resolve()
    try:
        policy_digest = sha256_file(policy_tree_path / lexical_policy_path.name)
        policy_tree_digest = sha256_tree(policy_tree_path)
        executable_digest = sha256_file(bound_executable_path)
        executable_permissions = permission_bits(bound_executable_path)
    except OSError as exc:
        raise ReplayInputError(
            "process executable or policy file could not be read"
        ) from exc
    try:
        snapshot_parent = Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReplayInputError("process snapshot parent could not be resolved") from exc
    runtime_environment = dict(PROCESS_ENVIRONMENT)
    normalized_environment = dict(PROCESS_ENVIRONMENT)
    if bound_executable_path == Path(sys.executable).resolve():
        runtime_environment["PYTHONHOME"] = sys.base_prefix
        normalized_environment["PYTHONHOME"] = "host-python-base-prefix"
    normalized_identity = {
        "schema_version": PROCESS_IDENTITY_VERSION,
        "executable": {
            "permission_bits": executable_permissions,
            "name": invocation_name,
            "sha256": executable_digest,
        },
        "arguments": argv[1:-1],
        "policy": {
            "name": lexical_policy_path.name,
            "sha256": policy_digest,
            "parent_tree_sha256": policy_tree_digest,
        },
        "environment": normalized_environment,
        "execution_inputs": "private-validated-identity-path-snapshot",
        "runner_directory_permission_bits": "0700",
        "snapshot_mtime_ns": SNAPSHOT_MTIME_NS,
        "snapshot_parent_sha256": sha256_bytes(os.fsencode(snapshot_parent)),
        "working_directory": "identity-bound-parent-and-derived-snapshot-policy-parent",
    }
    execution_argv = [
        str(bound_executable_path),
        *argv[1:-1],
        lexical_policy_path.name,
    ]
    try:
        source = ProcessDecisionSource(
            execution_argv, timeout_seconds=timeout
        ).with_runtime(
            cwd=lexical_policy_path.parent,
            environment=runtime_environment,
        )
        normalized_identity["timeout_seconds"] = source.timeout_seconds
        identity_sha256 = sha256_bytes(canonical_json_bytes(normalized_identity))
        source.with_input_binding(
            executable_path=bound_executable_path,
            executable_invocation_name=invocation_name,
            executable_sha256=executable_digest,
            executable_permissions=executable_permissions,
            policy_tree_path=policy_tree_path,
            policy_sha256=policy_digest,
            policy_tree_sha256=policy_tree_digest,
            snapshot_identity=identity_sha256,
            snapshot_parent_path=snapshot_parent,
        )
    except ValueError as exc:
        raise ReplayInputError(str(exc)) from exc
    return LoadedPolicySource(
        kind="process",
        source=source,
        identity={
            "kind": "process",
            "id": f"process-{identity_sha256}",
            "sha256": identity_sha256,
        },
    )


def _load_policy_source(value: str, timeout: float) -> LoadedPolicySource:
    kind, separator, payload = value.partition(":")
    if not separator or not payload:
        raise ReplayInputError(
            "policy source must use recorded:<path>, process:<argv>, "
            "or process-json:<JSON-array>"
        )
    if kind == "recorded":
        return _load_recorded_source(payload)
    if kind in {"process", "process-json"}:
        return _load_process_source(payload, timeout, json_argv=kind == "process-json")
    raise ReplayInputError(
        "policy source kind must be recorded, process, or process-json"
    )


def _generated_at() -> str:
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if raw_epoch is None:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    else:
        try:
            epoch = int(raw_epoch)
            if epoch < 0:
                raise ValueError
            timestamp = datetime.fromtimestamp(epoch, timezone.utc)
        except (ValueError, OSError, OverflowError) as exc:
            raise ReplayInputError(
                "SOURCE_DATE_EPOCH must be a non-negative supported integer"
            ) from exc
    return timestamp.isoformat().replace("+00:00", "Z")


def _reproduction_argv(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "-m",
        "charter_replay.cli",
        "replay",
        "--baseline",
        args.baseline,
        "--candidate",
        args.candidate,
        "--corpus",
        args.corpus,
        "--output",
        args.output,
        "--fail-on",
        ",".join(args.fail_on),
        "--timeout",
        str(args.timeout),
    ]


def _run_validate(args: argparse.Namespace) -> int:
    corpus = _load_charter_corpus(args.corpus)
    print(
        f"valid corpus {corpus.corpus_id}: {corpus.event_count} events; "
        f"manifest sha256 {corpus.manifest_sha256}"
    )
    return EXIT_OK


def _publish_report_set(
    output: Path,
    *,
    run_manifest_bytes: bytes,
    report_bytes: bytes,
    markdown_bytes: bytes,
) -> None:
    """Stage and transactionally replace the three report artifacts."""

    artifacts = (
        ("run-manifest.json", run_manifest_bytes),
        ("report.json", report_bytes),
        ("report.md", markdown_bytes),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=".replay-output-", dir=output.parent))
    staged = staging_root / "staged"
    previous = staging_root / "previous"
    preserve_staging = False
    try:
        staged.mkdir()
        previous.mkdir()
        for name, content in artifacts:
            (staged / name).write_bytes(content)

        output.mkdir(exist_ok=True)
        moved_previous: list[str] = []
        published: list[str] = []
        try:
            for name, _content in artifacts:
                target = output / name
                if target.is_symlink() or (target.exists() and not target.is_file()):
                    raise OSError(f"output artifact {name!r} is not a regular file")
                if target.exists():
                    target.replace(previous / name)
                    moved_previous.append(name)
            for name, _content in artifacts:
                (staged / name).replace(output / name)
                published.append(name)
        except OSError as publish_error:
            rollback_errors: list[OSError] = []
            for name in reversed(published):
                try:
                    (output / name).unlink()
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    rollback_errors.append(exc)
            for name in reversed(moved_previous):
                try:
                    (previous / name).replace(output / name)
                except OSError as exc:
                    rollback_errors.append(exc)
            if rollback_errors:
                preserve_staging = True
                raise OSError(
                    "report publication failed and rollback was incomplete; "
                    "recovery files were retained"
                ) from publish_error
            raise
    finally:
        if not preserve_staging:
            shutil.rmtree(staging_root, ignore_errors=True)


def _validated_output_path(
    raw_path: str,
    sources: tuple[LoadedPolicySource, ...],
) -> Path:
    """Keep runner reports outside bound process trees and reserved snapshots."""

    try:
        output = Path(raw_path).resolve()
        for loaded in sources:
            if loaded.kind != "process":
                continue
            source = loaded.source
            if (
                source.policy_tree_binding is None
                or source.snapshot_parent is None
                or source.snapshot_identity is None
            ):
                raise ReplayInputError("process source output boundary is unavailable")
            policy_root = source.policy_tree_binding[0].resolve(strict=True)
            snapshot_root = (
                source.snapshot_parent
                / f"replay-process-inputs-{source.snapshot_identity}"
            ).resolve()
            if output.is_relative_to(policy_root):
                raise ReplayInputError("output overlaps a bound process-policy tree")
            if output.is_relative_to(snapshot_root):
                raise ReplayInputError("output overlaps a reserved process snapshot")
            report_targets = {
                (output / name).resolve()
                for name in ("report.json", "report.md", "run-manifest.json")
            }
            for entry in policy_root.rglob("*"):
                if entry.is_symlink() and entry.resolve(strict=True) in report_targets:
                    raise ReplayInputError(
                        "output overlaps a bound process-policy file target"
                    )
    except ReplayInputError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise ReplayInputError("output boundary could not be resolved") from exc
    return Path(raw_path)


def _run_replay(args: argparse.Namespace) -> int:
    corpus = _load_charter_corpus(args.corpus)
    baseline = _load_policy_source(args.baseline, args.timeout)
    candidate = _load_policy_source(args.candidate, args.timeout)
    output = _validated_output_path(args.output, (baseline, candidate))
    run_manifest = build_run_manifest(
        generated_at=_generated_at(),
        baseline=baseline.identity,
        candidate=candidate.identity,
        corpus={
            "id": corpus.corpus_id,
            "manifest_sha256": corpus.manifest_sha256,
            "event_count": corpus.event_count,
        },
        fail_on=args.fail_on,
    )

    sources = (("baseline", baseline), ("candidate", candidate))
    results: dict[str, PolicySourceResult] = {}
    for name, loaded_source in sources:
        if loaded_source.kind != "recorded":
            continue
        result = loaded_source.source.evaluate(corpus.events)
        if result.failures:
            raise ReplayInputError(
                f"recorded {name} failed validation: "
                + ", ".join(failure.code for failure in result.failures)
            )
        results[name] = result
    for name, loaded_source in sources:
        if loaded_source.kind == "process":
            results[name] = loaded_source.source.evaluate(corpus.events)

    baseline_result = results["baseline"]
    candidate_result = results["candidate"]
    comparison = compare_decisions(
        corpus.events,
        list(baseline_result.decisions),
        list(candidate_result.decisions),
        case_values=corpus.cases,
    )
    report = build_json_report(
        comparison,
        run_manifest,
        baseline_failures=baseline_result.failures,
        candidate_failures=candidate_result.failures,
    )
    reproduction_argv = _reproduction_argv(args)
    reproduction_shell = "powershell" if os.name == "nt" else "posix-sh"

    try:
        _publish_report_set(
            output,
            run_manifest_bytes=manifest_json_bytes(run_manifest),
            report_bytes=report_json_bytes(report),
            markdown_bytes=render_markdown_report(
                report,
                reproduction_argv=reproduction_argv,
                reproduction_shell=reproduction_shell,
            ).encode("utf-8"),
        )
    except OSError as exc:
        print(f"replay output failed: {exc}", file=sys.stderr)
        return EXIT_SOURCE_FAILED

    if baseline_result.failures or candidate_result.failures:
        return EXIT_SOURCE_FAILED
    if report["gate"]["triggered"]:
        return EXIT_REGRESSION
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return its documented 0-3 exit code."""

    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            return _run_validate(args)
        return _run_replay(args)
    except (ReplayInputError, ManifestError, ValidationError, ComparisonError) as exc:
        print(f"replay input invalid: {exc}", file=sys.stderr)
        return EXIT_INPUT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
