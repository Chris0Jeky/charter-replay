"""Verified aggregate-only publication of a replay report (`aggregate.v1`).

The aggregate holds counts over fixed vocabularies and nothing else: no event
id, command, reason, family name, rationale, path, policy id, context id or
label text. Hashes of low-entropy inputs can be guessed, so none is included.

Three layers keep it that way. The builder reads only vocabulary keys from an
admitted report. The renderers refuse any document that is not exactly that
shape. `check_no_leak` then looks for every free-text value of the report in
the rendered bytes and refuses when one is found, whatever the cause.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from charter_replay.compare import DIFF_CLASSES, compare_decisions
from charter_replay.corpus import (
    CHARTER_CASE_VERSION,
    COMMAND_EVENT_VERSION,
    DECISION_EFFECTS,
    CASE_CLASSES,
    POLICY_DECISION_VERSION,
)
from charter_replay.hooks import FAILURE_OUTCOMES, OUTCOMES
from charter_replay.manifests import (
    RUN_GATE_CLASSES,
    RUN_MANIFEST_VERSION,
    _unique_object,
    validate_run_manifest,
)
from charter_replay.publication import PublicationError, new_destination
from charter_replay.reports import REPORT_VERSION, build_json_report
from charter_replay.variant_coverage import _finite_float, _reject_constant, _same
from charter_replay.variant_packs import _read_regular
from charter_replay.variant_review import _failures

AGGREGATE_VERSION = "aggregate.v1"
AGGREGATE_MARKER = f"<!-- charter-replay:{AGGREGATE_VERSION} -->"
AGGREGATE_JSON = "aggregate.json"
AGGREGATE_MD = "aggregate.md"
AGGREGATE_FILES = (AGGREGATE_JSON, AGGREGATE_MD)
# Sized for the whole fixed vocabulary at the largest count; a test renders that
# worst case, so the bound can be exceeded only when a vocabulary grows.
MAX_JSON_BYTES = 6 * 1024
MAX_MARKDOWN_BYTES = 4 * 1024
MAX_COUNT = 999_999_999_999
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
LEAK_MINIMUM = 4
OTHER = "other"
GATE_STATUSES = ("pass", "fail", "error")
SIDES = ("baseline", "candidate")

_RECORDING_SUFFIXES = (
    "json-invalid",
    "schema-invalid",
    "unexpected-event",
    "duplicate-event",
    "order-invalid",
    "missing-event",
    "untrustworthy-event",
)
# Every code the tool itself can put in `source_failures`. A code outside this
# set (an older or newer recording, a hand-made report) is counted as `other`.
FAILURE_CODES = tuple(
    sorted(
        {f"hook-{name}" for name in FAILURE_OUTCOMES}
        | {
            "hook-context-changed",
            "hook-context-unreadable",
            "hook-input-changed",
            "hook-input-unreadable",
            "hook-workspace-cleanup-failed",
            "process-exit-nonzero",
            "process-input-binding-invalid",
            "process-input-changed",
            "process-snapshot-changed",
            "process-snapshot-cleanup-failed",
            "process-snapshot-overlaps-input",
            "process-snapshot-unavailable",
            "process-start-failed",
            "process-stdout-utf8-invalid",
            "process-timeout",
            "recording-count-mismatch",
            "recording-digest-mismatch",
            "recording-file-mismatch",
            "recording-manifest-invalid",
            "recording-read-failed",
            "recording-utf8-invalid",
        }
        | {
            f"{prefix}-{suffix}"
            for prefix in ("process", "recording")
            for suffix in _RECORDING_SUFFIXES
        }
    )
)
FAILURE_KEYS = FAILURE_CODES + (OTHER,)

_TITLE = "## Guardrail replay (aggregate)"
_GATE = "Gate:"
_FAIL_ON = "fail on:"
_HEADINGS = ("Diff class", "Case class", "Outcome", "Source failure")
_COLUMNS = ("Events", "Baseline", "Candidate")
_SECTIONS = ("Cases by class", "Hook outcomes", "Source failures")
_NONE = "No source failures."
_UNAVAILABLE = "Hook outcomes are not part of this report directory."
_FOOTER = (
    "Case, policy, hook and context identifiers, commands, reasons, family names "
    "and paths are omitted. Small counts can still disclose information about a "
    "private corpus. Supplied labels are not independent safety evidence. No "
    "corpus command was executed. A green replay is not a proof of safety."
)
_VOCABULARY = (
    *DIFF_CLASSES,
    *OUTCOMES,
    *sorted(CASE_CLASSES),
    *sorted(DECISION_EFFECTS),
    *GATE_STATUSES,
    *sorted(RUN_GATE_CLASSES),
    *FAILURE_KEYS,
    *SIDES,
    AGGREGATE_VERSION,
    AGGREGATE_MARKER,
    REPORT_VERSION,
    RUN_MANIFEST_VERSION,
    CHARTER_CASE_VERSION,
    COMMAND_EVENT_VERSION,
    POLICY_DECISION_VERSION,
)
# Every word the artifacts can contain apart from counts. A corpus value that is
# already part of this fixed text says nothing about the corpus, so it is not
# a leak (a family named `unchanged`, `gate` or `hook`).
_STATIC_TEXT = "\n".join(
    (
        _TITLE,
        _GATE,
        _FAIL_ON,
        *_HEADINGS,
        *_COLUMNS,
        *_SECTIONS,
        _NONE,
        _UNAVAILABLE,
        _FOOTER,
        "schema_version gate status fail_on triggered counts case_classes events",
        "hook_outcomes source_failures",
        *_VOCABULARY,
    )
)


class AggregateInputError(ValueError):
    """The report or its manifest cannot be admitted. The text is fixed."""


class AggregateRefused(PublicationError):
    """A corpus value appeared in the rendered aggregate. The text is fixed."""


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNT:
        raise AggregateInputError("aggregate counts must be bounded integers")
    return value


def _json(data: bytes) -> Any:
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )


def admit_report(report_bytes: bytes, manifest_bytes: bytes) -> dict[str, Any]:
    """Re-derive the report from its run manifest and its own rows.

    The rows are compared again, the gate is rebuilt from the manifest and the
    source failures, and the result must equal the supplied report exactly.
    Nothing here reads the corpus, so this proves consistency, not authorship.
    """
    try:
        supplied, raw_manifest = _json(report_bytes), _json(manifest_bytes)
        manifest = validate_run_manifest(raw_manifest)
        if not _same(manifest, raw_manifest):
            raise ValueError("manifest is not canonical")
        if not isinstance(supplied, dict) or supplied.get("schema_version") != (
            REPORT_VERSION
        ):
            raise ValueError("not a report")
        rows = supplied["results"]
        keys = {"event", "case", "baseline", "candidate", "classification"}
        if not isinstance(rows, list) or not rows:
            raise ValueError("no results")
        if any(not isinstance(row, dict) or set(row) != keys for row in rows):
            raise ValueError("result shape")
        compared = compare_decisions(
            [row["event"] for row in rows],
            [row["baseline"] for row in rows],
            [row["candidate"] for row in rows],
            case_values=[row["case"] for row in rows],
        )
        failures = supplied["source_failures"]
        if not isinstance(failures, dict) or set(failures) != set(SIDES):
            raise ValueError("source failures")
        event_ids = {row.event["event_id"] for row in compared.results}
        rebuilt = build_json_report(
            compared,
            manifest,
            baseline_failures=_failures(failures["baseline"], event_ids),
            candidate_failures=_failures(failures["candidate"], event_ids),
        )
        if not _same(rebuilt, supplied):
            raise ValueError("report differs from its run manifest")
        return rebuilt
    except (ValueError, KeyError, TypeError, RecursionError, OSError) as exc:
        # No path, event id or parser excerpt in the diagnostic.
        raise AggregateInputError(
            "report does not match its run manifest; nothing was aggregated"
        ) from exc


def _zero(names: tuple[str, ...]) -> dict[str, int]:
    return dict.fromkeys(names, 0)


def _validated_outcomes(
    outcomes: dict[str, dict[str, int]] | None, events: int
) -> dict[str, dict[str, int]] | None:
    if outcomes is None:
        return None
    if not isinstance(outcomes, dict) or set(outcomes) != set(SIDES):
        raise AggregateInputError("hook outcomes must name both sides")
    result = {}
    for side in SIDES:
        row = outcomes[side]
        if not isinstance(row, dict) or set(row) != set(OUTCOMES):
            raise AggregateInputError("hook outcomes differ from the fixed vocabulary")
        result[side] = {name: _count(row[name]) for name in OUTCOMES}
        if sum(result[side].values()) != events:
            raise AggregateInputError("hook outcomes do not cover every event")
    return result


def build_aggregate(
    report: dict[str, Any],
    *,
    hook_outcomes: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """Pure: count an admitted report over fixed vocabularies only.

    `hook_outcomes` is optional because a kernel report directory does not hold
    them; it is then `None` (JSON null), never guessed.
    """
    classes = _zero(tuple(sorted(CASE_CLASSES)))
    for row in report["results"]:
        classes[row["case"]["case_class"]] += 1
    failures = {}
    for side in SIDES:
        counts = _zero(FAILURE_KEYS)
        for failure in report["source_failures"][side]:
            code = failure["code"]
            counts[code if code in counts else OTHER] += 1
        failures[side] = counts
    status = report["gate"]["status"]
    document = {
        "schema_version": AGGREGATE_VERSION,
        "gate": {
            "status": status,
            "fail_on": list(report["gate"]["fail_on"]),
            "triggered": list(report["gate"]["triggered"]),
        },
        "events": len(report["results"]),
        "counts": {name: report["counts"][name] for name in DIFF_CLASSES},
        "case_classes": classes,
        "hook_outcomes": _validated_outcomes(hook_outcomes, len(report["results"])),
        "source_failures": failures,
    }
    return validate_document(document)


def _mapping(value: object, names: tuple[str, ...]) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != set(names):
        raise AggregateInputError("aggregate document is not the fixed shape")
    return {name: _count(value[name]) for name in names}


def validate_document(document: object) -> dict[str, Any]:
    """Require exactly the fixed shape, so a renderer can only emit vocabulary."""
    keys = {
        "schema_version",
        "gate",
        "events",
        "counts",
        "case_classes",
        "hook_outcomes",
        "source_failures",
    }
    if not isinstance(document, dict) or set(document) != keys:
        raise AggregateInputError("aggregate document is not the fixed shape")
    if document["schema_version"] != AGGREGATE_VERSION:
        raise AggregateInputError("aggregate document is not the fixed shape")
    gate = document["gate"]
    if not isinstance(gate, dict) or set(gate) != {"status", "fail_on", "triggered"}:
        raise AggregateInputError("aggregate document is not the fixed shape")
    if gate["status"] not in GATE_STATUSES:
        raise AggregateInputError("aggregate document is not the fixed shape")
    for name in ("fail_on", "triggered"):
        chosen = gate[name]
        if (
            not isinstance(chosen, list)
            or len(set(chosen)) != len(chosen)
            or any(item not in RUN_GATE_CLASSES for item in chosen)
        ):
            raise AggregateInputError("aggregate document is not the fixed shape")
    outcomes = document["hook_outcomes"]
    if outcomes is not None:
        if not isinstance(outcomes, dict) or set(outcomes) != set(SIDES):
            raise AggregateInputError("aggregate document is not the fixed shape")
        outcomes = {side: _mapping(outcomes[side], OUTCOMES) for side in SIDES}
    failures = document["source_failures"]
    if not isinstance(failures, dict) or set(failures) != set(SIDES):
        raise AggregateInputError("aggregate document is not the fixed shape")
    return {
        "schema_version": AGGREGATE_VERSION,
        "gate": {
            "status": gate["status"],
            "fail_on": list(gate["fail_on"]),
            "triggered": list(gate["triggered"]),
        },
        "events": _count(document["events"]),
        "counts": _mapping(document["counts"], DIFF_CLASSES),
        "case_classes": _mapping(document["case_classes"], tuple(sorted(CASE_CLASSES))),
        "hook_outcomes": outcomes,
        "source_failures": {
            side: _mapping(failures[side], FAILURE_KEYS) for side in SIDES
        },
    }


def render_json(document: dict[str, Any]) -> bytes:
    """Deterministic bytes: sorted keys, ASCII, no timing, LF-terminated."""
    text = json.dumps(
        validate_document(document),
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    )
    data = (text + "\n").encode("ascii")
    if len(data) > MAX_JSON_BYTES:
        raise AggregateInputError("aggregate exceeds its byte bound")
    return data


def render_markdown(document: dict[str, Any]) -> bytes:
    """Render only fixed vocabulary and integers, so there is nothing to escape."""
    document = validate_document(document)
    gate = document["gate"]
    fail_on = ", ".join(gate["fail_on"]) or "none"
    lines = [
        AGGREGATE_MARKER,
        _TITLE,
        "",
        f"{_GATE} **{gate['status'].upper()}** ({_FAIL_ON} {fail_on})",
        "",
        f"| {_HEADINGS[0]} | {_COLUMNS[0]} |",
        "|---|---:|",
    ]
    lines += [f"| {name} | {document['counts'][name]} |" for name in DIFF_CLASSES]
    lines += ["", f"### {_SECTIONS[0]}", "", f"| {_HEADINGS[1]} | {_COLUMNS[0]} |"]
    lines += ["|---|---:|"]
    lines += [
        f"| {name} | {count} |" for name, count in document["case_classes"].items()
    ]
    lines += ["", f"### {_SECTIONS[1]}", ""]
    outcomes = document["hook_outcomes"]
    if outcomes is None:
        lines.append(_UNAVAILABLE)
    else:
        lines += [f"| {_HEADINGS[2]} | {_COLUMNS[1]} | {_COLUMNS[2]} |"]
        lines += ["|---|---:|---:|"]
        lines += [
            f"| {name} | {outcomes['baseline'][name]} | {outcomes['candidate'][name]} |"
            for name in OUTCOMES
            if outcomes["baseline"][name] or outcomes["candidate"][name]
        ]
    lines += ["", f"### {_SECTIONS[2]}", ""]
    failures = document["source_failures"]
    shown = [
        name
        for name in FAILURE_KEYS
        if failures["baseline"][name] or failures["candidate"][name]
    ]
    if shown:
        lines += [f"| {_HEADINGS[3]} | {_COLUMNS[1]} | {_COLUMNS[2]} |"]
        lines += ["|---|---:|---:|"]
        lines += [
            f"| {name} | {failures['baseline'][name]} | {failures['candidate'][name]} |"
            for name in shown
        ]
    else:
        lines.append(_NONE)
    lines += ["", _FOOTER, ""]
    data = "\n".join(lines).encode("ascii")
    if len(data) > MAX_MARKDOWN_BYTES:
        raise AggregateInputError("aggregate exceeds its byte bound")
    return data


def _strings(value: object, found: set[str]) -> None:
    if isinstance(value, str):
        found.add(value)
    elif isinstance(value, dict):
        for item in value.values():
            _strings(item, found)
    elif isinstance(value, list):
        for item in value:
            _strings(item, found)


def _sensitive(report: dict[str, Any], texts: tuple[str, ...]) -> list[str]:
    found = set(texts)
    for key in ("results", "source_failures", "policies", "corpus"):
        _strings(report[key], found)
    return sorted(
        value
        for value in found
        if len(value) >= LEAK_MINIMUM
        and not value.isdigit()
        and value not in _VOCABULARY
        and value not in _STATIC_TEXT
    )


def check_no_leak(
    report: dict[str, Any], rendered: tuple[bytes, ...], texts: tuple[str, ...] = ()
) -> None:
    """Fail closed if any free-text value of the report is in the rendered bytes.

    `texts` adds values that are not in the report, such as the corpus and
    output paths. A value already part of the fixed text is skipped, because it
    says nothing about the corpus. The message is fixed and echoes nothing.
    """
    haystacks = [data.decode("utf-8", "replace") for data in rendered]
    for value in _sensitive(report, texts):
        forms = {value, json.dumps(value)[1:-1]}
        if any(form in text for form in forms for text in haystacks):
            raise AggregateRefused(
                "aggregate refused: it contained corpus text; nothing was written"
            )


def build_files(
    report: dict[str, Any],
    *,
    hook_outcomes: dict[str, dict[str, int]] | None = None,
    texts: tuple[str, ...] = (),
) -> dict[str, bytes]:
    """Build, render and verify both artifacts; nothing is written here."""
    document = build_aggregate(report, hook_outcomes=hook_outcomes)
    files = {
        AGGREGATE_JSON: render_json(document),
        AGGREGATE_MD: render_markdown(document),
    }
    check_no_leak(report, tuple(files.values()), texts)
    return files


def read_report_directory(directory: str | Path) -> dict[str, Any]:
    """Admit `report.json` against `run-manifest.json` in a kernel report directory."""
    base = Path(directory)
    try:
        report_bytes = _read_regular(base / "report.json", MAX_REPORT_BYTES)
        manifest_bytes = _read_regular(base / "run-manifest.json", MAX_MANIFEST_BYTES)
    except ValueError as exc:
        raise AggregateInputError(
            "report directory needs readable report.json and run-manifest.json"
        ) from exc
    return admit_report(report_bytes, manifest_bytes)


def publish_files(targets: dict[Path, bytes]) -> None:
    """Create each target exclusively. An existing file or link is never replaced."""
    resolved = {new_destination(path): data for path, data in targets.items()}
    written: list[Path] = []
    try:
        for path, data in resolved.items():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            descriptor = os.open(path, flags, 0o600)
            written.append(path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
    except FileExistsError as exc:
        raise ValueError(
            "output appeared during publication; nothing is overwritten"
        ) from exc
    except BaseException:
        for path in written:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def run_aggregate(report_dir: str, output: str, markdown: str | None = None) -> None:
    """Standalone `aggregate`: verify, build, check, then create the new files."""
    targets = {Path(output): AGGREGATE_JSON}
    if markdown is not None:
        targets[Path(markdown)] = AGGREGATE_MD
    if len({new_destination(path) for path in targets}) != len(targets):
        raise ValueError("outputs must be different files")
    report = read_report_directory(report_dir)
    texts = tuple(
        {str(Path(report_dir)), str(Path(report_dir).resolve()), *map(str, targets)}
    )
    texts += tuple(str(new_destination(path)) for path in targets)
    files = build_files(report, texts=texts)
    publish_files({path: files[name] for path, name in targets.items()})
