"""Repeat one hook over the same captured inputs and measure its own variation.

A single recording cannot tell a deterministic hook from one whose decision
varies between invocations (time, randomness, races, network, mutable state).
Repeat mode records the hook N times through `record_hook`, keyed by the
`hook-context.v1` identity, and classifies every event by how its decision
varies across the repeats. It does not compare against a baseline.

Classification and rendering are pure functions of observations; process
running is kept separate. Nothing here executes corpus commands. Diagnostics
are fixed text: no path, hook output or reason text is echoed, and reasons are
counted by SHA-256 digest only.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Sequence

from charter_replay.hooks import ASK_EFFECTS, OUTCOMES, HookSpec, record_hook
from charter_replay.metrics import latency_summary
from charter_replay.publication import new_destination
from charter_replay.review_reports import markdown_literal

REPEAT_VERSION = "repeat-stability.v1"
MEASUREMENTS_VERSION = "repeat-measurements.v1"
MIN_REPEATS = 2
MAX_REPEATS = 50
# Ordered from mildest to strongest; the strongest difference names an event.
CLASSES = ("stable", "reason-varies", "outcome-varies", "effect-varies")
FAIL_ON_CLASSES = CLASSES[1:]
DEFAULT_FAIL_ON = ("effect-varies",)
# Codes this module adds on top of what `record_hook` reports.
CONTEXT_CHANGED = "repeat-context-changed"
NOT_RECORDED = "repeat-not-recorded"
UNREADABLE = "repeat-unreadable"
_VARYING_ROWS_SHOWN = 100
_DIGITS = re.compile(r"[0-9]{1,4}")
_LIMITATIONS = (
    "Repeats run one after another, so this measures variation under this host, "
    "timing and concurrency, not complete environment control.",
    "Agreement across the repeats is not proof of determinism.",
    "Reason variation may be benign, for example a timestamp in a message.",
)

# (effect, outcome, sha256 of the recorded reason string)
Observation = tuple[str, str, str]


class RepeatInputError(ValueError):
    """The repeat request cannot be admitted."""


def parse_repeats(value: str | int) -> int:
    """Admit an integer in [MIN_REPEATS, MAX_REPEATS]; nothing else."""

    text = str(value).strip()
    count = int(text) if _DIGITS.fullmatch(text) and value is not True else 0
    if not MIN_REPEATS <= count <= MAX_REPEATS:
        raise RepeatInputError("repeats must be an integer from 2 to 50")
    return count


def parse_fail_on(value: str) -> tuple[str, ...]:
    choices = [item.strip() for item in value.split(",")]
    if not choices or any(item not in FAIL_ON_CLASSES for item in choices):
        raise RepeatInputError(
            "fail-on must be a comma-separated selection from: "
            + ", ".join(FAIL_ON_CLASSES)
        )
    if len(set(choices)) != len(choices):
        raise RepeatInputError("fail-on values must not be duplicated")
    return tuple(sorted(choices))


def reason_digest(reason: str) -> str:
    # The hook's reason string is already sanitised; surrogatepass keeps this total.
    return hashlib.sha256(reason.encode("utf-8", "surrogatepass")).hexdigest()


def classify_event(observations: Sequence[Observation]) -> str:
    """Name how one event's decision varies; independent of observation order."""

    if not observations:
        raise ValueError("classification requires at least one observation")
    # Indeterminate is an effect like any other, so flaky timeouts land here.
    if len({item[0] for item in observations}) > 1:
        return "effect-varies"
    if len({item[1] for item in observations}) > 1:
        return "outcome-varies"
    if len({item[2] for item in observations}) > 1:
        return "reason-varies"
    return "stable"


def event_row(event_id: str, observations: Sequence[Observation]) -> dict[str, Any]:
    variants = Counter((effect, outcome) for effect, outcome, _digest in observations)
    reasons = Counter(digest for _effect, _outcome, digest in observations)
    return {
        "event_id": event_id,
        "class": classify_event(observations),
        "variants": [
            {"effect": effect, "outcome": outcome, "count": count}
            for (effect, outcome), count in sorted(variants.items())
        ],
        "reasons": [
            {"sha256": digest, "count": count}
            for digest, count in sorted(reasons.items())
        ],
    }


@dataclass(frozen=True)
class RepeatRecord:
    """What one repeat's recording gave, reduced to what classification needs."""

    index: int
    context_id: str | None
    # Failure code -> count, as reported by the recorder (or added by the runner).
    failures: dict[str, int] = field(default_factory=dict)
    # Event id -> observation; None when the recording could not be read back.
    observations: dict[str, Observation] | None = None
    measurements: dict[str, Any] | None = None


def build_document(
    event_ids: Sequence[str],
    records: Sequence[RepeatRecord],
    *,
    fail_on: Sequence[str] = DEFAULT_FAIL_ON,
) -> dict[str, Any]:
    """The deterministic `stability.json` content; it holds no timing."""

    ordered = sorted(records, key=lambda record: record.index)
    if not ordered or ordered[0].context_id is None:
        raise ValueError("repeat 1 must carry a context id")
    reference = ordered[0].context_id
    runs = []
    comparable: list[RepeatRecord] = []
    for record in ordered:
        failures = dict(record.failures)
        matches = record.context_id == reference
        if record.context_id is not None and not matches:
            failures[CONTEXT_CHANGED] = failures.get(CONTEXT_CHANGED, 0) + 1
        # Events are never merged across different contexts.
        if matches and record.observations is not None:
            comparable.append(record)
        runs.append(
            {
                "repeat": record.index,
                "context_matches": matches,
                "source_failures": dict(sorted(failures.items())),
            }
        )
    rows = []
    for event_id in event_ids:
        seen = [
            record.observations[event_id]
            for record in comparable
            if record.observations is not None and event_id in record.observations
        ]
        if seen:
            rows.append(event_row(event_id, seen))
    counts = {name: 0 for name in CLASSES}
    for row in rows:
        counts[row["class"]] += 1
    selected = tuple(sorted(fail_on))
    if any(run["source_failures"] for run in runs):
        status = "error"
    elif any(counts[name] for name in selected):
        status = "fail"
    else:
        status = "pass"
    return {
        "schema_version": REPEAT_VERSION,
        "context_id": reference,
        "repeats": len(ordered),
        "comparable_repeats": len(comparable),
        "events": len(event_ids),
        "counts": counts,
        "gate": {"fail_on": list(selected), "status": status},
        "repeat_runs": runs,
        "rows": rows,
    }


def exit_code(document: dict[str, Any]) -> int:
    """3 for any source failure, else 1 for a selected class, else 0."""

    status = document["gate"]["status"]
    return {"pass": 0, "fail": 1, "error": 3}[status]


def stability_bytes(document: dict[str, Any]) -> bytes:
    text = json.dumps(document, indent=2, sort_keys=True, allow_nan=False)
    return (text + "\n").encode("utf-8")


def render_markdown(document: dict[str, Any]) -> str:
    gate = document["gate"]
    lines = [
        "# Hook repeat stability",
        "",
        f"Gate: **{gate['status'].upper()}** (fail on: {', '.join(gate['fail_on'])})",
        "",
        f"Hook context `{document['context_id']}` ({document['comparable_repeats']} "
        f"of {document['repeats']} repeats comparable, {document['events']} events).",
        "",
        "| class | events |",
        "|---|---:|",
    ]
    lines += [f"| {name} | {document['counts'][name]} |" for name in CLASSES]
    varying = [row for row in document["rows"] if row["class"] != "stable"]
    if varying:
        lines += ["", "## Events that vary", ""]
        lines += ["| event | class | (effect, outcome) x count | distinct reasons |"]
        lines += ["|---|---|---|---:|"]
        for row in varying[:_VARYING_ROWS_SHOWN]:
            variants = ", ".join(
                f"{item['effect']}/{item['outcome']} x {item['count']}"
                for item in row["variants"]
            )
            lines.append(
                f"| {markdown_literal(row['event_id'])} | {row['class']} | "
                f"{variants} | {len(row['reasons'])} |"
            )
        if len(varying) > _VARYING_ROWS_SHOWN:
            lines += [
                "",
                f"{len(varying) - _VARYING_ROWS_SHOWN} more in stability.json.",
            ]
    failed = [run for run in document["repeat_runs"] if run["source_failures"]]
    if failed:
        lines += ["", "## Source failures", "", "| repeat | failures |", "|---|---|"]
        for run in failed:
            detail = ", ".join(
                f"{markdown_literal(code)} x {count}"
                for code, count in run["source_failures"].items()
            )
            lines.append(f"| {run['repeat']} | {detail} |")
    lines += ["", "## Limits", ""]
    lines += [f"- {text}" for text in _LIMITATIONS]
    lines += [
        "",
        "Recorded hook decisions were compared; no corpus command was executed.",
        "",
    ]
    return "\n".join(lines)


def measurements_bytes(records: Sequence[RepeatRecord]) -> bytes:
    """Observational timing per repeat; never part of stability identity."""

    document = {
        "schema_version": MEASUREMENTS_VERSION,
        "deterministic": False,
        "repeats": [
            {"repeat": record.index, "measurements": record.measurements}
            for record in sorted(records, key=lambda item: item.index)
        ],
    }
    text = json.dumps(document, indent=2, sort_keys=True, allow_nan=False)
    return (text + "\n").encode("utf-8")


def _jsonl(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    rows = [json.loads(line) for line in text.splitlines() if line]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("record rows must be objects")
    return rows


def read_run(
    run: Path, event_ids: Sequence[str]
) -> tuple[dict[str, Observation], list[dict[str, Any]]]:
    """Read one recording back: observations plus latency inputs.

    Raises OSError or ValueError when the files do not describe exactly the
    corpus events, in order.
    """

    decisions = _jsonl(run / "decisions.jsonl")
    outcomes = _jsonl(run / "outcomes.jsonl")
    if [row["event_id"] for row in decisions] != list(event_ids) or [
        row["event_id"] for row in outcomes
    ] != list(event_ids):
        raise ValueError("recording does not match the corpus events")
    observations: dict[str, Observation] = {}
    timing = []
    for decision, outcome in zip(decisions, outcomes):
        effect, name, reason = (
            decision["effect"],
            outcome["outcome"],
            decision["reason"],
        )
        if (
            effect not in ASK_EFFECTS
            or name not in OUTCOMES
            or not isinstance(reason, str)
        ):
            raise ValueError("recording holds an unknown effect or outcome")
        observations[decision["event_id"]] = (effect, name, reason_digest(reason))
        timing.append({"outcome": name, "elapsed_ms": outcome["elapsed_ms"]})
    return observations, timing


def _record_repeat(
    spec: HookSpec,
    events: list[dict[str, Any]],
    run: Path,
    *,
    index: int,
    workspace_template: Path | None,
    jobs: int,
) -> RepeatRecord:
    try:
        summary = record_hook(
            spec,
            events,
            run,
            policy_id="repeat-hook",
            workspace_template=workspace_template,
            jobs=jobs,
        )
    except (ValueError, OSError):
        # Repeat 1 was admitted; a later one failing to start is a source failure.
        if index == 1:
            raise
        return RepeatRecord(index, None, {NOT_RECORDED: 1})
    failures = Counter(failure["code"] for failure in summary["failures"])
    try:
        observations, timing = read_run(run, [event["event_id"] for event in events])
        measurements = latency_summary(timing, jobs=jobs, timeout_seconds=spec.timeout)
    except (OSError, ValueError, KeyError, TypeError):
        return RepeatRecord(index, summary["context_id"], {**failures, UNREADABLE: 1})
    return RepeatRecord(
        index, summary["context_id"], dict(failures), observations, measurements
    )


def run_repeat(
    spec: HookSpec,
    events: list[dict[str, Any]],
    output: str | Path,
    *,
    repeats: int,
    workspace_template: Path | None = None,
    jobs: int = 1,
    fail_on: Sequence[str] = DEFAULT_FAIL_ON,
) -> tuple[dict[str, Any], int]:
    """Record the hook `repeats` times and publish the result in a new directory.

    Every admission check runs before any hook starts. The recordings and
    summaries are built in a hidden staging directory beside the target and
    moved into place at the end, so a crash never leaves a half-written output
    that looks complete. Returns the stability document and the exit code.
    """

    repeats = parse_repeats(repeats)
    fail_on = parse_fail_on(",".join(fail_on))
    target = new_destination(output)
    if workspace_template is not None and target.parent.is_relative_to(
        workspace_template.resolve()
    ):
        # Staging sits beside the target, so every later repeat's workspace
        # would copy the earlier repeats' recordings and read as variation.
        raise RepeatInputError("output must be outside the workspace template")
    staging = Path(tempfile.mkdtemp(prefix=".charter-repeat-", dir=target.parent))
    published = False
    try:
        event_ids = [event["event_id"] for event in events]
        records = [
            _record_repeat(
                spec,
                events,
                staging / "runs" / f"{index:02d}",
                index=index,
                workspace_template=workspace_template,
                jobs=jobs,
            )
            for index in range(1, repeats + 1)
        ]
        document = build_document(event_ids, records, fail_on=fail_on)
        (staging / "stability.json").write_bytes(stability_bytes(document))
        (staging / "stability.md").write_bytes(
            render_markdown(document).encode("utf-8")
        )
        (staging / "measurements.json").write_bytes(measurements_bytes(records))
        # Renaming onto an empty directory replaces it on POSIX, so look again.
        if target.exists() or target.is_symlink():
            raise ValueError(
                "output appeared during publication; nothing is overwritten"
            )
        os.rename(staging, target)
        published = True
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)
    return document, exit_code(document)
