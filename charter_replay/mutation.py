"""Bounded decision sensitivity for explicit caller-selected hook mutations.

Only hooks run. Corpus commands stay data. Failed or indeterminate recordings
cannot count as killed mutations, and two healthy baseline passes are required.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any

from charter_replay import cli as kernel, hook_context
from charter_replay.corpus import validate_command_events, validate_charter_cases
from charter_replay.digests import sha256_bytes
from charter_replay.hooks import (
    ASK_EFFECTS,
    RUNTIMES,
    MIN_OUTPUT_LIMIT,
    DEFAULT_OUTPUT_LIMIT,
    HookSpec,
    record_hook,
)
from charter_replay.manifests import validate_corpus_manifest, _resolve_corpus_file
from charter_replay.publication import new_destination, publish_new_directory
from charter_replay.repeat import read_run
from charter_replay.review_reports import markdown_literal

PLAN_VERSION = "mutation-plan.v1"
REPORT_VERSION = "mutation-sensitivity.v1"
MAX_PLAN_BYTES = 64 * 1024
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_HOOK_BYTES = 32 * 1024 * 1024
MAX_MUTANTS = 32
MAX_EVENTS = 1000
MAX_INVOCATIONS = 2000
MAX_TIMEOUT_SECONDS = 300
STATUSES = ("killed", "survived", "invalid", "timeout")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


@dataclass(frozen=True)
class MutationHook:
    id: str
    spec: HookSpec
    descriptor: dict[str, Any]


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("mutation input exceeds its byte limit")
    return data


def _json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"), object_pairs_hook=kernel._unique_json_object
        )
    except (ValueError, RecursionError) as exc:
        raise ValueError("mutation input must be UTF-8 JSON with unique keys") from exc


def load_corpus(value: str) -> kernel.LoadedCharterCorpus:
    """Capture bounded exact bytes before hooks can change the input files."""
    path = kernel._resolve_manifest_path(value)
    raw = _read_bounded(path, MAX_PLAN_BYTES)
    manifest = validate_corpus_manifest(_json(raw))
    if not 1 <= manifest["event_count"] <= MAX_EVENTS:
        raise ValueError(f"mutation corpus must have 1 to {MAX_EVENTS} events")
    if {entry["path"] for entry in manifest["files"]} != {
        "events.jsonl",
        "cases.jsonl",
    }:
        raise ValueError(
            "mutation corpus requires exactly events.jsonl and cases.jsonl"
        )
    captured = {}
    for entry in manifest["files"]:
        data = _read_bounded(
            _resolve_corpus_file(path.parent, entry["path"]), MAX_INPUT_BYTES
        )
        if sha256_bytes(data) != entry["sha256"]:
            raise ValueError("mutation corpus file digest does not match")
        captured[entry["path"]] = data
    try:
        events = validate_command_events(
            kernel._read_jsonl_bytes(captured["events.jsonl"], "events.jsonl")
        )
        cases = validate_charter_cases(
            kernel._read_jsonl_bytes(captured["cases.jsonl"], "cases.jsonl")
        )
    except RecursionError as exc:
        raise ValueError("mutation corpus JSON is too deeply nested") from exc
    if len(events) != manifest["event_count"] or {e["event_id"] for e in events} != {
        c["event_id"] for c in cases
    }:
        raise ValueError("mutation corpus events and cases do not match its manifest")
    return kernel.LoadedCharterCorpus(
        events, cases, manifest["corpus_id"], len(events), sha256_bytes(raw)
    )


def _argv(value: Any, parent: Path) -> tuple[tuple[str, ...], list[str]]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 128
        or any(
            not isinstance(w, str) or not 1 <= len(w) <= 4096 or "\0" in w
            for w in value
        )
    ):
        raise ValueError(
            "mutation hook must be an argv array of 1 to 128 bounded strings"
        )
    # Existing files and path-shaped executables are relative to the plan,
    # independent of the CLI's working directory. No process-wide chdir.
    resolved = []
    kinds = []
    for index, word in enumerate(value):
        path = parent / word
        if index and path.is_dir():
            raise ValueError("mutation directory arguments are not supported")
        if path.is_file() or (index == 0 and ("/" in word or "\\" in word)):
            resolved.append(str(path.resolve()))
            kinds.append("executable" if index == 0 else "file")
        elif (
            index
            and not word.startswith("-")
            and Path(word).suffix.lower()
            in {".py", ".js", ".sh", ".ps1", ".mjs", ".cjs", ".ts", ".rb"}
        ):
            raise ValueError("mutation hook names a missing script")
        else:
            resolved.append(word)
            kinds.append("executable" if index == 0 else "word")
    return tuple(resolved), kinds


def load_plan(
    path: str, *, runtime: str, timeout: float, ask_effect: str, output_limit: int
) -> tuple[MutationHook, list[MutationHook]]:
    """Admit every hook before recording even the baseline."""
    if runtime not in RUNTIMES or ask_effect not in ASK_EFFECTS:
        raise ValueError("mutation runtime or ask mapping is invalid")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 10
    ):
        raise ValueError(
            "mutation timeout must be greater than 0 and at most 10 seconds"
        )
    if (
        type(output_limit) is not int
        or not MIN_OUTPUT_LIMIT <= output_limit <= DEFAULT_OUTPUT_LIMIT
    ):
        raise ValueError("mutation output limit must be from 1024 to 1048576 bytes")
    source = Path(path).resolve()
    plan = _json(_read_bounded(source, MAX_PLAN_BYTES))
    if (
        not isinstance(plan, dict)
        or set(plan) != {"schema_version", "baseline", "mutants"}
        or plan["schema_version"] != PLAN_VERSION
    ):
        raise ValueError("mutation plan must have schema_version, baseline and mutants")
    rows = plan["mutants"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_MUTANTS:
        raise ValueError(f"mutation plan must have 1 to {MAX_MUTANTS} mutants")
    specs = [("baseline", plan["baseline"])]
    ids = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"id", "hook"}
            or not isinstance(row["id"], str)
            or not _ID.fullmatch(row["id"])
        ):
            raise ValueError("each mutant requires a portable id and hook argv")
        if row["id"] in ids:
            raise ValueError("mutant ids must be unique")
        ids.add(row["id"])
        specs.append((row["id"], row["hook"]))
    admitted = []
    total_bytes = 0
    for name, argv in specs:
        resolved, kinds = _argv(argv, source.parent)
        spec = HookSpec(resolved, runtime, timeout, ask_effect, output_limit)
        executable = spec.argv[0]
        if os.name == "nt" and not Path(executable).suffix:
            executable += ".exe"
        found = shutil.which(executable)
        if found is None:
            raise ValueError("mutation hook executable must be resolvable")
        spec = HookSpec(
            (str(Path(found).resolve()), *spec.argv[1:]),
            runtime,
            timeout,
            ask_effect,
            output_limit,
        )
        # Preflight the entire plan before any file is hashed. The context
        # descriptor independently rechecks bytes; hook input changes are failures.
        for word, kind in zip(spec.argv, kinds):
            if kind == "word":
                continue
            path = Path(word)
            if path.is_dir():
                raise ValueError("mutation directory arguments are not supported")
            if path.is_file():
                size = path.stat().st_size
                if size > MAX_INPUT_BYTES:
                    raise ValueError("mutation hook file exceeds its byte limit")
                total_bytes += size
        admitted.append((name, spec, kinds))
    if total_bytes > MAX_HOOK_BYTES:
        raise ValueError("mutation hook inputs exceed the total byte limit")
    hooks = []
    actual_bytes = 0
    for name, spec, kinds in admitted:
        descriptor = hook_context.describe_hook_context(
            spec,
            workspace_template=None,
            jobs=1,
            max_file_bytes=MAX_INPUT_BYTES,
            argv_kinds=kinds,
        )
        for entry in descriptor["hook"]["argv"]:
            if entry.get("kind") in ("executable", "file", "directory"):
                if entry.get("status") != "bound":
                    raise ValueError(
                        "mutation hook executable and file inputs must be bound"
                    )
                if entry["size"] > MAX_INPUT_BYTES:
                    raise ValueError("mutation hook file grew beyond its byte limit")
                actual_bytes += entry["size"]
        hooks.append(MutationHook(name, spec, descriptor))
    if actual_bytes > MAX_HOOK_BYTES:
        raise ValueError("mutation hook inputs exceed the total byte limit")
    return hooks[0], hooks[1:]


def _observe(
    hook: MutationHook, events: list[dict], output: Path
) -> tuple[str, dict[str, str], list[str], bool]:
    expected_id = hook_context.context_id(hook.descriptor)
    try:
        current = hook_context.describe_hook_context(
            hook.spec,
            workspace_template=None,
            jobs=1,
            argv_kinds=hook_context.argv_kinds(hook.descriptor),
            max_file_bytes=MAX_INPUT_BYTES,
        )
        if hook_context.context_id(current) != expected_id:
            return "invalid", {}, ["input-changed"], False
        summary = record_hook(
            hook.spec,
            events,
            output,
            policy_id="mutation-hook",
            jobs=1,
            input_byte_limit=MAX_INPUT_BYTES,
            argv_kinds=hook_context.argv_kinds(hook.descriptor),
        )
    except (OSError, ValueError):
        return "invalid", {}, ["recording-failed"], True
    codes = sorted({f["code"] for f in summary["failures"]})
    if summary["context_id"] != expected_id:
        codes.append("input-changed")
    if codes:
        return (
            ("timeout" if set(codes) == {"hook-timeout"} else "invalid"),
            {},
            codes,
            True,
        )
    try:
        observations, _timing = read_run(
            output, [event["event_id"] for event in events]
        )
    except (OSError, ValueError, KeyError, TypeError):
        return "invalid", {}, ["recording-unreadable"], True
    effects = {event_id: row[0] for event_id, row in observations.items()}
    if "indeterminate" in effects.values():
        return "invalid", {}, ["indeterminate-effect"], True
    return "healthy", effects, [], True


def render_markdown(document: dict) -> str:
    lines = [
        "# Hook mutation sensitivity",
        "",
        f"Baseline: **{document['baseline']['status']}**",
        "",
        "| status | mutants |",
        "|---|---:|",
    ]
    lines += [f"| {status} | {document['counts'][status]} |" for status in STATUSES]
    score = document["score"]
    lines += [
        "",
        f"Sensitivity: {score['numerator']}/{score['denominator']} eligible mutants; invalid and timeout excluded.",
        "",
        "| mutant | status | changed events |",
        "|---|---|---:|",
    ]
    lines += [
        f"| {markdown_literal(row['id'])} | {row['status']} | {len(row['changed_event_ids'])} |"
        for row in document["mutants"]
    ]
    lines += [
        "",
        "Recorded hook decisions were compared; no corpus command was executed.",
        "",
        "Two baseline passes check observed effect stability only. Mutation sensitivity is not a security proof or independent label agreement.",
        "Hooks are unsandboxed. Context leaves helper imports, dependencies, environment values, network and time unbound.",
        "",
    ]
    return "\n".join(lines)


def run_mutation(
    baseline: MutationHook,
    mutants: list[MutationHook],
    corpus: kernel.LoadedCharterCorpus,
    output: str,
    *,
    max_invocations: int = MAX_INVOCATIONS,
    max_timeout_seconds: float = MAX_TIMEOUT_SECONDS,
) -> tuple[dict, int]:
    invocations = (2 + len(mutants)) * len(corpus.events)
    if (
        type(max_invocations) is not int
        or not 1 <= max_invocations <= MAX_INVOCATIONS
        or invocations > max_invocations
    ):
        raise ValueError(
            "mutation invocation budget exceeded or invalid (maximum 2000)"
        )
    if (
        isinstance(max_timeout_seconds, bool)
        or not isinstance(max_timeout_seconds, (int, float))
        or not math.isfinite(max_timeout_seconds)
        or not 0 < max_timeout_seconds <= MAX_TIMEOUT_SECONDS
        or invocations * baseline.spec.timeout > max_timeout_seconds
    ):
        raise ValueError(
            "mutation timeout sum exceeds its budget (maximum 300 seconds)"
        )
    target = new_destination(output)
    rows = []
    with tempfile.TemporaryDirectory(
        prefix=".charter-mutation-", dir=target.parent
    ) as raw:
        scratch = Path(raw)
        first = _observe(baseline, corpus.events, scratch / "baseline-1")
        second = (
            _observe(baseline, corpus.events, scratch / "baseline-2")
            if first[0] == "healthy"
            else first
        )
        status = first[0] if first[0] != "healthy" else second[0]
        if status == "healthy" and first[1] != second[1]:
            status = "unstable"
        baseline_result = dict(
            status=status,
            context_id=hook_context.context_id(baseline.descriptor),
            failure_codes=sorted(set(first[2] + second[2])),
        )
        for index, hook in enumerate(mutants):
            if status != "healthy":
                state, effects, failures, executed = (
                    "invalid",
                    {},
                    ["baseline-not-healthy"],
                    False,
                )
            else:
                state, effects, failures, executed = _observe(
                    hook, corpus.events, scratch / f"mutant-{index:02d}"
                )
            changed = [
                e["event_id"]
                for e in corpus.events
                if state == "healthy"
                and effects[e["event_id"]] != first[1][e["event_id"]]
            ]
            if state == "healthy":
                state = "killed" if changed else "survived"
            rows.append(
                dict(
                    id=hook.id,
                    status=state,
                    executed=executed,
                    context_id=hook_context.context_id(hook.descriptor),
                    failure_codes=failures,
                    changed_event_ids=changed,
                )
            )
        counts = {
            name: Counter(row["status"] for row in rows)[name] for name in STATUSES
        }
        denominator = counts["killed"] + counts["survived"]
        document = dict(
            schema_version=REPORT_VERSION,
            corpus_manifest_sha256=corpus.manifest_sha256,
            events=len(corpus.events),
            baseline=baseline_result,
            mutants=rows,
            counts=counts,
            score=dict(
                numerator=counts["killed"],
                denominator=denominator,
                rate=counts["killed"] / denominator if denominator else None,
            ),
            budget=dict(
                planned_invocations=invocations,
                max_invocations=max_invocations,
                planned_timeout_seconds=invocations * baseline.spec.timeout,
                max_timeout_seconds=float(max_timeout_seconds),
                jobs=1,
                output_limit_bytes=baseline.spec.output_limit,
            ),
        )
    # No raw recordings remain; publish the completion marker last after cleanup.
    publish_new_directory(
        target,
        {
            "mutation.json": (
                json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
            ).encode("utf-8"),
            "mutation.md": render_markdown(document).encode("utf-8"),
        },
        marker="mutation.json",
    )
    code = (
        3
        if status != "healthy" or counts["invalid"] or counts["timeout"]
        else 1 if counts["survived"] else 0
    )
    return document, code
