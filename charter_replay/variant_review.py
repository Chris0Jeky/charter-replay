"""Capture-bound offline review of an exact variant pack and replay evidence."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from charter_replay.digests import canonical_json_bytes, sha256_bytes
from charter_replay.manifests import _unique_object, manifest_json_bytes, validate_run_manifest
from charter_replay.policy_sources import SourceFailure
from charter_replay.publication import new_destination, publish_new_directory
from charter_replay.reports import build_json_report, report_json_bytes
from charter_replay.variant_coverage import _admit_report, _aggregate, _finite_float
from charter_replay.variant_coverage import _reject_constant, _same
from charter_replay.variant_packs import MAX_MANIFEST_BYTES, MAX_PACK_BYTES, PACK_FILES
from charter_replay.variant_packs import _read_regular, build_pack
from charter_replay.variant_review_views import NOTICE, render_review_views
from charter_replay.variants import DOMAIN, VariantError

MAX_REPORT_BYTES = 32 * 1024 * 1024


def _json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant, parse_float=_finite_float)


def _failures(value: Any, event_ids: set[str]) -> tuple[SourceFailure, ...]:
    if not isinstance(value, list):
        raise ValueError("source failures must be a list")
    result = []
    for entry in value:
        if (not isinstance(entry, dict) or not {"code", "message"} <= entry.keys()
                or entry.keys() - {"code", "message", "event_id"}):
            raise ValueError("source failure has an unsupported shape")
        code, message = entry["code"], entry["message"]
        if not isinstance(code, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", code):
            raise ValueError("source failure code is invalid")
        if not isinstance(message, str) or not message or len(message.encode("utf-8")) > 4096:
            raise ValueError("source failure message is invalid")
        if "event_id" in entry and entry["event_id"] not in event_ids:
            raise ValueError("source failure names an unknown event")
        result.append(SourceFailure(**entry))
    return tuple(result)


def _shape_disagreements(compared, lineage) -> dict[str, dict[str, int]]:
    rows = {row.event["event_id"]: row for row in compared.results}
    totals = {side: 0 for side in ("baseline", "candidate", "shared")}
    seeds = {side: set() for side in totals}
    for link in lineage["mappings"]:
        seed, shape = rows[link["seed_event_id"]], rows[link["event_id"]]
        pairs = {}
        for side in ("baseline", "candidate"):
            pairs[side] = getattr(seed, side)["effect"], getattr(shape, side)["effect"]
            if pairs[side][0] != pairs[side][1]:
                totals[side] += 1
                seeds[side].add(link["seed_event_id"])
        if pairs["baseline"] == pairs["candidate"] and pairs["baseline"][0] != pairs["baseline"][1]:
            totals["shared"] += 1
            seeds["shared"].add(link["seed_event_id"])
    return {side: dict(variants=count, seeds=len(seeds[side])) for side, count in totals.items()}


def _capture(source, pack, report_path, manifest_path):
    pack_files, lineage = build_pack(source, domain=DOMAIN)
    for name in PACK_FILES:
        if _read_regular(Path(pack) / name, MAX_PACK_BYTES) != pack_files[name]:
            raise VariantError("pack does not match exact-source regeneration")
    report_bytes = _read_regular(Path(report_path), MAX_REPORT_BYTES)
    manifest_bytes = _read_regular(Path(manifest_path), MAX_MANIFEST_BYTES)
    supplied, raw_manifest = _json(report_bytes), _json(manifest_bytes)
    manifest = validate_run_manifest(raw_manifest)
    if not _same(manifest, raw_manifest):
        raise ValueError("run manifest is not canonical in meaning")
    compared = _admit_report(supplied, pack_files, lineage)
    failures = supplied["source_failures"]
    if not isinstance(failures, dict) or set(failures) != {"baseline", "candidate"}:
        raise ValueError("source failures must name both policies")
    event_ids = {row.event["event_id"] for row in compared.results}
    report = build_json_report(
        compared, manifest,
        baseline_failures=_failures(failures["baseline"], event_ids),
        candidate_failures=_failures(failures["candidate"], event_ids),
    )
    # Rows were checked by ID; normalize their order to the verified corpus.
    expected = dict(report, results=supplied["results"])
    if not _same(expected, supplied):
        raise ValueError("report metadata or gate does not match its run manifest")
    coverage = _aggregate(compared, lineage)
    details = dict(
        schema_version="variant-review.v1",
        gate_status=report["gate"]["status"],
        shape_disagreements=_shape_disagreements(compared, lineage),
        verification="exact-source-regeneration-and-run-manifest-consistency",
        limitations=[NOTICE],
    )
    bindings = dict(
        source_manifest_sha256=lineage["source_manifest_sha256"],
        pack_manifest_sha256=lineage["output_manifest_sha256"],
        report_sha256=sha256_bytes(report_bytes),
        run_manifest_sha256=sha256_bytes(manifest_bytes),
    )
    return manifest, report, coverage, details, bindings


def build_review(
    source: str | Path, pack: str | Path, report: str | Path, run_manifest: str | Path
) -> tuple[dict[str, bytes], int]:
    """Read once, validate, and render. No detached coverage object is accepted."""
    try:
        manifest, report_value, coverage, details, bindings = _capture(source, pack, report, run_manifest)
        files = render_review_views(report_value, coverage, details)
        files.update({
            "run-manifest.json": manifest_json_bytes(manifest),
            "report.json": report_json_bytes(report_value),
            "variant-coverage.json": canonical_json_bytes(coverage) + b"\n",
            "variant-review.json": canonical_json_bytes(details) + b"\n",
        })
        marker = dict(
            schema_version="variant-review-manifest.v1", inputs=bindings,
            files={name: sha256_bytes(data) for name, data in sorted(files.items())},
            limitations=["Digests check consistency, not authorship or execution. "
                         "Full report artifacts retain private corpus text."],
        )
        files["review-manifest.json"] = manifest_json_bytes(marker)
        code = {"pass": 0, "fail": 1, "error": 3}[report_value["gate"]["status"]]
        return files, code
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        # No paths, private event IDs, or parser excerpts in public diagnostics.
        raise VariantError("inputs do not match the verified review contract") from exc


def publish_review(
    source: str | Path, pack: str | Path, report: str | Path,
    run_manifest: str | Path, output: str | Path,
) -> int:
    """Publish a new review directory and retain the admitted replay's gate exit."""
    target = new_destination(output)
    for protected in (source, pack):
        if target.is_relative_to(Path(protected).resolve()):
            raise VariantError("review output must be outside both corpus directories")
    files, code = build_review(source, pack, report, run_manifest)
    publish_new_directory(target, files, marker="review-manifest.json")
    return code


def verify_review(
    source: str | Path, pack: str | Path, report: str | Path,
    run_manifest: str | Path, review: str | Path,
) -> int:
    """Regenerate all named review artifacts; a rebinding of self-digests is insufficient."""
    files, code = build_review(source, pack, report, run_manifest)
    try:
        for name, expected in files.items():
            if _read_regular(Path(review) / name, len(expected)) != expected:
                raise VariantError("review differs from exact-source regeneration")
    except (OSError, ValueError, RuntimeError) as exc:
        raise VariantError("review differs from exact-source regeneration") from exc
    return code
