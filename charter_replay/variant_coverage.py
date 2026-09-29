"""Aggregate seed and shape behavior after exact pack and report-row admission."""

from __future__ import annotations

from collections import Counter
import json
import math
from pathlib import Path
from typing import Any

from charter_replay.cli import _read_jsonl_bytes
from charter_replay.compare import ComparisonResult, DIFF_CLASSES, compare_decisions
from charter_replay.corpus import DECISION_EFFECTS
from charter_replay.digests import canonical_json_bytes
from charter_replay.manifests import _unique_object
from charter_replay.reports import REPORT_VERSION
from charter_replay.variant_packs import MAX_PACK_BYTES, PACK_FILES, _read_regular
from charter_replay.variant_packs import build_pack
from charter_replay.variants import DOMAIN, TRANSFORMS, VariantError

MAX_REPORT_BYTES = 32 * 1024 * 1024
LIMITATIONS = (
    "Decisions are supplied evidence, not authenticated execution records.",
    "Corpus rows, decision contracts, classifications and counts are checked; "
    "policy identity, run identity, gate and execution are not verified.",
    "Derived labels are inherited assumptions; observations sharing a seed are "
    "dependent, not independent votes or proof of reachability or safety.",
    "No corpus command is executed. Aggregates omit identifiers and command "
    "bodies, but small counts can still disclose information about a private corpus.",
)


def _same(left: object, right: object) -> bool:
    # Plain Python equality equates True with 1. JSON identity does not.
    return canonical_json_bytes(left) == canonical_json_bytes(right)


def _reject_constant(value: str) -> None:
    raise VariantError("report contains a non-finite JSON number")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise VariantError("report contains an overflowing JSON number")
    return parsed


def _admit_report(
    report: Any, files: dict[str, bytes], lineage: dict[str, Any]
) -> ComparisonResult:
    if not isinstance(report, dict) or report.get("schema_version") != REPORT_VERSION:
        raise VariantError("expected a replay-report.v1 object")
    manifest = json.loads(files["corpus-manifest.json"])
    corpus = dict(
        id=manifest["corpus_id"],
        event_count=manifest["event_count"],
        manifest_sha256=lineage["output_manifest_sha256"],
    )
    if not _same(report.get("corpus"), corpus):
        raise VariantError("report corpus does not match the verified pack")
    events = _read_jsonl_bytes(files["events.jsonl"], "events.jsonl")
    cases = _read_jsonl_bytes(files["cases.jsonl"], "cases.jsonl")
    event_by_id = {event["event_id"]: event for event in events}
    case_by_id = {case["event_id"]: case for case in cases}
    rows = report.get("results")
    if not isinstance(rows, list) or len(rows) != len(events):
        raise VariantError("report must contain every verified event exactly once")
    baseline, candidate, by_id = [], [], {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "event",
            "case",
            "baseline",
            "candidate",
            "classification",
        }:
            raise VariantError("report result has an unsupported shape")
        event_id = row["event"]["event_id"]
        if not isinstance(event_id, str) or event_id in by_id:
            raise VariantError("report contains an invalid or duplicate event ID")
        if not _same(row["event"], event_by_id.get(event_id)) or not _same(
            row["case"], case_by_id.get(event_id)
        ):
            raise VariantError("report event or case differs from the verified pack")
        for side, decisions in (("baseline", baseline), ("candidate", candidate)):
            if row[side]["event_id"] != event_id:
                raise VariantError("report decision is paired with the wrong event")
            decisions.append(row[side])
        by_id[event_id] = row
    compared = compare_decisions(events, baseline, candidate, case_values=cases)
    if not _same(report.get("counts"), compared.counts):
        raise VariantError("report counts differ from recomputed comparisons")
    for result in compared.results:
        if by_id[result.event["event_id"]]["classification"] != result.classification:
            raise VariantError("report classification differs from its decisions")
    return compared


def _counts() -> dict[str, int]:
    return dict.fromkeys(DIFF_CLASSES, 0)


def _aggregate(
    compared: ComparisonResult, lineage: dict[str, Any]
) -> dict[str, Any]:
    links = {link["event_id"]: link for link in lineage["mappings"]}
    results = {result.event["event_id"]: result for result in compared.results}
    by_origin = {"seed": _counts(), "derived": _counts()}
    skipped = Counter(row["transform_id"] for row in lineage["skipped"])
    transitions = [
        f"{before}->{after}"
        for before in sorted(DECISION_EFFECTS)
        for after in sorted(DECISION_EFFECTS)
    ]
    by_transform = {
        transform: {
            "generated": 0,
            "skipped": skipped[transform],
            "changes": _counts(),
            "shape_effects": {
                side: dict.fromkeys(transitions, 0)
                for side in ("baseline", "candidate")
            },
        }
        for transform in TRANSFORMS
    }
    changed_seeds, unchanged_seeds = set(), set()
    for event_id, result in results.items():
        link = links.get(event_id)
        by_origin["derived" if link else "seed"][result.classification] += 1
        if link is None:
            continue
        seed_id = link["seed_event_id"]
        seed = results[seed_id]
        transform = by_transform[link["transform_id"]]
        transform["generated"] += 1
        transform["changes"][result.classification] += 1
        for side in ("baseline", "candidate"):
            before = getattr(seed, side)["effect"]
            after = getattr(result, side)["effect"]
            transform["shape_effects"][side][f"{before}->{after}"] += 1
        if result.classification != "unchanged":
            changed_seeds.add(seed_id)
            if seed.classification == "unchanged":
                unchanged_seeds.add(seed_id)
    return {
        "schema_version": "variant-coverage.v1",
        "status": "verified-projection",
        "counts": dict(lineage["counts"]),
        "by_origin": by_origin,
        "by_transform": by_transform,
        "clusters": {
            "total_seeds": lineage["counts"]["seeds"],
            "seeds_with_variants": len(
                {link["seed_event_id"] for link in links.values()}
            ),
            "seeds_with_changed_variants": len(changed_seeds),
            "unchanged_seeds_with_changed_variants": len(unchanged_seeds),
        },
        "limitations": list(LIMITATIONS),
    }


def build_coverage(
    source: str | Path, pack: str | Path, report: str | Path
) -> dict[str, Any]:
    """Project verified supplied rows into fixed-vocabulary, identifier-free counts."""
    files, lineage = build_pack(source, domain=DOMAIN)
    root = Path(pack)
    for name in PACK_FILES:
        if _read_regular(root / name, MAX_PACK_BYTES) != files[name]:
            raise VariantError("pack does not match exact-source regeneration")
    data = _read_regular(Path(report), MAX_REPORT_BYTES)
    try:
        supplied = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        compared = _admit_report(supplied, files, lineage)
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        # Existing validators can name private event IDs in errors. Do not echo
        # those or malformed report bodies in the aggregate CLI's diagnostics.
        raise VariantError(
            "report does not match the verified coverage contract"
        ) from exc
    return _aggregate(compared, lineage)
