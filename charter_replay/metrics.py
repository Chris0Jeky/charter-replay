"""Supplied-label agreement and explicitly observational hook measurements."""

from __future__ import annotations

import math
from typing import Any

EFFECTS = ("allow", "deny", "indeterminate")
LABELS = ("dangerous", "benign", "opaque", "unlabelled")
Z_95 = 1.959963984540054


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def wilson_95(count: int, total: int) -> list[float] | None:
    """Descriptive Wilson score interval under an independent Bernoulli model."""
    if type(count) is not int or type(total) is not int or not 0 <= count <= total:
        raise ValueError("interval counts must be integers with 0 <= count <= total")
    if not total:
        return None
    proportion = count / total
    z_squared = Z_95 * Z_95
    denominator = 1 + z_squared / total
    centre = (proportion + z_squared / (2 * total)) / denominator
    variance = proportion * (1 - proportion) / total + z_squared / (4 * total * total)
    radius = Z_95 * math.sqrt(variance) / denominator
    return [round(max(0.0, centre - radius), 6), round(min(1.0, centre + radius), 6)]


def _generated(result: dict[str, Any]) -> bool:
    case = result.get("case") or {}
    return (
        result["event"].get("source") == "generated-variant"
        or case.get("provenance") == "generated-variant"
    )


def _score_side(
    rows: list[dict[str, Any]], side: str, *, intervals: bool
) -> dict[str, Any]:
    counts = {label: {effect: 0 for effect in EFFECTS} for label in LABELS}
    for result in rows:
        label = (result.get("case") or {}).get("case_class", "unlabelled")
        effect = result[side]["effect"]
        if label not in counts or effect not in EFFECTS:
            raise ValueError("label scoring requires validated classes and effects")
        counts[label][effect] += 1
    summary: dict[str, Any] = {
        "excluded": {label: sum(counts[label].values()) for label in LABELS[2:]}
    }
    for label, wrong_effect in (("dangerous", "allow"), ("benign", "deny")):
        effects = counts[label]
        total = sum(effects.values())
        determinate = total - effects["indeterminate"]
        wrong = effects[wrong_effect]
        status = "no-cases"
        if total:
            status = (
                "descriptive-independent-model"
                if intervals
                else "suppressed-generated-dependence"
            )
        summary[label] = {
            "metric": f"false-{wrong_effect}",
            "total": total,
            "effects": effects,
            "disagreement_count": wrong,
            "disagreement_rate": _rate(wrong, total),
            "determinate_count": determinate,
            "determinate_disagreement_rate": _rate(wrong, determinate),
            "indeterminate_rate": _rate(effects["indeterminate"], total),
            "decision_coverage": _rate(determinate, total),
            "wilson_95": wilson_95(wrong, total) if intervals else None,
            "interval_status": status,
        }
    return summary


def score_labels(report: dict[str, Any]) -> dict[str, Any]:
    """Score effects, not safety; preserve generated and non-generated strata."""
    rows = report["results"]
    seeds = [row for row in rows if not _generated(row)]
    generated = [row for row in rows if _generated(row)]
    strata = {}
    for name, selected, intervals in (
        ("all", rows, not generated),
        ("seed", seeds, True),
        ("generated-variant", generated, False),
    ):
        strata[name] = {
            "events": len(selected),
            **{
                side: _score_side(selected, side, intervals=intervals)
                for side in ("baseline", "candidate")
            },
        }
    return {
        "schema_version": "label-agreement.v1",
        "label_basis": "supplied-v1-labels",
        "confidence_level": 0.95,
        "limitations": [
            "Supplied v1 labels are not independent ground truth "
            "or a safety certificate.",
            "Wilson intervals are descriptive under an independent Bernoulli model; "
            "a convenience corpus does not establish population coverage.",
            "Generated cases and pooled samples containing them have no interval. "
            "Seed means non-generated origin, not independent adjudication.",
            "Origin is self-declared; v1 cannot identify all hook-derived "
            "or correlated cases.",
        ],
        "strata": strata,
    }


def render_label_summary(scores: dict[str, Any]) -> str:
    """Render only controlled labels and numeric aggregates, never case text."""
    lines = [
        "## Supplied-label agreement",
        "",
        "These labels are not independently certified safety evidence. Rates use",
        "all cases in each class, including indeterminate effects. JSON also shows",
        "decision coverage, conditional rates and qualified descriptive intervals.",
        "",
        "| group | side | label | disagreements / all | rate | indeterminate |",
        "|---|---|---|---:|---:|---:|",
    ]
    for name, stratum in scores["strata"].items():
        if name != "all" and not stratum["events"]:
            continue
        for side in ("baseline", "candidate"):
            for label in ("dangerous", "benign"):
                row = stratum[side][label]
                rate = row["disagreement_rate"]
                shown = "n/a" if rate is None else f"{rate:.2%}"
                lines.append(
                    f"| {name} | {side} | {label} | "
                    f"{row['disagreement_count']} / {row['total']} | {shown} | "
                    f"{row['effects']['indeterminate']} |"
                )
    lines += [
        "",
        "Generated variants do not receive independent-sample intervals.",
        "Latency is observational and lives in each side's measurements.json,",
        "not in this deterministic summary or the run identity.",
    ]
    return "\n".join(lines)


def latency_summary(
    observations: list[dict[str, Any]], *, jobs: int, timeout_seconds: float
) -> dict[str, Any]:
    """Summarize observed process time, retaining censoring and admission counts."""
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 86400
    ):
        raise ValueError("timeout must be finite, positive and at most 86400 seconds")
    elapsed = []
    timeouts = start_failed = 0
    allowed = {
        "allow",
        "deny",
        "ask",
        "stop",
        "timeout",
        "crash",
        "invalid-output",
        "start-failed",
        "output-limit",
    }
    for observation in observations:
        value, outcome = observation["elapsed_ms"], observation["outcome"]
        if type(value) is not int or value < 0 or outcome not in allowed:
            raise ValueError(
                "expected a known outcome and non-negative integer elapsed_ms"
            )
        if outcome == "start-failed":
            start_failed += 1
        else:
            elapsed.append(value)
        timeouts += outcome == "timeout"
    elapsed.sort()

    def percentile(percent: int) -> int | None:
        return elapsed[(percent * len(elapsed) + 99) // 100 - 1] if elapsed else None

    return {
        "schema_version": "hook-measurements.v1",
        "deterministic": False,
        "event_count": len(observations),
        "sample_count": len(elapsed),
        "timeout_count": timeouts,
        "start_failed_count": start_failed,
        "jobs": jobs,
        "timeout_seconds": timeout_seconds,
        "percentile_method": "nearest-rank",
        "elapsed_ms": {
            "p50": percentile(50),
            "p95": percentile(95),
            "max": percentile(100),
        },
        "limitations": [
            "Observed process wall time excludes workspace preparation "
            "and final cleanup.",
            "Timeout samples are censored observations, not completion latencies.",
            "Unstarted events are excluded. Different jobs settings "
            "are not comparable.",
        ],
    }
