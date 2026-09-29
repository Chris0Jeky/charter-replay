"""Semantic PolicyDecision comparison in corpus order."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from charter_replay.corpus import (
    validate_charter_cases,
    validate_command_events,
    validate_policy_decisions,
)

DIFF_CLASSES = (
    "unchanged",
    "newly-allowed",
    "newly-denied",
    "newly-indeterminate",
    "resolved-indeterminate",
)


class ComparisonError(ValueError):
    """The supplied records cannot form a complete trustworthy comparison."""


@dataclass(frozen=True)
class EventComparison:
    """One baseline/candidate pair classified without command interpretation."""

    event: dict[str, Any]
    baseline: dict[str, Any]
    candidate: dict[str, Any]
    classification: str
    case: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {
            "event": dict(self.event),
            "classification": self.classification,
            "baseline": dict(self.baseline),
            "candidate": dict(self.candidate),
        }
        if self.case is not None:
            value["case"] = dict(self.case)
        return value


@dataclass(frozen=True)
class ComparisonResult:
    """Complete event results and fixed-order class counts."""

    results: tuple[EventComparison, ...]
    counts: dict[str, int]


def classify_effects(baseline: str, candidate: str) -> str:
    """Classify one already-validated effect transition."""

    if baseline == candidate:
        return "unchanged"
    if baseline == "deny" and candidate == "allow":
        return "newly-allowed"
    if baseline == "allow" and candidate == "deny":
        return "newly-denied"
    if baseline in {"allow", "deny"} and candidate == "indeterminate":
        return "newly-indeterminate"
    if baseline == "indeterminate" and candidate in {"allow", "deny"}:
        return "resolved-indeterminate"
    raise ComparisonError(
        f"unsupported effect transition: {baseline!r} to {candidate!r}"
    )


def _index_exact_decisions(
    decisions: list[dict[str, Any]],
    expected_ids: set[str],
    label: str,
) -> dict[str, dict[str, Any]]:
    by_event_id = {decision["event_id"]: decision for decision in decisions}
    actual_ids = set(by_event_id)
    missing = sorted(expected_ids - actual_ids)
    unexpected = sorted(actual_ids - expected_ids)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ComparisonError(
            f"{label} decisions do not match corpus: {'; '.join(details)}"
        )
    return by_event_id


def compare_decisions(
    event_values: list[object],
    baseline_values: list[object],
    candidate_values: list[object],
    *,
    case_values: list[object] | None = None,
) -> ComparisonResult:
    """Compare validated decisions by id and emit rows in corpus order."""

    events = validate_command_events(event_values)
    expected_ids = {event["event_id"] for event in events}
    baseline = _index_exact_decisions(
        validate_policy_decisions(baseline_values), expected_ids, "baseline"
    )
    candidate = _index_exact_decisions(
        validate_policy_decisions(candidate_values), expected_ids, "candidate"
    )

    cases_by_event_id: dict[str, dict[str, Any]] = {}
    if case_values is not None:
        cases = validate_charter_cases(case_values)
        cases_by_event_id = {case["event_id"]: case for case in cases}
        case_ids = set(cases_by_event_id)
        if case_ids != expected_ids:
            missing = sorted(expected_ids - case_ids)
            unexpected = sorted(case_ids - expected_ids)
            details: list[str] = []
            if missing:
                details.append("missing " + ", ".join(missing))
            if unexpected:
                details.append("unexpected " + ", ".join(unexpected))
            raise ComparisonError(
                "charter cases do not match corpus: " + "; ".join(details)
            )

    counts = {classification: 0 for classification in DIFF_CLASSES}
    results: list[EventComparison] = []
    for event in events:
        event_id = event["event_id"]
        baseline_decision = baseline[event_id]
        candidate_decision = candidate[event_id]
        classification = classify_effects(
            baseline_decision["effect"], candidate_decision["effect"]
        )
        counts[classification] += 1
        results.append(
            EventComparison(
                event=event,
                baseline=baseline_decision,
                candidate=candidate_decision,
                classification=classification,
                case=cases_by_event_id.get(event_id),
            )
        )
    return ComparisonResult(tuple(results), counts)
