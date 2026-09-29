"""Strict standard-library validators for replay v0 records."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
import re
from typing import Any

COMMAND_EVENT_VERSION = "command-event.v1"
POLICY_DECISION_VERSION = "policy-decision.v1"
CHARTER_CASE_VERSION = "charter-case.v1"

EVENT_SOURCES = frozenset({"synthetic", "historical-redacted", "generated-variant"})
DECISION_EFFECTS = frozenset({"allow", "deny", "indeterminate"})
CASE_CLASSES = frozenset({"dangerous", "benign", "opaque"})

_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}" r"(?:\.[0-9]+)?Z$"
)


class ValidationError(ValueError):
    """A replay record failed its versioned contract."""


def split_jsonl_records(text: str) -> list[str]:
    """Split JSONL only on LF, dropping at most one conventional final delimiter."""

    records = text.split("\n")
    if records and records[-1] == "":
        records.pop()
    return records


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValidationError(f"{label}: expected a JSON object with string keys")
    return value


def _require_shape(
    record: dict[str, Any],
    label: str,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
) -> None:
    missing = [field for field in required if field not in record]
    if missing:
        raise ValidationError(
            f"{label}: missing required field(s): {', '.join(missing)}"
        )
    unexpected = sorted(set(record) - set(required) - set(optional))
    if unexpected:
        raise ValidationError(f"{label}: unexpected field(s): {', '.join(unexpected)}")


def _require_string(
    record: dict[str, Any],
    field: str,
    label: str,
    *,
    max_length: int | None = None,
    single_line: bool = False,
) -> str:
    value = record[field]
    if not isinstance(value, str):
        raise ValidationError(f"{label}.{field}: expected a string")
    if not value:
        raise ValidationError(f"{label}.{field}: must not be empty")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{label}.{field}: must be valid UTF-8") from exc
    if max_length is not None and len(value) > max_length:
        raise ValidationError(
            f"{label}.{field}: must be at most {max_length} characters"
        )
    if single_line and ("\n" in value or "\r" in value):
        raise ValidationError(f"{label}.{field}: must be a single line")
    return value


def _require_constant(
    record: dict[str, Any], field: str, expected: str, label: str
) -> None:
    value = _require_string(record, field, label)
    if value != expected:
        raise ValidationError(f"{label}.{field}: expected {expected!r}")


def _require_enum(
    record: dict[str, Any],
    field: str,
    allowed: frozenset[str],
    label: str,
) -> None:
    value = _require_string(record, field, label)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ValidationError(f"{label}.{field}: expected one of: {choices}")


def _require_timestamp(record: dict[str, Any], label: str) -> None:
    value = _require_string(record, "timestamp", label)
    if not _RFC3339_UTC.fullmatch(value):
        raise ValidationError(
            f"{label}.timestamp: expected an RFC 3339 UTC timestamp ending in Z"
        )
    try:
        datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as exc:
        raise ValidationError(
            f"{label}.timestamp: expected a valid calendar timestamp"
        ) from exc


def validate_command_event(value: object) -> dict[str, Any]:
    """Validate and return one `CommandEvent` v1 without mutating it."""

    label = "CommandEvent"
    record = _require_object(value, label)
    _require_shape(
        record,
        label,
        ("schema_version", "event_id", "timestamp", "command", "source"),
        ("cwd",),
    )
    _require_constant(record, "schema_version", COMMAND_EVENT_VERSION, label)
    _require_string(record, "event_id", label)
    _require_timestamp(record, label)
    _require_string(record, "command", label)
    if "cwd" in record:
        _require_string(record, "cwd", label)
    _require_enum(record, "source", EVENT_SOURCES, label)
    return dict(record)


def validate_policy_decision(value: object) -> dict[str, Any]:
    """Validate and return one `PolicyDecision` v1 without mutating it."""

    label = "PolicyDecision"
    record = _require_object(value, label)
    _require_shape(record, label, ("schema_version", "event_id", "effect", "reason"))
    _require_constant(record, "schema_version", POLICY_DECISION_VERSION, label)
    _require_string(record, "event_id", label)
    _require_enum(record, "effect", DECISION_EFFECTS, label)
    _require_string(record, "reason", label, max_length=500, single_line=True)
    return dict(record)


def validate_charter_case(value: object) -> dict[str, Any]:
    """Validate and return one `CharterCase` v1 without mutating it."""

    label = "CharterCase"
    record = _require_object(value, label)
    _require_shape(
        record,
        label,
        (
            "schema_version",
            "event_id",
            "case_class",
            "case_family",
            "rationale",
            "provenance",
        ),
    )
    _require_constant(record, "schema_version", CHARTER_CASE_VERSION, label)
    _require_string(record, "event_id", label)
    _require_enum(record, "case_class", CASE_CLASSES, label)
    _require_string(record, "case_family", label)
    _require_string(record, "rationale", label)
    _require_enum(record, "provenance", EVENT_SOURCES, label)
    return dict(record)


def _validate_unique_records(
    values: Iterable[object],
    validator: Callable[[object], dict[str, Any]],
    label: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        record = validator(value)
        event_id = record["event_id"]
        if event_id in seen:
            raise ValidationError(f"{label}: duplicate event_id {event_id!r}")
        seen.add(event_id)
        records.append(record)
    return records


def validate_command_events(values: Iterable[object]) -> list[dict[str, Any]]:
    """Validate an ordered corpus and enforce unique event ids."""

    records = _validate_unique_records(
        values, validate_command_event, "CommandEvent corpus"
    )
    if not records:
        raise ValidationError("CommandEvent corpus: expected at least one record")
    return records


def validate_charter_cases(values: Iterable[object]) -> list[dict[str, Any]]:
    """Validate ordered charter metadata and enforce unique event ids."""

    records = _validate_unique_records(
        values, validate_charter_case, "CharterCase corpus"
    )
    if not records:
        raise ValidationError("CharterCase corpus: expected at least one record")
    return records


def validate_policy_decisions(values: Iterable[object]) -> list[dict[str, Any]]:
    """Validate ordered policy decisions and enforce unique event ids."""

    return _validate_unique_records(
        values, validate_policy_decision, "PolicyDecision stream"
    )
