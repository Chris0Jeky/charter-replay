"""Bounded string-only POSIX shapes with explicit label-transfer assumptions."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Any

from charter_replay.corpus import validate_charter_cases, validate_command_events
from charter_replay.digests import canonical_json_bytes, sha256_bytes

DOMAIN = "posix-external.v1"
GENERATOR = "posix-shapes.v1"
TRANSFORMS = ("prefix-whitespace.v1", "quote-words.v1", "env-wrapper.v1")
MAX_SEEDS = 5000
MAX_DERIVED = 15000
MAX_COMMAND_BYTES = 4096

# Shell builtins and interpreters used as wrappers are deliberately absent.
EXTERNAL_COMMANDS = frozenset(
    "git rm rmdir cp mv ls cat grep find head tail sed awk sort uniq wc cut tr "
    "diff mkdir touch tar gzip curl wget scp rsync npm npx node python python3 "
    "pip pip3".split()
)
ASSUMPTIONS = (
    "Non-interactive POSIX shell with the same external tools and configuration.",
    "Admitted executable names have no aliases or shell functions.",
    "env resolves to the standard external utility and preserves the environment.",
    "Supplied seed labels are inherited assumptions, not independent safety votes.",
)


class VariantError(ValueError):
    """A source, domain, budget or exact-byte lineage cannot be admitted."""


@dataclass(frozen=True)
class VariantBatch:
    events: list[dict[str, Any]]
    cases: list[dict[str, Any]]
    mappings: list[dict[str, str]]
    skipped: list[dict[str, str]]


def _literal_words(command: str) -> tuple[list[str] | None, str]:
    """Admit a literal external invocation, not general shell grammar."""
    if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
        return None, "command-too-long"
    quote = ""
    start = True
    for character in command:
        if (ord(character) < 32 and character != "\t") or ord(character) == 127:
            return None, "unsupported-syntax"
        if quote == "'":
            if character == "'":
                quote = ""
            continue
        if quote == '"':
            if character in "\\$`":
                return None, "unsupported-syntax"
            if character == '"':
                quote = ""
            continue
        if character in "'\"":
            quote = character
            start = False
        elif character in " \t":
            start = True
        elif character in "\\$`;&|<>(){}*?[]#" or (character == "~" and start):
            return None, "unsupported-syntax"
        else:
            start = False
    if quote:
        return None, "unsupported-syntax"
    try:
        words = shlex.split(command, comments=False, posix=True)
    except ValueError:
        return None, "unsupported-syntax"
    if not words or words[0] not in EXTERNAL_COMMANDS:
        return None, "unsupported-executable"
    return words, ""


def _quote_word(word: str) -> str:
    return "'" + word.replace("'", "'\"'\"'") + "'"


def derive_variants(
    events: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    source_manifest_sha256: str,
    *,
    domain: str,
    max_derived: int = MAX_DERIVED,
) -> VariantBatch:
    """Return derived rows and explicit skips without executing or mutating input."""
    if domain != DOMAIN:
        raise VariantError(f"domain must be explicitly selected as {DOMAIN}")
    if not isinstance(source_manifest_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", source_manifest_sha256
    ):
        raise VariantError("source manifest digest must be lowercase SHA-256")
    if type(max_derived) is not int or not 0 <= max_derived <= MAX_DERIVED:
        raise VariantError(f"max-derived must be an integer from 0 to {MAX_DERIVED}")
    if len(events) > MAX_SEEDS or len(cases) > MAX_SEEDS:
        raise VariantError(f"source exceeds the {MAX_SEEDS} seed budget")
    events = validate_command_events(events)
    cases = validate_charter_cases(cases)
    case_by_id = {case["event_id"]: case for case in cases}
    seen = {event["event_id"] for event in events}
    if seen != set(case_by_id):
        raise VariantError("source case IDs do not match event IDs")
    if any(event["source"] == "generated-variant" for event in events) or any(
        case["provenance"] == "generated-variant" for case in cases
    ):
        raise VariantError(
            "generated input is not a seed corpus; recursive derivation is disabled"
        )

    batch = VariantBatch([], [], [], [])
    for event in events:
        case = case_by_id[event["event_id"]]
        if case["case_class"] == "opaque":
            words, reason = None, "opaque-label"
        else:
            words, reason = _literal_words(event["command"])
        shapes = (
            (
                " \t" + event["command"],
                " ".join(map(_quote_word, words)),
                "env " + event["command"],
            )
            if words is not None
            else (None,) * len(TRANSFORMS)
        )
        for transform, command in zip(TRANSFORMS, shapes):
            skip = reason
            if command == event["command"]:
                skip = "unchanged-command"
            elif (
                command is not None
                and len(command.encode("utf-8")) > MAX_COMMAND_BYTES
            ):
                skip = "derived-command-too-long"
            if skip:
                batch.skipped.append(
                    dict(
                        seed_event_id=event["event_id"],
                        transform_id=transform,
                        reason=skip,
                    )
                )
                continue
            if len(batch.events) >= max_derived:
                raise VariantError(
                    "derived event budget exceeded; no partial selection is published"
                )
            event_id = "variant-" + sha256_bytes(
                canonical_json_bytes(
                    dict(
                        generator=GENERATOR,
                        domain=DOMAIN,
                        source_manifest_sha256=source_manifest_sha256,
                        seed_event_id=event["event_id"],
                        transform_id=transform,
                    )
                )
            )
            if event_id in seen:
                raise VariantError("derived event ID collides with another event")
            seen.add(event_id)
            batch.events.append(
                dict(
                    event, event_id=event_id, command=command, source="generated-variant"
                )
            )
            batch.cases.append(
                dict(case, event_id=event_id, provenance="generated-variant")
            )
            batch.mappings.append(
                dict(
                    event_id=event_id,
                    seed_event_id=event["event_id"],
                    transform_id=transform,
                )
            )
    validate_command_events(events + batch.events)
    validate_charter_cases(cases + batch.cases)
    return batch
