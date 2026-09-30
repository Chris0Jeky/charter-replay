"""Gemini CLI BeforeTool contract `gemini-beforetool.v1`.

A documentation- and source-derived model of the Gemini CLI command-hook grammar
(see docs/RUNTIME_CONTRACTS.md for sources and the pinned upstream revision), not
a certification against a running Gemini CLI binary. The rule it is built on:
whatever Gemini CLI would treat as a failed hook and continue past is
`invalid-output` or `crash`, both indeterminate, so a fail-open reply is never
scored as a block. Where the documentation and the upstream source disagree, or
either is silent, the classifier chooses `invalid-output` rather than an allow or
deny.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from charter_replay.adapters.base import event_cwd

_TOP_KEYS = frozenset(
    {
        "continue",
        "stopReason",
        "suppressOutput",
        "systemMessage",
        "decision",
        "reason",
        "hookSpecificOutput",
    }
)
_SPECIFIC_KEYS = frozenset({"hookEventName", "tool_input"})
_INVALID = "invalid-output"
# Replay timestamps are fixed so a recording does not depend on the wall clock.
_TIMESTAMP = "1970-01-01T00:00:00.000Z"


class _DuplicateKey(ValueError):
    """A reply repeated a member name; a strict parser would reject it."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Python and Node both keep the last duplicate; this contract fails the reply.
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(key)
        value[key] = item
    return value


def _invalid(detail: str) -> tuple[str, str]:
    return _INVALID, detail


def _text_or_none(value: object) -> bool:
    return value is None or isinstance(value, str)


def _reason(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _parses_as_json(text: str) -> bool:
    # Upstream `trim()` strips a byte-order mark before parsing; Python's does not.
    text = text.lstrip("\ufeff")
    try:
        json.loads(text)
    except json.JSONDecodeError:
        return False
    except (RecursionError, ValueError):
        return True  # cannot tell, so the caller must not treat it as plain text
    return True


def _object_reply(value: dict[str, Any]) -> tuple[str, str]:
    unknown = sorted(set(value) - _TOP_KEYS)
    if unknown:
        return _invalid(f"unknown field {unknown[0]!r} in a gemini reply")
    if not isinstance(value.get("continue", True), bool):
        return _invalid("continue must be a boolean")
    if not isinstance(value.get("suppressOutput", False), bool):
        return _invalid("suppressOutput must be a boolean")
    for key in ("stopReason", "systemMessage", "reason", "decision"):
        if not _text_or_none(value.get(key)):
            return _invalid(f"{key} must be a string")
    decision = value.get("decision")
    if decision not in (None, "allow", "deny", "block"):
        # `ask` and `approve` exist in the upstream types but not in the
        # documented BeforeTool reply, so neither is treated as a decision.
        return _invalid("decision is not allow, deny or block")
    specific = value.get("hookSpecificOutput")
    if specific is not None and not isinstance(specific, dict):
        return _invalid("hookSpecificOutput must be an object")

    rewrite = False
    if specific is not None:
        unknown = sorted(set(specific) - _SPECIFIC_KEYS)
        if unknown:
            return _invalid(f"unknown hookSpecificOutput field {unknown[0]!r}")
        if "hookEventName" not in specific:
            return _invalid("hookSpecificOutput has no hookEventName")
        if specific["hookEventName"] != "BeforeTool":
            return _invalid("hookEventName is not BeforeTool")
        rewrite = "tool_input" in specific

    if value.get("continue", True) is False:
        # The tool call never runs and the agent loop stops; a rewrite is moot.
        detail = _reason(value.get("stopReason")) or _reason(value.get("reason"))
        return "stop", detail or "continue is false"
    if decision in ("deny", "block"):
        reason = _reason(value.get("reason"))
        if not reason:
            return _invalid("deny without a reason")
        return "deny", reason
    if rewrite:
        return _invalid(
            "hookSpecificOutput.tool_input rewrites the command; not modelled"
        )
    return "allow", "no decision field" if decision is None else "decision allow"


class GeminiAdapter:
    name = "gemini"
    contract_id = "gemini-beforetool.v1"

    def build_payload(
        self, event: dict[str, Any], *, workspace: Path, index: int
    ) -> dict[str, Any]:
        """Build the documented BeforeTool input for one shell command."""

        return {
            "session_id": "replay-session",
            "transcript_path": "",
            "cwd": str(event_cwd(event, workspace)),
            "hook_event_name": "BeforeTool",
            "timestamp": _TIMESTAMP,
            "tool_name": "run_shell_command",
            "tool_input": {"command": event["command"]},
        }

    def classify(self, exit_code: int, stdout: str, stderr: str) -> tuple[str, str]:
        """Map one completed hook process onto (outcome, detail)."""

        if exit_code == 2:
            reason = stderr.strip()
            if stdout.strip():
                # Upstream parses stdout first and ignores the exit code for a
                # JSON reply; the docs say exit 2 blocks with stderr as reason.
                return _invalid("exit 2 with stdout is ambiguous")
            if not reason:
                # Upstream lets a call with no output at all continue.
                return _invalid("exit 2 without a blocking reason on stderr")
            if _parses_as_json(reason):
                # Upstream would read this stderr as the reply, not as a reason.
                return _invalid("exit 2 with JSON on stderr is ambiguous")
            return "deny", reason
        if exit_code != 0:
            first = stderr.strip().splitlines()[:1]
            return "crash", f"exit {exit_code}" + (f": {first[0]}" if first else "")
        body = stdout.strip()
        if not body:
            if stderr.strip() and _parses_as_json(stderr.strip()):
                # The docs say stderr is never parsed; upstream parses it when
                # stdout is empty.
                return _invalid("empty stdout with JSON on stderr is ambiguous")
            return "allow", "exit 0, no output"
        if body[0] == "\ufeff":
            # Undocumented; a PowerShell hook's BOM-prefixed JSON is ambiguous.
            return _invalid("stdout starts with a byte-order mark")
        try:
            value = json.loads(body, object_pairs_hook=_unique_object)
        except _DuplicateKey:
            return _invalid("JSON reply repeats a member name")
        except RecursionError:
            return _invalid("JSON reply is nested too deeply")
        except ValueError:
            # Documented as "pollution = failure": the CLI allows the call and
            # shows the text. A blocking reply spoiled by a stray line would be
            # scored as an allow, so this is a failed hook, not an allow.
            return _invalid("stdout is not JSON")
        if not isinstance(value, dict):
            return _invalid("JSON reply is not an object")
        return _object_reply(value)

    def environment(self, workspace: Path) -> dict[str, str]:
        # Documented hook variables that the replay can state truthfully. The
        # per-event GEMINI_CWD and the machine-specific GEMINI_PLANS_DIR are not
        # provided; the hook still runs with the event cwd as its working dir.
        return {
            "GEMINI_PROJECT_DIR": str(workspace),
            "GEMINI_SESSION_ID": "replay-session",
            "CLAUDE_PROJECT_DIR": str(workspace),
        }
