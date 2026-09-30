"""Codex PreToolUse contract `codex-pretooluse.v1`.

A documentation-derived model of the Codex command-hook grammar (see
docs/RUNTIME_CONTRACTS.md for sources), not a certification against a running
Codex binary. The rule it is built on: whatever Codex would mark as a failed
hook run and continue past is `invalid-output`, which is indeterminate, so a
fail-open reply is never scored as a block. Where the documentation is
ambiguous the classifier chooses `invalid-output` rather than an allow or deny.
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
_SPECIFIC_KEYS = frozenset(
    {
        "hookEventName",
        "permissionDecision",
        "permissionDecisionReason",
        "updatedInput",
        "additionalContext",
    }
)
_INVALID = "invalid-output"


class _DuplicateKey(ValueError):
    """A reply repeated a member name; a strict parser would reject it."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Python keeps the last duplicate; Codex's strict parser fails the hook.
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
    """Codex trims a reason and treats a blank one as missing."""

    return value.strip() if isinstance(value, str) else ""


def _object_reply(value: dict[str, Any]) -> tuple[str, str]:
    unknown = sorted(set(value) - _TOP_KEYS)
    if unknown:
        return _invalid(f"unknown field {unknown[0]!r} in a codex reply")
    if not isinstance(value.get("continue", True), bool):
        return _invalid("continue must be a boolean")
    if not isinstance(value.get("suppressOutput", False), bool):
        return _invalid("suppressOutput must be a boolean")
    for key in ("stopReason", "systemMessage", "reason"):
        if not _text_or_none(value.get(key)):
            return _invalid(f"{key} must be a string")
    decision = value.get("decision")
    if decision not in (None, "approve", "block"):
        return _invalid("decision is not approve or block")
    specific = value.get("hookSpecificOutput")
    if specific is not None and not isinstance(specific, dict):
        return _invalid("hookSpecificOutput must be an object")

    if value.get("continue", True) is False:
        return _invalid("continue:false is unsupported by codex")
    if value.get("stopReason") is not None:
        return _invalid("stopReason is unsupported by codex")
    if value.get("suppressOutput") is True:
        return _invalid("suppressOutput is unsupported by codex")

    permission = None
    permission_reason = None
    updated = None
    if specific is not None:
        unknown = sorted(set(specific) - _SPECIFIC_KEYS)
        if unknown:
            return _invalid(f"unknown hookSpecificOutput field {unknown[0]!r}")
        if "hookEventName" not in specific:
            return _invalid("hookSpecificOutput has no hookEventName")
        if specific["hookEventName"] != "PreToolUse":
            # Codex parses any event name here; the published schema requires
            # PreToolUse. Ambiguous, so it is not treated as a decision.
            return _invalid("hookEventName is not PreToolUse")
        permission = specific.get("permissionDecision")
        if permission not in (None, "allow", "deny", "ask"):
            return _invalid("permissionDecision is not allow, deny or ask")
        for key in ("permissionDecisionReason", "additionalContext"):
            if not _text_or_none(specific.get(key)):
                return _invalid(f"{key} must be a string")
        permission_reason = specific.get("permissionDecisionReason")
        updated = specific.get("updatedInput")

    if permission is not None or permission_reason is not None or updated is not None:
        if decision is not None or value.get("reason") is not None:
            # The documentation does not say which form wins when both appear.
            return _invalid("mixes hookSpecificOutput and legacy decision fields")
        if updated is not None and permission != "allow":
            return _invalid("updatedInput without permissionDecision allow")
        if permission == "allow":
            if updated is None:
                return _invalid("permissionDecision allow without updatedInput")
            return _invalid(
                "allow with updatedInput rewrites the command; not modelled"
            )
        if permission == "ask":
            return _invalid("ask is unsupported by codex")
        if permission == "deny":
            reason = _reason(permission_reason)
            if not reason:
                return _invalid("deny without a permissionDecisionReason")
            return "deny", reason
        return _invalid("permissionDecisionReason without permissionDecision")

    if decision == "approve":
        return _invalid("legacy decision approve is unsupported by codex")
    if decision == "block":
        reason = _reason(value.get("reason"))
        if not reason:
            return _invalid("legacy decision block without a reason")
        return "deny", reason
    if value.get("reason") is not None:
        return _invalid("reason without decision")
    # No decision: systemMessage and additionalContext do not stop the call.
    return "allow", "no decision field"


class CodexAdapter:
    name = "codex"
    contract_id = "codex-pretooluse.v1"

    def build_payload(
        self, event: dict[str, Any], *, workspace: Path, index: int
    ) -> dict[str, Any]:
        """Build the documented PreToolUse input for one shell command."""

        return {
            "session_id": "replay-session",
            "turn_id": f"replay-turn-{index:06d}",
            "transcript_path": None,
            "cwd": str(event_cwd(event, workspace)),
            "hook_event_name": "PreToolUse",
            "model": "codex-replay",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": event["command"]},
            "tool_use_id": f"replay-{index:06d}",
        }

    def classify(self, exit_code: int, stdout: str, stderr: str) -> tuple[str, str]:
        """Map one completed hook process onto (outcome, detail)."""

        if exit_code == 2:
            reason = stderr.strip()
            if reason:
                return "deny", reason
            return _invalid("exit 2 without a blocking reason on stderr")
        if exit_code != 0:
            first = stderr.strip().splitlines()[:1]
            return "crash", f"exit {exit_code}" + (f": {first[0]}" if first else "")
        body = stdout.strip()
        if not body:
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
            if body[0] in "{[":
                return _invalid("stdout looks like JSON but is malformed")
            return "allow", "exit 0, plain-text stdout ignored"
        if not isinstance(value, dict):
            return _invalid("JSON reply is not an object")
        return _object_reply(value)

    def environment(self, workspace: Path) -> dict[str, str]:
        # Documented command hooks get the session environment only; the
        # replay's own allow-list stays. No project-dir variable is documented.
        return {}
