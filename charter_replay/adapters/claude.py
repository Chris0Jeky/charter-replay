"""Claude PreToolUse grammar preserved from the v0.1 recorder."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from charter_replay.adapters.base import event_cwd


def _json_decision(value: object) -> tuple[str, str] | None:
    """Return (outcome, reason) for a JSON hook reply, or None when it is not one."""

    if not isinstance(value, dict):
        return None
    if value.get("continue") is False:
        return "stop", str(value.get("stopReason") or "continue is false")
    specific = value.get("hookSpecificOutput")
    if isinstance(specific, dict) and "permissionDecision" in specific:
        if specific.get("hookEventName") != "PreToolUse":
            # The runtime rejects a decision without the matching event name.
            return None
        decision = specific.get("permissionDecision")
        reason = str(specific.get("permissionDecisionReason") or "")
        if decision in ("allow", "deny", "ask"):
            return decision, reason
        return None
    legacy = value.get("decision")
    if legacy == "approve":
        return "allow", str(value.get("reason") or "")
    if legacy == "block":
        return "deny", str(value.get("reason") or "")
    if legacy is not None:
        return None
    # A JSON reply without a decision lets the normal permission flow continue.
    return "allow", "no decision field"


class ClaudeAdapter:
    name = "claude"
    contract_id = "claude-pretooluse.v1"

    def build_payload(
        self, event: dict[str, Any], *, workspace: Path, index: int
    ) -> dict[str, Any]:
        """Build the PreToolUse payload a runtime sends for one Bash command."""

        return {
            "session_id": "replay-session",
            "transcript_path": str(workspace / ".replay" / "transcript.jsonl"),
            "cwd": str(event_cwd(event, workspace)),
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": event["command"]},
            "tool_use_id": f"replay-{index:06d}",
            "model": f"{self.name}-replay",
        }

    def classify(self, exit_code: int, stdout: str, stderr: str) -> tuple[str, str]:
        """Map one completed hook process onto (outcome, detail)."""

        if exit_code == 2:
            return "deny", stderr.strip() or "exit 2"
        if exit_code != 0:
            first = stderr.strip().splitlines()[:1]
            return "crash", f"exit {exit_code}" + (f": {first[0]}" if first else "")
        body = stdout.strip()
        if not body:
            return "allow", "exit 0, no output"
        try:
            value = json.loads(body)
        except ValueError:
            return "invalid-output", "exit 0 with stdout that is not JSON"
        result = _json_decision(value)
        if result is None:
            return "invalid-output", "JSON reply without a recognised decision"
        return result

    def environment(self, workspace: Path) -> dict[str, str]:
        return {"CLAUDE_PROJECT_DIR": str(workspace)}
