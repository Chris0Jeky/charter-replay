"""Legacy Codex floor compatibility (`--runtime codex-legacy`), not certification.

The v0.1 recorder treats ask as deny. This adapter keeps that behaviour byte for
byte so old recordings stay reproducible. It is fail-safe for nothing: current
Codex documentation says an unsupported ask marks the hook failed and lets the
tool call continue, so this floor reports deny where the runtime would proceed.
The current contract is `codex.CodexAdapter` (`--runtime codex`).
"""

from pathlib import Path
from typing import Any

from charter_replay.adapters.claude import ClaudeAdapter


class CodexLegacyAdapter(ClaudeAdapter):
    name = "codex-legacy"
    contract_id = "codex-legacy-floor.v1"

    def build_payload(
        self, event: dict[str, Any], *, workspace: Path, index: int
    ) -> dict[str, Any]:
        payload = super().build_payload(event, workspace=workspace, index=index)
        # The v0.1 runtime was named "codex"; the payload stays byte-identical.
        payload["model"] = "codex-replay"
        return payload

    def classify(self, exit_code: int, stdout: str, stderr: str) -> tuple[str, str]:
        outcome, reason = super().classify(exit_code, stdout, stderr)
        if outcome == "ask":
            return "deny", f"ask is unsupported on codex: {reason}"
        return outcome, reason
