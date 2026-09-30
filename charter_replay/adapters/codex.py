"""Legacy Codex floor compatibility, not current-runtime certification.

The v0.1 recorder treats ask as deny. Keep that behaviour during extraction;
correcting the fail-open runtime contract requires a separate versioned change.
"""

from charter_replay.adapters.claude import ClaudeAdapter


class CodexAdapter(ClaudeAdapter):
    name = "codex"
    contract_id = "codex-legacy-floor.v1"

    def classify(self, exit_code: int, stdout: str, stderr: str) -> tuple[str, str]:
        outcome, reason = super().classify(exit_code, stdout, stderr)
        if outcome == "ask":
            return "deny", f"ask is unsupported on codex: {reason}"
        return outcome, reason
