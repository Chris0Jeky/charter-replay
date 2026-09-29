"""Run a PreToolUse command hook over a corpus and record its decisions.

The hook is invoked the way a coding-agent runtime invokes it: one process per
command, the PreToolUse JSON payload on standard input, and the decision read
from the exit code, standard output and standard error. Each invocation is
classified into one hook outcome and mapped onto the replay v0 effect set
(`allow`, `deny`, `indeterminate`); the outcome survives as the reason prefix.

This module never executes corpus commands. It executes the hook, which is an
unsandboxed program chosen by the caller.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import subprocess
import tempfile
import time
from typing import Any, Sequence

from charter_replay.corpus import POLICY_DECISION_VERSION
from charter_replay.digests import sha256_bytes
from charter_replay.policy_sources import _run_policy_process

RUNTIMES = ("claude", "codex")
ASK_EFFECTS = ("deny", "allow", "indeterminate")
REASON_LIMIT = 500
OUTCOMES = (
    "allow",
    "deny",
    "ask",
    "stop",
    "timeout",
    "crash",
    "invalid-output",
    "start-failed",
)
# Environment names passed through to the hook. Everything else is dropped so a
# recording does not depend on, or leak into, the caller's full environment.
PASSTHROUGH_ENV = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
)


_SCRIPT_SUFFIXES = frozenset(
    {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".ps1", ".rb"}
)


class HookSpecError(ValueError):
    """A hook command or option cannot be used."""


@dataclass(frozen=True)
class HookSpec:
    argv: tuple[str, ...]
    runtime: str = "claude"
    timeout: float = 10.0
    ask_effect: str = "deny"


@dataclass(frozen=True)
class HookOutcome:
    outcome: str
    detail: str
    exit_code: int | None
    elapsed_ms: int


def parse_hook_command(value: str) -> tuple[str, ...]:
    """Split a hook command without a shell: a JSON array, or POSIX-style words."""

    text = value.strip()
    if text.startswith("["):
        try:
            argv = json.loads(text)
        except ValueError as exc:
            raise HookSpecError("hook command JSON is not a valid array") from exc
        if not isinstance(argv, list) or not all(
            isinstance(item, str) and item for item in argv
        ):
            raise HookSpecError("hook command JSON must be an array of strings")
    else:
        try:
            # POSIX mode would eat Windows backslashes (`.\hooks\g.py`).
            argv = shlex.split(text, posix=os.name != "nt")
        except ValueError as exc:
            raise HookSpecError("hook command has unbalanced quotes") from exc
        if os.name == "nt":
            argv = [_unquote(word) for word in argv]
    if not argv:
        raise HookSpecError("hook command is empty")
    head = Path(argv[0])
    # A path-shaped executable (`./hook`, `tools/hook`) must survive the move
    # into the workspace; a bare name keeps its PATH lookup.
    path_shaped = "/" in argv[0] or "\\" in argv[0]
    resolved = [str(head.resolve()) if path_shaped and head.exists() else argv[0]]
    for word in argv[1:]:
        path = Path(word)
        if path.is_file():
            # The hook runs inside the replay workspace, so an argument naming
            # an existing file relative to the caller is made absolute first.
            resolved.append(str(path.resolve()))
        elif _looks_like_file(word):
            # A missing script makes most interpreters exit 2, which would be
            # recorded as a deny for every event and measure nothing.
            raise HookSpecError(f"hook argument names a missing file: {word}")
        else:
            resolved.append(word)
    return tuple(resolved)


def _unquote(word: str) -> str:
    if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'":
        return word[1:-1]
    return word


def _looks_like_file(word: str) -> bool:
    # Only a script name: URLs, directories and inline code also contain slashes.
    return (
        not word.startswith("-")
        and Path(word).suffix.lower() in _SCRIPT_SUFFIXES
        and not Path(word).exists()
    )


def event_cwd(event: dict[str, Any], workspace: Path) -> Path:
    """Place an event's corpus-relative `cwd` inside the replay workspace."""

    relative = str(event.get("cwd") or "").replace("\\", "/")
    parts = [
        part
        for part in PurePosixPath(relative).parts
        if part not in ("", ".", "..", "/") and ":" not in part
    ]
    return workspace.joinpath(*parts)


def build_payload(
    event: dict[str, Any], *, runtime: str, workspace: Path, index: int
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
        "model": f"{runtime}-replay",
    }


def _single_line(text: str) -> str:
    return " ".join(text.split())


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


def classify(
    exit_code: int, stdout: str, stderr: str, *, runtime: str
) -> tuple[str, str]:
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
    outcome, reason = result
    if runtime == "codex" and outcome == "ask":
        # Codex has no ask decision; the floor contract treats it as deny.
        return "deny", f"ask is unsupported on codex: {reason}"
    return outcome, reason


def _hook_env(workspace: Path) -> dict[str, str]:
    env = {name: os.environ[name] for name in PASSTHROUGH_ENV if name in os.environ}
    env["CLAUDE_PROJECT_DIR"] = str(workspace)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run_hook(
    spec: HookSpec, payload: dict[str, Any], *, workspace: Path
) -> HookOutcome:
    """Invoke the hook once, shell-free, and classify what it did."""

    started = time.monotonic()
    try:
        # The replay kernel's runner: temporary-file streams, and the hook's
        # whole process family is killed on timeout (Job Object / process group).
        completed = _run_policy_process(
            list(spec.argv),
            json.dumps(payload).encode("utf-8"),
            timeout_seconds=spec.timeout,
            cwd=str(workspace),
            environment=_hook_env(workspace),
        )
    except subprocess.TimeoutExpired:
        elapsed = int((time.monotonic() - started) * 1000)
        return HookOutcome(
            "timeout", f"no reply within {spec.timeout:g}s", None, elapsed
        )
    except OSError as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        return HookOutcome("start-failed", exc.__class__.__name__, None, elapsed)
    elapsed = int((time.monotonic() - started) * 1000)
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    outcome, detail = classify(
        completed.returncode, stdout, stderr, runtime=spec.runtime
    )
    # Keep the throwaway workspace location out of recorded reasons.
    forms = {str(workspace), workspace.as_posix()}
    forms |= {form.replace("\\", "\\\\") for form in forms}
    for form in sorted(forms, key=len, reverse=True):
        detail = detail.replace(form, "<workspace>")
    return HookOutcome(outcome, detail, completed.returncode, elapsed)


def effect_for(outcome: str, ask_effect: str) -> str:
    if outcome == "allow":
        return "allow"
    if outcome in ("deny", "stop"):
        return "deny"
    if outcome == "ask":
        return ask_effect
    return "indeterminate"


def decision_record(event_id: str, outcome: HookOutcome, ask_effect: str) -> dict:
    reason = _single_line(f"{outcome.outcome}: {outcome.detail}".strip())
    # A lone surrogate from a hook's JSON would make the record unencodable.
    reason = reason.encode("utf-8", "replace").decode("utf-8")
    if len(reason) > REASON_LIMIT:
        reason = reason[: REASON_LIMIT - 3] + "..."
    return {
        "schema_version": POLICY_DECISION_VERSION,
        "event_id": event_id,
        "effect": effect_for(outcome.outcome, ask_effect),
        "reason": reason,
    }


def hook_identity(argv: Sequence[str]) -> str:
    """Digest the hook's argv words and the bytes of any argument that is a file.

    The executable contributes only its name, and paths are reduced to their
    basename, so the identity is portable across hosts.
    """

    digest = hashlib.sha256()
    for position, word in enumerate(argv):
        path = Path(word)
        if position and path.is_file():
            digest.update(b"file\0" + path.name.encode("utf-8") + b"\0")
            digest.update(path.read_bytes())
        else:
            name = Path(word).name if os.sep in word or "/" in word else word
            digest.update(b"word\0" + name.encode("utf-8") + b"\0")
    return digest.hexdigest()


def prepare_workspace(template: Path | None) -> Path:
    """Create a fresh workspace, copying a template tree when one is given."""

    # Resolved, so a short (8.3) temporary path cannot hide from the reason scrub.
    root = Path(tempfile.mkdtemp(prefix="hook-replay-")).resolve()
    workspace = root / "workspace"
    if template is not None:
        shutil.copytree(template, workspace)
    else:
        workspace.mkdir()
    return workspace


def record_hook(
    spec: HookSpec,
    events: list[dict[str, Any]],
    output: Path,
    *,
    policy_id: str,
    workspace_template: Path | None = None,
    jobs: int = 1,
) -> dict[str, Any]:
    """Record one decision per event and write a replay v0 recorded source.

    Writes `decisions.jsonl`, its `.manifest.json` sidecar, and `outcomes.jsonl`
    (hook outcome, exit code and latency per event). Returns an outcome summary.
    """

    if spec.runtime not in RUNTIMES:
        raise HookSpecError(f"runtime must be one of: {', '.join(RUNTIMES)}")
    if spec.ask_effect not in ASK_EFFECTS:
        raise HookSpecError(f"ask effect must be one of: {', '.join(ASK_EFFECTS)}")
    workspace = prepare_workspace(workspace_template)
    try:
        for event in events:
            event_cwd(event, workspace).mkdir(parents=True, exist_ok=True)

        def one(item: tuple[int, dict[str, Any]]) -> HookOutcome:
            index, event = item
            payload = build_payload(
                event, runtime=spec.runtime, workspace=workspace, index=index
            )
            return run_hook(spec, payload, workspace=workspace)

        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            outcomes = list(pool.map(one, enumerate(events)))
    finally:
        shutil.rmtree(workspace.parent, ignore_errors=True)

    output.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(
            decision_record(event["event_id"], outcome, spec.ask_effect),
            separators=(",", ":"),
            ensure_ascii=False,
        )
        for event, outcome in zip(events, outcomes)
    ]
    decisions_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    (output / "decisions.jsonl").write_bytes(decisions_bytes)
    manifest = {
        "schema_version": "recorded-policy-manifest.v1",
        "policy_id": policy_id,
        # The recorded-source contract names a 40-hex commit. A hook is not
        # always a commit, so this carries a truncated content digest instead.
        "policy_commit": hook_identity(spec.argv)[:40],
        "decisions_file": "decisions.jsonl",
        "decisions_sha256": sha256_bytes(decisions_bytes),
        "decision_count": len(lines),
    }
    (output / "decisions.jsonl.manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    outcome_lines = [
        json.dumps(
            {
                "event_id": event["event_id"],
                "outcome": outcome.outcome,
                "exit_code": outcome.exit_code,
                "elapsed_ms": outcome.elapsed_ms,
            },
            separators=(",", ":"),
        )
        for event, outcome in zip(events, outcomes)
    ]
    (output / "outcomes.jsonl").write_text(
        "\n".join(outcome_lines) + "\n", encoding="utf-8", newline="\n"
    )
    counts = {name: 0 for name in OUTCOMES}
    for outcome in outcomes:
        counts[outcome.outcome] += 1
    return {"policy_id": policy_id, "events": len(events), "outcomes": counts}
