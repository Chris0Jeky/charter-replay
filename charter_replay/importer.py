"""Build a private, scrubbed replay corpus from local agent transcripts.

Reads Claude Code project transcripts (`tool_use` blocks named Bash or
PowerShell) and Codex session rollouts (`shell_command` / `shell` function
calls), scrubs each command, and writes a charter-shaped corpus that the replay
kernel can load. The output is private: it is written only outside any Git
work tree or to a path that Git ignores, and it must never be committed.

Scrubbing is defence in depth, not anonymisation. Treat the output as private.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
import random
from pathlib import Path
import re
import socket
import subprocess
from typing import Any, Iterator

from charter_replay.corpus import (
    CHARTER_CASE_VERSION,
    COMMAND_EVENT_VERSION,
)
from charter_replay.digests import sha256_bytes

CORPUS_ID = "private-local"
FALLBACK_TIMESTAMP = "2000-01-01T00:00:00Z"
CODEX_SHELL_CALLS = frozenset({"shell_command", "shell"})
_PLAIN_WORD = re.compile(r"^[A-Za-z0-9_./:=@%+,-]+$")
_FAMILY_WORD = re.compile(r"[^a-z0-9]+")

# Order matters: specific credential shapes before generic ones, paths before
# bare usernames.
_TOKEN_PATTERNS = (
    (
        re.compile(
            r"(?i)(--?(?:password|passwd|pass|token|secret|api-?key|client-secret)"
            r"(?:=|\s+))(\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
        ),
        r"\1<redacted>",
    ),
    (
        re.compile(r"((?:^|\s)(?:-u|--user)(?:=|\s+))[^\s:]+:[^\s;&|]+"),
        r"\1<redacted>",
    ),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}"), "<token>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}"), "<token>"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}"), "<token>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "<token>"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<token>"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), "<token>"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "<token>",
    ),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <token>"),
    (
        re.compile(
            r"(?i)\b([A-Za-z_]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth)"
            r"[A-Za-z_]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
        ),
        r"\1<redacted>",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
        "<private-key>",
    ),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<hex>"),
    (re.compile(r"[A-Za-z0-9+/]{48,}={0,2}"), "<blob>"),
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")
_GITHUB_REPO = re.compile(r"(?i)(github\.com[:/])[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_REPOS_API = re.compile(r"\b(repos/)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_REPO_FLAG = re.compile(
    r"((?:--repo(?:=|\s+)|-R\s+))[\"']?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[\"']?"
)
# Any scheme (https, ssh, git, ...): a private host loses its path too. Paths
# stop at shell control characters so `url;next-command` keeps its command.
_URL_HOST = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)([A-Za-z0-9.-]+)(:[0-9]+)?(/[^\s\"';&|<>()`]*)?"
)
# scp-style remotes, dotted or single-label: `git@code.example.corp:team/x.git`,
# `git@buildhost:team/x.git`.
_SCP_REMOTE = re.compile(
    r"\b[\w.-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*):(?!//)([^\s\"';&|<>()`]+)"
)
_PUBLIC_HOSTS = frozenset(
    {
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "example.com",
        "example.org",
        "localhost",
        "127.0.0.1",
    }
)
_HOME_PATHS = (
    re.compile(
        r"(?i)\b([A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+)[^\\/\s\"']+"
    ),
    re.compile(r"(/(?:Users|home)/)[^/\s\"']+"),
    re.compile(r"(?i)(/[a-z]/Users/)[^/\s\"']+"),
    re.compile(r"(/mnt/[a-z]/Users/)[^/\s\"']+"),
    re.compile(r"(?i)(%5CUsers%5C)[^%\s\"']+"),
)


def _git_identity() -> set[str]:
    """The local Git user name and email, which often name the account owner."""

    found: set[str] = set()
    for key in ("user.name", "user.email"):
        try:
            result = subprocess.run(
                ["git", "config", "--global", key],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        value = result.stdout.strip()
        if value:
            found.add(value)
            found.update(part for part in re.split(r"[@\s]", value) if part)
    return found


class Scrubber:
    """Replace machine, identity and credential material in command text."""

    def __init__(self, terms: list[str] | None = None) -> None:
        words = {os.environ.get("USERNAME", ""), os.environ.get("USER", "")}
        words.add(Path.home().name)
        words.update(Path.home().name.split())
        try:
            words.add(socket.gethostname())
        except OSError:
            pass
        words.update(_git_identity())
        words.update(terms or [])
        self.terms = sorted(
            (word for word in words if len(word) >= 3), key=len, reverse=True
        )
        # Long terms are replaced anywhere (paths get concatenated or
        # URL-encoded); short ones only as whole words.
        self._term_patterns = [
            re.compile(
                rf"(?i){re.escape(word)}"
                if len(word) >= 5
                else rf"(?i)(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])"
            )
            for word in self.terms
        ]
        self._spaced_term_patterns = [
            pattern
            for word, pattern in zip(self.terms, self._term_patterns)
            if " " in word
        ]

    def scrub(self, text: str) -> str:
        # Names containing a space go first: the home-path rule stops at
        # whitespace. Every other term waits, so the repo and email rules still
        # see whole `owner/repo` and `user@domain` shapes.
        for pattern in self._spaced_term_patterns:
            text = pattern.sub("<redacted>", text)
        for pattern, replacement in _TOKEN_PATTERNS:
            text = pattern.sub(replacement, text)
        text = _URL_USERINFO.sub(r"\1", text)
        text = _GITHUB_REPO.sub(r"\1<owner>/<repo>", text)
        text = _SCP_REMOTE.sub(self._scp, text)
        text = _EMAIL.sub("<email>", text)
        text = _REPOS_API.sub(r"\1<owner>/<repo>", text)
        text = _REPO_FLAG.sub(r"\1<owner>/<repo>", text)
        text = _URL_HOST.sub(self._host, text)
        for pattern in _HOME_PATHS:
            text = pattern.sub(r"\1<user>", text)
        for pattern in self._term_patterns:
            text = pattern.sub("<redacted>", text)
        return text

    @staticmethod
    def _host(match: re.Match[str]) -> str:
        host = match.group(2).lower()
        if host in _PUBLIC_HOSTS:
            return match.group(0)
        return f"{match.group(1)}<host>" + ("/<path>" if match.group(4) else "")

    @staticmethod
    def _scp(match: re.Match[str]) -> str:
        if match.group(1).lower() in _PUBLIC_HOSTS:
            return match.group(0)
        return "<host>:<path>"


def _iter_jsonl(path: Path, stats: Counter[str]) -> Iterator[dict[str, Any]]:
    try:
        handle = path.open(encoding="utf-8", errors="replace")
    except OSError:
        stats["unreadable-files"] += 1
        return
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                stats["unparsed-lines"] += 1
                continue
            if isinstance(record, dict):
                yield record


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        return FALLBACK_TIMESTAMP
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return FALLBACK_TIMESTAMP
    if moment.tzinfo is None:
        return FALLBACK_TIMESTAMP
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def claude_commands(
    root: Path, stats: Counter[str]
) -> Iterator[tuple[str, str, str | None]]:
    """Yield (command, timestamp, cwd) for each Bash/PowerShell tool call."""

    for path in sorted(root.rglob("*.jsonl")):
        stats["claude-files"] += 1
        for record in _iter_jsonl(path, stats):
            message = record.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, list):
                continue
            for block in content:
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_use"
                    and block.get("name") in ("Bash", "PowerShell")
                    and isinstance(block.get("input"), dict)
                    and isinstance(block["input"].get("command"), str)
                ):
                    stats["claude-commands"] += 1
                    cwd = record.get("cwd")
                    yield (
                        block["input"]["command"],
                        _timestamp(record.get("timestamp")),
                        cwd if isinstance(cwd, str) else None,
                    )


def _argv_command(argv: list[object]) -> str | None:
    """Recover a command line from a legacy argv call only when it is unambiguous."""

    if not argv or not all(isinstance(word, str) for word in argv):
        return None
    words = [str(word) for word in argv]
    head = Path(words[0].replace("\\", "/")).name.lower().removesuffix(".exe")
    if head in ("bash", "sh", "zsh") and len(words) >= 3 and words[1] in ("-c", "-lc"):
        return words[2]
    if head in ("powershell", "pwsh") and "-Command" in words:
        rest = words[words.index("-Command") + 1 :]
        return " ".join(rest) or None
    if all(_PLAIN_WORD.fullmatch(word) for word in words):
        return " ".join(words)
    return None


def codex_commands(
    root: Path, stats: Counter[str]
) -> Iterator[tuple[str, str, str | None]]:
    """Yield (command, timestamp, cwd) for each Codex shell function call."""

    for path in sorted(root.rglob("*.jsonl")):
        stats["codex-files"] += 1
        cwd: str | None = None
        for record in _iter_jsonl(path, stats):
            payload = record.get("payload")
            if not isinstance(payload, dict):
                continue
            if isinstance(payload.get("cwd"), str):
                cwd = payload["cwd"]
            if payload.get("type") != "function_call":
                continue
            if payload.get("name") not in CODEX_SHELL_CALLS:
                continue
            try:
                arguments = json.loads(payload.get("arguments") or "")
            except (TypeError, ValueError):
                stats["codex-unparsed-calls"] += 1
                continue
            command = arguments.get("command") if isinstance(arguments, dict) else None
            if isinstance(command, list):
                command = _argv_command(command)
            if not isinstance(command, str):
                stats["codex-unparsed-calls"] += 1
                continue
            stats["codex-commands"] += 1
            yield command, _timestamp(record.get("timestamp")), cwd


def _family(runtime: str, command: str) -> str:
    words = command.split()
    head = words[0] if words else "empty"
    head = Path(head.replace("\\", "/")).name.lower()
    head = _FAMILY_WORD.sub("-", head).strip("-")[:24] or "other"
    if head.startswith("redacted") or head in ("user", "token", "hex", "blob"):
        head = "other"
    return f"{runtime}-{head}"


def output_is_private(output: Path) -> bool:
    """True when `output` is outside every Git work tree or ignored by Git."""

    target = output.resolve()
    for parent in (target, *target.parents):
        if (parent / ".git").exists():
            break
    else:
        return True
    # Every file the importer writes must be ignored, not just one of them.
    for name in ("events.jsonl", "cases.jsonl", "corpus-manifest.json"):
        try:
            result = subprocess.run(
                ["git", "-C", str(parent), "check-ignore", "-q", str(target / name)],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0:
            return False
    return True


def build_private_corpus(
    sources: list[tuple[str, Iterator[tuple[str, str, str | None]]]],
    scrubber: Scrubber,
    *,
    dedupe: bool = True,
    limit: int = 0,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Counter[str]]:
    events: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    seen: set[str] = set()
    for runtime, commands in sources:
        for command, timestamp, _cwd in commands:
            if not command.strip():
                stats["empty-commands"] += 1
                continue
            clean = scrubber.scrub(command)
            if dedupe and clean in seen:
                stats["duplicates"] += 1
                continue
            seen.add(clean)
            event_id = f"imp-{runtime}-{len(events) + 1:06d}"
            events.append(
                {
                    "schema_version": COMMAND_EVENT_VERSION,
                    "event_id": event_id,
                    "timestamp": timestamp,
                    "command": clean,
                    "cwd": "project",
                    "source": "historical-redacted",
                }
            )
            cases.append(
                {
                    "schema_version": CHARTER_CASE_VERSION,
                    "event_id": event_id,
                    "case_class": "opaque",
                    "case_family": _family(runtime, clean),
                    "rationale": "Imported from a local transcript; not labelled.",
                    "provenance": "historical-redacted",
                }
            )
            if limit and len(events) >= limit:
                return events, cases, stats
    return events, cases, stats


def _jsonl_bytes(records: list[dict[str, Any]]) -> bytes:
    lines = [
        json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        for record in records
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_corpus(
    output: Path, events: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    files = {"events.jsonl": _jsonl_bytes(events), "cases.jsonl": _jsonl_bytes(cases)}
    for name, content in files.items():
        (output / name).write_bytes(content)
    manifest = {
        "schema_version": "corpus-manifest.v1",
        "corpus_id": CORPUS_ID,
        "event_count": len(events),
        "files": [
            {"path": name, "sha256": sha256_bytes(content)}
            for name, content in files.items()
        ],
    }
    (output / "corpus-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )


def _root(value: str | None, *default: str) -> Path | None:
    if value == "none":
        return None
    return Path(value) if value else Path.home().joinpath(*default)


def run_import(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if not output_is_private(output):
        print(
            "import: refusing to write inside a Git work tree to a path Git does "
            "not ignore; choose an ignored or external --output",
            flush=True,
        )
        return 2
    terms: list[str] = []
    if args.redact_terms:
        terms = [
            line.strip()
            for line in Path(args.redact_terms).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    stats: Counter[str] = Counter()
    sources: list[tuple[str, Iterator[tuple[str, str, str | None]]]] = []
    claude_root = _root(args.claude_root, ".claude", "projects")
    codex_root = _root(args.codex_root, ".codex", "sessions")
    if claude_root is not None and claude_root.is_dir():
        sources.append(("claude", claude_commands(claude_root, stats)))
    if codex_root is not None and codex_root.is_dir():
        sources.append(("codex", codex_commands(codex_root, stats)))
    if not sources:
        print("import: no transcript root found", flush=True)
        return 2
    events, cases, build_stats = build_private_corpus(
        sources,
        Scrubber(terms),
        dedupe=not args.keep_duplicates,
        limit=args.limit,
    )
    stats.update(build_stats)
    if args.sample and args.sample < len(events):
        keep = sorted(random.Random(args.seed).sample(range(len(events)), args.sample))
        events = [events[index] for index in keep]
        cases = [cases[index] for index in keep]
    if not events:
        print("import: no commands found", flush=True)
        return 2
    write_corpus(output, events, cases)
    stats["events-written"] = len(events)
    print(json.dumps(dict(sorted(stats.items())), indent=2))
    return 0
