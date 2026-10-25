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
import urllib.parse
import subprocess
from typing import Any, Iterator

from charter_replay.corpus import (
    CHARTER_CASE_VERSION,
    COMMAND_EVENT_VERSION,
)
from charter_replay.digests import sha256_bytes
from charter_replay.publication import new_destination, publish_new_directory

CORPUS_ID = "private-local"
FALLBACK_TIMESTAMP = "2000-01-01T00:00:00Z"
CODEX_SHELL_CALLS = frozenset({"shell_command", "shell"})
_PLAIN_WORD = re.compile(r"^[A-Za-z0-9_./:=@%+,-]+$")
_FAMILY_WORD = re.compile(r"[^a-z0-9]+")

# Bound regex work per line; dropping an oversized line avoids both expensive
# near-matches and leaking a credential cut in half by chunking.
_MAX_SCRUB_LINE = 4096
_MAX_CREDENTIAL_LINES = 16
_LINE_ENDINGS = "\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"
_LINE_BREAKS = r"\r\n\v\f\x1c-\x1e\x85\u2028\u2029"
# Do not let a missing END rescan through subsequent BEGIN markers. Both the
# labels and body are bounded; this is the only whole-text scrubbing regex.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-----"
    r"(?:(?!-----BEGIN )[\s\S]){0,65536}?"
    r"-----END [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-----"
)
_QUOTED_CREDENTIAL = (
    rf"\\\"[^\\\"{_LINE_BREAKS}]*\\\"|"
    rf'"(?:[^"\\{_LINE_BREAKS}]|\\.)*+"|'
    rf"'[^'{_LINE_BREAKS}]*'"
)
_CREDENTIAL_NAME = (
    r"[A-Za-z0-9_]{0,64}(?:token|secret|passw(?:or)?d|api[_-]?key|auth)"
    r"[A-Za-z0-9_]{0,64}"
)
# Recognise our own marker before a bare value: a second pass must not swallow
# JSON punctuation and neighbouring fields after an already-redacted value.
# Bare escapes consume two characters; possessive repetition prevents a quoted
# segment from being reconsidered as individual escapes on a later near-match.
_CREDENTIAL_VALUE = (
    r"(<redacted>(?=[,}\]])|(?:"
    + _QUOTED_CREDENTIAL
    + r"""|\\.|[^\s;&|'"\\])++(?:["'][^\s;&|]*)?|[^\s;&|]+)"""
)
_CLOSED_CREDENTIAL = re.compile(_QUOTED_CREDENTIAL)
_CREDENTIAL_PREFIX = re.compile(
    r"(?i)(?:\bmysql(?:\.exe)?\b[^;|&]{0,256}?\s-p(?=\S|$)|"
    r"--?(?:password|passwd|pass|token|secret|api-?key|client-secret)(?:=|\s+|$)|"
    r"\b" + _CREDENTIAL_NAME + r"\\?[\"']?\s*[=:]\s*|(?<!\S)-p\s*$)"
)
_MYSQL_COMMAND = re.compile(r"(?i)\bmysql(?:\.exe)?\b[^;|&]*$")
_MYSQL_CONTINUED_PREFIX = re.compile(r"(?<!\S)-p(?=\S)")
_MYSQL_CONTINUED_VALUE = re.compile(r"((?<!\S)-p)" + _CREDENTIAL_VALUE)


def _credential_end(text: str, start: int, quote: str = "") -> tuple[int, str]:
    """Scan one shell-like value, retaining an unfinished quote across lines."""
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if quote:
            if char == quote:
                quote = ""
        elif char.isspace() or char in ";&|":
            break
        elif char in "\"'":
            quote = char
        index += 1
    return min(index, len(text)), quote


def _redact_credential(match: re.Match[str]) -> str:
    value = match.group(2)
    # A bare value can end at the enclosing command's quote. Preserve that
    # unmatched delimiter, but still remove complete quote-concatenated values.
    closing = value[-1] if value[-1] in "\"'" else ""
    if closing and (
        value.count(closing) % 2 == 0 or _CLOSED_CREDENTIAL.fullmatch(value)
    ):
        closing = ""
    return match.group(1) + "<redacted>" + closing


# Order matters: specific credential shapes before generic ones, paths before
# bare usernames.
_TOKEN_PATTERNS = (
    (
        re.compile(
            rf"(?i)(\bmysql(?:\.exe)?\b[^;{_LINE_BREAKS}|&]{{0,256}}?\s-p)"
            + _CREDENTIAL_VALUE
        ),
        _redact_credential,
    ),
    (
        re.compile(
            r"(?i)(\bConvertTo-SecureString\s+(?:-String\s+)?)"
            + _CREDENTIAL_VALUE
            + r"(?=\s+-AsPlainText\b)"
        ),
        _redact_credential,
    ),
    (
        re.compile(
            r"(?i)(--?(?:password|passwd|pass|token|secret|api-?key|client-secret)"
            r"(?:=|\s+))" + _CREDENTIAL_VALUE
        ),
        _redact_credential,
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
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}"), "<token>"),
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.(?:[A-Za-z0-9_-]{8,})?"
        ),
        "<token>",
    ),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <token>"),
    # Any other scheme (Token, Bot, ApiKey, Digest) after an Authorization header.
    (
        re.compile(r"(?i)\b(authorization\s*:\s*[A-Za-z]+)\s+[A-Za-z0-9._~+/=-]{8,}"),
        r"\1 <token>",
    ),
    (
        # Scrub JSON strings individually before shell matching can consume
        # attached punctuation. The marker then preserves neighbouring fields.
        re.compile(
            r"(?i)(\b"
            + _CREDENTIAL_NAME
            + r"""\\?["']\s*:\s*)("""
            + _QUOTED_CREDENTIAL
            + r")(?=[,}\]])"
        ),
        _redact_credential,
    ),
    (
        re.compile(
            r"(?i)\b(" + _CREDENTIAL_NAME + r"\\?[\"']?\s*[=:]\s*)" + _CREDENTIAL_VALUE
        ),
        _redact_credential,
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
    r"(?i)\b([a-z][a-z0-9+.-]*://)([A-Za-z0-9_.-]+)(:[0-9]+)?(/[^\s\"';&|<>()`]*)?"
)
# scp-style remotes, dotted or single-label: `git@code.example.corp:team/x.git`,
# `git@buildhost:team/x.git`.
_SCP_REMOTE = re.compile(
    r"\b[\w.-]+@([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*):(?!//)([^\s\"';&|<>()`]+)"
)
# A quoted URL keeps `&`, `;` and `|` in its query; only the quote ends it.
_QUOTED_URL = re.compile(
    rf"(?i)(['\"])([a-z][a-z0-9+.-]*://(?:(?!\1)[^{_LINE_BREAKS}])*)\1"
)
_URL_HOST_QUOTED = re.compile(
    r"(?i)\A([a-z][a-z0-9+.-]*://)([A-Za-z0-9_.-]+)(:[0-9]+)?([/?#]\S*)?"
)
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_PLACEHOLDER = re.compile(
    r"<(?:redacted|token|user|host|path|owner|repo|email|hex|blob|private-key)>"
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
# Inside quotes a home folder may hold a space ("C:\Users\Jane Roe\x"), so the
# separator or quote, not whitespace, ends the username there.
# UNC homes (\\server\Users\name): both the server and the name identify.
_UNC_HOME = re.compile(
    r"(?i)(?<![:\w])(\\\\|//)[^\\/\s\"']+"
    r"((?:[\\/]+[A-Z]\$)?[\\/]+Users[\\/]+|"
    r"[\\/]+[^\\/\s\"']+[\\/]+home[\\/]+)[^\\/\s\"']+"
)
_QUOTED_HOME_PATHS = (
    re.compile(
        rf"(?i)([\"'][^\"'{_LINE_BREAKS}]{{0,256}}?[A-Z]:[\\/]+"
        rf"(?:Users|Documents and Settings)[\\/]+)[^\\/\"'{_LINE_BREAKS}]+"
    ),
    re.compile(
        rf"([\"'][^\"'{_LINE_BREAKS}]{{0,256}}?/(?:Users|home)/)[^/\"'{_LINE_BREAKS}]+"
    ),
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
        text = self._scrub_lines(text)
        # Decode at most twice, including combined percent/quote splitting.
        # Keep the most redacted variant; equal scores preserve earlier text.
        words = []
        for word in re.split(r"(\s+)", text):
            variants = [word, self._dequote(word)]
            # Dequote before decoding too: quotes can split the escape itself.
            for base in tuple(variants):
                for _ in range(2):
                    if not _PERCENT.search(base):
                        break
                    base = urllib.parse.unquote(base)
                    variants.append(base)
            best = word
            best_count = len(_PLACEHOLDER.findall(word))
            candidates = variants[1:] + [self._dequote(v) for v in variants]
            for variant in dict.fromkeys(candidates):
                if variant != word:
                    cleaned = self._scrub_lines(variant)
                    count = len(_PLACEHOLDER.findall(cleaned))
                    if count > best_count:
                        best, best_count = cleaned, count
            words.append(best)
        return "".join(words)

    def _scrub_lines(self, text: str) -> str:
        lines = []
        waiting = False
        quote = ""
        quote_lines = 0
        mysql_continued = False
        for line in _PRIVATE_KEY.sub("<private-key>", text).splitlines(keepends=True):
            body = line.rstrip(_LINE_ENDINGS)
            ending = line[len(body) :]
            if len(body) > _MAX_SCRUB_LINE:
                lines.append("<redacted>" + ending)
                waiting, quote, quote_lines, mysql_continued = False, "", 0, False
                continue

            # Only an odd trailing backslash escapes the physical line ending.
            continued = bool(ending) and (len(body) - len(body.rstrip("\\"))) % 2 == 1
            command = body[:-1] if continued else body
            next_mysql = continued and (
                bool(_MYSQL_COMMAND.search(command))
                or (mysql_continued and not any(c in command for c in ";&|"))
            )
            # Preserve rule keywords until single-line scrubbing has run.
            # Cross-line state is always detected from the original command.
            scrubbed = self._scrub(command)
            start = 0
            cut_start = None
            cut_quote = quote
            if quote or (waiting and command.strip()):
                if not quote:
                    start = len(command) - len(command.lstrip())
                cut_start = start
                start, quote = _credential_end(command, start, quote)
                waiting = False
                quote_lines += 1

            if not quote:
                prefixes = list(_CREDENTIAL_PREFIX.finditer(command, start))
                if mysql_continued:
                    # Shell controls end the inherited mysql command's scope.
                    limit = re.search(r"[;&|]", command)
                    prefixes.extend(
                        _MYSQL_CONTINUED_PREFIX.finditer(
                            command, start, limit.start() if limit else len(command)
                        )
                    )
                scanned_end = start
                shell_index = 0
                shell_quote = ""
                for match in sorted(prefixes, key=lambda match: match.end()):
                    if match.start() < scanned_end:
                        continue
                    value_start = match.end()
                    # Scan forward once to distinguish an enclosing closing
                    # quote from the start of a multiline credential value.
                    while shell_index < value_start:
                        char = command[shell_index]
                        if char == "\\" and shell_quote != "'":
                            shell_index += 2
                            continue
                        if shell_quote:
                            if char == shell_quote:
                                shell_quote = ""
                        elif char in "\"'":
                            shell_quote = char
                        shell_index += 1
                    # Only a quote that closes the string AND ends the line is
                    # a prompt (read -p "Password: "): with text after it the
                    # scan may be wrong about the quote, so carry as before.
                    if value_start == len(command) or (
                        shell_quote
                        and command[value_start] == shell_quote
                        and not command[value_start + 1 :].strip()
                    ):
                        waiting = True
                    elif command[value_start] in "\"'":
                        # A complete JSON value ends before its punctuation;
                        # the enclosing shell quote is not part of the value.
                        closed = _CLOSED_CREDENTIAL.match(command, value_start)
                        if closed and command[closed.end() : closed.end() + 1] in (
                            ",",
                            "}",
                            "]",
                        ):
                            continue
                        scanned_end, open_quote = _credential_end(command, value_start)
                        if open_quote:
                            cut = len(self._scrub(command[:value_start]))
                            scrubbed = scrubbed[:cut] + "<redacted>"
                            quote, quote_lines = open_quote, 1
                            break

            if cut_start is not None:
                # Markers contain no whitespace, so scan the scrubbed value
                # again rather than applying offsets from the original text.
                end, _ = _credential_end(scrubbed, cut_start, cut_quote)
                scrubbed = scrubbed[:cut_start] + "<redacted>" + scrubbed[end:]
            if quote_lines >= _MAX_CREDENTIAL_LINES:
                quote = ""
            if not quote:
                quote_lines = 0
            if mysql_continued:
                limit = re.search(r"[;&|]", scrubbed)
                end = limit.start() if limit else len(scrubbed)
                scrubbed = (
                    _MYSQL_CONTINUED_VALUE.sub(_redact_credential, scrubbed[:end])
                    + scrubbed[end:]
                )
            body = scrubbed + ("\\" if continued else "")
            lines.append(body + ending)
            mysql_continued = next_mysql
        return "".join(lines)

    @staticmethod
    def _dequote(word: str) -> str:
        # Keep matching outer quotes and a quote that continues into another
        # whitespace-separated word. Remove paired quotes inside a joined word.
        prefix = suffix = ""
        if word and word[0] in "\"'":
            quote = word[0]
            if word.endswith(quote) or word.count(quote) % 2:
                prefix = quote
        if len(word) > 1 and word[-1] in "\"'":
            quote = word[-1]
            if word.startswith(quote) or word.count(quote) % 2:
                suffix = quote
        return prefix + word.replace("'", "").replace('"', "") + suffix

    def _scrub(self, text: str) -> str:
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
        text = _QUOTED_URL.sub(self._quoted_url, text)
        text = _URL_HOST.sub(self._host, text)
        text = _UNC_HOME.sub(r"\1<host>\2<user>", text)
        for pattern in _QUOTED_HOME_PATHS + _HOME_PATHS:
            text = pattern.sub(r"\1<user>", text)
        for pattern in self._term_patterns:
            text = pattern.sub("<redacted>", text)
        return text

    @classmethod
    def _host(cls, match: re.Match[str]) -> str:
        host = match.group(2).lower()
        if host in _PUBLIC_HOSTS:
            # A public URL can carry a private URL in its query. Scan its tail
            # rather than letting the outer match shield the nested address.
            tail = match.group(4)
            if tail:
                return match.group(0)[: -len(tail)] + _URL_HOST.sub(cls._host, tail)
            return match.group(0)
        return f"{match.group(1)}<host>" + ("/<path>" if match.group(4) else "")

    @classmethod
    def _quoted_url(cls, match: re.Match[str]) -> str:
        inner = _URL_HOST_QUOTED.sub(cls._host, match.group(2), count=1)
        return f"{match.group(1)}{inner}{match.group(1)}"

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
    missing = []
    parent = output.absolute().parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    output = new_destination(output)
    if not output_is_private(output):
        raise ValueError("output must be outside a Git work tree or ignored by Git")
    files = {"events.jsonl": _jsonl_bytes(events), "cases.jsonl": _jsonl_bytes(cases)}
    manifest = {
        "schema_version": "corpus-manifest.v1",
        "corpus_id": CORPUS_ID,
        "event_count": len(events),
        "files": [
            {"path": name, "sha256": sha256_bytes(content)}
            for name, content in files.items()
        ],
    }
    files["corpus-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode(
        "utf-8"
    )
    publish_new_directory(output, files, marker="corpus-manifest.json")


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
