"""Versioned, input-only identity for the context a hook is recorded in.

The descriptor names what a recording was given: adapter contract, ask mapping,
timeout and concurrency, the admitted argv (executable and file bytes), the
workspace template tree and the environment the hook receives. It is derived
from inputs only, never from decisions or outcomes, so a changed result cannot
change the identity. It is a consistency key, not execution authentication:
anything listed under `unbound` is declared, not covered.

Nothing machine-specific is emitted: no absolute path, user name, environment
value or raw argv word. Hashes can still reveal a low-entropy input.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any

from charter_replay.adapters import RUNTIMES, get_adapter
from charter_replay.hooks import ASK_EFFECTS, PASSTHROUGH_ENV, HookSpec

HOOK_CONTEXT_VERSION = "hook-context.v1"
# Bounds are checked from stat data before any content is read or hashed.
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_CONTEXT_BYTES = 256 * 1024 * 1024
MAX_TEMPLATE_ENTRIES = 10_000
_CHUNK = 1024 * 1024
FIXED_ENVIRONMENT = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"}
# Declared, not covered: a stronger comparability claim must not assume these.
STATIC_UNBOUND = (
    "ambient-environment-values",
    "executable-dependencies",
    "file-permissions",
    "helper-imports",
    "mutable-external-state",
    "network",
    "time",
)
_FILE_REASONS = ("unreadable", "limit-exceeded")
_EXECUTABLE_REASONS = ("unresolved",) + _FILE_REASONS
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_ARGV_FILE_UNBOUND = re.compile(r"argv-file:(0|[1-9][0-9]{0,5})")
_DOCUMENT_KEYS = {"schema_version", "context_id", "descriptor"}
_DESCRIPTOR_KEYS = {
    "schema_version",
    "adapter",
    "decision_mapping",
    "execution",
    "hook",
    "workspace_template",
    "environment",
    "unbound",
}
_MAX_ARGV_WORDS = 4096
_MAX_NAME = 4096


class _LimitExceeded(Exception):
    """A bounded read would exceed its byte or entry limit."""


def _hash_file(path: Path, limit: int) -> tuple[str, int]:
    """Stream a regular file's SHA-256; refuse before reading if stat is over."""

    if path.stat().st_size > limit:
        raise _LimitExceeded
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            size += len(chunk)
            # The file may grow after the stat above.
            if size > limit:
                raise _LimitExceeded
            digest.update(chunk)
    return digest.hexdigest(), size


def _display_name(text: str) -> str:
    # A lone surrogate from a POSIX argv must not make the descriptor unencodable.
    clean = text.encode("utf-8", "replace").decode("utf-8")
    return clean[:_MAX_NAME] or "-"


def _reduced(word: str) -> str:
    return Path(word).name if os.sep in word or "/" in word else word


def _bound_file(kind: str, path: Path, name: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"kind": kind, "name": _display_name(name)}
    try:
        sha256, size = _hash_file(path, MAX_FILE_BYTES)
    except _LimitExceeded:
        return {**entry, "status": "unbound", "reason": "limit-exceeded"}
    except OSError:
        return {**entry, "status": "unbound", "reason": "unreadable"}
    return {**entry, "status": "bound", "sha256": sha256, "size": size}


def _executable(argv0: str) -> dict[str, Any]:
    # Resolve the way the runtime would, against the PATH the hook receives.
    if os.sep in argv0 or "/" in argv0:
        found = argv0 if Path(argv0).is_file() else None
    else:
        found = shutil.which(argv0, path=os.environ.get("PATH"))
    name = _reduced(argv0)
    if found is None:
        return {
            "kind": "executable",
            "name": _display_name(name),
            "status": "unbound",
            "reason": "unresolved",
        }
    return _bound_file("executable", Path(found), name)


def _is_file(word: str) -> bool:
    try:
        return Path(word).is_file()
    except (OSError, ValueError):
        return False


def _argv_word(word: str, kind: str | None) -> dict[str, Any]:
    # `kind` fixes a position seen earlier, so a file the hook itself creates
    # (an output path) never turns a word into a file on re-observation.
    if kind == "file" or (kind is None and _is_file(word)):
        return _bound_file("file", Path(word), Path(word).name)
    reduced = _reduced(word).encode("utf-8", "surrogatepass")
    return {"kind": "word", "sha256": hashlib.sha256(reduced).hexdigest()}


def _template(root: Path) -> dict[str, Any]:
    """Describe the tree `shutil.copytree(root, ...)` would copy (links followed)."""

    def unbound(reason: str) -> dict[str, Any]:
        return {"status": "unbound", "reason": reason}

    entries: list[tuple[str, str, int]] = []
    total = 0
    try:
        if not root.is_dir():
            return unbound("unreadable")
        stack = [("", os.path.realpath(root), frozenset())]
        # Walk and stat first: nothing is read until both limits are known to hold.
        while stack:
            prefix, real, ancestors = stack.pop()
            if real in ancestors:
                return unbound("unreadable")
            ancestors = ancestors | {real}
            with os.scandir(root / prefix if prefix else root) as scan:
                found = sorted(scan, key=lambda item: item.name)
            for item in found:
                relative = f"{prefix}/{item.name}" if prefix else item.name
                if len(entries) >= MAX_TEMPLATE_ENTRIES:
                    return unbound("limit-exceeded")
                if item.is_dir():
                    entries.append((relative, "dir", 0))
                    stack.append((relative, os.path.realpath(item.path), ancestors))
                elif item.is_file():
                    size = item.stat().st_size
                    total += size
                    if total > MAX_CONTEXT_BYTES:
                        return unbound("limit-exceeded")
                    entries.append((relative, "file", size))
                else:
                    # A broken link or special file that a copy could not follow.
                    return unbound("unreadable")
        tree = hashlib.sha256(b"hook-context.tree.v1\n")
        content = 0
        for relative, kind, _size in sorted(entries):
            if kind == "dir":
                record: list[Any] = ["dir", relative]
            else:
                sha256, size = _hash_file(root / relative, MAX_CONTEXT_BYTES)
                content += size
                if content > MAX_CONTEXT_BYTES:
                    return unbound("limit-exceeded")
                record = ["file", relative, size, sha256]
            tree.update(json.dumps(record, separators=(",", ":")).encode() + b"\n")
    except _LimitExceeded:
        return unbound("limit-exceeded")
    except (OSError, ValueError):
        return unbound("unreadable")
    return {
        "status": "bound",
        "entries": len(entries),
        "bytes": content,
        "tree_sha256": tree.hexdigest(),
    }


def _unbound_names(argv: list[dict[str, Any]], template: dict[str, Any] | None):
    names = set(STATIC_UNBOUND)
    for index, item in enumerate(argv):
        if item.get("status") == "unbound":
            names.add("executable" if index == 0 else f"argv-file:{index}")
    if template is not None and template["status"] == "unbound":
        names.add("workspace-template")
    return sorted(names)


def argv_kinds(descriptor: dict[str, Any]) -> list[str]:
    """The per-word kinds of a descriptor, to pin a later observation to them."""

    return [item["kind"] for item in descriptor["hook"]["argv"]]


def describe_hook_context(
    spec: HookSpec,
    *,
    workspace_template: Path | None,
    jobs: int,
    argv_kinds: list[str] | None = None,
) -> dict[str, Any]:
    """Return the input-only descriptor for one hook recording.

    Pass the `argv_kinds` of an earlier descriptor to re-observe the same
    inputs: each word keeps its kind, only its bytes are looked at again.
    """

    adapter = get_adapter(spec.runtime)
    kinds = argv_kinds or [None] * len(spec.argv)
    if len(kinds) != len(spec.argv):
        raise ValueError("argv kinds do not match the hook argv")
    argv = [_executable(spec.argv[0])]
    argv += [_argv_word(word, kind) for word, kind in zip(spec.argv[1:], kinds[1:])]
    template = None if workspace_template is None else _template(workspace_template)
    return {
        "schema_version": HOOK_CONTEXT_VERSION,
        "adapter": {"runtime": spec.runtime, "contract_id": adapter.contract_id},
        "decision_mapping": {"ask_effect": spec.ask_effect},
        "execution": {"timeout_seconds": float(spec.timeout), "jobs": jobs},
        "hook": {"argv": argv},
        "workspace_template": template,
        "environment": {
            "passthrough_names": sorted(PASSTHROUGH_ENV),
            "fixed": dict(FIXED_ENVIRONMENT),
            # Names only: the adapter's values contain the workspace path.
            "adapter_names": sorted(adapter.environment(Path("workspace"))),
        },
        "unbound": _unbound_names(argv, template),
    }


def context_id(descriptor: dict[str, Any]) -> str:
    """Full SHA-256 of the canonical descriptor, framed by its version."""

    canonical = json.dumps(
        descriptor,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(HOOK_CONTEXT_VERSION.encode() + b"\0" + canonical).hexdigest()


def context_document(descriptor: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": HOOK_CONTEXT_VERSION,
        "context_id": context_id(descriptor),
        "descriptor": descriptor,
    }


def hook_context_bytes(document: dict[str, Any]) -> bytes:
    """Deterministic file form, so equal inputs give equal bytes."""

    text = json.dumps(document, indent=2, sort_keys=True, allow_nan=False)
    return (text + "\n").encode("utf-8")


def _fail(where: str) -> ValueError:
    # Only fixed location text: a rejected file's contents are never echoed.
    return ValueError(f"hook context is invalid: {where}")


def _mapping(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _fail(f"{where} must have exactly its defined keys")
    return value


def _hex(value: Any, where: str) -> None:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise _fail(f"{where} must be 64 lowercase hex characters")


def _count(value: Any, where: str, limit: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"{where} must be an integer")
    if not 0 <= value <= limit:
        raise _fail(f"{where} is out of range")


def _name(value: Any, where: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_NAME:
        raise _fail(f"{where} must be a short non-empty string")
    if "/" in value or "\x00" in value:
        raise _fail(f"{where} must be a bare name")


def _validate_argv_item(item: Any, index: int) -> bool:
    """Validate one argv entry; return whether it is unbound."""

    where = f"descriptor.hook.argv[{index}]"
    if not isinstance(item, dict) or item.get("kind") not in (
        ("executable",) if index == 0 else ("file", "word")
    ):
        raise _fail(f"{where} has an unsupported kind")
    if item["kind"] == "word":
        _mapping(item, {"kind", "sha256"}, where)
        _hex(item["sha256"], f"{where}.sha256")
        return False
    if item.get("status") == "bound":
        _mapping(item, {"kind", "name", "status", "sha256", "size"}, where)
        _hex(item["sha256"], f"{where}.sha256")
        _count(item["size"], f"{where}.size", MAX_FILE_BYTES)
        _name(item["name"], f"{where}.name")
        return False
    _mapping(item, {"kind", "name", "status", "reason"}, where)
    reasons = _EXECUTABLE_REASONS if index == 0 else _FILE_REASONS
    if item["status"] != "unbound" or item["reason"] not in reasons:
        raise _fail(f"{where} has an unsupported status or reason")
    _name(item["name"], f"{where}.name")
    return True


def _validate_template(template: Any) -> bool:
    if template is None:
        return False
    if isinstance(template, dict) and template.get("status") == "bound":
        _mapping(
            template,
            {"status", "entries", "bytes", "tree_sha256"},
            "descriptor.workspace_template",
        )
        _count(template["entries"], "descriptor.workspace_template.entries", 10**9)
        _count(template["bytes"], "descriptor.workspace_template.bytes", 2**63)
        _hex(template["tree_sha256"], "descriptor.workspace_template.tree_sha256")
        return False
    _mapping(template, {"status", "reason"}, "descriptor.workspace_template")
    if template["status"] != "unbound" or template["reason"] not in _FILE_REASONS:
        raise _fail("descriptor.workspace_template has an unsupported status")
    return True


def _names(value: Any, where: str) -> None:
    ok = (
        isinstance(value, list)
        and value == sorted(set(value))
        and all(isinstance(name, str) and _ENV_NAME.fullmatch(name) for name in value)
    )
    if not ok:
        raise _fail(f"{where} must be a sorted list of environment names")


def validate_hook_context(document: Any) -> None:
    """Reject anything but a well-formed `hook-context.v1` document.

    Checks exact key sets, types, hex formats, fixed vocabularies and that the
    stored `context_id` matches the descriptor. Raises ValueError with a fixed
    location message that never quotes the document.
    """

    document = _mapping(document, _DOCUMENT_KEYS, "document")
    if document["schema_version"] != HOOK_CONTEXT_VERSION:
        raise _fail("document.schema_version is not supported")
    _hex(document["context_id"], "document.context_id")
    descriptor = _mapping(document["descriptor"], _DESCRIPTOR_KEYS, "descriptor")
    if descriptor["schema_version"] != HOOK_CONTEXT_VERSION:
        raise _fail("descriptor.schema_version is not supported")
    adapter = _mapping(
        descriptor["adapter"], {"runtime", "contract_id"}, "descriptor.adapter"
    )
    if adapter["runtime"] not in RUNTIMES:
        raise _fail("descriptor.adapter.runtime is not a supported runtime")
    if not isinstance(adapter["contract_id"], str) or not _TOKEN.fullmatch(
        adapter["contract_id"]
    ):
        raise _fail("descriptor.adapter.contract_id is malformed")
    mapping = _mapping(
        descriptor["decision_mapping"], {"ask_effect"}, "descriptor.decision_mapping"
    )
    if mapping["ask_effect"] not in ASK_EFFECTS:
        raise _fail("descriptor.decision_mapping.ask_effect is not supported")
    execution = _mapping(
        descriptor["execution"], {"timeout_seconds", "jobs"}, "descriptor.execution"
    )
    timeout = execution["timeout_seconds"]
    if (
        not isinstance(timeout, float)
        or isinstance(timeout, bool)
        or not 0 < timeout <= 86400
    ):
        raise _fail("descriptor.execution.timeout_seconds is out of range")
    if isinstance(execution["jobs"], bool) or not isinstance(execution["jobs"], int):
        raise _fail("descriptor.execution.jobs must be an integer")
    if not 1 <= execution["jobs"] <= 2**31:
        raise _fail("descriptor.execution.jobs is out of range")
    hook = _mapping(descriptor["hook"], {"argv"}, "descriptor.hook")
    argv = hook["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= _MAX_ARGV_WORDS:
        raise _fail("descriptor.hook.argv must be a bounded non-empty list")
    expected = set(STATIC_UNBOUND)
    for index, item in enumerate(argv):
        if _validate_argv_item(item, index):
            expected.add("executable" if index == 0 else f"argv-file:{index}")
    if _validate_template(descriptor["workspace_template"]):
        expected.add("workspace-template")
    environment = _mapping(
        descriptor["environment"],
        {"passthrough_names", "fixed", "adapter_names"},
        "descriptor.environment",
    )
    _names(environment["passthrough_names"], "descriptor.environment.passthrough")
    _names(environment["adapter_names"], "descriptor.environment.adapter_names")
    if environment["fixed"] != FIXED_ENVIRONMENT:
        raise _fail("descriptor.environment.fixed is not the supported set")
    # The declaration must match the components, in both directions.
    if descriptor["unbound"] != sorted(expected):
        raise _fail("descriptor.unbound does not match the described components")
    try:
        recomputed = context_id(descriptor)
    except (TypeError, ValueError) as exc:
        raise _fail("descriptor is not canonical JSON") from exc
    if recomputed != document["context_id"]:
        raise _fail("document.context_id does not match the descriptor")
