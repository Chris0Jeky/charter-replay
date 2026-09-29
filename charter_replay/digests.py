"""Exact-byte and canonical semantic digests for replay v0."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
from typing import Any


def sha256_bytes(value: bytes) -> str:
    """Return the lowercase SHA-256 hex digest of exact bytes."""

    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str:
    """Hash a file's exact bytes without newline or encoding normalization."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def permission_bits(path: str | Path) -> str:
    """Return the four-octal-digit permission mode preserved by snapshot copies."""

    return f"{stat.S_IMODE(Path(path).stat().st_mode):04o}"


def sha256_tree(path: str | Path) -> str:
    """Hash tree names, regular-file bytes, and preserved permission modes."""

    root = Path(path)
    if not root.is_dir() or root.is_symlink():
        raise OSError("tree digest root must be a readable directory")

    entries: list[dict[str, str]] = [
        {
            "permission_bits": permission_bits(root),
            "kind": "directory",
            "path": "",
        }
    ]
    for entry in root.rglob("*"):
        relative_path = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            if not entry.is_file():
                raise OSError(
                    "tree digest does not support directory or broken symlinks"
                )
            entries.append(
                {
                    "permission_bits": permission_bits(entry),
                    "kind": "file",
                    "path": relative_path,
                    "sha256": sha256_file(entry),
                }
            )
        elif entry.is_dir():
            entries.append(
                {
                    "permission_bits": permission_bits(entry),
                    "kind": "directory",
                    "path": relative_path,
                }
            )
        elif entry.is_file():
            entries.append(
                {
                    "permission_bits": permission_bits(entry),
                    "kind": "file",
                    "path": relative_path,
                    "sha256": sha256_file(entry),
                }
            )
        else:
            raise OSError("tree digest supports only directories and regular files")
    entries.sort(key=lambda item: item["path"])
    return sha256_bytes(canonical_json_bytes(entries))


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a JSON value deterministically for semantic identity derivation."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
