"""No-replace publication of a new, manifest-last artifact directory."""

from __future__ import annotations

import os
from pathlib import Path
import re
import tempfile

MAX_PUBLICATION_BYTES = 128 * 1024 * 1024
_RESERVED_STEMS = {"con", "prn", "aux", "nul", "conin$", "conout$"}
_RESERVED_STEMS.update(
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
)


class PublicationError(OSError):
    """An output failure whose message is fixed text, safe to show as it is.

    It never carries a path, file name or hook output. Callers print `str(exc)`
    and exit 3, where a plain OSError is reduced to its class name.
    """


def new_destination(output: str | Path) -> Path:
    """Resolve an existing parent while refusing every pre-existing target."""
    raw = Path(output).absolute()
    if raw.name in ("", ".", ".."):
        raise ValueError("output must name a new directory")
    try:
        target = raw.parent.resolve(strict=True) / raw.name
        if not target.parent.is_dir():
            raise ValueError("output parent must be a directory")
    except (OSError, RuntimeError) as exc:
        raise ValueError("output parent must already exist") from exc
    if target.exists() or target.is_symlink():
        raise ValueError("output already exists; nothing is overwritten")
    return target


def publish_new_directory(
    output: str | Path, files: dict[str, bytes], *, marker: str
) -> None:
    """Publish only owned files, with the completion marker linked last.

    Requires hard links and a caller-owned parent. This is not a hostile-filesystem
    boundary or crash-durable storage. A directory without its marker is incomplete.
    """
    if not files or marker not in files:
        raise ValueError("publication requires a completion marker")
    if any(
        not isinstance(name, str)
        or not re.fullmatch(r"[a-z][a-z0-9.-]{0,79}", name)
        or name.endswith(".")
        or name.split(".", 1)[0] in _RESERVED_STEMS
        or not isinstance(data, bytes)
        for name, data in files.items()
    ):
        raise ValueError("publication requires flat portable names and byte contents")
    if sum(map(len, files.values())) > MAX_PUBLICATION_BYTES:
        raise ValueError("publication exceeds the byte budget")
    target = new_destination(output)
    names = sorted(set(files) - {marker}) + [marker]
    with tempfile.TemporaryDirectory(
        prefix=".charter-publish-", dir=target.parent
    ) as raw:
        staging = Path(raw)
        for name in names:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            descriptor = os.open(staging / name, flags, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(files[name])
        try:
            target.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise ValueError(
                "output appeared during publication; nothing is overwritten"
            ) from exc
        owned = []
        try:
            for name in names:
                os.link(staging / name, target / name)
                owned.append(name)
        except BaseException:
            for name in reversed(owned):
                path = target / name
                try:
                    if not path.is_symlink() and path.samefile(staging / name):
                        with path.open("rb") as stream:
                            unchanged = stream.read(len(files[name]) + 1) == files[name]
                        if unchanged:
                            path.unlink()
                except OSError:
                    pass
            try:
                target.rmdir()
            except OSError:
                pass  # Another writer's data is never recursively removed.
            raise
