"""Exact-byte capture, manifest-last publication and regeneration verification."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from charter_replay.cli import _read_jsonl_bytes
from charter_replay.digests import canonical_json_bytes, sha256_bytes
from charter_replay.manifests import (
    _unique_object,
    manifest_json_bytes,
    validate_corpus_manifest,
)
from charter_replay.variants import (
    ASSUMPTIONS,
    DOMAIN,
    GENERATOR,
    MAX_DERIVED,
    MAX_SEEDS,
    TRANSFORMS,
    VariantError,
    derive_variants,
)

MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PACK_BYTES = 64 * 1024 * 1024
PACK_FILES = ("events.jsonl", "cases.jsonl", "lineage.json", "corpus-manifest.json")


def _read_regular(path: Path, limit: int) -> bytes:
    """Bound allocation and refuse symlinks, devices, directories and FIFOs."""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise VariantError(f"{path.name} must be a regular file, not a link")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            after = os.fstat(stream.fileno())
            if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                raise VariantError(f"{path.name} changed during admission")
            if after.st_size > limit:
                raise VariantError(f"{path.name} exceeds the byte budget")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise VariantError(f"{path.name} exceeds the byte budget")
            return data
    except OSError as exc:
        raise VariantError(f"{path.name} is not a readable regular file") from exc


def _source_root(source: str | Path) -> Path:
    try:
        root = Path(source).resolve(strict=True)
        if not root.is_dir():
            raise VariantError("source must be a corpus directory")
        return root
    except (OSError, RuntimeError) as exc:
        raise VariantError("source must be a readable corpus directory") from exc


def build_pack(
    source: str | Path, *, domain: str, max_derived: int = MAX_DERIVED
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Capture once, then derive every output byte from that validated capture."""
    root = _source_root(source)
    manifest_bytes = _read_regular(root / "corpus-manifest.json", MAX_MANIFEST_BYTES)
    try:
        manifest = validate_corpus_manifest(
            json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
        )
        if manifest["event_count"] > MAX_SEEDS:
            raise VariantError("source exceeds the seed record budget")
        expected = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
        if set(expected) != {"events.jsonl", "cases.jsonl"}:
            raise VariantError(
                "source manifest must bind exactly events.jsonl and cases.jsonl"
            )
        captured = {
            name: _read_regular(root / name, MAX_SOURCE_FILE_BYTES) for name in expected
        }
        if any(sha256_bytes(data) != expected[name] for name, data in captured.items()):
            raise VariantError("source file does not match its manifest SHA-256")
        for data in captured.values():
            record_count = data.count(b"\n") + int(not data.endswith(b"\n"))
            if record_count > MAX_SEEDS:
                raise VariantError("source exceeds the seed record budget")
        events = _read_jsonl_bytes(captured["events.jsonl"], "events.jsonl")
        cases = _read_jsonl_bytes(captured["cases.jsonl"], "cases.jsonl")
        if len(events) != manifest["event_count"]:
            raise VariantError("source event count does not match manifest")
        source_digest = sha256_bytes(manifest_bytes)
        batch = derive_variants(
            events, cases, source_digest, domain=domain, max_derived=max_derived
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, VariantError):
            raise
        raise VariantError("source is not a valid bounded v1 charter corpus") from exc

    files = {}
    for name, rows in (("events.jsonl", batch.events), ("cases.jsonl", batch.cases)):
        original = captured[name]
        separator = b"\n" if rows and not original.endswith(b"\n") else b""
        files[name] = original + separator + b"".join(
            canonical_json_bytes(row) + b"\n" for row in rows
        )
    output_manifest = validate_corpus_manifest(
        dict(
            schema_version="corpus-manifest.v1",
            corpus_id="posix-v1-" + source_digest[:24],
            event_count=len(events) + len(batch.events),
            files=[dict(path=name, sha256=sha256_bytes(files[name])) for name in files],
        )
    )
    files["corpus-manifest.json"] = manifest_json_bytes(output_manifest)
    lineage = dict(
        schema_version="variant-lineage.v1",
        domain=DOMAIN,
        generator=GENERATOR,
        source_manifest_sha256=source_digest,
        output_manifest_sha256=sha256_bytes(files["corpus-manifest.json"]),
        assumptions=list(ASSUMPTIONS),
        transforms=list(TRANSFORMS),
        counts=dict(
            seeds=len(events), derived=len(batch.events), skipped=len(batch.skipped)
        ),
        mappings=batch.mappings,
        skipped=batch.skipped,
    )
    files["lineage.json"] = canonical_json_bytes(lineage) + b"\n"
    if sum(map(len, files.values())) > MAX_PACK_BYTES:
        raise VariantError("derived pack exceeds the byte budget")
    return files, lineage


def _destination(source: str | Path, destination: str | Path) -> Path:
    lexical = Path(destination).absolute()
    if lexical.name in ("", ".", ".."):
        raise VariantError("output must be a new named directory")
    try:
        target = lexical.parent.resolve(strict=True) / lexical.name
    except (OSError, RuntimeError) as exc:
        raise VariantError("output parent must already exist") from exc
    if target.is_relative_to(_source_root(source)):
        raise VariantError("output must not be inside the source corpus")
    if target.exists() or target.is_symlink():
        raise VariantError("output already exists; no files are overwritten")
    return target


def generate_pack(
    source: str | Path,
    destination: str | Path,
    *,
    domain: str,
    max_derived: int = MAX_DERIVED,
) -> dict[str, Any]:
    """Commit a new pack with an atomic, no-overwrite manifest link as marker."""
    target = _destination(source, destination)
    files, lineage = build_pack(source, domain=domain, max_derived=max_derived)
    with tempfile.TemporaryDirectory(
        prefix=".charter-variants-", dir=target.parent
    ) as raw:
        staging = Path(raw)
        for name, data in files.items():
            descriptor = os.open(
                staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
        try:
            target.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise VariantError(
                "output appeared during publication; nothing is overwritten"
            ) from exc
        owned = []
        try:
            # Readers require the manifest. Publish it last, without replacing
            # any competing path, rather than rename-overwriting an empty folder.
            for name in PACK_FILES:
                os.link(staging / name, target / name)
                owned.append(name)
        except OSError:
            for name in reversed(owned):
                try:
                    path = target / name
                    if (
                        path.samefile(staging / name)
                        and _read_regular(path, MAX_PACK_BYTES) == files[name]
                    ):
                        path.unlink()
                except (OSError, VariantError):
                    pass  # A concurrent writer's changed path is not ours to delete.
            try:
                target.rmdir()
            except OSError:
                pass  # Preserve anything supplied by another writer.
            raise
    return lineage


def verify_pack(source: str | Path, pack: str | Path) -> dict[str, Any]:
    """Regenerate from the supplied source and compare all four complete files."""
    expected, lineage = build_pack(source, domain=DOMAIN)
    root = _source_root(pack)
    for name in PACK_FILES:
        actual = _read_regular(root / name, MAX_PACK_BYTES)
        if actual != expected[name]:
            raise VariantError(
                f"{name} does not match regeneration from the exact source"
            )
    return lineage
