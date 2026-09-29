"""Strict corpus and replay-run manifests with canonical field validation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from charter_replay import __version__
from charter_replay.digests import canonical_json_bytes, sha256_bytes, sha256_file

CORPUS_MANIFEST_VERSION = "corpus-manifest.v1"
RUN_MANIFEST_VERSION = "replay-run.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PORTABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}" r"(?:\.[0-9]+)?Z$"
)
_POLICY_KINDS = frozenset({"process", "recorded"})
RUN_GATE_CLASSES = frozenset(
    {
        "newly-allowed",
        "newly-denied",
        "newly-indeterminate",
    }
)


class ManifestError(ValueError):
    """A replay manifest or one of its exact-byte bindings is invalid."""


@dataclass(frozen=True)
class LoadedCorpusManifest:
    """A validated manifest plus its exact source and bound corpus bytes."""

    value: dict[str, Any]
    manifest_sha256: str
    file_bytes: tuple[tuple[str, bytes], ...]


def _require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ManifestError(f"{label}: expected a JSON object with string keys")
    return value


def _require_shape(
    value: Mapping[str, object], label: str, required: tuple[str, ...]
) -> None:
    missing = [field for field in required if field not in value]
    if missing:
        raise ManifestError(f"{label}: missing field(s): {', '.join(missing)}")
    unexpected = sorted(set(value) - set(required))
    if unexpected:
        raise ManifestError(f"{label}: unexpected field(s): {', '.join(unexpected)}")


def _require_portable_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _PORTABLE_ID.fullmatch(value):
        raise ManifestError(f"{label}: expected a portable identifier")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ManifestError(f"{label}: expected a lowercase SHA-256 digest")
    return value


def _require_count(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ManifestError(f"{label}: expected a non-negative integer")
    return value


def _require_positive_count(value: object, label: str) -> int:
    count = _require_count(value, label)
    if count == 0:
        raise ManifestError(f"{label}: expected a positive integer")
    return count


def _require_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{label}: expected a relative POSIX path")
    if "\0" in value or "\\" in value or ":" in value or value.startswith("/"):
        raise ManifestError(f"{label}: expected a relative POSIX path")
    candidate = PurePosixPath(value)
    if (
        candidate.as_posix() != value
        or candidate.is_absolute()
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ManifestError(f"{label}: expected a normalized relative POSIX path")
    return value


def _resolve_corpus_file(base: Path, relative_path: str) -> Path:
    """Resolve an ordinary in-tree file before reading its bytes.

    This path check does not replace caller-owned storage isolation or prevent
    every concurrent rename/link race. Policy-tree alias rules are unchanged.
    """
    label = f"Corpus file {relative_path!r}"
    try:
        resolved_base = base.resolve(strict=True)
        target = base.joinpath(*PurePosixPath(relative_path).parts).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ManifestError(f"{label} could not be resolved") from exc
    if not target.is_relative_to(resolved_base):
        raise ManifestError(f"{label} resolves outside corpus directory")
    if not target.is_file():
        raise ManifestError(f"{label} is not a regular file")
    return target


def _require_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not _RFC3339_UTC.fullmatch(value):
        raise ManifestError(f"{label}: expected an RFC 3339 UTC timestamp")
    try:
        datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as exc:
        raise ManifestError(f"{label}: expected a valid calendar timestamp") from exc
    return value


def validate_corpus_manifest(value: object) -> dict[str, Any]:
    """Validate and normalize a corpus-manifest v1 JSON value."""

    manifest = _require_mapping(value, "CorpusManifest")
    required = ("schema_version", "corpus_id", "event_count", "files")
    _require_shape(manifest, "CorpusManifest", required)
    if manifest["schema_version"] != CORPUS_MANIFEST_VERSION:
        raise ManifestError(
            f"CorpusManifest.schema_version: expected {CORPUS_MANIFEST_VERSION!r}"
        )
    corpus_id = _require_portable_id(manifest["corpus_id"], "CorpusManifest.corpus_id")
    event_count = _require_positive_count(
        manifest["event_count"], "CorpusManifest.event_count"
    )
    raw_files = manifest["files"]
    if not isinstance(raw_files, list) or not raw_files:
        raise ManifestError("CorpusManifest.files: expected a non-empty array")

    files: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for index, raw_file in enumerate(raw_files):
        label = f"CorpusManifest.files[{index}]"
        entry = _require_mapping(raw_file, label)
        _require_shape(entry, label, ("path", "sha256"))
        relative_path = _require_relative_path(entry["path"], f"{label}.path")
        if relative_path in seen_paths:
            raise ManifestError(f"{label}.path: duplicate path")
        seen_paths.add(relative_path)
        files.append(
            {
                "path": relative_path,
                "sha256": _require_sha256(entry["sha256"], f"{label}.sha256"),
            }
        )

    return {
        "schema_version": CORPUS_MANIFEST_VERSION,
        "corpus_id": corpus_id,
        "event_count": event_count,
        "files": files,
    }


def build_corpus_manifest(
    *,
    corpus_id: str,
    event_count: int,
    base_directory: str | Path,
    files: Sequence[str],
) -> dict[str, Any]:
    """Build a corpus manifest from exact bytes under a caller-supplied base."""

    if isinstance(files, (str, bytes)):
        raise ManifestError("CorpusManifest.files: expected a sequence of paths")
    event_count = _require_positive_count(event_count, "CorpusManifest.event_count")
    base = Path(base_directory)
    entries: list[dict[str, str]] = []
    for index, raw_path in enumerate(files):
        relative_path = _require_relative_path(
            raw_path, f"CorpusManifest.files[{index}].path"
        )
        target = _resolve_corpus_file(base, relative_path)
        try:
            digest = sha256_file(target)
        except OSError as exc:
            raise ManifestError(
                f"CorpusManifest.files[{index}]: file could not be read"
            ) from exc
        entries.append({"path": relative_path, "sha256": digest})
    return validate_corpus_manifest(
        {
            "schema_version": CORPUS_MANIFEST_VERSION,
            "corpus_id": corpus_id,
            "event_count": event_count,
            "files": entries,
        }
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ManifestError(f"JSON object contains duplicate key {key!r}")
        value[key] = item
    return value


def load_corpus_manifest(path: str | Path) -> LoadedCorpusManifest:
    """Load a manifest and verify every listed file before policy execution."""

    manifest_path = Path(path)
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise ManifestError("Corpus manifest could not be read") from exc
    try:
        raw_value = json.loads(
            manifest_bytes.decode("utf-8"), object_pairs_hook=_unique_object
        )
    except ManifestError:
        # Do not replace the more specific duplicate-key diagnostic.
        raise
    except ValueError as exc:
        raise ManifestError("Corpus manifest is not valid UTF-8 JSON") from exc
    manifest = validate_corpus_manifest(raw_value)

    captured_files: list[tuple[str, bytes]] = []
    for entry in manifest["files"]:
        target = _resolve_corpus_file(manifest_path.parent, entry["path"])
        try:
            captured_bytes = target.read_bytes()
        except OSError as exc:
            raise ManifestError(
                f"Corpus file {entry['path']!r} could not be read"
            ) from exc
        actual_digest = sha256_bytes(captured_bytes)
        if actual_digest != entry["sha256"]:
            raise ManifestError(
                f"Corpus file {entry['path']!r} does not match its SHA-256"
            )
        captured_files.append((entry["path"], captured_bytes))

    return LoadedCorpusManifest(
        manifest,
        sha256_bytes(manifest_bytes),
        tuple(captured_files),
    )


def _validate_policy_identity(value: object, label: str) -> dict[str, str]:
    identity = _require_mapping(value, label)
    _require_shape(identity, label, ("kind", "id", "sha256"))
    kind = identity["kind"]
    if not isinstance(kind, str) or kind not in _POLICY_KINDS:
        raise ManifestError(f"{label}.kind: expected process or recorded")
    return {
        "kind": kind,
        "id": _require_portable_id(identity["id"], f"{label}.id"),
        "sha256": _require_sha256(identity["sha256"], f"{label}.sha256"),
    }


def _validate_run_corpus(value: object) -> dict[str, object]:
    corpus = _require_mapping(value, "RunManifest.corpus")
    _require_shape(
        corpus, "RunManifest.corpus", ("id", "manifest_sha256", "event_count")
    )
    return {
        "id": _require_portable_id(corpus["id"], "RunManifest.corpus.id"),
        "manifest_sha256": _require_sha256(
            corpus["manifest_sha256"], "RunManifest.corpus.manifest_sha256"
        ),
        "event_count": _require_positive_count(
            corpus["event_count"], "RunManifest.corpus.event_count"
        ),
    }


def _validate_fail_on(value: object) -> list[str]:
    if not isinstance(value, list):
        raise ManifestError("RunManifest.fail_on: expected an array")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or item not in RUN_GATE_CLASSES:
            raise ManifestError(
                f"RunManifest.fail_on[{index}]: expected a replay gate class"
            )
        if item in result:
            raise ManifestError(f"RunManifest.fail_on[{index}]: duplicate class")
        result.append(item)
    return result


def derive_run_id(
    *,
    runner_version: str,
    baseline_sha256: str,
    candidate_sha256: str,
    corpus_manifest_sha256: str,
    fail_on: Sequence[str],
) -> str:
    """Derive a stable run identity from only the declared semantic inputs."""

    _require_portable_id(runner_version, "RunIdentity.runner_version")
    baseline_digest = _require_sha256(baseline_sha256, "RunIdentity.baseline_sha256")
    candidate_digest = _require_sha256(candidate_sha256, "RunIdentity.candidate_sha256")
    corpus_digest = _require_sha256(
        corpus_manifest_sha256, "RunIdentity.corpus_manifest_sha256"
    )
    if isinstance(fail_on, (str, bytes)):
        raise ManifestError("RunIdentity.fail_on: expected a sequence")
    gate = _validate_fail_on(list(fail_on))
    identity = {
        "runner_version": runner_version,
        "baseline_sha256": baseline_digest,
        "candidate_sha256": candidate_digest,
        "corpus_manifest_sha256": corpus_digest,
        "fail_on": gate,
    }
    return sha256_bytes(canonical_json_bytes(identity))


def build_run_manifest(
    *,
    generated_at: str,
    baseline: object,
    candidate: object,
    corpus: object,
    fail_on: Sequence[str],
    runner_version: str = __version__,
) -> dict[str, Any]:
    """Build and self-validate a replay-run v1 manifest."""

    baseline_identity = _validate_policy_identity(baseline, "RunManifest.baseline")
    candidate_identity = _validate_policy_identity(candidate, "RunManifest.candidate")
    corpus_identity = _validate_run_corpus(corpus)
    if isinstance(fail_on, (str, bytes)):
        raise ManifestError("RunManifest.fail_on: expected a sequence")
    gate = _validate_fail_on(list(fail_on))
    run_id = derive_run_id(
        runner_version=runner_version,
        baseline_sha256=baseline_identity["sha256"],
        candidate_sha256=candidate_identity["sha256"],
        corpus_manifest_sha256=str(corpus_identity["manifest_sha256"]),
        fail_on=gate,
    )
    return validate_run_manifest(
        {
            "schema_version": RUN_MANIFEST_VERSION,
            "run_id": run_id,
            "generated_at": generated_at,
            "runner_version": runner_version,
            "baseline": baseline_identity,
            "candidate": candidate_identity,
            "corpus": corpus_identity,
            "fail_on": gate,
        }
    )


def validate_run_manifest(value: object) -> dict[str, Any]:
    """Validate a run manifest and prove that its run_id matches its inputs."""

    manifest = _require_mapping(value, "RunManifest")
    required = (
        "schema_version",
        "run_id",
        "generated_at",
        "runner_version",
        "baseline",
        "candidate",
        "corpus",
        "fail_on",
    )
    _require_shape(manifest, "RunManifest", required)
    if manifest["schema_version"] != RUN_MANIFEST_VERSION:
        raise ManifestError(
            f"RunManifest.schema_version: expected {RUN_MANIFEST_VERSION!r}"
        )
    run_id = _require_sha256(manifest["run_id"], "RunManifest.run_id")
    generated_at = _require_timestamp(
        manifest["generated_at"], "RunManifest.generated_at"
    )
    runner_version = _require_portable_id(
        manifest["runner_version"], "RunManifest.runner_version"
    )
    baseline = _validate_policy_identity(manifest["baseline"], "RunManifest.baseline")
    candidate = _validate_policy_identity(
        manifest["candidate"], "RunManifest.candidate"
    )
    corpus = _validate_run_corpus(manifest["corpus"])
    fail_on = _validate_fail_on(manifest["fail_on"])
    expected_run_id = derive_run_id(
        runner_version=runner_version,
        baseline_sha256=baseline["sha256"],
        candidate_sha256=candidate["sha256"],
        corpus_manifest_sha256=str(corpus["manifest_sha256"]),
        fail_on=fail_on,
    )
    if run_id != expected_run_id:
        raise ManifestError("RunManifest.run_id does not match its semantic inputs")
    return {
        "schema_version": RUN_MANIFEST_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "runner_version": runner_version,
        "baseline": baseline,
        "candidate": candidate,
        "corpus": corpus,
        "fail_on": fail_on,
    }


def manifest_json_bytes(value: object) -> bytes:
    """Serialize a validated manifest-like value with stable LF-terminated JSON."""

    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def write_manifest(path: str | Path, value: object) -> None:
    """Write deterministic manifest bytes; callers choose the output directory."""

    Path(path).write_bytes(manifest_json_bytes(value))
