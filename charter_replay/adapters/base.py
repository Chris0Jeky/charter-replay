"""Pure runtime adapter contract and portable workspace mapping."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any, Protocol


class RuntimeAdapter(Protocol):
    """Runtime grammar only; process lifecycle belongs to the hook runner."""

    name: str
    contract_id: str

    def build_payload(
        self, event: dict[str, Any], *, workspace: Path, index: int
    ) -> dict[str, Any]: ...

    def classify(self, exit_code: int, stdout: str, stderr: str) -> tuple[str, str]: ...

    def environment(self, workspace: Path) -> dict[str, str]: ...


def event_cwd(event: dict[str, Any], workspace: Path) -> Path:
    """Place an event's corpus-relative `cwd` inside the replay workspace."""

    relative = str(event.get("cwd") or "").replace("\\", "/")
    parts = [
        part
        for part in PurePosixPath(relative).parts
        if part not in ("", ".", "..", "/") and ":" not in part
    ]
    return workspace.joinpath(*parts)
