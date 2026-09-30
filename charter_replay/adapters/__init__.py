"""Explicit built-in runtime registry; no dynamic code loading."""

from types import MappingProxyType

from charter_replay.adapters.base import RuntimeAdapter
from charter_replay.adapters.claude import ClaudeAdapter
from charter_replay.adapters.codex import CodexAdapter
from charter_replay.adapters.codex_legacy import CodexLegacyAdapter

_ADAPTERS = MappingProxyType(
    {
        "claude": ClaudeAdapter(),
        "codex": CodexAdapter(),
        "codex-legacy": CodexLegacyAdapter(),
    }
)
RUNTIMES = tuple(_ADAPTERS)


def get_adapter(name: str) -> RuntimeAdapter:
    """Resolve a supported runtime before any hook process is started."""
    try:
        return _ADAPTERS[name]
    except (KeyError, TypeError) as exc:  # TypeError: an unhashable name
        raise ValueError(
            f"unsupported runtime {name!r}; choose {', '.join(RUNTIMES)}"
        ) from exc
