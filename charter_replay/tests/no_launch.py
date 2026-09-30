"""One place that forbids every way this interpreter can start a process."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import importlib
import os
import subprocess
from typing import Iterator
from unittest import mock

_OS_NAMES = (
    "system",
    "popen",
    "startfile",
    *(f"spawn{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    *(f"exec{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    "posix_spawn",
    "posix_spawnp",
    "fork",
    "forkpty",
)
_SUBPROCESS_NAMES = (
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
)


def _launch(name: str):
    def refuse(*_args, **_kwargs):
        raise AssertionError(f"process launch through {name}")

    return refuse


@contextmanager
def forbid_process_launch() -> Iterator[None]:
    """Make os.system/spawn*/exec*/popen and every subprocess entry point fail."""

    with ExitStack() as stack:
        for name in _OS_NAMES:
            if hasattr(os, name):
                stack.enter_context(
                    mock.patch.object(os, name, side_effect=_launch(f"os.{name}"))
                )
        for name in _SUBPROCESS_NAMES:
            stack.enter_context(
                mock.patch.object(
                    subprocess, name, side_effect=_launch(f"subprocess.{name}")
                )
            )
        # Lower-level primitives, as defence in depth behind the entry points
        # above. `_winapi.CreateProcess` is the Windows process start. On
        # Python 3.12+ POSIX, `subprocess` binds `_fork_exec` when it is
        # imported, so patching `_posixsubprocess.fork_exec` here does not
        # intercept it. That is not a false green: `subprocess.Popen` is
        # patched above (every `subprocess` entry point ends in it) and the
        # `os` launchers are patched separately.
        for module_name, attribute in (
            ("_winapi", "CreateProcess"),
            ("_posixsubprocess", "fork_exec"),
        ):
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                continue
            if hasattr(module, attribute):
                stack.enter_context(
                    mock.patch.object(module, attribute, side_effect=_launch(attribute))
                )
        yield
