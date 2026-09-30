"""Directory links for tests: symlinks, or junctions on Windows without privilege."""

from __future__ import annotations

import os
from pathlib import Path
import unittest


def link_directory(
    case: unittest.TestCase, link: Path, target: Path, *, junction: bool = False
) -> None:
    """Make `link` lead to `target`, or skip the test when the host cannot.

    A symlink is tried first unless `junction` is set. On Windows a junction
    needs no privilege, so it stands in when symlinks are unavailable.
    """

    if not junction:
        try:
            link.symlink_to(target, target_is_directory=True)
            return
        except (OSError, NotImplementedError):
            pass
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
        return
    case.skipTest("directory links are unavailable")
