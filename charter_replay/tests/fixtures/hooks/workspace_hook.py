"""Synthetic hook exercises its own workspace, never the supplied command."""

import json
import os
from pathlib import Path
import sys

payload = json.load(sys.stdin)
root = Path(os.environ["CLAUDE_PROJECT_DIR"])
mode = payload["tool_input"]["command"]
allowed = True
if mode == "state":
    try:
        with (root / "seen").open("x", encoding="utf-8") as stream:
            stream.write("hook-owned state")
    except FileExistsError:
        allowed = False
elif mode == "cwd":
    allowed = (
        Path.cwd() == Path(payload["cwd"])
        and Path.cwd() == root / "nested"
        and (Path.cwd() / "fixture.txt").read_text("utf-8") == "original"
    )
    if allowed:
        (Path.cwd() / "fixture.txt").write_text("changed copy", encoding="utf-8")
elif mode == "readonly":
    directory = root / "readonly"
    directory.mkdir()
    file = directory / "note.txt"
    file.write_text("hook-owned state", encoding="utf-8")
    file.chmod(0o400)
    directory.chmod(0o500)
print(json.dumps({"decision": "approve" if allowed else "block"}))
