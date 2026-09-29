"""Synthetic process-policy modes used by the replay v0 contract tests."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time

STARTED_CHILD = """
import json
import os
from pathlib import Path
import sys
import time

state_path = Path(sys.argv[1])
pending_path = state_path.with_suffix(".pending")
pending_path.write_text(
    json.dumps({
        "pid": os.getpid(),
        "isolated": sys.flags.isolated,
        "site_loaded": "site" in sys.modules,
    }),
    encoding="ascii",
)
pending_path.replace(state_path)
time.sleep(5)
"""

SET_PGRP_CHILD = """
import json
import os
from pathlib import Path
import sys
import time

state_path = Path(sys.argv[1])
trigger_path = Path(sys.argv[2])
ack_path = Path(sys.argv[3])
os.setpgrp()
pending_path = state_path.with_suffix(".pending")
pending_path.write_text(
    json.dumps(
        {
            "pid": os.getpid(),
            "isolated": sys.flags.isolated,
            "site_loaded": "site" in sys.modules,
            "ppid": os.getppid(),
            "pgid": os.getpgrp(),
            "sid": os.getsid(0),
        }
    ),
    encoding="ascii",
)
pending_path.replace(state_path)
deadline = time.monotonic() + 20
while not trigger_path.is_file():
    if time.monotonic() >= deadline:
        raise SystemExit(2)
    time.sleep(0.01)
sys.stdout.write("escaped-output-after-return\\n")
sys.stdout.flush()
ack_path.write_text("wrote-after-return", encoding="ascii")
time.sleep(30)
"""


def decision(event: dict[str, object]) -> dict[str, str]:
    effect = "deny" if "--force" in str(event["command"]) else "allow"
    return {
        "schema_version": "policy-decision.v1",
        "event_id": str(event["event_id"]),
        "effect": effect,
        "reason": f"Synthetic fixture returned {effect}.",
    }


events = [json.loads(line) for line in sys.stdin if line.strip()]
mode = sys.argv[1]
rows = [decision(event) for event in events]

if mode in {"setpgrp-exit", "setpgrp-timeout"}:
    pid_path = Path(sys.argv[2])
    state_path = Path(sys.argv[3])
    trigger_path = Path(sys.argv[4])
    ack_path = Path(sys.argv[5])
    child = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            SET_PGRP_CHILD,
            str(state_path),
            str(trigger_path),
            str(ack_path),
        ],
        close_fds=True,
    )
    pid_path.write_text(str(child.pid), encoding="ascii")
    deadline = time.monotonic() + 5
    while not state_path.is_file():
        if child.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("setpgrp child did not publish its state")
        time.sleep(0.01)
    if mode == "setpgrp-timeout":
        time.sleep(30)
    else:
        for row in rows:
            print(json.dumps(row, sort_keys=True, separators=(",", ":")))
elif mode in {"descendant-exit", "descendant-timeout"}:
    pid_path = Path(sys.argv[2])
    state_path = pid_path.with_suffix(".json")
    child = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", STARTED_CHILD, str(state_path)],
        close_fds=False,
    )
    pid_path.write_text(str(child.pid), encoding="ascii")
    deadline = time.monotonic() + 5
    while not state_path.is_file():
        if child.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("group child did not publish its startup state")
        time.sleep(0.01)
    if mode == "descendant-timeout":
        time.sleep(5)
    else:
        for row in rows:
            print(json.dumps(row, sort_keys=True, separators=(",", ":")))
elif mode == "timeout":
    time.sleep(2)
elif mode == "malformed":
    print("{not-json")
    print(json.dumps(rows[1], sort_keys=True, separators=(",", ":")))
elif mode == "duplicate":
    print(json.dumps(rows[0], sort_keys=True, separators=(",", ":")))
    print(json.dumps(rows[0], sort_keys=True, separators=(",", ":")))
    print(json.dumps(rows[1], sort_keys=True, separators=(",", ":")))
elif mode == "partial":
    print(json.dumps(rows[0], sort_keys=True, separators=(",", ":")))
elif mode == "nonzero":
    print(json.dumps(rows[0], sort_keys=True, separators=(",", ":")))
    raise SystemExit(7)
elif mode == "reversed":
    for row in reversed(rows):
        print(json.dumps(row, sort_keys=True, separators=(",", ":")))
elif mode == "success":
    print("synthetic diagnostic", file=sys.stderr)
    for row in rows:
        print(json.dumps(row, sort_keys=True, separators=(",", ":")))
else:
    raise SystemExit(64)
