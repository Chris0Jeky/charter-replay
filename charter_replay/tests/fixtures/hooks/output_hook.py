"""Synthetic hook that prints on purpose, to exercise the output limit.

usage: output_hook.py MODE LIMIT [PID_FILE]

Floods are paced (16 KiB then a short sleep) so a test never fills a disk even
if the watchdog is late. `family-*` modes start a descendant that floods the
inherited stdout and publishes its own pid to PID_FILE before the parent goes on.
"""

import os
from pathlib import Path
import subprocess
import sys
import time

CHUNK = 16 * 1024

GRANDCHILD = """
import os, sys, time
from pathlib import Path
pid_path = Path(sys.argv[1])
pending = pid_path.with_suffix(".pending")
pending.write_text(str(os.getpid()), encoding="ascii")
pending.replace(pid_path)
while True:
    sys.stdout.buffer.write(b"g" * 16384)
    sys.stdout.buffer.flush()
    time.sleep(0.002)
"""


def flood(stream) -> None:
    while True:
        stream.write(b"x" * CHUNK)
        stream.flush()
        time.sleep(0.002)


def spawn_flooder(pid_file: Path) -> None:
    subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", GRANDCHILD, str(pid_file)],
        close_fds=False,
    )
    deadline = time.monotonic() + 20
    while not pid_file.is_file():
        if time.monotonic() >= deadline:
            raise SystemExit("flooder did not start")
        time.sleep(0.01)


sys.stdin.read()
mode, limit = sys.argv[1], int(sys.argv[2])
out, err = sys.stdout.buffer, sys.stderr.buffer
if mode == "stdout-flood":
    flood(out)
elif mode == "stderr-flood":
    flood(err)
elif mode == "stdout-exact":
    # Blank output is an allow, so only the size decides the outcome.
    out.write(b" " * (limit - 1) + b"\n")
elif mode == "stdout-over":
    out.write(b" " * limit + b"\n")
elif mode == "stderr-exact":
    err.write(b"e" * limit)
    sys.exit(2)
elif mode == "stderr-over":
    err.write(b"e" * (limit + 1))
    sys.exit(2)
elif mode == "family-exit":
    # The parent leaves early, once the descendant has printed past the limit.
    spawn_flooder(Path(sys.argv[3]))
    deadline = time.monotonic() + 20
    while os.fstat(1).st_size <= limit and time.monotonic() < deadline:
        time.sleep(0.005)
elif mode == "family-sleep":
    spawn_flooder(Path(sys.argv[3]))
    time.sleep(60)
else:
    raise SystemExit(64)
out.flush()
err.flush()
