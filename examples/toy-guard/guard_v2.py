"""Toy PreToolUse guard, version 2: v1 plus help/dry-run exemptions.

The exemption fixes false positives on `--help` and `--dry-run`, and the new
prefix match catches `--force-with-lease`. It also carries a deliberate
regression for the demo: `git clean` was dropped from the list.
Exit code 2 with a reason on stderr is the other way to block.
"""

import json
import sys

DENY = (
    ("git", "push", "--force"),
    ("git", "reset", "--hard"),
    ("rm", "-rf"),
    ("terraform", "destroy"),
    ("kubectl", "delete"),
)
EXEMPT = ("--help", "--dry-run", "--dry-run=client", "-n")


def matches(rule, words):
    return all(any(word.startswith(part) for word in words) for part in rule)


def main():
    payload = json.load(sys.stdin)
    words = payload.get("tool_input", {}).get("command", "").split()
    if any(word in EXEMPT for word in words):
        return
    if any(matches(rule, words) for rule in DENY):
        print("toy guard v2: matched a denylist rule", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
