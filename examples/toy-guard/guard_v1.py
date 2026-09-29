"""Toy PreToolUse guard, version 1: a short keyword denylist.

Reads the hook payload on stdin. Exit 0 with no output allows the command;
a JSON `permissionDecision` of `deny` blocks it.
"""

import json
import sys

DENY = (
    ("git", "push", "--force"),
    ("git", "reset", "--hard"),
    ("git", "clean"),
    ("rm", "-rf"),
    ("terraform", "destroy"),
    ("kubectl", "delete"),
)


def blocked(words):
    return any(all(word in words for word in rule) for rule in DENY)


def main():
    payload = json.load(sys.stdin)
    words = payload.get("tool_input", {}).get("command", "").split()
    if blocked(words):
        reply = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "toy guard v1: matched a denylist rule",
            }
        }
        print(json.dumps(reply))


if __name__ == "__main__":
    main()
