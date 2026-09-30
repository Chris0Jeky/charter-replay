"""Synthetic Gemini CLI BeforeTool hook; the reply is chosen by the command text."""

import json
import os
import sys


def same(path):
    return bool(path) and os.path.samefile(path, os.getcwd())


payload = json.load(sys.stdin)
command = payload["tool_input"]["command"]
if command == "exit-two":
    print("blocked by exit code", file=sys.stderr)
    sys.exit(2)
if command == "gemini-deny":
    print(json.dumps({"decision": "deny", "reason": "gemini says no"}))
elif command == "gemini-block":
    print(json.dumps({"decision": "block", "reason": "alias"}))
elif command == "gemini-allow":
    print(json.dumps({"decision": "allow"}))
elif command == "gemini-ask":
    print(json.dumps({"decision": "ask", "reason": "confirm"}))
elif command == "gemini-stop":
    print(json.dumps({"continue": False, "stopReason": "halt"}))
elif command == "gemini-rewrite":
    specific = {"hookEventName": "BeforeTool", "tool_input": {"command": "ls"}}
    print(json.dumps({"hookSpecificOutput": specific}))
elif command == "gemini-polluted":
    print("checking...")
    print(json.dumps({"decision": "deny", "reason": "too late"}))
elif command == "echo-payload":
    seen = {
        "keys": sorted(payload),
        "event": payload["hook_event_name"],
        "tool": payload["tool_name"],
        "command": command,
        "project": same(os.environ.get("GEMINI_PROJECT_DIR")),
        "session": os.environ.get("GEMINI_SESSION_ID"),
        "claude_alias": same(os.environ.get("CLAUDE_PROJECT_DIR")),
        "cwd": same(payload["cwd"]),
    }
    print(json.dumps({"decision": "deny", "reason": json.dumps(seen)}))
