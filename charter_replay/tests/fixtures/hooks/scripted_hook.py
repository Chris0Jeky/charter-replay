"""Test hook whose reply is chosen by the command text it receives."""

import json
import os
import sys
import time

payload = json.load(sys.stdin)
command = payload["tool_input"]["command"]
specific = {"hookEventName": "PreToolUse"}
if command == "exit-two":
    print("blocked by exit code", file=sys.stderr)
    sys.exit(2)
if command == "json-deny":
    specific.update(permissionDecision="deny", permissionDecisionReason="json says no")
    print(json.dumps({"hookSpecificOutput": specific}))
elif command == "json-ask":
    specific.update(permissionDecision="ask", permissionDecisionReason="confirm")
    print(json.dumps({"hookSpecificOutput": specific}))
elif command == "json-allow":
    specific.update(permissionDecision="allow")
    print(json.dumps({"hookSpecificOutput": specific}))
elif command == "legacy-block":
    print(json.dumps({"decision": "block", "reason": "legacy"}))
elif command == "stop":
    print(json.dumps({"continue": False, "stopReason": "halt"}))
elif command == "not-json":
    print("hello")
elif command == "unknown-decision":
    print(json.dumps({"decision": "maybe"}))
elif command == "crash":
    print("boom", file=sys.stderr)
    sys.exit(1)
elif command == "slow":
    time.sleep(30)
elif command == "echo-env":
    print(json.dumps({"reason": os.environ.get("CLAUDE_PROJECT_DIR", "")}))
