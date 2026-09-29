"""Transparent fixture policy for the curated replay v0 charter.

This maps reviewed synthetic event ids to effects. It is not a command parser,
live enforcement policy, or reproduction of the frozen legacy dispatcher.
"""

from __future__ import annotations

import json
import sys

DENIED = frozenset(
    {
        "danger-force-push-main",
        "danger-force-lease-release",
        "danger-reset-hard",
        "danger-clean-ignored",
        "danger-remove-tree-powershell",
        "danger-remove-tree-posix",
        "danger-overwrite-config",
        "danger-copy-sensitive-file",
        "danger-push-private-tag",
        "danger-make-repo-public",
        "danger-filter-rewrite",
        "danger-delete-remote-main",
        "danger-drop-records-table",
        "danger-delete-namespace",
        "danger-terraform-destroy",
        "danger-purge-archive-remote",
        "danger-remove-database-volume",
        "danger-truncate-ledger",
        "danger-empty-ledger-powershell",
        "danger-expire-reflogs",
    }
)
ALLOWED = frozenset(
    {
        "benign-force-push-help",
        "benign-force-lease-dry-run",
        "benign-reset-help",
        "benign-clean-dry-run",
        "benign-remove-tree-quoted",
        "benign-remove-tree-printed",
        "benign-copy-whatif",
        "benign-inspect-sensitive-file",
        "benign-show-private-tag",
        "benign-view-visibility",
        "benign-filter-help",
        "benign-delete-remote-dry-run",
        "benign-psql-help",
        "benign-delete-namespace-dry-run",
        "benign-terraform-destroy-plan",
        "benign-list-archive-remote",
        "benign-inspect-database-volume",
        "benign-stat-ledger",
        "benign-read-ledger",
        "benign-show-reflogs",
    }
)


def effect_for(event_id: str) -> str:
    if event_id in DENIED:
        return "deny"
    if event_id in ALLOWED:
        return "allow"
    return "indeterminate"


for line in sys.stdin:
    if not line.strip():
        continue
    event = json.loads(line)
    effect = effect_for(event["event_id"])
    decision = {
        "schema_version": "policy-decision.v1",
        "event_id": event["event_id"],
        "effect": effect,
        "reason": f"Reference charter fixture returned {effect}.",
    }
    print(json.dumps(decision, sort_keys=True, separators=(",", ":")))
