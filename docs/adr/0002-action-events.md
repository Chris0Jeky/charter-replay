# ADR 0002: Add a typed action envelope without widening v1 command records

Status: accepted design; implementation follows adapter stabilization.

## Context

The current command schema deliberately rejects unknown keys. Editing it into a
catch-all tool event would break strict readers and hide context assumptions.
File, network and MCP guardrails need different typed inputs. Context-sensitive
rules cannot be keyed by a command string alone.

## Options considered

1. Add optional generic tool fields to `command-event.v1`.
2. A new `action-event.v1` envelope with a discriminated payload and pure v1 bridge.
3. Store raw runtime JSON and make every consumer understand every runtime.

## Decision

Choose option 2. Preserve all existing v1 validators. Normalize command events
into a shell action in memory with the same event ID and original command text.
The new format has a kind-specific strict payload and a context reference bound
by digest. Do not infer a POSIX shell from the host running replay.

Initial kinds are shell, file-write, file-edit, network-fetch and mcp-call.
Content is represented by digest and optional digest-bound synthetic fixtures;
digest-only inputs are explicitly unsupported for content-sensitive hooks.
Unknown kinds and unsupported adapter/kind pairs fail admission, not silently
allow. Context binds tier, permissions, config, platform/shell and workspace.
The first implementation must define and test each complete wire schema before
CLI support, rather than publish this prose as a working schema.

## Consequences

Corpora can remain on v1 indefinitely. Multi-action packs need a versioned reader
and manifest contract; a migration emits new files and never rewrites originals.
The action abstraction does not authorize any described operation to execute.

## Revisit when

An adapter needs ordered multi-action transactions or input rewrites. Those
require a distinct semantic contract, not an untyped metadata escape hatch.
