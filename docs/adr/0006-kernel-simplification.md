# ADR 0006: Simplify boundaries, not identity guarantees

Status: accepted direction.

## Context

`policy_sources.py` is large, but much of its size protects real invariants:
exact-byte capture, snapshot identity, writable cleanup, duplicate-key handling,
Windows process-tree termination and fail-closed validation. Removing it would
move complexity into callers and weaken the strongest part of the system.

## Options considered

1. Replace the process source with a short subprocess wrapper.
2. Extract cohesive modules behind compatibility imports and existing tests.
3. Rewrite the kernel around a new framework or dependency.

## Decision

Choose option 2. First move pure runtime grammar out of `hooks.py`, then move
pure rendering out of CLI orchestration. Next isolate supervised process IO,
recorded source validation and snapshot lifecycle without changing wire records
or identity preimages. Keep old imports as facades until all callers migrate.

Before moving snapshot machinery, retain tests for mutation before/during a run,
symlinks and reparse points, normalized metadata, cleanup failure, output
boundary conflicts, duplicate keys, rollback and source failure precedence.
A reduction in line count is not evidence of correctness. Improve hook-source
identity using the same principles rather than downgrading kernel identity to
match the convenience recorder.

## Consequences

Refactors are reviewable and separable from semantic fixes. Windows-specific
code stays explicit and receives real Windows CI; a mock cannot certify Job
Objects. No caching is added until the complete context participates in a key.

## Revisit when

A second independently implemented source needs a shared abstraction, or profiling
shows an actual snapshot bottleneck. Avoid generic factories before that need.
