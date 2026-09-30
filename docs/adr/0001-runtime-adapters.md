# ADR 0001: Separate runtime contracts from invocation

Status: accepted direction; first extraction preserves v0.1 behaviour.

## Context

`hooks.py` combines command parsing, payload grammar, reply interpretation,
workspace lifecycle, subprocess supervision and recording. Adding a runtime by
another conditional makes contract drift hard to see. The current Codex floor
is not the same as the current documented Codex behaviour.

## Options considered

1. Keep runtime branches in `hooks.py`. Small now, but hard to audit and extend.
2. An explicit registry of small adapters implementing a stdlib Protocol.
3. Dynamic entry-point plugins with arbitrary import/configuration machinery.

## Decision

Choose option 2. The protocol owns name, versioned contract ID, payload builder,
reply classifier and environment additions. The runner owns shell-free argv,
stdin encoding, timeout, elapsed time and platform cleanup. Share only genuinely
common helpers. Keep the original `hooks` functions as thin compatibility
facades. Unknown names are invalid input. No adapter executes corpus content.

Use contract fixtures for silent success, exit 2, other exits, malformed JSON,
legacy fields, stop, ask and wrong event names. The first extraction retains
existing Claude/Codex output byte-for-byte. Correct runtime semantics in a
separate, documented change; an adapter version belongs in future source identity.

## Consequences

A third runtime becomes a module plus contract tests. This is not permission to
claim live-runtime certification based only on fixtures. Preserve the explicit
outcome/effect distinction and keep fail-open observations indeterminate.

## Revisit when

Two independent consumers need external adapters, or a runtime needs multiple
hook stages or input rewrites. Revisit plugin discovery then, not before.
