# ADR 0005: One decision model, separate volatile observations

Status: accepted direction.

## Context

Kernel reports and hook summaries overlap but do not share all failure evidence.
Timing is useful but incompatible with same-input/same-byte decision artifacts.
Raw commands and reasons can be private even after rendering is injection-safe.

## Options considered

1. Put counts, timing, host paths and HTML into one mutable summary.
2. One deterministic decision model with pure renderers and a timing sidecar.
3. Add a hosted report service and external frontend dependencies.

## Decision

Choose option 2. Enrich the existing report with explicit hook failures before
rendering any view. Derived JSON summary, Markdown, HTML and PR text use the same
counts and gate. HTML is self-contained, accessible without scripts and has no
remote assets. Escape all user-controlled text and restrict any supplied links.
Default PR text omits command/reason bodies and prioritizes newly allowed
case IDs labeled dangerous. Aggregate-only export must omit identifiers too.

Put p50/p95/max and repeat timing in `measurements.json`, marked observational
and excluded from run identity and stable renderers. Document fixed
`SOURCE_DATE_EPOCH` for legacy report timestamps. A future report version removes
clock dependence and host-local reproduction paths from committable artifacts.
This deliberately places determinism above the suggested latency-in-summary field.

The Action executes with read-only permissions in a `pull_request` job. Candidate
hooks are untrusted code. Do not pass secrets, persist credentials or execute
candidate code in a privileged comment-posting context. Uploading a private
full report requires explicit consent; aggregate publication is the default.

## Consequences

Timing remains visible without breaking reproducible diffs. Pure renderers can
be tested against hostile HTML/Markdown and fixed input bytes. Privacy and
injection safety are separate properties, each with explicit tests and limits.

## Revisit when

Trend storage is requested or an authenticated report viewer is justified.
Neither is required for a useful offline report and PR review experience.
