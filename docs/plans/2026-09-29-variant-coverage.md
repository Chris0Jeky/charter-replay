# Verified seed and variant coverage implementation plan

Goal: show shape-specific decision changes without treating inherited labels as
independent votes. Builds on PR #14 and the report direction in ADR 0005 of #2.

Assumption: a report is supplied evidence, not an authenticated execution record.
This increment verifies its corpus/rows/decisions/classifications/counts, not its
policy identities, run manifest, gate, author or execution. It emits no gate pass.
It leaves replay-report.v1 unchanged and exports a separate aggregate projection.

1. Write failing tests for a canonical seed that stays denied while its env shape
   newly allows, benign shapes newly denied, indeterminate outcomes, reordered
   rows, privacy, forged rows/counts/IDs, bad lineage, resource limits and CLI.
2. Implement `variant_coverage.py`: derive and capture once, verify the four pack
   files, bind every report event and case, validate the decision IDs and effects,
   recompute comparisons with the existing kernel, then aggregate seed, derived
   and per-transform counts plus cluster-aware shape disagreements.
3. Expose `variants coverage` through the existing CLI. Output only fixed-vocabulary
   JSON counts and limitations, with no commands, reasons, IDs, corpus digests,
   paths, family names or policy identity. Exit 0 is successful projection, not a
   gate pass; invalid evidence returns 2 without JSON output.
4. Run focused/full tests, document the distinction between cross-version diff
   and within-policy shape disagreement, and publish a stacked draft PR.

Review focus: byte-verified inputs cannot be reopened for counting; a report from
another corpus must not be accepted by matching IDs; missing or duplicate rows
must fail rather than reduce counts; reordered decision IDs must not cross-pair;
indeterminate is its own effect, never silently folded into allow or deny.
