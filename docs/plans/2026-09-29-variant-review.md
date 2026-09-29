# Capture-bound variant review implementation plan

Goal: complete issue #16 without weakening the replay gate, binding or privacy
contracts. Specification: issue #16, the maintainer's north-star brief, and the
existing report and variant designs in #12, #14 and #15.

## Decisions

Assumption: integration stays on a new branch. Reason: the two reviewed stacks
are still open. Reversible by discarding this branch; no parent PR head or main
moves. Preserve both parents in the integration commit so subsequent merges do
not duplicate or lose either history. Resolve app.py by retaining the report
stack and adding the variant stack's existing five-line route.

Assumption: offline review consumes an explicit run manifest as well as source,
pack and report. Reason: coverage projection alone deliberately ignores gate and
run identity. Reversible by a separately versioned evidence envelope. Validate
internal consistency, not authorship or actual execution; never call a digest a
signature or turn successful projection into a passed gate.

## Tasks and checks

1. Add public-CLI integration regressions before joining stacks. Exercise generated
   corpus -> real toy hooks -> HTML/metrics -> verified coverage, plus errored
   hooks whose valid coverage must leave an error gate. Run on the report-only
   branch, observe missing-variant failures, then integrate both exact heads.
2. Add a captured review admission model. Regenerate source/pack once; validate
   every report row and the explicit run manifest; recompute gate and comparison
   metadata. Reject swapped reports, forged detached aggregates, missing lineage,
   changed failure/gate fields, invalid decisions and oversized/deep input. Retain
   captured bytes through rendering instead of reopening verified paths.
3. Add HTML and bounded PR coverage sections from the admitted model. Separate
   unchanged seeds with changed variants from shape disagreements shared by both
   versions. Keep indeterminate, affected seed groups and privacy limits visible.
4. Add `variants review` with new-output publication and existing exit meanings:
   0 clean comparison, 1 triggered gate, 2 invalid evidence, 3 source/output failure.
   Test rollback/no-overwrite and input immutability before publication code.
5. Run all available local checks and the full hosted suite for exact final heads.
   Exercise desktop/mobile/no-JavaScript/hostile-text browser cases. Record changed,
   verified, not verified and residual risk in the PR, with no release or main merge.

## Global constraints and review focus

Python 3.11+, zero runtime dependencies, Linux/macOS/Windows, no corpus command
execution, no private fixtures, additive schemas and no machine paths in stable
reports. Avoid duplicated comparison logic and public mutable trust flags. Do not
accept a supplied coverage JSON as proof. Reject booleans substituted for counts,
keep errored source evidence visible, and avoid deleting another writer's output.
