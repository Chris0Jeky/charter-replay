# Verified seed and shape coverage

A cross-version diff answers whether a candidate changes a decision. A shape
comparison asks whether one policy treats a seed and its derived command shape
the same way. Neither question replaces the other. Two policies can both allow a
quoted variant while denying its seed, and still produce an unchanged diff.

`charter-replay variants coverage` reads a completed kernel `report.json`, the
exact source corpus and its generated pack. It emits `variant-coverage.v1` JSON
on stdout. It does not run a hook, shell or corpus command, alter the report,
change the gate or modify the replay identity.

```console
python -m charter_replay.app variants coverage --source charter_replay/corpora/charter --pack ./derived --report ./replay/report/report.json
```

## What is verified

The command captures the source once and regenerates the expected pack. All four
core pack files must match that regeneration byte-for-byte. It then admits one
bounded report capture, using those same verified in-memory bytes for counting.
It does not reopen a path after verification to fetch the event or label values.

The report must name the exact corpus ID, manifest digest and count. Every event
and case must exactly match the verified pack, including command, timestamp,
working-directory context, rationale, label and provenance. Each event occurs
once. Both decisions must name that event and satisfy the existing v1 contract.
The kernel recomputes the classifications and counts. Wrong IDs, duplicates,
missing rows, changed commands or labels, mismatched decisions, edited counts
and even `true` used in place of count `1` fail admission. Row order does not
change the aggregate result.

Report input is limited to 32 MiB, is read only from a regular file, and rejects
duplicate JSON keys, malformed/deep JSON and non-finite JSON numbers. Existing
source and generated-pack limits still apply. Admission errors return exit 2
without a JSON result. Success returns exit 0 for a verified projection, not a
replay gate pass. A failed or errored replay can still have useful coverage.

This is not whole-report authentication. Policy identities, the run identity,
source-process failures, gate correctness, author and claimed execution are not
verified by this command. A person who fabricates internally consistent decisions
can produce an internally consistent projection. Keep the original replay and
its provenance when reviewing evidence. The output does not echo its gate.

## Reading the projection

`by_origin.seed` and `by_origin.derived` count cross-version classifications
separately. `by_transform` adds each transform's generated and skipped counts,
cross-version changes, and a 3-by-3 seed-effect to variant-effect matrix for each
policy. For example, candidate `deny->allow` means the candidate denies the seed
but allows that shape. It is not a baseline-to-candidate transition.

`clusters` counts distinct seeds, not generated observations. It shows how many
seeds have variants, how many have a changed variant, and how many unchanged seeds
have a changed variant. Several changed shapes of one seed count once. Skips are
transform attempts, not distinct seed cases. Indeterminate remains a separate
row and column rather than becoming allow or deny.

The output uses fixed vocabulary and counts. It omits commands, reasons, event
IDs, case-family strings, paths, timestamps, policy IDs, run IDs and corpus
digests. That is deliberate aggregate minimization, not anonymization: small
counts can still reveal information. Derived labels remain inherited assumptions;
correlated shapes do not become independent labelling votes or a safety score.

## Reproduce the checked toy demonstration

From a checkout, use new output directories. The middle command intentionally
returns exit 1 because the repository's toy candidate has a regression. Run the
coverage command afterward rather than chaining it with success-only `&&`.

```console
python -m charter_replay.app variants generate --source charter_replay/corpora/charter --output ./derived --domain posix-external.v1 --recipe examples/packs/charter-posix-v1.json
python -m charter_replay.app hooks --baseline "python examples/toy-guard/guard_v1.py" --candidate "python examples/toy-guard/guard_v2.py" --corpus ./derived --output ./replay
python -m charter_replay.app variants coverage --source charter_replay/corpora/charter --pack ./derived --report ./replay/report/report.json
```

The checked aggregate is `examples/packs/charter-posix-v1.coverage.json`. It is
captured from running both toy hook programs against all 104 events, not from
executing any corpus commands. The 50 seeds produce 54 shapes from 18 eligible
seeds, with 96 explicit skipped transform attempts.

The seed diff contains 45 unchanged, 4 newly allowed and 1 newly denied decisions.
The derived diff contains 46 unchanged, 6 newly allowed and 2 newly denied
observations. Four seed clusters have changed variants.

All 18 quoting variants have unchanged cross-version decisions. Despite that,
the baseline has 6 seed-deny/quoted-allow pairs, and the candidate has 4. These
are shape disagreements, not independently adjudicated safety findings. The toy
policies tokenize by whitespace rather than parsing quoted words, which explains
this particular result. The example demonstrates why unchanged replay counts
alone do not establish shape invariance or prove untested commands unreachable.

The fast test suite uses synthetic decision reports, checks wrapper-only changes
under unchanged seeds, and covers malformed/bounded input, capture consistency,
privacy and indeterminate effects. The full toy invocation is a documented local
integration check rather than 208 extra process launches in every unit-test run.

## Follow-up boundary

This increment adds a JSON projection. Automatic attachment to HTML and PR text,
an authenticated run-manifest join, repeat stability, additional shell domains
and mutation-test adequacy are separate changes. No new safety gate or release
claim follows from aggregate coverage alone.
