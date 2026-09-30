# Label agreement and latency

The `hooks` command adds `label_agreement` to `summary.json` and an aggregate
section to `summary.md`. The baseline/candidate regression gate is unchanged.
An improved label score cannot override a newly allowed or failed-source gate.

## What the score means

The score measures agreement with supplied `charter-case.v1` labels. It does
not measure independently established safety. The production-derived pack's
labels describe a particular hook's expectations. v1 origin metadata cannot
identify all hook-derived or correlated cases.

Each side reports dangerous and benign strata separately. For dangerous cases,
`false-allow` counts allow effects; for benign cases, `false-deny` counts deny
effects. `disagreement_rate` divides that count by all cases in the class,
including indeterminate results. It is not a determinate-only accuracy score.
`determinate_disagreement_rate` instead divides by allow plus deny counts.
Both denominators, all effect counts, indeterminate rate and decision coverage
are explicit. A missing denominator yields JSON null, not a perfect zero.
Opaque and unlabelled cases are counted as exclusions, not relabeled as safe.

The `all`, `seed` and `generated-variant` groups show separate results. Here,
seed means non-generated origin, not independent review. An event or case marked
`generated-variant` enters the generated group. These self-declared flags do
not verify a derivation or its semantics. The generated group and any combined
group containing generated cases suppress independent-sample intervals.

Other non-empty classes carry a descriptive 95% Wilson score interval under an
independent Bernoulli model, rounded to six decimal places. This model does not
turn a convenience corpus into a population sample, establish independence, or
provide a safety guarantee. The implementation uses the Wilson formula in the
[NIST reference](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm),
checked on 2026-09-29, with z = 1.959963984540054. Tests pin small-sample and
zero/all-disagreement cases. A future evidence schema must carry rubric,
context, assessments and disagreement before independent benchmark claims.

## Timing is a separate observation

Each recorded side writes `measurements.json` next to `outcomes.jsonl`. For
`hooks`, these live in `baseline/measurements.json` and
`candidate/measurements.json`. Timing never enters stable summary bytes or run
identity. A report-output failure returns exit 3 rather than a traceback.

The sidecar records event/sample counts, worker count, timeout budget, timeout
count, excluded start-failure count, and p50/p95/max observed milliseconds.
Percentiles use nearest rank: sorted sample at `ceil(p * n)`, indexed from one.
For example, samples 1 through 20 have p50 10, p95 19 and maximum 20. No started
samples gives null percentiles. The clock is the existing monotonic process
observation; workspace preparation and final workspace cleanup are excluded.
Timeout observations are censored: they show how long the runner waited, not
when that hook would have finished. Start failures are excluded from latency
percentiles but counted. Different worker counts or machines are not directly
comparable. No new latency threshold changes the regression gate.

`measurements.json` contains aggregates, not event IDs, commands or reasons.
That does not make the surrounding full replay report safe to publish: it still
contains corpus command text and hook reasons. Use the separate private-corpus
and aggregate-publication workflows for sensitive input.
