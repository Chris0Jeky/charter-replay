# ADR 0003: Separate label agreement from independent evidence

Status: accepted direction.

## Context

The 494-case pack contains production-hook expectations. Agreement measures
conformance to those expectations, not independent truth. v1 `provenance`
describes event origin and has no rubric, reviewer or disagreement record.

## Options considered

1. Call every dangerous/allow mismatch a certified false allow.
2. Report explicitly scoped label agreement now; introduce separate adjudication evidence.
3. Delay all scoring until an independently labeled corpus is available.

## Decision

Choose option 2. Keep baseline/candidate diffing and label scoring separate.
For each side show dangerous totals with allow/deny/indeterminate counts, and
benign totals with the same counts. Report allow/dangerous and deny/benign rates
against all cases in the respective class; show indeterminate rates and decision
coverage alongside them. Also expose determinate denominators explicitly when
using a conditional rate. Opaque and unlabelled cases are excluded and counted.
An empty denominator is null, never zero.

A 95% Wilson interval can describe a supplied sample under an independent
Bernoulli assumption. It must carry that assumption and cannot be advertised as
a population or safety guarantee, especially for correlated generated variants.
Report seed and generated strata separately before any combined headline.

A new case-evidence contract records rubric/version, applicability/context,
label origin (independent, hook-derived or inherited), assessments, disagreement
and adjudication. Unresolved disagreement is an abstention. A transform carries
inherited evidence; it does not manufacture independent assessments.

## Consequences

Useful metrics arrive without upgrading the credibility of circular labels.
Rates cannot replace raw counts, coverage or the regression gate. Independent
benchmark claims wait for the evidence model and reviewed corpus.

## Revisit when

There are enough independently sampled seed clusters to support a cluster-aware
interval, or maintainers agree an explicit deployment-specific loss function.
