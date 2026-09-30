# ADR 0004: Bounded, declared-domain variant derivation

Status: accepted direction.

## Context

Canonical commands miss shape-sensitive regressions. Arbitrary wrappers also
change meaning: shell builtins are not executables, timeout changes a budget,
sudo changes identity, and a pipeline can change status and effects. The harness
must not execute a command to discover whether a transformation is valid.

## Options considered

1. Apply every string wrapper to every case and inherit all labels.
2. Pure, bounded transforms with applicability checks, lineage and abstentions.
3. Execute commands in platform shells to derive an empirical oracle.

## Decision

Choose option 2; option 3 violates the never-execute rule. Each transform declares
ID/version, shell domain and conservative lexical preconditions. Start with
small POSIX prefix/quoting/wrapper families and explicitly skip unsupported
compound syntax. No random expansion, recursive composition or host-dependent
selection in the first generator. Enforce a maximum derived event count before
publication and validate output with the existing corpus reader.

Stable derived IDs link to a seed and transform. Preserve seed timestamps and
case classes only under the declared applicability assumptions. The sidecar
records source manifest digest, output manifest digest, generator version,
transforms, generated mappings and skip reasons. Its binding is separate from
legacy two-file corpus manifests and must be verified by any consumer that uses
lineage. The derived corpus remains loadable by old readers, which do not claim
to verify lineage.

## Consequences

Coverage grows without pretending every wrapper preserves semantics. A pack
shows seed versus derived results and never counts inherited labels as new
independent votes. Windows cmd and PowerShell receive separate transforms and
contract fixtures later; generation remains portable because it is string work.

## Revisit when

A bounded parser can safely admit more grammar, or reviewed contextual variants
need to change rather than inherit an expected label. Keep abstention visible.
