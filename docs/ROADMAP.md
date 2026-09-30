# Roadmap: v0.2 through v1.0

This is an ordered delivery plan, not a release-date promise. Versions describe
capabilities and acceptance gates; the package stays at its current version
until the maintainer releases it. See [architecture](ARCHITECTURE.md) and
[codebase map](CODEBASE_MAP.md). Every issue below is a separately reviewable
scope. S means one narrow boundary, M means a feature with integration tests,
and L means a subsystem or migration.

## Delivery status (2026-09-30)

Merged to `main`. The PR is the evidence; its review record and exact-head CI are on it.

| ID | State | Delivered by |
|---|---|---|
| R02-1 | done | #5 runtime adapter registry |
| R02-2 | done | #9 failure admission and exit precedence |
| R02-3 | done | #10 per-event workspace isolation |
| R02-4 | done | #11 label agreement, coverage and observational latency |
| R02-5 | done | #12 offline HTML and bounded PR text; #17 verified variant review |
| R02-6 | done | #14 bounded POSIX variants; #15 seed and shape coverage |
| R03-1 | done | #29 least-privilege composite Action with a three-OS self-test |
| R03-2 | done | #39 `aggregate.v1` with a fail-closed leak check, an `aggregate` command and Action `summary-mode: aggregate` |
| R03-3 | done | #31 `codex-pretooluse.v1`, with the v0.1 floor kept as `codex-legacy` |
| R03-4 | done | #35 `gemini-beforetool.v1` |
| R04-1 | first increment | #20 bracketed input observations; #23 `hook-context.v1` descriptor. Executable dependencies, helper imports, permissions and environment values are declared unbound, not bound |
| R04-3 | done | #25 repeat-stability mode keyed by context id |
| R08-2 | first increment | #37 per-stream hook output limit that kills the process family on overflow. Adversarial long-input and disk-budget work remains |

Review follow-ups landed as #26 and #36. Acceptance CI covers browser and
installed-wheel review (#18) and a three-OS Action self-test (#29). Still planned:
R04-2, R05-x (R05-2 needs real independent human review), R06-x, R07-x and
R08-1. None of the runtime contracts is certified against a running binary.

## v0.2: Trustworthy and reviewable shell diffs

Goal: de-risk boundaries and make today's hook changes easier to review.
User outcome: failures cannot pass as healthy comparisons, supplied labels are
visible, and an offline report explains regressions.

| ID | Issue title | Size | Acceptance criteria |
|---|---|---|---|
| R02-1 | Extract versioned runtime adapter boundary | M | Preserve existing payload/reply fixtures and compatibility imports; unknown runtimes fail admission; all-platform CI and toy counts unchanged. |
| R02-2 | Preserve hook failure exits and validate before invocation | M | Both-side crash/timeout/malformed-output cannot return 0; report and summary gates agree; invalid options/second-side command run no hook; 0/1/2/3 precedence tested. |
| R02-3 | Isolate case workspaces and honor event cwd | M | Serial and parallel side-effecting fixture hooks see fresh state; cwd matches payload; cleanup occurs on error; no corpus execution. |
| R02-4 | Report supplied-label agreement and observational latency | M | Explicit denominators, exclusions, coverage and empty-class nulls; interval assumptions documented; timing outside stable summaries/identity. |
| R02-5 | Add static HTML and compact PR renderer | M | One result model; filters for class/family/effect/diff; readable without JS; no external assets; hostile text escaped; PR output excludes commands/reasons by default. |
| R02-6 | Generate a bounded POSIX variant pack with lineage | M | Wrapper/prefix/quoting families have preconditions; deterministic output and budget; original seeds retained; valid two-file corpus plus digest-bound lineage; skips visible. |

Definition of done: local full tests, formatter/linter and exact-head Linux,
macOS and Windows CI pass; documentation distinguishes conformance from safety;
reports and generated corpus reproduce under documented inputs. No new runtime
dependency. R02-1 precedes runtime fixes. R02-2 precedes publishing gate results.
R02-4/R02-5 can share the result model but remain separate commits. R02-6 does
not depend on a generalized event migration.

## v0.3: Put evidence on the PR

Goal: reduce adoption friction without crossing trust/privacy boundaries.
User outcome: a read-only Action produces a check, job summary and optional
report artifact, with a documented separate comment-posting workflow.

| ID | Issue title | Size | Acceptance criteria |
|---|---|---|---|
| R03-1 | Ship a least-privilege replay Action | M | CLI args passed without shell interpolation; exact tool revision; exit preserved; read-only fork-safe example; no secrets or credential persistence; untrusted candidates replay only public synthetic corpora and their reports are untrusted until an OS isolation boundary separates hook from report. |
| R03-2 | Add verified aggregate-only publication | M | No commands, reasons, paths or event IDs in aggregate mode; opt-in full artifacts; comments have a stable marker and bounded size; malicious artifact tests. |
| R03-3 | Correct and version the Codex contract | M | Current pinned runtime fixtures; unsupported replies remain indeterminate; old floor explicitly identified; migration and run-identity distinction. |
| R03-4 | Add a Gemini BeforeTool adapter | M | Dedicated payload/classifier/environment fixtures; documented unsupported rewrites; third-runtime tests do not execute actions. |

Definition of done: end-to-end synthetic Action demonstration and inspected
exact-head logs; no privileged execution of PR code; no live API token required
by unit tests. R03-2 must not be implemented by sharing a privileged process
with candidate hook execution. R03-3/4 depend on R02-1.

## v0.4: Bind the complete decision context

Goal: make recordings defensible when hooks depend on code, tier or config.
User outcome: changing a hook dependency or permission context changes identity,
and changing a file during a run cannot produce trusted evidence.

| ID | Issue title | Size | Acceptance criteria |
|---|---|---|---|
| R04-1 | Bind hook code, workspace and adapter context | L | Capture before invocation; include executable/script/config/workspace and adapter identity; verify after; path-portable manifest; mutation and relocation tests. |
| R04-2 | Separate kernel supervision and snapshot modules | M | Existing identities/report bytes unchanged; compatibility imports; process-tree, symlink/reparse and rollback regressions retained. |
| R04-3 | Add repeat stability and budget observations | M | Fresh workspaces per repeat; deterministic outcome disagreement summaries; timing records include sample count/jobs/budget; no timing in semantic identity. |

Definition of done: context changes are distinguishable, snapshot mutation cannot
be certified, and repeat instability is visible independently of baseline diffs.
Do not introduce caching before R04-1.

## v0.5: Independent evidence and corpus strength

Goal: stop conflating source-hook expectations with independent labels.
User outcome: reviewers can inspect rubric, evidence and disagreement, and see
whether a corpus detects controlled hook mutations.

| ID | Issue title | Size | Acceptance criteria |
|---|---|---|---|
| R05-1 | Add case-evidence schema and labeling rubric | L | Independent/hook-derived/inherited origins; context applicability; multiple assessments; disagreement and adjudication; strict schema plus migrations. |
| R05-2 | Review a shell-core seed benchmark | L | Published synthetic rubric/evidence per seed; no unresolved case silently scored; independent review actually performed, not simulated. |
| R05-3 | Add bounded mutation sensitivity evaluation | M | Synthetic toy mutations; deterministic killed/survived/invalid/timeout accounting; baseline sanity; execution limited to hooks; no security-proof claim. |

Definition of done: every scored independent case has supporting evidence and
review history; inherited variants stay grouped by seed. R05-2 requires real
additional labeling/review and is not something an automated author can declare
complete alone.

## v0.6: Generalize actions without breaking old corpora

Goal: cover file, network and MCP guardrails.
User outcome: old command packs still replay while new action packs exercise
non-shell hooks as data.

| ID | Issue title | Size | Acceptance criteria |
|---|---|---|---|
| R06-1 | Implement action-event.v1 and legacy bridge | L | Strict discriminated schemas; lossless v1 normalization; context references; migrations emit new files; unknown kinds rejected. |
| R06-2 | Add non-shell adapter mappings and fixtures | L | File edit/write digests, network and MCP inputs; synthetic content fixtures for content-dependent hooks; unsupported combinations rejected before execution. |

Definition of done: old v1 fixtures remain byte-stable and executable operations
never arise from event data. R06-1 follows R04-1 and R05-1 to avoid redesigning
context and evidence twice.

## v0.7: Portable packs and private workflows

Goal: make measurements reproducible and shareable without exposing transcripts.
User outcome: cite an installed pack by name, version and verified digest, or
share only aggregate observations from a private pack.

| ID | Issue title | Size | Acceptance criteria |
|---|---|---|---|
| R07-1 | Add versioned digest-verified pack install/export | L | Offline import; exact bytes; archive traversal/link/size limits; rollback; explicit source and digest pinning; no claim that a hash is an author signature. |
| R07-2 | Add private aggregate trends | M | Stable aggregate schema; no command/ID/path leakage; context/pack compatibility checks; local storage; incompatible runs not merged into one trend. |

Definition of done: corrupt or malicious packs cannot be installed as verified,
and public aggregate export passes adversarial privacy tests.

## v0.8: Cross-platform coverage and hardening

Goal: expand shapes only where semantics and context are stated.
User outcome: Windows cmd/PowerShell and POSIX packs have explicit domains and
predictable resource usage.

| ID | Issue title | Size | Acceptance criteria |
|---|---|---|---|
| R08-1 | Add reviewed Windows and contextual transforms | L | Platform-independent generation; shell-specific assumptions; conservative skips; serializable lineage; no local-shell oracle. |
| R08-2 | Bound process output and adversarial inputs | M | Output byte caps, disk/memory budgets, long-input tests, timeout cleanup on all OSes; no unbounded regex oracle. |

Definition of done: all supported domains have negative as well as positive
fixtures and documented resource limits.

## v0.9: Release candidate and migration rehearsal

Goal: audit public contracts and packaging.
User outcome: clean installs, stable APIs, migration examples and reproducible
reports work without reading kernel internals.

R09-1 (M): freeze supported contract/capability matrix; verify fresh-environment
CLI and wheel contents on all OSes; migration round-trips; run identity and
privacy audit; documentation distinguishes proposed and implemented features.
Definition of done: no unresolved release-blocking defects, no accidental private
fixtures, and a documented rollback path.

## v1.0: Stable regression harness

Goal: commit to a maintainable compatibility contract, not universal safety.
User outcome: reproducible packs, versioned runtime adapters, contextual evidence
and review integrations can be used routinely.

R10-1 (M): publish compatibility/deprecation policy and support boundaries;
validate supported runtime revisions and sample CI integrations; release only
with maintainer approval. Definition of done: stable schemas and migration
promises are backed by tests. PyPI account setup and release authorization stay
with the maintainer; they do not block code/PR delivery.

## Ready-to-file issue index

Each title below maps to the acceptance criteria and size in its milestone above.
Use this list to create any issue not yet linked from the design tracking issue.

```text
R02-1 [M] Extract versioned runtime adapter boundary
R02-2 [M] Preserve hook failure exits and validate before invocation
R02-3 [M] Isolate case workspaces and honor event cwd
R02-4 [M] Report supplied-label agreement and observational latency
R02-5 [M] Add static HTML and compact PR renderer
R02-6 [M] Generate a bounded POSIX variant pack with lineage
R03-1 [M] Ship a least-privilege replay Action
R03-2 [M] Add verified aggregate-only publication
R03-3 [M] Correct and version the Codex contract
R03-4 [M] Add a Gemini BeforeTool adapter
R04-1 [L] Bind hook code, workspace and adapter context
R04-2 [M] Separate kernel supervision and snapshot modules
R04-3 [M] Add repeat stability and budget observations
R05-1 [L] Add case-evidence schema and labeling rubric
R05-2 [L] Review a shell-core seed benchmark
R05-3 [M] Add bounded mutation sensitivity evaluation
R06-1 [L] Implement action-event.v1 and legacy bridge
R06-2 [L] Add non-shell adapter mappings and fixtures
R07-1 [L] Add versioned digest-verified pack install/export
R07-2 [M] Add private aggregate trends
R08-1 [L] Add reviewed Windows and contextual transforms
R08-2 [M] Bound process output and adversarial inputs
R09-1 [M] Rehearse release contracts, packaging and migrations
R10-1 [M] Publish stable compatibility and support policy
```

## First delivery sequence

Architecture and ADRs first, then no-behaviour adapter extraction, failure and
admission repair, report/scoring improvements, conservative derivation, and the
Action. Workspace isolation and source identity are correctness work, not
cosmetic refactors. Every PR ends with changed / verified / NOT verified /
residual risk and records the exact tested head. Do not infer that an issue is
complete merely because it has a draft PR.
