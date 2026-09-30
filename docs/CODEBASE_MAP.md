# Codebase map and first findings

> This is the v0.1.0 baseline snapshot that the roadmap was planned from. The
> ranked blockers below are kept as written. Their resolution is recorded under
> "Status since the baseline" at the end, and delivery state is tracked in
> [the roadmap](ROADMAP.md#delivery-status-2026-09-30).

Inspected baseline: `4a208a5dafc05f8282a4d3ff393aa1af70d2769e` (v0.1.0).
The supplied archive reconstructs the exact Git tree
`00f5903b730f262c3db48ddbf66ace491597e058`. No open issues or PRs preceded this work.
The baseline local test lane runs 188 tests in 66.493 seconds, with one
Windows-only test skipped on Linux. This is not evidence of a Windows run.

## Modules and data flow

| Boundary | Modules | Responsibility |
|---|---|---|
| User entry | `app.py` | Dispatch `hooks`, `record`, `import`; delegate `replay` and `validate` to the kernel; render hook summaries. |
| Runtime bridge | `hooks.py` | Parse shell-free hook argv; construct PreToolUse payloads; classify replies; map outcomes to effects; create workspaces; record decisions and observations. |
| Trusted input | `corpus.py`, `manifests.py`, `digests.py` | Validate strict v1 shapes and unique IDs; capture exact corpus bytes; bind files, identities and gate settings. |
| Comparison orchestration | `cli.py` | Load sources and corpus, construct a run manifest, evaluate sources, compare and transactionally publish the kernel report set. |
| Policy execution | `policy_sources.py` | Validate recordings; snapshot process inputs; verify identities before and after execution; supervise POSIX process groups and Windows Job Objects. |
| Semantics | `compare.py` | Join by event ID in corpus order and classify effect transitions without interpreting command text. |
| Presentation | `reports.py`, `app.py` | Kernel JSON/Markdown and hook summary JSON/Markdown. |
| Private collection | `importer.py` | Extract shell events from local transcripts, scrub identifying data, and refuse Git-trackable destinations. |

```mermaid
flowchart LR
    Corpus[Manifest + exact event/case bytes] --> Validate[Validate and capture]
    Validate --> Hook[Hook payload adapter]
    Hook --> Process[Caller-selected hook process]
    Process --> Records[Decisions + outcome observations]
    Records --> Sources[Recorded source validation]
    Validate --> Compare[Effect comparison]
    Sources --> Compare
    Compare --> Report[Run identity + report model]
    Report --> JSON[JSON]
    Report --> MD[Markdown]
```

Only the caller-selected hook or policy program runs. Corpus commands remain
strings on stdin. This is not a sandbox for an untrusted hook.

## Contracts to preserve

`command-event.v1`, `policy-decision.v1` and `charter-case.v1` reject unexpected
fields. The two-file corpus manifest binds `events.jsonl` and `cases.jsonl` by
SHA-256. Recorded decisions have an exact-byte sidecar. The process source has
stronger snapshot binding than the convenience hook recorder. These are not
interchangeable guarantees.

Effects are `allow`, `deny`, `indeterminate`. Actual kernel diff names are
`unchanged`, `newly-allowed`, `newly-denied`, `newly-indeterminate`, and
`resolved-indeterminate`. The brief's phrase “newly blocked” is descriptive,
not a new wire value. Exit 0 means gate pass; 1 means configured regression;
2 means invalid or unbound inputs; 3 means source/output failure when a
comparison can be formed. Failure has precedence over the regression exit.

Run identity binds runner version, policy identities, corpus manifest and gate.
`generated_at` is excluded from that identity, but enters report bytes. The
current kernel needs a fixed `SOURCE_DATE_EPOCH` for byte-identical reports.
Kernel Markdown deliberately includes host-local reproduction paths. Timing
in `outcomes.jsonl` is observational and not deterministic.

## Ranked blockers and fragile boundaries

1. **Failure evidence can disappear at the convenience boundary.** `hooks`
   records crashes/timeouts as indeterminate decisions, then asks the kernel to
   compare recordings. Two crashing hooks can therefore have an unchanged diff
   and a passing gate. Add failure propagation and exit-code regressions first.
2. **Runtime fidelity is not yet certified.** Both payload builders are the
   same for Claude and `codex-legacy`; `codex` has its own payload and reply
   grammar. Current official Codex documentation says unsupported
   ask/legacy approve/continue fields fail the hook and continue the call, which
   `codex-pretooluse.v1` records as indeterminate; the old floor stays as
   `codex-legacy`, not as runtime truth. See [runtime notes](RUNTIME_CONTRACTS.md).
3. **Hook input/context identity is weaker than process identity.** Hook
   argv/file identity is calculated after execution, omits executable bytes at
   argv[0], and does not bind runtime, workspace context or inherited config.
   Do not simplify the kernel by deleting protections the recorder needs.
4. **Workspace and admission can affect results.** A side shares one writable
   workspace across concurrent cases. Its process cwd is the workspace root,
   even when the payload names a nested cwd. Several CLI inputs are validated
   only after another side has already executed.
5. **Labels and variants can create false confidence.** v1 provenance describes
   event origin, not independent adjudication. Copying a label across arbitrary
   shell wrappers does not establish equivalent semantics. Report observations
   honestly and expose applicability/abstentions and seed lineage.
6. **Presentation is split and privacy is easy to overstate.** Summary Markdown
   interpolates free-text family names without the kernel's escaping. Full
   reports carry commands and reasons. A private corpus needs a separate
   aggregate-only export, not a claim that HTML escaping anonymizes content.
7. **The large process module mixes real boundaries.** About 1,250 lines combine
   process supervision, Windows support, snapshots, recordings and validation.
   Extract pure runtime adapters and rendering first; split supervision and
   snapshot internals only behind their existing contract tests.

## Assumptions

The brief authorizes autonomous, separately reviewable increments. Release
names, licence and zero runtime dependencies stay unchanged. No package release,
external account registration or claim of independently certified safety occurs
in this work. Proposed architecture is distinguished from implemented behaviour
in the roadmap and individual PR evidence.

## Status since the baseline

1. Failure evidence: fixed by #9. Hook failures are source failures, both-side
   failures cannot pass, and both sides are admitted before either runs.
2. Runtime fidelity: `codex-pretooluse.v1` (#31) models current Codex documentation
   and upstream parsing, with the old floor kept as `codex-legacy`, and
   `gemini-beforetool.v1` (#35) models Gemini CLI. None of these is certified
   against a running binary.
3. Hook identity: the fingerprint is taken before execution and re-checked (#20).
   `hook-context.v1` (#23) binds executable bytes, runtime, ask mapping, timeout,
   jobs and the workspace template, and declares the rest unbound.
4. Workspace and admission: each event gets a fresh workspace and the payload cwd
   (#10). Admission precedes execution (#9). Derived outputs are cleared before a
   rerun (#26).
5. Labels and variants: label agreement exposes denominators and coverage (#11).
   Variants carry verified seed lineage and visible skips (#14). Coverage separates
   cross-version changes from within-policy shape disagreement (#15, #17).
6. Presentation: the HTML report, the PR text and `summary.md` escape every
   free-text field (#12). The kernel `report.md` escapes only HTML and table pipes.
   By default the PR text omits commands and reasons but still lists up to 20
   changed case identifiers. Only `pr-comment-aggregate.md` omits case and policy
   identifiers. `aggregate.v1` (#39) adds a verified, fixed-vocabulary aggregate
   with a fail-closed leak check, which the Action can use as its job summary.
7. Process module: not yet split (R04-2).

New modules since the baseline: `adapters/` (runtime contracts), `hook_context.py`,
`repeat.py`, `aggregate.py`, `metrics.py`, `review_reports.py`, `publication.py`, `variants*.py`,
`variant_packs.py`, `variant_coverage.py`, `variant_review*.py`, and the composite
`action.yml`.
