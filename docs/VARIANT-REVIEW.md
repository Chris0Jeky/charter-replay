# Capture-bound variant review

`variants review` joins the verified variant pack, replay rows, run manifest and
review views. It does not accept a detached coverage JSON as proof. It neither
runs a hook nor executes a corpus command. Existing replay artifacts remain
unchanged; the joined review goes into a new directory.

## Review and verify

Generate the pack and record the comparison as described in `VARIANTS.md` and
`VARIANT-COVERAGE.md`. Then supply the source, pack, report and run manifest:

```console
python -m charter_replay.app variants review --source charter_replay/corpora/charter --pack ./derived --report ./replay/report/report.json --run-manifest ./replay/report/run-manifest.json --output ./review
python -m charter_replay.app variants verify-review --source charter_replay/corpora/charter --pack ./derived --report ./replay/report/report.json --run-manifest ./replay/report/run-manifest.json --review ./review
```

The output parent must exist and the review directory must be new, even when a
pre-existing directory is empty. Output must be outside both corpus directories.
The commands use the installed `charter-replay variants` entry point too.

Both commands preserve the admitted replay's exit: 0 for a passed gate, 1 for a
triggered gate, and 3 when source failure evidence makes the gate errored. Invalid
inputs or review contents return 2. Publication IO failure returns 3. In contrast,
`variants coverage` still returns 0 for a valid projection, not a gate pass.
Do not chain expected exit-1 demonstrations with success-only `&&`.

## Admission and output

The review captures source bytes and regenerates the pack. All four pack files
must match. Each report event, label and decision is checked against the same
captured values. The kernel recomputes classifications, counts, triggered gates
and error precedence. The explicit run manifest must validate its own identity
and agree with all report metadata. Duplicate keys, malformed/deep JSON,
non-finite numbers, Boolean counts and extra detached coverage fields fail.
The report and run manifest are each read once; verified paths are not reopened
for rendering. The report budget is 32 MiB and the run manifest budget is 64 KiB.

The directory contains eight named files:

| File | Purpose |
|---|---|
| `report.html` | Full offline comparison and verified shape coverage |
| `pr-comment.md` | Bounded changes and coverage, with case identifiers |
| `pr-comment-aggregate.md` | Counts only, without case or policy identifiers |
| `report.json` | Validated replay report, normalized into corpus order |
| `run-manifest.json` | Validated run manifest |
| `variant-coverage.json` | Existing seed/derived/per-transform projection |
| `variant-review.json` | Gate and within-policy/shared shape observations |
| `review-manifest.json` | Exact input digests and all seven output digests |

Existing `replay-report.v1` and `variant-coverage.v1` stay unchanged. Review
metadata uses new additive versions. Reordered valid report rows produce the same
views, but the completion marker still records the distinct original input bytes.
No current time, absolute machine path or random identifier is added.

`verify-review` regenerates all eight files from the original inputs. It does not
trust a completion marker's self-reported digests: editing HTML and rebinding that
marker's digest still fails. The review directory must also
list exactly those eight names: an extra file, subdirectory or link beside them
fails verification, as does a renamed file. Keep the tool version used to generate a
review when reproducing its exact rendered bytes across future renderer changes.

## Reading the view

Verified coverage appears before supplied-label scores. It shows source seeds,
derived cases, skipped transform attempts, cross-version counts and transform
coverage. Expand **Seed to shape effects** for each policy's full effect matrix.
The native expansion works without JavaScript. Filters, search, keyboard reset,
mobile scrolling and the existing exact-hash content security policy remain.

Two observations stay distinct. An unchanged seed can have a variant whose
baseline-to-candidate decision changes. Separately, both policies can share the
same nontrivial seed-to-shape transition even when their cross-version diff is
unchanged. Shared disagreement requires the same transition in both policies;
opposite transitions are not grouped as shared. Counts include affected distinct
seeds, not new independent labelling votes. Indeterminate remains its own effect.

Both PR text modes include all five classifications by origin and bounded
transform counts. The combined text stays at or below 16,000 UTF-8 bytes by
reducing the changed-case preview, never by splitting a character or table row.
Coverage adds no new safety gate and cannot overwrite an error with a pass.

## Publication, privacy and evidence limits

Publication reserves a new directory, links private staged files without replacing
existing paths, and links `review-manifest.json` last. Readers require the marker.
A directory can temporarily exist without it. Failure cleanup removes only
unchanged files owned by this publication and preserves another writer's data.
Names reject path traversal, Windows device names and trailing-dot aliases on all
platforms. Published artifact sets are limited to 128 MiB. Rendering allocates in
memory before publication; this is not a peak-memory limit. Rollback reads are bounded.

This requires a hard-link-capable filesystem and caller-owned parent directories.
It is not crash-durable storage or a boundary against a hostile process replacing
parent directories. A crash can leave an incomplete directory; inspect it before
removal or retry. Existing output is never silently replaced.

Full HTML, JSON and non-aggregate PR text can contain private source material.
Escaping is not scrubbing. Only aggregate PR text omits commands, reasons, paths,
IDs and corpus digests, and small counts can still disclose private information.
No artifact is automatically uploaded or posted by these product commands.

Validation establishes internal consistency, not authorship, actual execution or
the truth of supplied labels. A person can fabricate mutually consistent decisions
and source-failure claims. Digests are not signatures. Inherited labels remain
dependent assumptions; an unchanged replay does not prove safety or reachability.

## Reproducible demonstration and browser checks

From the repository root:

```console
python -m examples.review_demo --output ./review-demo
```

The demonstration uses only the checked synthetic charter and two repository toy
hook programs. Its internal comparison, review and verification each return 1 as
expected. The demonstration itself returns 0 only after those checks pass. It
reconstructs 50 seeds, 54 variants and 96 skipped attempts, and observes three
shared seed-to-shape disagreements across three seeds. This is a toy regression
fixture, not an independently adjudicated safety result.

Optional development-only browser checks use Playwright 1.57.0:

```console
python -m pip install "playwright==1.57.0"
python -m playwright install chromium
python -m examples.review_demo --output ./review-browser-demo --browser
```

Pass `--executable` for an already installed Chromium. The helper checks desktop,
390-pixel mobile, JavaScript-disabled fallback, native matrix expansion, filters,
keyboard reset and hostile reason text. It aborts network requests and fails on
script errors, injected image elements or body overflow. Assertions must remain
enabled. The observed browser version and HTML digest accompany the screenshots.

The helper loads HTML in memory with its own CSP. It does not certify local-file
URL opening, other browser engines or screen-reader behavior. Screenshots contain
full corpus text. Use synthetic data for publicly shared browser evidence.

`REVIEW-ACCEPTANCE.md` describes the automated browser and isolated installed-wheel
checks, their retained synthetic evidence, and their platform limits.
