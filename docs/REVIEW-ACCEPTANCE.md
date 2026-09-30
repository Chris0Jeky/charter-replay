# Review acceptance checks

The Review acceptance workflow tests the complete synthetic review independently
of the fast unit suite. It runs for every pull request and main push, alongside
the existing six OS/Python test lanes, lint and package build. It tests the normal
PR merge checkout; the workflow run identifies the PR head and base, and the job
summary records the tested checkout commit.

## Browser job

The job installs development-only Playwright 1.57.0 and its Chromium build, then
runs `python -m examples.review_demo --browser` against the checked synthetic
charter and the two repository toy hooks. Both normal and hostile-reason reports
receive desktop, mobile and JavaScript-disabled checks. Filters, keyboard reset,
native matrix expansion, zero report network requests, absence of script errors
and page overflow are assertions, not a screenshot-only claim.

The toy candidate intentionally creates a regression. Hook comparison, review
publication and review regeneration verification each return 1. The demonstration
returns 0 only when these expected codes, counts and browser checks agree. The
Actions summary labels this expected-regression fixture before showing its
aggregate review; a FAIL in that fixture is not a failed acceptance assertion.

Screenshots and their HTML digests, observed browser version and JSON check results
remain available as named Actions artifacts for seven days. Upload runs after a
failed check when partial evidence exists, but never converts a failed test into
a success. Only explicit synthetic browser evidence paths are uploaded, not a
source archive, arbitrary working-directory contents or private transcript data.
The screenshots still contain full synthetic corpus text and are not a scrubber.

## Installed-wheel job

Testing while sitting in a source checkout can import local modules even after
installing a wheel. This lane builds the wheel, creates a fresh environment outside
the checkout, and installs the produced wheel with `--no-index --no-deps`. It then
runs `examples/check_installed_review.py` with Python isolated mode from outside
the repository, with PYTHONPATH set to the checkout. Under `python -I` that
variable is ignored, so this setting does not test isolation by itself: it would
only act as a negative control if `-I` were dropped, when the checkout would
shadow the wheel and the helper's location checks would fail. Isolation rests on
`-I`, the environment outside the checkout and those checks. The helper rejects
a package outside that environment, a package inside the checkout, a missing
packaged corpus or a non-isolated interpreter.

The installed package generates the 104-event pack from its packaged 50-case
charter, checks the repository recipe, invokes the two fixed toy hook programs,
publishes the review and verifies it by regeneration. All product subprocesses
use isolated module invocation. The installed console entry point also receives
a help check outside the checkout with Python path overrides removed.

The helper writes an identifier-free result only after counts and all expected
exit codes pass. Six fast unit tests cover the import-location guard before the
full installed-wheel invocation. This checks a real built artifact without adding
runtime dependencies or relying on editable installation behavior.

## Permissions, scope and limits

The workflow uses contents-read permission, disables persisted checkout credentials,
pins actions by full commit SHA, bounds both job durations and uses no repository
secrets. It does not post PR comments, push commits, publish releases or run corpus
command strings. Package/browser setup uses network access; the zero-request
assertion applies to rendering the offline report, not to installing dev tools.

Browser and installed-wheel acceptance currently run on Ubuntu with Python 3.11.
They complement, not replace, unit/contract and installed README checks on Linux,
macOS and Windows with Python 3.11 and 3.13. One Chromium engine is covered, using
in-memory HTML with its own content security policy. Local-file URL loading,
other engines, screen readers and production agent runtimes remain unverified.
The built wheel is a test artifact, not a release.

Review publication caps the sum of encoded artifact bytes at 128 MiB before
staging. Rendering allocates in memory first; that cap is not a peak-memory
limit. Input byte limits and bounded cleanup reads are separate guarantees.

A future reusable consumer Action should accept an explicitly selected hook and
keep private corpus data local or aggregate-only. It must not run privileged code
from untrusted PRs or trust detached report counts. Automatic PR-comment posting
is intentionally outside this acceptance workflow.
