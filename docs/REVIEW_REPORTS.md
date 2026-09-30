# Offline and PR review reports

Both `hooks` and kernel `replay` publish three additional views next to
`report.json`: `report.html`, `pr-comment.md`, and `pr-comment-aggregate.md`.
For `hooks`, these are inside the output directory's `report/` subdirectory.
The original JSON/Markdown and all new views participate in one publication
transaction. A blocked new artifact restores the previous artifact set and
returns exit 3 rather than leaving a partially successful replacement.

## Open the full report locally

Open `report.html` in a browser. The page has no external assets, fonts or
requests. It shows the same gate, counts and explicit source failures as the
kernel report. Newly allowed dangerous cases come first. Filters select case
class, family, baseline effect, candidate effect, diff class and declared origin;
text search applies to the case rows. Reset restores all rows. Without
JavaScript, all cases remain readable and inactive filter controls stay hidden.
Keyboard labels, focus indicators, a live result count and horizontally scrolling
tables support small screens and keyboard use.

Effects are not inferred runtime outcomes. A reason starting with a familiar word
is still untrusted text, not structured evidence. Label scoring retains the
[metrics limitations](METRICS.md). Generated origin flags are declarations, not
verified lineage or independent labels. The HTML omits volatile timestamps and
latency; the legacy JSON timestamp still needs a fixed `SOURCE_DATE_EPOCH` for
byte-identical reruns.

This full report contains commands and hook reasons. Escaping is not
anonymization. Do not upload it from a sensitive corpus without reviewing its
contents. The page encodes HTML/attributes and displays control and directional
characters visibly. Its Content Security Policy permits only the exact bundled
script and style hashes and denies other resources. No corpus data enters script
source, event handlers or an HTML insertion API.

## Review text and aggregate publication

`pr-comment.md` contains gate/counts, source-failure counts and at most 20 changed
case ID previews, ordered with dangerous relaxations first. It omits commands,
reasons, family names, policy IDs and corpus metadata. A long ID is truncated
visibly. Output is bounded to 16000 UTF-8 bytes. The pure renderer accepts an
explicit limit from 0 through 100 and an optional bounded HTTPS report link
without credentials. The CLI does not post comments or contact GitHub.

Case IDs themselves can be sensitive. `pr-comment-aggregate.md` omits all case,
policy, corpus and run identifiers. It contains only controlled categories,
aggregate counts, gate status and limitations. Counts can still be sensitive in
a particular context; aggregate mode does not promise differential privacy.
Both text variants have the stable marker `charter-replay:review.v1` for an
explicitly authorized future comment updater. A static text artifact is not
an authenticated attestation, and consuming CI workflows must verify its origin.

## Validation

Unit tests check hostile markup, attributes, Markdown links and mentions,
directional controls, byte stability, input immutability, prioritization,
identifier omission and byte/row limits. Contract tests verify hook failure
agreement across views, kernel-only replay output, and transactional rollback.
The existing output-boundary checks include all new report names.

A local Chromium 144 check exercises filters, reset, search, no-JavaScript
fallback, hostile text and a 390-pixel mobile viewport. It observes zero network
requests, no script errors, no injected image/script elements and no page-wide
horizontal overflow. The test loads generated HTML in memory with its CSP:
container policy blocks file-URL navigation. Opening a file URL on a user's
machine, other browser engines and screen-reader behavior are not certified by
that check. No browser dependency is added to the package or required test lane.
