# Aggregate-only publication (`aggregate.v1`)

The full summary (`summary.md`, `summary.json`) and the report carry free text
from the corpus: case family names, event ids, commands, hook reasons and paths.
For a private corpus every one of them can be sensitive, and a job summary is
readable by everyone who can read the workflow run. `aggregate.v1` is a counts-only
artifact that is safe to publish, and it is checked before it is written.

## What it holds

A deterministic JSON document (`aggregate.json`: sorted keys, ASCII, LF, no
timing) and a Markdown rendering (`aggregate.md`, marker
`<!-- charter-replay:aggregate.v1 -->`). Both hold only:

| field | content |
|---|---|
| `gate` | `status` (`pass`, `fail`, `error`), `fail_on`, `triggered` (replay gate classes) |
| `events` | number of events |
| `counts` | events per diff class (`unchanged`, `newly-allowed`, ...) |
| `case_classes` | events per `charter-case.v1` `case_class` (`dangerous`, `benign`, `opaque`) |
| `hook_outcomes` | per side, count per hook outcome (`allow`, `deny`, `crash`, ...); `null` when built from a report directory alone |
| `source_failures` | per side, count per failure code; every code the tool emits has a key, and any other code is counted as `other` |

Never included: event ids, commands, reasons, family names, rationales, paths,
policy ids, context ids, hashes, label text or timestamps. Hashes of low-entropy
inputs (a short command, a small family name) can be guessed, so none is emitted.
The Markdown renderer emits only fixed vocabulary and integers, so it has no
free text to escape. Small counts can still disclose information about a private
corpus; this is not differential privacy.

Size is bounded by the vocabularies, not by the corpus: at most 4 KiB of Markdown
and 6 KiB of JSON. A unit test renders every vocabulary entry at the largest
count, so the bound can only be exceeded when a vocabulary grows.

## Written by `hooks`

`charter-replay hooks` writes `aggregate.json` and `aggregate.md` into `--output`
next to `summary.json`. Both are in the stale-output list, so a rerun that fails
cannot leave a previous run's aggregate looking current. The aggregate is built
from the just-written `report/report.json`, after it is re-admitted against
`report/run-manifest.json`, and with the run's per-side hook outcomes.

If the aggregate is refused (see below) the summary files are still written, the
aggregate files are not, and the command exits 3 with a fixed message.

## The `aggregate` command

```bash
charter-replay aggregate --report reports/demo/report --output aggregate.json [--markdown aggregate.md]
```

It reads `report.json` and `run-manifest.json` from a kernel report directory and
re-validates them with the existing validators: the manifest and its run id, the
event, case and decision records, the recomputed classifications, counts and
gate, and the source failures. The rebuilt report must equal the supplied one.
Any mismatch exits 2 with a fixed message. It refuses an existing output file
(exit 2) and creates the files exclusively. A kernel report directory holds no
hook outcomes, so `hook_outcomes` is `null` there.

The check proves that the report is consistent with its manifest. It does not
read the corpus, so it does not prove authorship, and it does not authenticate
the run.

## Leak verification

Before anything is written, every free-text value of the report is collected:
every string in the result rows (events, cases, decisions), source failures and
policy and corpus identities, plus the corpus, report and output paths. A value
of 4 characters or more that is not purely digits is looked for as a substring of
the rendered JSON and Markdown bytes (and, for JSON, in its `\u`-escaped form). If
one is found, `aggregate.v1` is refused: exit 3, the fixed message
`aggregate refused: it contained corpus text; nothing was written`, and nothing
is echoed.

A value that is already part of the fixed text is not a leak and is skipped: the
fixed vocabularies (diff classes, outcomes, case classes, gate statuses, failure
codes, schema names) and the template words. A family called `unchanged` or `gate`
is therefore fine. The check compares whole values, so it catches a renderer that
emits an identifier, not one that emits only part of it. It is the last of three
layers: the builder reads only vocabulary keys, and both renderers refuse any
document that is not exactly the fixed shape.

## GitHub Action

`summary-mode: aggregate` appends `aggregate.md` to the job summary instead of
`summary.md`, and keeps the CLI's stdout (which prints the full summary) out of
the step log, which is as visible as the job summary. `full` is the default and
changes nothing. The output `aggregate-path` names `aggregate.json`. See
[ACTION.md](ACTION.md). Use `aggregate` for a private corpus. The output
directory still holds the full summary, report and recordings; do not upload it.

Aggregate mode hides stdout, not stderr. When the input itself is invalid (a
missing or mismatched corpus entry), the error printed on stderr, and so in the
step log, can still name a corpus entry. Validate a private corpus locally
before wiring it into a shared workflow.
