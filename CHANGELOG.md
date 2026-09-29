# Changelog

## 0.1.0 (2026-09-29)

First release.

- `charter-replay hooks` records two PreToolUse command hooks over a corpus and
  reports newly blocked, newly allowed, unchanged and indeterminate decisions,
  broken down by case class and family, with a regression exit code.
- `charter-replay record` writes one hook's decisions as a recorded source.
- `charter-replay replay` and `validate` compare recorded or process sources
  over a pinned corpus (the decision-replay kernel).
- `charter-replay import` builds a private, scrubbed corpus from local Claude
  Code and Codex transcripts.
- Corpora: `charter` (50 hand-labelled cases) and `charter-v0.2` (494 cases).
