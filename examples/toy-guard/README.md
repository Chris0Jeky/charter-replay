# Toy guard: version 1 against version 2

`guard_v1.py` and `guard_v2.py` are two versions of a small PreToolUse hook.
Version 2 exempts `--help` and dry runs, and matches flag prefixes, but it
drops `git clean` from its list. Replaying both over the charter corpus shows
both effects:

```bash
charter-replay hooks \
  --baseline "python examples/toy-guard/guard_v1.py" \
  --candidate "python examples/toy-guard/guard_v2.py" \
  --corpus charter_replay/corpora/charter \
  --output reports/toy-guard
```

The run exits 1 because the default gate fails on newly allowed decisions.
[`report/summary.md`](report/summary.md) is the Markdown result and
[`report/report.json`](report/report.json) the machine-readable one. The
recorded decisions in `report/baseline/` and `report/candidate/` reproduce the
comparison without running either hook:

```bash
charter-replay replay \
  --baseline recorded:examples/toy-guard/report/baseline/decisions.jsonl \
  --candidate recorded:examples/toy-guard/report/candidate/decisions.jsonl \
  --corpus charter_replay/corpora/charter \
  --output reports/toy-guard-recorded
```
