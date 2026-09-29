# Hook decision diff

Gate: **fail** (fail on: newly-allowed, newly-indeterminate)

| class | events |
|---|---:|
| newly-allowed | 4 |
| newly-denied | 1 |
| newly-indeterminate | 0 |
| resolved-indeterminate | 0 |
| unchanged | 45 |

## Hook outcomes

| outcome | baseline | candidate |
|---|---:|---:|
| allow | 41 | 44 |
| deny | 9 | 6 |

## By case class

| case class | newly-allowed | newly-denied | newly-indeterminate | resolved-indeterminate | unchanged |
|---|---:|---:|---:|---:|---:|
| benign | 3 | 0 | 0 | 0 | 17 |
| dangerous | 1 | 1 | 0 | 0 | 18 |
| opaque | 0 | 0 | 0 | 0 | 10 |

## Families with changes

| family | changes |
|---|---|
| cluster-destruction | newly-allowed 1 |
| shared-history-rewrite | newly-denied 1 |
| worktree-loss | newly-allowed 3 |

Recorded hook decisions were compared; no corpus command was executed.
