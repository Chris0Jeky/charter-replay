# GitHub Action

The repository root is a composite Action that runs `charter-replay hooks` in
the caller's job. It installs the tool from its own checkout, so pinning the
Action by commit SHA pins the tool revision exactly (the build backend it
installs with is not pinned; see Runner requirements). It needs no token
permissions, uploads nothing and posts no comment.

## Least-privilege workflow

```yaml
name: Hook replay
on: pull_request            # never pull_request_target

permissions:
  contents: read

jobs:
  replay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          persist-credentials: false
      - id: replay
        uses: Chris0Jeky/charter-replay@<sha>
        with:
          baseline: python hooks/guard_main.py
          candidate: python hooks/guard.py
```

Check out the baseline hook yourself (for example a second checkout of the
base ref into a subdirectory) and point `baseline` at it. The step fails when
the CLI exits nonzero, after the outputs and job summary are written. Add
`continue-on-error: true` to the step to read the outputs and decide yourself.

## Inputs

| input | default | meaning |
|---|---|---|
| `baseline`, `candidate` | required | hook commands: POSIX-quoted words or a JSON array |
| `corpus` | bundled `charter` corpus | corpus directory |
| `workspace` | none | template directory copied into each hook's cwd |
| `runtime` | CLI default (`claude`) | `claude`, `codex`, `codex-legacy` or `gemini` (see RUNTIME_CONTRACTS.md) |
| `ask-as` | CLI default (`deny`) | replay effect of an `ask` decision |
| `hook-timeout` | CLI default (10) | seconds per hook invocation |
| `jobs` | CLI default (4) | parallel invocations |
| `fail-on` | CLI default | comma-separated classes that fail the gate |
| `output` | fresh directory under the runner temp | output directory |
| `summary` | `true` | append `summary.md` to the job summary |

An empty optional input is not passed to the CLI, so its default applies.
Every input reaches the shell through `env:` and quoted expansion
(`"$CR_BASELINE"`), and the arguments are a bash array. No input is
interpolated into script text, so a command substitution or backticks in an
input are data to the CLI, not shell syntax. The self-test job asserts this.

## Outputs

| output | value |
|---|---|
| `exit-code` | the CLI exit code: 0 pass, 1 regression, 2 invalid input, 3 hook or source failure |
| `gate` | `pass`, `regression` or `error`, read from `summary.json` (`fail` becomes `regression`) |
| `output-dir` | directory with `summary.json`, `summary.md`, recordings and the report |

`gate` is `error` when the gate reports an error and also when no
`summary.json` exists, which is what an invalid-input exit (code 2) produces.
The job summary carries `summary.md` truncated at 60 KiB with a marker.

## Runner requirements

Python 3.11 or newer as `python3` or `python` on `PATH` (GitHub-hosted Ubuntu,
Windows and macOS runners have it). The Action does not install or select a
Python version. It creates a virtual environment under the runner temp and runs
`pip install --no-deps` on its own checkout. The package has no runtime
dependencies; pip fetches only the `setuptools` build backend, so the install
needs the package index unless your pip is configured with a mirror. That build
backend is resolved by pip at run time (`setuptools>=77`), not pinned by the
Action's commit SHA, and its code runs in your job during the install. Hooks run
with whatever is on `PATH` in your job, not the Action's environment.

## Trust

Read-only permissions limit the token, not the hook. As
[ARCHITECTURE.md](ARCHITECTURE.md) states, the hook runner is unsandboxed: a
candidate hook can read and write the job's filesystem, reach the network and
rewrite the corpus, recordings or reports it shares a job with. A report
produced in the same job as an untrusted hook is evidence of that job's claims
only, never a trusted artifact.

- Use `on: pull_request` with `permissions: contents: read`, no secrets and
  `persist-credentials: false`. Never `pull_request_target`.
- For fork or otherwise unreviewed candidates, use only the bundled public
  synthetic corpus or another public one. Never a private corpus.
- The Action uploads no artifact. If you add `actions/upload-artifact`, remember
  that `output-dir` holds every recorded decision and the full report, and the
  artifact is readable by anyone who can read the run. Do not upload it for a
  private corpus.
