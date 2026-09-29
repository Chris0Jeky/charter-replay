# Initial increments implementation plan

Goal: make existing shell replay extensible, failure-aware and reviewable before
adding broader action kinds. Spec: `docs/ARCHITECTURE.md` and ADRs in PR #2.
Execution is inline in isolated branches, as authorized by the working brief.

## Global constraints

Python 3.11+, stdlib only, Linux/macOS/Windows, no corpus execution, strict v1
readers, exact-byte manifests, exit codes 0/1/2/3, and no private public fixtures.
Docs use plain present-tense prose and no em dashes. No package release occurs.

## Review focus

Unknown runtime must not launch a process. Both failed hooks must not pass.
Nested cwd and writable hook state must not cross event boundaries. HTML and
Markdown must treat all corpus text as untrusted. Derived labels and timing
must not masquerade as independent, deterministic safety evidence.

## 1. Adapter extraction (#3)

Files: new `charter_replay/adapters/{__init__,base,claude,codex}.py`, modify
`hooks.py`, add `tests/unit/test_runtime_registry.py`.
Interface: `get_adapter(name: str) -> RuntimeAdapter`; protocol methods
`build_payload(event, *, workspace, index) -> dict`,
`classify(exit_code, stdout, stderr) -> tuple[str, str]`, and
`environment(workspace) -> dict[str, str]`, plus name/contract_id.

- [x] Add registry, unique contract identity, payload parity, reply parity,
  environment and unsupported-name tests; run and observe missing interface.
- [x] Move the current pure grammar unchanged into explicit adapters. Keep
  hooks compatibility facades and process ownership in the runner.
- [x] Run existing hook tests and full discovery: 192 tests, one Windows-only
  skip on Linux. Pinned Ruff/Black await CI because package installation is
  unavailable locally. Commit the extraction separately.

## 2. Failure-aware admission and recording

Files: `app.py`, `hooks.py`, new contract tests in
`tests/contract/test_hook_failures.py`.
Interfaces: preflight both HookSpec values and workspaces before either side
runs; derive structured source failures from outcomes; publish one coherent
report/summary gate and preserve source-failure precedence.

- [ ] Add both-side crash, malformed output, timeout and single-record failure
  regressions, invalid second-side hook and invalid gate/options no-launch tests.
- [ ] Verify failures against baseline; validate finite positive timeout and
  positive jobs; propagate failures without folding them into allow/deny.
- [ ] Assert exits 0/1 remain on healthy fixtures, 2 on invalid input, 3 on
  process failures; rerun the complete suite and commit.

## 3. Isolated event workspaces

Files: `hooks.py`, `tests/unit/test_hook_workspace.py`.
Interface: each event gets a fresh template copy; process cwd equals its
contained payload cwd; environment retains the event's workspace root.

- [ ] Prove a stateful fixture contaminates serial events today and a nested
  cwd is not honored; verify failures before repair.
- [ ] Prepare/cleanup inside each worker, preserve input order, and handle
  copy/run errors without leaking temporary directories.
- [ ] Verify serial/parallel parity, template immutability and cleanup; run all
  tests and commit independently of runtime grammar changes.

## 4. Deterministic label metrics and report renderers

Files: new `scoring.py`, `review_reports.py`, integrate `app.py`; corresponding
unit and contract tests.
Interfaces: `score_labels(report) -> dict`, `render_html(report) -> str`,
`render_pr_comment(report, *, limit=20) -> str`. Stable renderers consume the
same report; measurements never enter stable summaries or run identity.

- [ ] Add exact small-sample counts/denominators, empty strata and exclusion
  tests; hostile family/ID/reason HTML/Markdown fixtures; byte-equality tests.
- [ ] Implement rates and clearly qualified descriptive intervals; static
  standalone HTML with accessible filters; bounded default aggregate PR text.
- [ ] Write measurement percentiles only to an observational sidecar. Verify
  all formats agree with counts/gate; run full checks and commit in reviewable
  metric/report increments.

## 5. Conservative variant derivation

Files: new `variants.py`, CLI integration and tests.
Interface: bounded deterministic pure transformations, strict applicability,
source/output digest-bound lineage and a legacy-loadable two-file corpus.

- [ ] Add inert seed cases covering quoting, wrappers, prefix, unsupported
  compound syntax, deterministic IDs, input immutability, budget and no-execute.
- [ ] Implement only declared POSIX domains; record skips rather than invent
  grammar equivalence. Keep original 50 charter seeds in the derived pack.
- [ ] Validate the generated corpus with the kernel and regenerate identical
  bytes; test lineage mutation and source/output binding; run full checks.

## 6. Least-privilege Action

Files: composite action, stdlib launcher, workflow example, docs and tests.
Interface: arguments through environment/argv, preserved CLI exits, aggregate
job summary, optional explicitly consented full report artifact.

- [ ] Test malicious argument strings, exit forwarding, output path handling
  and private aggregate output before implementing the launcher.
- [ ] Do not execute PR code in privileged comment-posting context; use
  read-only permissions and no persisted checkout credentials.
- [ ] Exercise a synthetic invocation and inspect exact-head Action logs.

## Evidence contract

Each PR records changed / verified / NOT verified / residual risk. Compare the
published tree SHA against the tested local tree and fetch CI for the exact PR
head. Do not claim Windows/macOS, independent review, live runtime certification
or a release unless those checks actually occur. Self-review is not independent
review. Unfinished scopes remain open issues or draft PRs.
