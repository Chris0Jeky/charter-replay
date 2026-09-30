# Hook input observations

A recording observes the existing hook fingerprint before workspace preparation
and again after all invocations finish. Its recorded manifest retains the initial
fingerprint. Previously the manifest fingerprint was calculated only after the
hook ran, so a hook that changed its own script could be attributed to the final
bytes and leave an unchanged, apparently healthy comparison.

## Behavior

A changed final fingerprint adds `hook-input-changed` to structured source failure
evidence. An unreadable final fingerprint adds `hook-input-unreadable`. Actual
hook replies, outcome counts, decision effects and latency observations remain
intact. An allow reply is not rewritten to deny or indeterminate merely because
input change was observed; the recording's source health fails separately.

`record` returns 3 and prints this failure in its JSON summary. `hooks` propagates
the failure through `summary.json`, `report.json`, Markdown and HTML. Its gate is
error and exit 3 takes precedence over a triggered regression. Identical allow
replies from two self-modifying hooks cannot make that comparison pass.

An initial fingerprint read failure is invalid input: it starts no invocation for
that recording, prepares no workspace and writes no recording output. Its CLI
returns 2 with a fixed diagnostic that contains no private path or file body.
Each side is observed when its recording begins; this does not freeze or admit
both sides' file bytes together before the first side starts.

The fingerprint algorithm and `recorded-policy-manifest.v1` stay unchanged.
Unchanged hook inputs keep the same `policy_commit` value. That field still holds
the first 40 hexadecimal characters of the legacy fingerprint, not a Git commit.
New failure messages and codes use fixed text and reveal no input path.

The final observation reuses the initial classification of each argument. An
argument that was a plain word stays a word, so an output path the hook creates,
such as `--log /tmp/out.json`, is not reported as a changed input. An argument
that was a file and has vanished still changes the fingerprint.

## Evidence and limits

These are two observations of the existing argv/file fingerprint, not an immutable
snapshot. A script can change and restore itself between observations without
being detected. Several invocations can see different intermediate contents.
Equal fingerprints at the two boundaries do not prove a stable execution context.

The legacy fingerprint binds argv words and bytes of existing file arguments.
Executable inputs contribute their name, not executable bytes. Helper imports,
workspace templates, inherited environment, runtime adapter settings, permissions
and other external state are not newly bound by this repair. File reads retain
the existing fingerprint behavior; this is not a new hostile-filesystem or
bounded-source-snapshot interface.

The returned source failures and direct comparison preserve the observation.
A later replay of only a v1 `decisions.jsonl` and its manifest remains effect-only:
it does not reconstruct original process health from reason text or fingerprints.
Retain the original hook comparison and its provenance when reviewing that claim.
Neither the manifest nor these observations authenticate execution or authorship.

## Regression tests

`test_hook_input_changes.py` covers changed and deleted script files, initial and
final read failures, observation order, unchanged-manifest compatibility, preserved
process failures and two CLI cases with real synthetic self-modifying hook
programs. Those programs modify only their own temporary test scripts. Corpus
commands remain inert data and are never executed.

The next provenance increment needs an explicitly versioned source/context model
before repeat-stability results can claim that their inputs are comparable. Do not
use the output-dependent recorded manifest digest as that context key.
