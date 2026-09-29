# Bounded POSIX variant packs

`charter-replay variants` derives command strings. It does not run a shell, a
corpus command, a hook, a network request or a subprocess. A seed's supplied label
is inherited under explicit assumptions. The generator does not certify safety,
prove shell equivalence or manufacture independent labelling evidence.

## Generate and verify

Run from a checkout containing the command. The output parent must exist; the
output directory must not exist, even as an empty directory or a dangling link.

```console
python -m charter_replay.app variants generate --source charter_replay/corpora/charter --output ./derived --domain posix-external.v1
python -m charter_replay.app variants verify --source charter_replay/corpora/charter --pack ./derived
```

The installed console entry point accepts the same `variants` arguments. The
standalone `python -m charter_replay.variants_cli` entry point also works. Success
returns 0; invalid arguments, bindings and publication failures return 2. These
commands do not create a policy comparison and do not use gate exit 1 or policy
process failure exit 3. The existing hook and replay exit contracts do not change.

Verification requires the original exact-byte source. It regenerates every byte
of the four core files rather than trusting a sidecar's claimed self-digest.
Editing a derived command, rebinding its corpus manifest and changing the sidecar
to match still fails verification. Reformatting a source file and updating its
manifest produces a different source identity, even when its JSON values match.

## The domain is an assertion by the caller

`posix-external.v1` means a non-interactive POSIX shell, the same external tools
and configuration, no aliases or functions for admitted executable names, and a
standard external `env` preserving the environment. This is not host detection.
Generation works on Windows too, but its output still describes POSIX commands.

The initial vocabulary is deliberately finite: `git`, `rm`, `rmdir`, `cp`, `mv`,
`ls`, `cat`, `grep`, `find`, `head`, `tail`, `sed`, `awk`, `sort`, `uniq`, `wc`,
`cut`, `tr`, `diff`, `mkdir`, `touch`, `tar`, `gzip`, `curl`, `wget`, `scp`,
`rsync`, `npm`, `npx`, `node`, `python`, `python3`, `pip` and `pip3`. Their
arguments remain uninterpreted strings, including an interpreter's program text.
This vocabulary is not an allow list for safe commands or permission to run them.

For an admitted single literal command, the generator proposes three shapes:
leading space/tab, single-quoting every parsed word, and an `env` prefix. Single
and double quotes may delimit literal arguments. Unquoted operators, expansions,
globs, redirects, comments, backslash escapes, compound syntax, unknown executable
names and shell builtins are outside v1. Opaque labels are not transferred.
Each transform records a skip reason when it cannot apply. No-op quoting is also
a skip. There is no random selection, recursive composition or silent truncation.

The source's full seeds, timestamps, case labels, rationale and optional working
directory remain intact. Derived IDs bind the source manifest digest, generator,
domain, seed ID and transform. Derived events and cases use the existing
`generated-variant` provenance vocabulary. Existing v1 readers load the two-file
corpus, but do not thereby verify the additional lineage.

## Files, limits and publication

The generated directory contains `events.jsonl`, `cases.jsonl`,
`corpus-manifest.json` and `lineage.json`. The sidecar records the domain,
assumptions, generator, transforms, seed links, skips and source/output manifest
digests. Verification covers these four files, not unrelated files placed beside
them. No timestamp, absolute machine path or random identifier is added.

The limits are 5,000 source events and cases, 15,000 derived events, 4,096 UTF-8
bytes per admitted or derived command, 8 MiB per source JSONL file, 64 KiB for the
source manifest and 64 MiB for all generated files. `--max-derived` may lower,
but not raise, the event budget. A budget failure publishes no partial selection.
Files are size-bounded and record-count-bounded before JSONL decoding. Symlinks,
FIFOs, devices, directories and files replaced between admission and open are
rejected as file inputs.

Generation stages files beside the destination, reserves a new directory and
publishes each file with a no-replace hard link. The corpus manifest is published
last as the commit marker: a reader never sees a valid manifest for a partial
normal publication. The directory itself can briefly exist without a manifest.
On failure, cleanup removes only unchanged files owned by this publication and
preserves other writers' files. A hard-link-capable filesystem is required;
unsupported filesystems fail rather than silently weaken no-overwrite behavior.
This is not crash-durable storage or protection against a hostile process that
can replace parent directories. Use caller-owned, non-adversarial directories.
A process crash can leave an incomplete directory; inspect and remove it manually
before retrying. The generator never replaces a pre-existing output directory.

## Included reproducible pack recipe

`examples/packs/charter-posix-v1.json` binds a 104-event pack: all 50 charter seeds
plus 54 derived shapes. There are 96 transform skips: 66 for unsupported
executable forms and 30 for opaque labels. These counts measure this restricted
vocabulary, not universal reachability. Dangerous and benign seeds both produce
variants. Cases sharing a seed are dependent observations, not 54 new votes.

```console
python -m charter_replay.app variants generate --source charter_replay/corpora/charter --output ./derived --domain posix-external.v1 --recipe examples/packs/charter-posix-v1.json
python -m charter_replay.app variants verify --source charter_replay/corpora/charter --pack ./derived
```

Source manifest SHA-256:
`ce500fe221ba4d49b107ad83895c97fadebf19a6998916b75ff02bf9a49ef9e2`.
Output manifest SHA-256:
`b1d9d64b3d532d4a1bbcb3a7ef575a83bef0b305ab846a8d52797081127447f1`.
The recipe records all four expected file digests, generator/domain versions,
source/output manifest digests and counts. `--recipe` checks them against the same
captured bytes used for publication, before reserving the output directory. A
stale recipe, a changed source, unexpected recipe keys or a malformed recipe
fails with exit 2 and publishes nothing. This avoids committing expanded data
that can drift away from the generator. Tests rebuild the complete 104-event pack
and verify every digest. The checked recipe is a repository example; installed
users can generate the same pack from the packaged charter seed.

A recipe binds the expected bytes, not the truth of supplied labels. Its digest
values are not digital signatures. Regeneration plus review of the source and
recipe is still required. Keep the generated directory local or package its four
files for distribution; any ZIP's compression metadata is outside corpus identity.

## Privacy and evidence limits

Generation is not scrubbing. It preserves all source bodies, and lineage contains
seed identifiers. Keep derived packs private when their source is private; a
successful verification is neither anonymization nor permission to publish.
The repository's checked recipe uses only the synthetic charter source material.
A source digest binds bytes, not their author, truth, review quality or fitness.
The source-hook-derived labels in other packs remain source-hook-derived labels.
A clean replay on variants is not evidence that untested shapes are unreachable.
