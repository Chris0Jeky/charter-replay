# Hook context identity

Each `record` (and each side of `hooks`) writes `hook-context.json` next to its
decisions. It holds a versioned, input-only descriptor of what the recording was
given, and a full SHA-256 `context_id` over it. The version is `hook-context.v1`.

The descriptor is a consistency key: two recordings with equal IDs were given the
same captured inputs. It is not execution authentication, not repeat mode, not an
immutable snapshot and not a safety certificate.

## Input-only

Nothing in the descriptor derives from decisions, outcomes, exit codes or timing.
A different result under identical inputs keeps the same ID; a changed input under
an identical result changes it. That is why `recorded-policy-manifest.v1` cannot
serve as this key: its digest covers the decisions. Neither the manifest,
`decisions.jsonl` nor `policy_commit` changed.

The ID is `sha256("hook-context.v1" + NUL + canonical JSON)`, with sorted keys,
compact separators and UTF-8, so equal descriptors always give equal IDs.

## Bound

Read and hashed (bytes, not paths):

- The adapter contract id and runtime, the `ask` mapping, the per-invocation
  timeout and the `--jobs` value.
- The hook executable's bytes, resolved as the runtime would: a path-shaped
  `argv[0]` as given, a bare name on the `PATH` the hook receives. The name is
  part of the identity, so an alias is a different context.
  On Windows, `CreateProcess` searches the application and system directories
  before `PATH`, so a bare name can resolve differently from the bytes hashed.
- Each later argv word that is an existing regular file: its basename, size and
  SHA-256.
- The `--workspace` template tree, as `shutil.copytree` would copy it (links
  followed): entry count, total bytes and one hash over sorted POSIX relative
  paths, entry kinds, sizes and file hashes. Empty directories count.

## Declared only

Recorded as names or hashes, never as values:

- Other argv words: the SHA-256 of the word after a path-shaped word is reduced
  to its basename. The raw word is never written, since it may carry a secret or
  a machine path.
- Environment: the names passed through to the hook, the two fixed Python
  settings, and the names the adapter sets. The values of passed-through and
  adapter variables are not recorded (the adapter's contain the workspace path).

## Unbound

`unbound` lists what a comparison must not assume is covered:
`ambient-environment-values`, `executable-dependencies`, `file-permissions`,
`helper-imports`, `mutable-external-state`, `network` and `time`. It also names
any component that could not be bound: `executable`, `argv-file:<index>` or
`workspace-template`, each with a fixed reason (`unresolved`, `unreadable`,
`limit-exceeded`) on its entry. An unbound component still contributes to the
ID, so unreadable inputs never look equal to readable ones.

Reads are bounded before any content is read: 256 MiB per file, 256 MiB and
10,000 entries per template. A link cycle or a broken link in the template is
unbound as unreadable.

## Observation, not snapshot

The descriptor is computed before any workspace is prepared and again after the
last invocation. The file holds the initial one. If the second differs, the
recording fails with `hook-context-changed` (exit 3); if it cannot be read,
`hook-context-unreadable`. Each argv word keeps the kind it had initially, so a
path the hook creates as its own output stays a word and is not a change. The
converse follows: an input file that appears mid-recording at a path that did
not exist initially is not detected, since argv alone cannot tell it from an
output. A file
that is changed and restored between the two observations is not detected, and
invocations in between may see intermediate contents. The two sides of `hooks`
are observed when each begins, not together.

`summary.json` gains `contexts` (baseline and candidate IDs) and `summary.md`
one line with both.

## Privacy

No absolute path, user name, environment value or raw argv word is emitted.
Hashes can still reveal low-entropy inputs, such as a short word or a small
known file, to anyone who can guess them. Keep descriptors local when the inputs
are sensitive, and do not publish them by default.

`validate_hook_context` (in `charter_replay/hook_context.py`) checks the file
form strictly: exact keys, types, hex formats, fixed vocabularies, an `unbound`
list consistent with the components, and a recomputed `context_id`. Its errors
name a location, never the file's contents.
