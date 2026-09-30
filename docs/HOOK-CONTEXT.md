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
  On Windows a bare name without an extension is resolved as `<name>.exe`,
  since `CreateProcess` appends only `.exe`, but `CreateProcess` also searches
  the application and system directories before `PATH`, so a bare name can
  still resolve differently from the bytes hashed. Prefer an absolute path.
- Each later argv word that is an existing regular file: its basename, size and
  SHA-256.
- The `--workspace` template tree, as `shutil.copytree` would copy it (links
  followed): entry count, total bytes and one hash over sorted POSIX relative
  paths, entry kinds, sizes and file hashes. Empty directories count. A
  template that contains the recording's own output directory is unbound as
  `contains-output`: earlier recordings written there would otherwise feed
  decisions back into an input-only identity. This includes an output reached
  through a symlink or junction inside the template, since a copy follows links.

## Validation

`validate_hook_context` accepts a document only when its runtime and adapter
contract id form a known pair: every `(runtime, contract_id)` in the runtime
registry at the time of the call, plus the historical pair `codex` with
`codex-legacy-floor.v1` that recordings made before the Codex contract change
carry. A fabricated pair, such as `claude` with `codex-pretooluse.v1`, is
rejected even though each half is valid alone. A newly registered runtime needs
no change to the validator.

## Declared only

Recorded as names or hashes, never as values:

- Other argv words: the SHA-256 of the whole word, except that an absolute path
  (POSIX or Windows form) is first reduced to its basename so an output path does
  not make the identity host-specific. Inline code, regexes, URLs and `--flag=a/b`
  values are hashed in full, and so is any word that contains whitespace, even
  one that starts with `/` (a regex such as `/rm -rf/`). A real path argument
  with a space in it is therefore hashed whole: the identity then depends on
  where it lives, which costs portability between machines but never lets two
  different inputs share an identity. The raw word is never written, since it may carry a
  secret or a machine path.
- Directory arguments: recorded as kind `directory`, unbound with reason
  `not-captured` and listed as `argv-directory:<index>`. Their contents are not
  read, so two different trees at such a position are not distinguished.
- Environment: the names passed through to the hook, the two fixed Python
  settings, and the names the adapter sets. The values of passed-through and
  adapter variables are not recorded (the adapter's contain the workspace path).

## Unbound

`unbound` lists what a comparison must not assume is covered:
`ambient-environment-values`, `executable-dependencies`, `file-permissions`,
`helper-imports`, `mutable-external-state`, `network` and `time`. It also names
any component that could not be bound: `executable`, `argv-file:<index>`,
`argv-directory:<index>` or `workspace-template`, each with a fixed reason
(`unresolved`, `unreadable`, `limit-exceeded`, `not-captured`,
`contains-output`) on its entry. An unbound component still contributes to the
ID, so unreadable inputs never look equal to readable ones.

Descriptor reads are bounded before any content is read: 256 MiB per file,
256 MiB and 10,000 entries per template, counted while directories are listed.
The legacy fingerprint behind `policy_commit` (see
[hook input observations](HOOK-INPUT-OBSERVATIONS.md)) still reads argv files
whole and is not bounded by these limits. A link cycle or a broken link in the template is
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
