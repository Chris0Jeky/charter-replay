# Verified POSIX variants implementation plan

Goal: implement issue #13 without depending on unmerged runtime or report changes.
Spec: issue #13 and ADR 0004 in architecture PR #2.

The generator stays stdlib-only, supports Python 3.11+, never launches a process,
and preserves all seeds. It transfers supplied labels, not independent truth.
Assumption: the caller explicitly selects `posix-external.v1`, where admitted
executable names resolve to external tools with no aliases/functions and unchanged
configuration. Unsupported grammar is a visible skip. The assumption is reversible
by adding a separately versioned domain; do not broaden v1 in place.

## Tasks

1. Add `variants.py`: bounded pure lexical derivation, stable IDs, inherited labels,
   three transforms and skip reasons. Test dangerous and benign cases, quoted
   literals, shell expansions, unsupported executables, repeat input and budgets.
2. Add `variant_packs.py`: bounded exact-byte source capture, deterministic legacy
   corpus plus lineage, exclusive destination reservation, manifest-last commit,
   rollback of only owned files and byte-for-byte regeneration verification.
   Test tampered/rebound files, duplicate lineage keys, relocation, symlinks,
   non-regular files, publication failure and pre-existing destinations.
3. Add `variants_cli.py` and the additive `app.py` route. Test successful generation
   and verification, explicit domain, invalid arguments and input-error exit 2.
4. Generate the charter seed pack reproducibly, document assumptions and residual
   limits, run focused/full tests and publish an independent draft PR against main.
5. Add report coverage separately: verified seed/derived joins and per-transform
   changes, with missing/forged report regressions before implementation.

## Review focus

Do not reinterpret shell expansions as literals. Do not replace an existing empty
output directory. Do not treat a self-edited digest as lineage verification. Keep
source capture bounded even when bytes change during a read. Never turn inherited
labels into independent votes or a reachability/safety certificate.

## Validation record

The ZIP matches main's Git tree `00f5903b730f262c3db48ddbf66ace491597e058`.
The first 26 generator/pack/CLI regressions fail against missing interfaces, then
pass. Further review adds admission, publication-race and exact-capture tests.
The record-count preflight test fails before its repair and passes afterward.
Hosted exact-head CI remains the authority for the supported operating systems;
local Linux results do not imply a Windows or macOS pass.

Distribution decision: commit a checked pack recipe and all four file digests
under `examples/packs`, not an opaque generated archive. `--recipe` verifies the
same captured bytes before publication. Tests materialize all 104 events and
verify every bound digest. Generated output remains reproducible from source.
