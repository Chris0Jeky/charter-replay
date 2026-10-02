# Release verification and rollback

The established distribution path is a GitHub release. Publishing a release
starts `.github/workflows/release.yml`: Python 3.11 builds a wheel and source
archive, then the workflow attaches both to that release. The optional PyPI job
runs only when the owner has registered its trusted publisher and explicitly set
`PYPI_TRUSTED_PUBLISHER=true`. A skipped PyPI job means no PyPI publication was
performed; GitHub assets are a separate distribution destination.

## Prepare and qualify

Advance both `pyproject.toml` and `charter_replay/__init__.py` to the same version.
Move the completed changelog entries under a dated release heading, leaving an
Unreleased section. Runner version is part of the run identity: a version bump
changes newly generated run IDs, while existing recordings keep their manifests.
Keep historical fixtures and earlier release tags unchanged.

Review the final integration head and run the repository checks from
[CONTRIBUTING.md](../CONTRIBUTING.md). Public hosted qualification includes the
Linux/macOS Python 3.11/3.13 and Windows Python 3.11/3.13/3.14 suites, all Action
lanes, lint/build and the isolated installed-wheel/browser review checks. Record
the exact commit, results and platform skips. A local Windows pass establishes
only the local platform result.

Build artifacts in an isolated build environment:

```sh
python -m build
```

Check the wheel metadata and package version match. Install the wheel without
dependencies into a fresh environment, outside the source checkout, and run its
CLI help and a public synthetic hook/mutation smoke. The checked-in toy mutation
plan and corpus require the source checkout for their example files; the wheel
contains the runner, schemas and built-in corpora. The toy plan should complete
with a healthy baseline, one killed mutant, one survivor, no invalid/timeouts,
score 1/2 and exit 1. That exit is the expected sensitivity gate result.

## Publish and verify

Create the version tag/release targeting the qualified exact main commit.
Wait for both release build and GitHub asset-upload jobs to succeed. Verify the
tag resolves to that commit and download the attached wheel and source archive.
Record their SHA-256 digests and compare with the GitHub asset digests when
available. Repeat metadata and installed-wheel smoke checks on the downloaded
wheel; a local build alone does not verify the published artifact. Record the
optional PyPI job's actual result without changing owner activation settings.

## Roll back a consumer

The previous `v0.1.0` GitHub release remains the rollback artifact. Download its
original wheel from
[the v0.1.0 release](https://github.com/Chris0Jeky/charter-replay/releases/tag/v0.1.0)
and install that file into a clean environment:

```sh
python -m pip install --no-deps /path/to/charter_replay-0.1.0-py3-none-any.whl
```

Pin an Action consumer to the previously qualified full commit SHA if needed.
Keep previous tags/assets immutable. A repository-code rollback should be a
reviewed revert pull request with its own qualification, rather than moving a
released tag. Compare reports using their recorded runner versions and inputs;
a rollback does not make run IDs from different runner versions identical.
