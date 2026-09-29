# Contributing

- **Open an issue first** for anything beyond a small fix, so the scope is
  agreed before the work.
- **One purpose per pull request.** Keep the change and its tests together.
- **Synthetic fixtures only.** Commands, paths, hosts and names in tests and
  corpora must be fictional.
- **Corpus cases** need their provenance, a case class (`dangerous`, `benign`
  or `opaque`), a one-line rationale, and a note on why they are not a
  duplicate of an existing case.
- **Run the checks** before opening a pull request:

  ```bash
  python -m unittest discover -s charter_replay/tests -v
  python -m ruff check charter_replay examples
  python -m black --check charter_replay examples
  ```

- **Stay inside the scope.** This is decision replay: no live interception,
  no policy language, no new decision effects. New runtime dependencies,
  schema fields, integrations and public claims need a design issue first.
- Never include real secrets, private commands, malware or instructions for
  bypassing someone else's controls.
