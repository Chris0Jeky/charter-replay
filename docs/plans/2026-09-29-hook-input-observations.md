# Hook input observation repair

Goal: implement issue #19 without claiming that the legacy hook fingerprint is a
complete context identity or immutable snapshot.

Assumption: preserve the current fingerprint algorithm and manifest schema.
Reason: this is a narrow health and attribution repair, not a migration.
Reversible by a separately versioned source/context model. Cost: executable bytes,
imports, environment, workspace inputs and restored-between-read changes remain
outside this fingerprint's evidence.

1. Reproduce changed/deleted argv files, initial/post read failures, missing health
   propagation, and a real self-modifying synthetic hook whose allow reply is
   currently reported healthy. Keep one clean compatibility control.
2. Capture the legacy fingerprint before workspace preparation. Initial read
   failure is invalid input and starts no hook. Retain this original fingerprint
   in the manifest rather than calculating identity after recording.
3. Observe the fingerprint again after all invocations. Changed or unreadable
   input contributes a structured source failure while preserving real replies,
   existing process failures and observational latency. Existing record/hooks
   exit-3 propagation handles these failures, with no renderer special case.
4. Run focused and complete available local tests, publish an isolated draft on
   #18, and check all hosted test/install, lint, build and acceptance jobs against
   the final head. Document the remaining v1 provenance limits precisely.

Review focus: no private paths in new diagnostics, no loss of real replies, no
rewriting an observed source change as a deny, no claim that two equal fingerprints
prove stable context, and no inference of process health when replaying an old
recorded v1 decision file alone.
