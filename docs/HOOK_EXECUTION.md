# Hook execution and failure evidence

`hooks` validates both hook commands, both workspace arguments, the comparison
gate, the timeout and the worker count before invoking either hook. Timeout must
be finite, greater than zero and at most 86400 seconds. Jobs must be positive.
JSON argv must not contain NUL bytes. The same validated corpus capture supplies
both hook invocations and the final comparison, even if on-disk corpus files
change during invocation. The report binds the bytes the hooks actually saw,
not a second read. A caller-selected hook is still an
unsandboxed executable; corpus commands remain input data and never execute.

## Exit-code precedence

A hook's crash, timeout, invalid output or inability to start has an
indeterminate effect and is also an explicit source failure. Identical failures
on both sides are not a healthy unchanged comparison. The kernel report and
hook summary share the same error gate and source failures.

- 0: valid comparison, no configured regression and no invocation failure.
- 1: valid comparison with a configured regression and no invocation failure.
- 2: invalid input or broken exact-byte binding.
- 3: hook/source failure after usable decisions can be formed, or report output failure.

Exit 3 takes precedence over exit 1. A hook's exit 2 is a deny decision, not a
process failure. An ask mapped to indeterminate by `--ask-as` is not itself a
process failure; it remains a configured policy mapping and can trigger exit 1.

`record` also returns 3 for invocation failures while retaining valid recorded
decisions and its diagnostic outcomes file. Replaying those decisions later
compares recorded effects only; it does not rerun the original hook or infer
process health from a reason string. Failure evidence for the immediate `hooks`
comparison comes directly from the recorder's structured observations.

The JSON report stays free of machine-local reproduction paths. The existing
kernel Markdown includes local reproduction argv, and legacy report timestamps
still require `SOURCE_DATE_EPOCH` for byte-identical reruns. Timing remains an
observation, not part of decision identity.
