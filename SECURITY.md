# Security policy

## Supported versions

Only the latest 0.x release receives fixes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(**Security > Report a vulnerability**). Please do not open a public issue for
a vulnerability. Reports are read and answered on a best-effort basis; there is
no guaranteed response time.

## Security boundary

charter-replay compares policy decisions. It never executes the commands in a
corpus, and it is not a sandbox, a guard or an enforcement layer. The hooks you
point it at are ordinary programs that it runs with your privileges: run only
hooks you trust, and isolate them yourself if you need containment.

## Corpora and reports

Do not submit credentials, private repository names, raw transcripts, customer
data or working exploit payloads. When a synthetic command reproduces the
problem, send that instead. `charter-replay import` output is private even
after scrubbing and must never be published or attached to an issue.
