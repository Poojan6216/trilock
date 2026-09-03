# Security policy

Trilock is a security control, so a bug in it is a security bug. Please report
privately, and expect a straight answer.

## Report a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/Poojan6216/trilock/security>. You will hear back within a
few days; this is a small project with one maintainer, so "a few days" is
honest rather than "24 hours".

Please include the policy file, the tool calls in order, and what Trilock
decided versus what it should have decided. The audit log
(`.trilock/audit.jsonl`) is the ideal attachment: `trilock replay` reproduces
every decision from it, it names every rule that fired, and it never contains
secret values.

## In scope

- Any way to complete the lethal trifecta in one session without a human
  approval: untrusted input, sensitive data and an external action.
- Taint evasion: content the ledger should have attributed to an untrusted
  source and did not (encoding, chunking, laundering through another tool).
- Session confusion: one principal's provenance applied to another, or a
  session that should have been refused as degraded and was not.
- Approval bypass: an escalation that resolves without a human, a reused
  nonce, or an approval memory that fires on a different call.
- Secret values appearing in logs, audit records, error messages or
  persisted files.

## Out of scope, by design

- Two-leg *integrity* attacks (untrusted input + external action with no
  sensitive data) under `strict` and `dataflow`. The threat model says why;
  the `integrity` policy exists to close them at a utility cost.
- Attacks that require the operator to have written a policy classifying a
  tool wrongly. Report those as documentation issues if the docs led you
  there.
- The advisory detectors. They are advisory; a false negative there is not a
  bypass, because no decision depends on them.

## Supported versions

The latest minor release on PyPI. Older releases receive fixes only if the
fix is trivial to backport.
