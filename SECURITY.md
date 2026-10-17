# Security policy

## Status

`slhsig` 0.x is experimental and has not been independently reviewed. Production use is not
supported until the 1.0.0 release gate, which requires a published independent review.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting for this
repository. Do not open a public issue.

Include the affected version or commit, the parameter set, and a reproducer if you have one.
We will acknowledge the report, agree a disclosure date with you, fix it on the latest minor
release, and publish a RustSec advisory.

## Scope

In scope: incorrect signatures or verification results, secret-dependent timing in key
generation or signing, panics or unbounded resource use on untrusted input, secrets left in
memory that the crate owns, and fault-check bypasses.

Out of scope: weaknesses of SLH-DSA itself, compromised hosts, and misuse of the `hazmat`
feature.
