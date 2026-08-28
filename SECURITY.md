# Security Policy

## Supported versions

Only the **most recent tagged release** is supported: security fixes land on `main`
and ship in the next tag, and `agssh` is a single self-contained binary, so
upgrading is a drop-in. Pin to a SHA (or a full `vX.Y.Z` tag) in CI and bump it to
pick up fixes; the moving `@v1` tag always resolves to the newest release.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

- Preferred: open a private [GitHub Security Advisory](https://github.com/fabriziosalmi/agssh/security/advisories/new).
- Alternative: email **fabrizio.salmi@gmail.com** with the details and, if possible,
  a minimal reproduction.

You can expect an acknowledgement within **72 hours** and a status update within
**7 days**. Coordinated disclosure is appreciated: we will agree a disclosure
timeline with you once a fix is available.

## Scope

`agssh` is a fail-closed conformance runner: it makes network requests only to the
surfaces you point it at, and shells out to optional scanners (`gitleaks`,
`osv-scanner`, `cosign`) when present on `PATH`. Reports of unsafe defaults,
sandbox escapes, or checks that can be made to report a false `PASS` are in scope.
