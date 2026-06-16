# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed (adversarial review pass)
- **TLS floor false-PASS, take 2.** The probe offered only CBC-SHA1 suites, so an
  AEAD/ChaCha-only-but-TLS-1.0-permitting server answered `handshake_failure` and
  was misread as "refused" → PASS. The probe now decodes the alert: only a clean
  `protocol_version` alert counts as a refusal; any other answer (or an unreachable
  host) is INCONCLUSIVE, never PASS.
- **IPv6 surfaces are no longer mangled.** `hostOnly`/`surfaceAddr` used first-colon
  splitting (`[::1]` → `[`), silently breaking the TLS/DNS/dynamic checks for every
  IPv6 surface. Now parsed with `net/url`.
- **AG-CI-02:** a top-level `permissions` block no longer hides a per-job
  `permissions: write-all`. **AG-CI-03:** now also flags `github.head_ref`,
  `with.repository: …head.repo…`, and `refs/pull/…/merge` checkouts, and matches
  `actions/checkout` exactly (no typosquat). **AG-CI-01:** uppercase commit SHAs
  accepted.
- **AG-CI-05:** reads the modern `required_status_checks.checks[]` (not only the
  legacy `contexts[]`) so a properly-protected branch isn't false-FAILed, and now
  requires ≥1 approving review.
- **AG-DNS-03:** the takeover body-fingerprint check is gated on a takeover-prone
  provider and the over-generic phrases ("Repository not found", "project not
  found") were removed — no more false FAIL on benign pages.
- **AG-SUP-02:** stronger lockfile markers — poetry/Pipfile match a per-dependency
  `sha256:` (not the lockfile-wide `content-hash`), yarn berry's `checksum:` is
  recognized, an empty `go.sum` no longer false-PASSes, and the weak composer
  `shasum` marker was dropped.
- **AG-PRV-04:** evaluates only `localStorage`/`sessionStorage` — server-set
  (`Set-Cookie`) cookies are no longer mis-attributed as un-minimized client
  storage (that's AG-PRV-05's job), and the storage JS is now exception-safe.
- **Engine:** declared `surface.paths` are now restricted to the **same origin**
  (an off-origin `//evil.com` path can no longer poison worst-case static analysis
  or the signed record), and fetch retries share one per-check budget instead of
  multiplying latency.
- osv-scanner results are also read from `groups[].ids` (modern schema), not only
  `vulnerabilities[].id`.

### Fixed
- **AG-HDR-08 (TLS floor) no longer false-PASSes.** The legacy-refusal probe used
  `crypto/tls`, whose client refuses TLS 1.0/1.1 on its own (Go 1.22+), so it
  scored PASS even against servers that still accept legacy TLS. Replaced with a
  raw TLS 1.0 `ClientHello` probe (with EC group/point-format extensions so ECDSA
  servers negotiate) that reflects the server's policy. (#2)
- **CI checks (AG-CI-01/02/03) parse a real YAML AST** instead of `strings.Contains`.
  Job-level `permissions` no longer satisfies the top-level rule, commented
  directives no longer count, and `pull_request_target` is flagged only when it
  actually checks out an untrusted ref. (#3)
- **AG-SUP-06 reads osv-scanner JSON**: a scan error / missing lockfile is now
  INCONCLUSIVE, not a misreported "vulnerabilities found". (#4)
- **AG-DNS-03 detects resolving-but-unclaimed takeover targets** via provider +
  body fingerprints, not only NXDOMAIN. (#5)

### Added
- **AG-SUP-02 is now implemented**: audits the recognised lockfiles present
  (npm/yarn/pnpm/Cargo/go.sum/poetry/Pipfile/composer) for integrity hashes. No
  recognised lockfile → INCONCLUSIVE (fail-closed). (#9)
- **AG-CI-05 is now implemented**: verifies the default branch is protected
  (required PR reviews + ≥1 required status check) via the GitHub API. Owner/repo
  from `GITHUB_REPOSITORY` or the `github.com` remote; without a token →
  INCONCLUSIVE, never a silent PASS. The verdict logic is a pure, fully-tested
  function. (#9)
- **Dynamic plane: AG-NET-07 and AG-PRV-04 implemented.** Service-worker hygiene
  (every registration's script and scope must be same-origin) and client-storage
  minimization (localStorage/sessionStorage/cookie keys must be within
  `allow.storage`). Each dynamic check is split into thin headless-browser
  observation + a **pure, hermetically-tested verdict** (offline-proof,
  pre-consent, egress-canary, service-worker, storage); a skip-guarded
  integration test drives a real browser when one is resolvable. (#9)
- **Multi-path surfaces**: a surface may declare extra `paths:`; static
  header/CSP checks are evaluated **worst-case** across the root + every path, and
  fetches now retry transient failures within the per-check budget. (#7)

### Changed
- **DNS resolver is configurable** (`dns.resolver` in the manifest, or `-resolver`)
  and defaults to the host's `resolv.conf` — no public IP baked into the runner. (#6)

### Tests
- The fail-closed gate is now pinned by an **exhaustive truth table**, and waiver
  governance (MUST-non-waivable, expiry, Gold segregation-of-duties, debt ceiling)
  by direct cases. Coverage: `internal/engine` 0% → ~59%, `internal/rules`
  0% → ~50%, `internal/manifest` 0% → ~75%. (#1)


## [1.0.0]

### Added
- **AGSSH-STD-001 v1.0.0** — property-based, risk-proportional conformance standard
  for air-gapped static surfaces: 57 rules across 9 families, three cumulative
  profiles (Bronze ⊂ Silver ⊂ Gold), assurance tiers, governed waivers, and signed
  external attestation. Rendered PDF plus a single-source generator that emits both
  the document and the runner's rule manifest.
- **`agssh`** — deterministic, fail-closed runner: single static Go binary, native
  DNS (`miekg/dns`) and TLS (`crypto/tls`), headless verification via `chromedp`,
  signing via `cosign`. Verification planes: static, dns, tls, dynamic, supply, ci,
  engine.
- GitHub Action wrapper (`action.yml`) with `conformant` / `report` step outputs,
  running from a prebuilt image published to `ghcr.io/fabriziosalmi/agssh`. Runtime
  image (`Dockerfile`) pinned to a base digest.
- CI: build, `go vet`, `gofmt`, `go test -race`, spec↔runner skew enforcement, and
  a goreleaser release pipeline.

[Unreleased]: https://github.com/fabriziosalmi/agssh/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/fabriziosalmi/agssh/releases/tag/v1.0.0
