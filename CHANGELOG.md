# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
