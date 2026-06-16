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

### Changed
- **DNS resolver is configurable** (`dns.resolver` in the manifest, or `-resolver`)
  and defaults to the host's `resolv.conf` — no public IP baked into the runner. (#6)
- First real unit tests for the checkers (HTTP/DNS/TLS fixtures); `internal/rules`
  coverage 0% → ~34%. (#1)


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
